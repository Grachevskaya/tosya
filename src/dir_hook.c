// SPDX-License-Identifier: GPL-2.0
/*
 * dir_hook.c - the data directories a package is not supposed to have.
 *
 * A package's data lives in directories whose names are known before anything is
 * looked up: /data/user/<u>/<pkg> (which /data/data/<pkg> is the same inode as)
 * and /data/user_de/<u>/<pkg>. Hiding those names is therefore a question about one
 * dentry name, asked inside the parent: the parent inode's
 * i_op is copied -- one copy per inode, everything but ->lookup unchanged, so no
 * other inode and no shared const table is touched -- and the copy's ->lookup is
 * tosya_lookup().
 *
 * The answer depends on who is asking, and the dcache is shared by everyone: a
 * name can be hidden from one caller and visible to the next. One inline hook,
 * on lookup_fast(struct nameidata *), makes the whole difference: before the
 * VFS asks the dcache, it probes the published set the same fixed number of
 * times for every name, then selects -- with conditional selects, not branches
 * -- the entry's stored mask bytes and precomputed hash(M), or the original
 * bytes and hash. The mask is generated once at publication and kept in the
 * entry; the hook never hashes or builds it.
 *
 * A mask that the dcache does not have takes the ordinary slow path. The
 * replaced ->lookup finds the entry by the dentry's hash and its stored mask
 * bytes, and leaves a negative dentry of its own (d_add(dentry, NULL)) without
 * asking the filesystem. The next fast walk finds that entry and answers
 * ENOENT. Every other name goes to the original lookup unchanged.
 *
 * The caller is the same identity the uid policy uses: the app id a process was
 * born with (tosya_tag_app()), never the uid it happens to run as now.
 */
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/rcupdate.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/stringhash.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "tosya.h"
#include "kaux.h"

/* TOSYA_DIR_BEGIN: scripts/extract_dir.py lifts this block into the host test */

#define DIR_ALIGN(p) ((u8 *)(((unsigned long)(p) + 7ul) & ~7ul))

/*
 * One name in the published set: hashed for the pair table, kept in the arena
 * twice -- the original bytes a candidate is compared by, and the mask bytes
 * the walk puts in nd->last. The entry also carries hash(M), precomputed at
 * publication so the walk never has to hash the mask again.
 */
struct dir_ent {
	u64 hash; // the name's hash, for the pair table
	u32 len;
	u32 name_off;
	u32 mask_off; // the stored mask bytes, one per name byte
	u32 mask_hash; // hash(M), precomputed at publication
};

/*
 * How many pair slots one query reads. The table is built so that every
 * (caller, name) pair is reachable within this many probes, and a query always
 * walks exactly this many and never stops early: a hidden name and a name that
 * is not in the set cost the same number of probes.
 */
#define DIR_PAIR_PROBES 16u

/*
 * A pair slot is the caller and the entry index + 1, packed into one word: the
 * entry only holds the name, and the same name is a different pair for every
 * caller. The caller is an app id (< TOSYA_APP_SPAN = 10000) and the entry
 * index is below TOSYA_HIDDEN_MAX = 8192, so sixteen bits hold each; zero is
 * "empty", which the + 1 keeps out of the entry field.
 */
#define DIR_PAIR_APP(slot) ((slot) >> 16)
#define DIR_PAIR_ENT(slot) ((slot) & 0xffffu)
#define DIR_PAIR_MAKE(app, ent) ((((u32)(app)) << 16) | (u32)(ent))

/* dir_hidden_probe()'s answer for a name that is not hidden: no entry index. */
#define DIR_HIT_NONE 0xffffffffu

/*
 * The published set. It is never written after it is handed over: a lookup
 * reads the pointer once, inside its own RCU read side, and then only touches
 * this object. A replacement is built on the side and published with one store;
 * the one it replaces is kept on a retired list rather than freed, because a
 * walk can still be using a pointer into its mask bytes.
 */
struct dir_names {
	u32 nent; // distinct names
	u32 pair_bits; // pair table: 1 << pair_bits slots
	u32 mask_bits; // cold-path mask table: 1 << mask_bits slots
	u32 arena_bytes;
	struct dir_ent *ent; // [nent] distinct names
	u32 *pair; // [1 << pair_bits], DIR_PAIR_MAKE(caller, ent + 1), 0 = empty
	u32 *mask_slot; // [1 << mask_bits], entry index + 1, 0 = empty
	u8 *arena; // the names, then the masks, then a zeroed TOSYA_NAME_MAX tail
	struct dir_names *retired; // kept alive: nd->last may still point into it
};

/*
 * One protected parent: the inode, the dentry the cache is asked through, the
 * table it had, and the copy the inode points at now. The numbers are the
 * record's identity in a report; the pointer comparison in tosya_lookup() is
 * what finds it, because each inode has a copy of its own.
 */
struct dir_guard {
	struct inode_operations iop;
	struct inode *inode;
	struct dentry *dentry;
	const struct inode_operations *orig;
	u64 ino;
	dev_t dev;
};

// One record waiting for the end of its stream.
struct dir_stage {
	u32 app;
	u32 len;
	u64 hash;
	u32 off;
};

static struct dir_names __rcu *g_dir_names;
/*
 * Replaced sets are kept, not freed: a walk that is past the fast hook can
 * still hold a pointer into one (nd->last.name), and the cold path reads it.
 * The module is pinned once the inline hook is installed, so this retention
 * ends with the boot; at teardown the whole chain is freed after a grace
 * period.
 */
static struct dir_names *g_dir_retired;

/*
 * The operations the filesystem itself uses for a protected parent. Every parent is on the same
 * filesystem, so one copy answers for the walk of a record that is no longer in the table -- and an
 * answer is what the caller needs: a lookup that reports "no such file" because this module lost track
 * of a directory would take the directory away from every process on the device.
 */
static const struct inode_operations *g_dir_fallback;
static struct dir_guard *g_dir_guard[TOSYA_DIR_MAX];
static u32 g_dir_guards;
/*
 * A module reference taken with the first record. i_op has no owner the VFS
 * could get a reference on, so without this a task that read ->lookup just
 * before unload could enter freed module text. Armed, the module refuses to
 * unload; the module already takes its own name off the module list, so this
 * changes no workflow.
 */
static bool g_dir_pinned;

static DEFINE_MUTEX(g_dir_lock);
static DECLARE_RWSEM(g_dir_sem);

static struct dir_stage *g_dir_stage;
static u32 g_dir_stage_n, g_dir_stage_cap;
static u8 *g_dir_stage_names;
static u32 g_dir_stage_names_n, g_dir_stage_names_cap;

#ifdef TOSYA_DIR_TEST
/*
 * What one walk did, for the host tests. The counters are bumped by the same
 * code the kernel runs, so a test can compare the hidden path and the ordinary
 * path instead of assuming they match from the source.
 */
static u32 g_dir_test_hash_calls;
static u32 g_dir_test_hash_iters;
static u32 g_dir_test_probes;
static u32 g_dir_test_probe_slots;
static u32 g_dir_test_walk_hits;
#endif

/*
 * The name's hash for our own tables: it selects a name bucket and, mixed with
 * the caller, a pair slot. Every match is still decided by the bytes.
 */
static u64 dir_hash(const u8 *name, u32 len)
{
	u64 h = 0xcbf29ce484222325ull;

#ifdef TOSYA_DIR_TEST
	g_dir_test_hash_calls++;
	g_dir_test_hash_iters += len;
#endif
	while (len--) {
		h ^= *name++;
		h *= 0x100000001b3ull;
	}
	return h;
}

// The caller's app id, the way policy_query() reads it: the birth tag, not the uid.
static u32 dir_caller_app(void)
{
#ifdef TOSYA_DIR_TEST
	return g_dir_test_app;
#else
	const u32 tag = tosya_tag_app();
	const u32 app = tag - 1u;

	if (tag == 0)
		return POLICY_ID_NONE;
	return app < TOSYA_APP_SPAN ? app : POLICY_ID_NONE;
#endif
}

// The caller a record names: 0 is every caller, anything else an app uid.
static int dir_caller_app_of(u32 caller, u32 *app)
{
	u32 a;

	if (caller == 0) {
		*app = TOSYA_APP_SPAN;
		return 0;
	}
	a = caller % 100000u;
	if (a < TOSYA_APP_MIN || a >= TOSYA_APP_MIN + TOSYA_APP_SPAN)
		return -EINVAL;
	*app = a - TOSYA_APP_MIN;
	return 0;
}

static bool dir_ent_is(const struct dir_names *s, u32 idx, const u8 *name,
		       u32 len, u64 hash)
{
	const struct dir_ent *e = &s->ent[idx];

	return e->hash == hash && e->len == len &&
	       memcmp(s->arena + e->name_off, name, len) == 0;
}

/*
 * Mixing for the mask bytes and for the pair table. Nothing here is random per
 * call: the same name and the same token give the same mask, so a published set
 * keeps the bytes and hash it was built with, and a new token gives every name a
 * new mask.
 */
static u64 dir_mix64(u64 x)
{
	x += 0x9e3779b97f4a7c15ull;
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
	x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
	return x ^ (x >> 31);
}

/*
 * The mask bytes for one name, made at publication and then stored in the
 * entry. Four 64-bit mixing rounds per eight bytes: one round per word of the
 * 128-bit token, started from the name's own hash and block index. Every output
 * byte has its top bit set, so the mask lies outside the package-name alphabet
 * and outside any name a directory on the device can hold.
 */
static void dir_mask_make(const u32 key[4], u64 name_hash, u32 len, u8 *out)
{
	const u64 k0 = ((u64)key[0] << 32) | key[1];
	const u64 k1 = ((u64)key[2] << 32) | key[3];
	const u64 k2 = ((u64)key[0] << 32) | key[2];
	const u64 k3 = ((u64)key[1] << 32) | key[3];
	u32 at;

	for (at = 0; at < len; at += 8u) {
		u64 x = dir_mix64(name_hash ^ ((u64)at << 32));
		u32 i;

		x = dir_mix64(x ^ k0);
		x = dir_mix64(x ^ k1);
		x = dir_mix64(x ^ k2);
		x = dir_mix64(x ^ k3);
		for (i = 0; i < 8u && at + i < len; i++)
			out[at + i] = (u8)(0x80u | ((x >> (8u * i)) & 0x7fu));
	}
}

/*
 * hash(M): our own FNV over the stored mask bytes, mixed with the length. It is
 * the word the walk puts in nd->last.hash and the word the negative dentry is
 * cached under; it does not have to equal the VFS's full_name_hash(parent, M),
 * only to be the same value on both sides.
 */
static u32 dir_mask_hash(const u8 *mask, u32 len)
{
	return (u32)dir_hash(mask, len) ^ (len * 0x9e3779b9u);
}

/*
 * Constant-time byte equality: every byte is read from both sides and folded
 * into one accumulated difference, so a comparison that fails on its first byte
 * costs the same loads and the same branches as one that matches all the way.
 */
static bool dir_bytes_eq(const u8 *a, const u8 *b, u32 len)
{
	u32 diff = 0;
	u32 i;

#ifdef __clang__
#pragma clang loop vectorize(disable) unroll(disable)
#endif
	for (i = 0; i < len; i++)
		diff |= (u32)a[i] ^ (u32)b[i];
	return diff == 0;
}

/*
 * The cold path's mask table: mask_hash -> entry index + 1. It is not the fast
 * probe run (that one is keyed by the original name), so it only has to find a
 * stored mask quickly. Open addressing, with the table sized above the name
 * count; the query compares the stored bytes before believing the hash.
 */
static bool dir_mask_insert(struct dir_names *s, u32 idx)
{
	const struct dir_ent *e = &s->ent[idx];
	const u32 slot_mask = (1u << s->mask_bits) - 1u;
	u32 pos = dir_mix64(e->mask_hash) & slot_mask;
	u32 i;

	for (i = 0; i <= slot_mask; i++) {
		const u32 cur = s->mask_slot[pos];

		if (cur == 0u) {
			s->mask_slot[pos] = idx + 1u;
			return true;
		}
		if (cur == idx + 1u)
			return true;
		pos = (pos + 1u) & slot_mask;
	}
	return false;
}

static u32 dir_mask_find(const struct dir_names *s, const u8 *name, u32 len,
			 u32 hash)
{
	const u32 slot_mask = (1u << s->mask_bits) - 1u;
	u32 pos = dir_mix64(hash) & slot_mask;
	u32 i;

	for (i = 0; i <= slot_mask; i++) {
		const u32 cur = s->mask_slot[pos];
		const struct dir_ent *e;

		if (cur == 0u)
			return DIR_HIT_NONE;
		e = &s->ent[cur - 1u];
		if (e->mask_hash == hash && e->len == len &&
		    memcmp(s->arena + e->mask_off, name, len) == 0)
			return cur - 1u;
		pos = (pos + 1u) & slot_mask;
	}
	return DIR_HIT_NONE;
}

/*
 * The zeroed slots, entry and arena a query reads when no set is published (or
 * the published set has no names). They have the size a real table has, so an
 * empty table costs exactly the fixed run a full one does and every comparison
 * in it fails without an invalid address to guard.
 */
#define DIR_EMPTY_PAIR_BITS 4u
static u32 g_dir_zero_pair[1u << DIR_EMPTY_PAIR_BITS];
static u32 g_dir_zero_mask[1u << DIR_EMPTY_PAIR_BITS];
static u8 g_dir_zero_arena[TOSYA_NAME_MAX];
static struct dir_ent g_dir_zero_ent;
static struct dir_names g_dir_empty_names = {
	.pair_bits = DIR_EMPTY_PAIR_BITS,
	.mask_bits = DIR_EMPTY_PAIR_BITS,
	.arena_bytes = TOSYA_NAME_MAX,
	.ent = &g_dir_zero_ent,
	.pair = g_dir_zero_pair,
	.mask_slot = g_dir_zero_mask,
	.arena = g_dir_zero_arena,
};

// One slot index for a (caller, name) pair: 32 bits are enough for the table.
static u32 dir_pair_hash(u32 app, u64 hash, u32 len)
{
	return (u32)dir_mix64(((u64)app << 32) ^ hash ^
			      ((u64)len * 0x9e3779b97f4a7c15ull));
}

/*
 * The entry this caller hides (name, len), or DIR_HIT_NONE. Every call reads
 * both DIR_PAIR_PROBES-slot runs in full and never stops at the first empty
 * slot or the first match: the caller's own pair and the wildcard pair are both
 * probed the same number of times, so a hidden name and a name that is not in
 * the set cost the same probes.
 *
 * The per-slot work is branchless: an empty slot is read as entry 0 (a valid
 * allocation in every table, stand-in included), the byte comparison folds all
 * bytes into one difference, and the hit index is carried in a conditional
 * select, never a branch. The arena always has a TOSYA_NAME_MAX tail, so a
 * comparison may read the caller's length even when the entry is shorter.
 */
static __attribute__((__noinline__)) u32 dir_hidden_probe(
	const struct dir_names *s, u32 app, const u8 *name, u32 len, u64 hash)
{
	const struct dir_names *t = s != NULL ? s : &g_dir_empty_names;
	const u32 slot_mask = (1u << t->pair_bits) - 1u;
	const u32 own_app = app < TOSYA_APP_SPAN ? app : TOSYA_APP_SPAN;
	u32 own = dir_pair_hash(own_app, hash, len) & slot_mask;
	u32 wild = dir_pair_hash(TOSYA_APP_SPAN, hash, len) & slot_mask;
	u32 hit = DIR_HIT_NONE;
	u32 i;

#ifdef TOSYA_DIR_TEST
	g_dir_test_probes++;
#endif
	for (i = 0; i < DIR_PAIR_PROBES; i++) {
		const u32 pair = t->pair[own];
		const u32 live = 0u - (u32)(pair != 0u);
		const u32 at = (DIR_PAIR_ENT(pair) - 1u) & live;
		const struct dir_ent *e = &t->ent[at];
		const bool same =
			(pair != 0u) & (DIR_PAIR_APP(pair) == own_app) &
			(e->hash == hash) & (e->len == len) &
			dir_bytes_eq(t->arena + e->name_off, name, len);

#ifdef TOSYA_DIR_TEST
		g_dir_test_probe_slots++;
#endif
		hit = same ? at : hit;
		own = (own + 1u) & slot_mask;
	}
	for (i = 0; i < DIR_PAIR_PROBES; i++) {
		const u32 pair = t->pair[wild];
		const u32 live = 0u - (u32)(pair != 0u);
		const u32 at = (DIR_PAIR_ENT(pair) - 1u) & live;
		const struct dir_ent *e = &t->ent[at];
		const bool same =
			(pair != 0u) & (DIR_PAIR_APP(pair) == TOSYA_APP_SPAN) &
			(e->hash == hash) & (e->len == len) &
			dir_bytes_eq(t->arena + e->name_off, name, len);

#ifdef TOSYA_DIR_TEST
		g_dir_test_probe_slots++;
#endif
		hit = same ? at : hit;
		wild = (wild + 1u) & slot_mask;
	}
	return hit;
}

/*
 * One fixed probe of the published set: the only table read the fast walk does.
 * Both paths run it the same number of times, with the same number of slot
 * reads and byte comparisons. It reports the hit, the entry's stored mask bytes
 * and the entry's precomputed hash(M); the hook turns those into two csel
 * choices, and the length is never touched.
 *
 * The mask pointer is into the published set. Replaced sets are retained, not
 * freed, because nd->last may still point at their bytes when lookup_slow()
 * reads it after this function (and the hook) has returned.
 */
bool tosya_dir_walk_last(const struct qstr *last, const u8 **mask_bytes,
			 u32 *mask_hash)
{
	const struct dir_names *s;
	const struct dir_ent *e;
	u32 app, idx, at, keep, hit;
	u64 name_hash;

	rcu_read_lock();
	s = rcu_dereference(g_dir_names);
	if (s == NULL)
		s = &g_dir_empty_names;
	app = dir_caller_app();
	name_hash = dir_hash(last->name, last->len);
	idx = dir_hidden_probe(s, app, last->name, last->len, name_hash);
	/* An untagged caller may see every name, wildcard records included. */
	keep = 0u - (u32)(app != POLICY_ID_NONE);
	idx = (idx & keep) | (DIR_HIT_NONE & ~keep);
	at = idx & (0u - (u32)(idx != DIR_HIT_NONE));
	e = &s->ent[at];
	hit = (idx != DIR_HIT_NONE);
	*mask_bytes = s->arena + e->mask_off;
	*mask_hash = e->mask_hash;
	rcu_read_unlock();
#ifdef TOSYA_DIR_TEST
	g_dir_test_walk_hits += hit;
#endif
	return hit != 0u;
}

static struct dir_guard *dir_guard_of(struct inode *dir)
{
	const u32 n = smp_load_acquire(&g_dir_guards);
	u32 i;

	for (i = 0; i < n; i++) {
		struct dir_guard *g = READ_ONCE(g_dir_guard[i]);

		if (g != NULL && g->inode == dir && dir->i_op == &g->iop)
			return g;
	}
	return NULL;
}

/*
 * d_add() is resolved by kallsyms instead of being taken as an undefined symbol:
 * the operation it performs is one dentry, but a direct reference would put a
 * new name in the module's undefined set that the previous build did not need.
 * The call is made after g_dir_sem and RCU are released, so the first lazy lookup
 * takes no lock the walk is already holding.
 */
typedef void (*dir_d_add_t)(struct dentry *, struct inode *);
static dir_d_add_t g_dir_d_add;

static dir_d_add_t dir_d_add_get(void)
{
	dir_d_add_t fn = READ_ONCE(g_dir_d_add);

	if (fn == NULL) {
#ifdef TOSYA_DIR_TEST
		fn = d_add;
#else
		fn = (dir_d_add_t)tosya_sym("d_add");
#endif
		WRITE_ONCE(g_dir_d_add, fn);
	}
	return fn;
}

static noinline
#ifdef __KERNEL__
	__nocfi
#endif
	void dir_negative_add(struct dentry *dentry)
{
	dir_d_add_t fn = dir_d_add_get();

	if (fn != NULL)
		fn(dentry, NULL);
}

/*
 * The copy's ->lookup.
 *
 * The fast walk has already turned a hidden name N into its mask M and put
 * hash(M) in nd->last; when the dcache had no entry for that pair, this is the
 * cold path that leaves one behind. The dentry it receives is a copy of M with
 * the entry's hash(M). The mask table finds the entry by that hash and the
 * stored mask bytes confirm it. The answer is then built here:
 * d_add(dentry, NULL) makes it the negative entry the next fast walk will find,
 * and NULL tells the walk "no such file". No filesystem lookup is made, so
 * hidden and absent still cost the same from the caller's side.
 *
 * Any other name goes to the table this inode had, unchanged.
 */
static struct dentry *tosya_lookup(struct inode *dir, struct dentry *dentry,
				   unsigned int flags)
{
	const u8 *name = dentry->d_name.name;
	const u32 len = dentry->d_name.len;
	const struct dir_names *s;
	struct dir_guard *g;
	struct dentry *res;
	u32 midx;
	bool mask = false;

	down_read(&g_dir_sem);
	g = dir_guard_of(dir);
	if (unlikely(g == NULL)) {
		/*
		 * The record is gone but this inode still points at a copy of the operations, so the walk
		 * must not be told the name does not exist: it is answered by the filesystem itself, the
		 * way it would have been before this module registered the directory.
		 */
		const struct inode_operations *fallback =
			READ_ONCE(g_dir_fallback);

		up_read(&g_dir_sem);
		if (fallback != NULL && fallback->lookup != NULL)
			return fallback->lookup(dir, dentry, flags);
		return ERR_PTR(-EAGAIN);
	}
	if (len != 0 && len <= TOSYA_NAME_MAX) {
		rcu_read_lock();
		s = rcu_dereference(g_dir_names);
		if (s != NULL) {
			/*
			 * The dentry carries the hash the fast walk put there and
			 * the stored mask bytes. Finding that pair in the mask
			 * table is the whole test: the walk only substitutes a
			 * stored mask, so this cannot match an ordinary name.
			 */
			midx = dir_mask_find(s, name, len, dentry->d_name.hash);
			mask = midx != DIR_HIT_NONE;
		}
		rcu_read_unlock();
	}
	if (mask) {
		up_read(&g_dir_sem);
		dir_negative_add(dentry);
		return NULL;
	}
	res = g->orig->lookup(dir, dentry, flags);
	up_read(&g_dir_sem);
	return res;
}

/*
 * One protected parent. The copy is the inode's own: two directories of the
 * same filesystem get two copies, so nothing that was not registered changes.
 * Called under g_dir_sem (writing) and g_dir_lock.
 */
static int dir_guard_add_inode(struct inode *inode, struct dentry *dentry)
{
	const struct inode_operations *orig;
	struct dir_guard *g;
	u32 i, n;

	if (inode == NULL || dentry == NULL)
		return -EINVAL;
	orig = READ_ONCE(inode->i_op);
	if (orig == NULL || orig->lookup == NULL)
		return -EOPNOTSUPP;
	if (g_dir_fallback == NULL)
		g_dir_fallback = orig;
	n = smp_load_acquire(&g_dir_guards);
	for (i = 0; i < n; i++) {
		g = READ_ONCE(g_dir_guard[i]);
		if (g != NULL && g->inode == inode)
			return 0;
	}
	if (n >= TOSYA_DIR_MAX) {
		pr_warn_once("tosya: no room for more protected directories\n");
		return -ENOSPC;
	}
	if (!g_dir_pinned) {
		if (!try_module_get(THIS_MODULE))
			return -ENODEV;
		g_dir_pinned = true;
	}
	g = kzalloc(sizeof(*g), GFP_KERNEL);
	if (g == NULL)
		return -ENOMEM;
	g->inode = igrab(inode);
	if (g->inode == NULL) {
		kfree(g);
		return -ENOENT;
	}
	g->dentry = dget(dentry);
	g->orig = orig;
	g->dev = inode->i_sb->s_dev;
	g->ino = inode->i_ino;
	g->iop = *orig;
	g->iop.lookup = tosya_lookup;
	/*
	 * The copy is complete before the inode can point at it, and the record
	 * is complete before it can be found by a lookup.
	 */
	WRITE_ONCE(g_dir_guard[n], g);
	smp_store_release(&g_dir_guards, n + 1u);
	WRITE_ONCE(inode->i_op, &g->iop);
	return 0;
}

// One allocation, one grace period: the arrays are laid out behind the header.
static struct dir_names *dir_names_alloc(u32 pair_bits, u32 mask_bits)
{
	const u32 n = g_dir_stage_n;
	const u32 ent_n = n + 1u; // entry 0 is readable even when n == 0
	struct dir_names *s;
	size_t total;
	u8 *p;

	/*
	 * The names, one stored mask per distinct name, a zeroed TOSYA_NAME_MAX
	 * tail for the fixed probe run, and both lookup tables.
	 */
	total = sizeof(*s) + 8u;
	total += (size_t)ent_n * sizeof(struct dir_ent) + 8u;
	total += (size_t)(1u << pair_bits) * sizeof(u32) + 8u;
	total += (size_t)(1u << mask_bits) * sizeof(u32) + 8u;
	total += 2u * (size_t)g_dir_stage_names_n + TOSYA_NAME_MAX + 8u;
	s = kvzalloc(total, GFP_KERNEL);
	if (s == NULL)
		return NULL;
	p = DIR_ALIGN((u8 *)s + sizeof(*s));
	s->ent = (struct dir_ent *)p;
	p = DIR_ALIGN(p + (size_t)ent_n * sizeof(struct dir_ent));
	s->pair = (u32 *)p;
	p = DIR_ALIGN(p + (size_t)(1u << pair_bits) * sizeof(u32));
	s->mask_slot = (u32 *)p;
	p = DIR_ALIGN(p + (size_t)(1u << mask_bits) * sizeof(u32));
	s->arena = p;
	s->pair_bits = pair_bits;
	s->mask_bits = mask_bits;
	s->arena_bytes = g_dir_stage_names_n;
	if (g_dir_stage_names_n != 0)
		memcpy(s->arena, g_dir_stage_names, g_dir_stage_names_n);
	return s;
}

/*
 * Lay the staged records out: one entry per distinct name, one pair-table slot
 * per (caller, name), duplicate pairs included once, and the hash of the mask
 * each name will build. False means a pair did not fit inside DIR_PAIR_PROBES
 * slots, the one reason to build again with a larger table.
 */
static bool dir_names_fill(struct dir_names *s)
{
	const u32 n = g_dir_stage_n;
	const u32 pair_mask = (1u << s->pair_bits) - 1u;
	const u32 names_bytes = g_dir_stage_names_n;
	u32 bits = 4;
	u32 *seen;
	u32 i, nent = 0, mask_bytes = 0;
	u32 key[4];

	while ((1u << bits) < (n != 0 ? n * 2u : 1u) && bits < 20)
		bits++;
	seen = kvzalloc((size_t)(1u << bits) * sizeof(u32), GFP_KERNEL);
	if (seen == NULL)
		return false;
	tosya_token_get(key);

	for (i = 0; i < n; i++) {
		const struct dir_stage *st = &g_dir_stage[i];
		const u8 *name = g_dir_stage_names + st->off;
		const u32 name_mask = (1u << bits) - 1u;
		u32 pos = (u32)(st->hash ^
				((u64)st->len * 0x9e3779b97f4a7c15ull)) &
			  name_mask;
		u32 e = 0;
		u32 probe;

		for (probe = 0; probe <= name_mask; probe++) {
			const u32 cur = seen[pos];

			if (cur == 0)
				break;
			if (dir_ent_is(s, cur - 1, name, st->len, st->hash)) {
				e = cur;
				break;
			}
			pos = (pos + 1u) & name_mask;
		}
		if (e == 0) {
			struct dir_ent *ent;
			u8 *mask;

			e = ++nent;
			ent = &s->ent[e - 1];
			ent->hash = st->hash;
			ent->len = st->len;
			ent->name_off = st->off;
			ent->mask_off = names_bytes + mask_bytes;
			mask = s->arena + ent->mask_off;
			/*
			 * The mask is generated here, once, and stored: the walk
			 * only reads it. Its hash is stored too, so neither the
			 * hook nor the cold path recomputes anything.
			 */
			dir_mask_make(key, st->hash, st->len, mask);
			ent->mask_hash = dir_mask_hash(mask, st->len);
			if (!dir_mask_insert(s, e - 1u)) {
				kvfree(seen);
				return false;
			}
			mask_bytes += st->len;
			seen[pos] = e;
		}
		pos = dir_pair_hash(st->app, st->hash, st->len) & pair_mask;
		for (probe = 0; probe < DIR_PAIR_PROBES; probe++) {
			const u32 cur = s->pair[pos];
			const u32 pair = DIR_PAIR_MAKE(st->app, e);

			if (cur == 0) {
				s->pair[pos] = pair;
				break;
			}
			if (cur == pair)
				break;
			pos = (pos + 1u) & pair_mask;
		}
		if (probe == DIR_PAIR_PROBES) {
			kvfree(seen);
			return false;
		}
	}
	kvfree(seen);
	s->nent = nent;
	s->arena_bytes = names_bytes + mask_bytes;
	return true;
}

static struct dir_names *dir_names_build(void)
{
	u32 pair_bits = 4;
	u32 mask_bits = 4;

	/*
	 * At one eighth full, a pair is reachable in a handful of probes. The
	 * table grows if the staged names, hashed with this boot's token, do not
	 * fit that budget; a set that cannot be laid out is refused rather than
	 * published with a name dir_hidden_probe() could not find.
	 */
	while ((1u << pair_bits) <
		       (g_dir_stage_n != 0 ? g_dir_stage_n * 8u : 1u) &&
	       pair_bits < 20)
		pair_bits++;
	/*
	 * The cold path's mask table is open-addressed; keeping it at most half
	 * full means a probe always finds an empty slot, so insertion cannot fail
	 * for lack of room.
	 */
	while ((1u << mask_bits) <
		       (g_dir_stage_n != 0 ? g_dir_stage_n * 2u : 1u) &&
	       mask_bits < 20)
		mask_bits++;
	while (pair_bits <= 20 && mask_bits <= 20) {
		struct dir_names *s = dir_names_alloc(pair_bits, mask_bits);

		if (s == NULL)
			return NULL;
		if (dir_names_fill(s))
			return s;
		kvfree(s);
		if (mask_bits < 20)
			mask_bits++;
		else
			pair_bits++;
	}
	return NULL;
}

static void dir_stage_reset(void)
{
	kvfree(g_dir_stage);
	kvfree(g_dir_stage_names);
	g_dir_stage = NULL;
	g_dir_stage_n = 0;
	g_dir_stage_cap = 0;
	g_dir_stage_names = NULL;
	g_dir_stage_names_n = 0;
	g_dir_stage_names_cap = 0;
}

// app is an app id, or TOSYA_APP_SPAN for every caller.
static int dir_stage_add(u32 app, const u8 *name, u32 len)
{
	if (app > TOSYA_APP_SPAN || len == 0 || len > TOSYA_NAME_MAX)
		return -EINVAL;
	if (g_dir_stage_n >= TOSYA_HIDDEN_MAX)
		return -ENOSPC;
	if (g_dir_stage_n == g_dir_stage_cap) {
		const u32 cap = g_dir_stage_cap != 0 ? g_dir_stage_cap * 2u :
						       64u;
		struct dir_stage *grown;

		grown = kvzalloc((size_t)cap * sizeof(*grown), GFP_KERNEL);
		if (grown == NULL)
			return -ENOMEM;
		if (g_dir_stage_n != 0)
			memcpy(grown, g_dir_stage,
			       (size_t)g_dir_stage_n * sizeof(*grown));
		kvfree(g_dir_stage);
		g_dir_stage = grown;
		g_dir_stage_cap = cap;
	}
	if (g_dir_stage_names_n + len > g_dir_stage_names_cap) {
		u32 cap = g_dir_stage_names_cap != 0 ?
				  g_dir_stage_names_cap * 2u :
				  4096u;
		u8 *grown;

		while (cap < g_dir_stage_names_n + len)
			cap *= 2u;
		grown = kvzalloc(cap, GFP_KERNEL);
		if (grown == NULL)
			return -ENOMEM;
		if (g_dir_stage_names_n != 0)
			memcpy(grown, g_dir_stage_names, g_dir_stage_names_n);
		kvfree(g_dir_stage_names);
		g_dir_stage_names = grown;
		g_dir_stage_names_cap = cap;
	}
	g_dir_stage[g_dir_stage_n].app = app;
	g_dir_stage[g_dir_stage_n].len = len;
	g_dir_stage[g_dir_stage_n].hash = dir_hash(name, len);
	g_dir_stage[g_dir_stage_n].off = g_dir_stage_names_n;
	memcpy(g_dir_stage_names + g_dir_stage_names_n, name, len);
	g_dir_stage_names_n += len;
	g_dir_stage_n++;
	return 0;
}

static int dir_names_apply(void)
{
	struct dir_names *s, *old;

	down_write(&g_dir_sem);
	mutex_lock(&g_dir_lock);
	s = dir_names_build();
	if (s == NULL) {
		mutex_unlock(&g_dir_lock);
		up_write(&g_dir_sem);
		return -ENOMEM;
	}
	old = rcu_dereference_protected(g_dir_names,
					lockdep_is_held(&g_dir_lock));
	rcu_assign_pointer(g_dir_names, s);
	if (old != NULL) {
		old->retired = g_dir_retired;
		g_dir_retired = old;
	}
	mutex_unlock(&g_dir_lock);
	up_write(&g_dir_sem);
	dir_stage_reset();
	return 0;
}

static void dir_guard_remove_all(void)
{
	struct dir_names *old, *retired;
	u32 i, n;

	down_write(&g_dir_sem);
	mutex_lock(&g_dir_lock);
	n = smp_load_acquire(&g_dir_guards);
	/* With the count at zero no new lookup can find a record. */
	smp_store_release(&g_dir_guards, 0);
	for (i = 0; i < n; i++) {
		struct dir_guard *g = READ_ONCE(g_dir_guard[i]);

		if (g == NULL)
			continue;
		if (g->inode != NULL && READ_ONCE(g->inode->i_op) == &g->iop)
			WRITE_ONCE(g->inode->i_op, g->orig);
	}
	old = rcu_dereference_protected(g_dir_names,
					lockdep_is_held(&g_dir_lock));
	rcu_assign_pointer(g_dir_names, NULL);
	if (old != NULL) {
		old->retired = g_dir_retired;
		g_dir_retired = old;
	}
	retired = g_dir_retired;
	g_dir_retired = NULL;
	mutex_unlock(&g_dir_lock);
	up_write(&g_dir_sem);
	/*
	 * The fast walk enters under RCU, and the replaced lookup is kept out by
	 * g_dir_sem. One grace period after the count and the set are gone, no
	 * reader can still be inside a record.
	 */
	synchronize_rcu();
	while (retired != NULL) {
		struct dir_names *next = retired->retired;

		kvfree(retired);
		retired = next;
	}
	for (i = 0; i < n; i++) {
		struct dir_guard *g = READ_ONCE(g_dir_guard[i]);

		if (g == NULL)
			continue;
		iput(g->inode);
		dput(g->dentry);
		kfree(g);
		g_dir_guard[i] = NULL;
	}
	dir_stage_reset();
	if (g_dir_pinned) {
		module_put(THIS_MODULE);
		g_dir_pinned = false;
	}
}

static u32 dir_name_count(void)
{
	const struct dir_names *s;
	u32 n;

	rcu_read_lock();
	s = rcu_dereference(g_dir_names);
	n = s != NULL ? s->nent : 0;
	rcu_read_unlock();
	return n;
}

static u32 dir_guard_count(void)
{
	return smp_load_acquire(&g_dir_guards);
}

/* TOSYA_DIR_END */

#define DIR_PATH_MAX 160
#define DIR_SCAN_MAX 64

static DEFINE_MUTEX(g_dir_refresh_lock);

static int dir_register_path(const char *path)
{
	struct inode *inode;
	struct path p;
	int rc;

	rc = kern_path(path, LOOKUP_FOLLOW, &p);
	if (rc != 0)
		return rc;
	inode = d_backing_inode(p.dentry);
	if (inode == NULL || !S_ISDIR(inode->i_mode)) {
		path_put(&p);
		return -ENOTDIR;
	}
	down_write(&g_dir_sem);
	mutex_lock(&g_dir_lock);
	rc = dir_guard_add_inode(inode, p.dentry);
	if (rc != 0)
		pr_info("tosya: parent %s not protected: %d\n", path, rc);
	mutex_unlock(&g_dir_lock);
	up_write(&g_dir_sem);
	path_put(&p);
	return rc;
}

struct dir_scan {
	struct dir_context ctx;
	char name[DIR_SCAN_MAX][12];
	u32 n;
};

/*
 * filldir_t returns int (0 = keep going) before 6.0 and bool (true = keep going)
 * from 6.0 on. This actor only ever asks to go on: the list is short and a name
 * that is not a user id is skipped, not a reason to stop.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
typedef bool dir_scan_ret;
#define DIR_SCAN_MORE true
#else
typedef int dir_scan_ret;
#define DIR_SCAN_MORE 0
#endif

static dir_scan_ret dir_scan_actor(struct dir_context *ctx, const char *name,
				   int len, loff_t pos, u64 ino, unsigned type)
{
	struct dir_scan *s = container_of(ctx, struct dir_scan, ctx);
	int i;

	(void)pos;
	(void)ino;
	(void)type;
	if (len <= 0 || len > 8 || s->n >= DIR_SCAN_MAX)
		return DIR_SCAN_MORE;
	for (i = 0; i < len; i++)
		if (name[i] < '0' || name[i] > '9')
			return DIR_SCAN_MORE;
	memcpy(s->name[s->n], name, len);
	s->name[s->n][len] = '\0';
	s->n++;
	return DIR_SCAN_MORE;
}

/*
 * Every numeric entry under root is a user id, and the directory named after it is
 * what gets registered.
 */
static void dir_scan_users(const char *root)
{
	struct dir_scan s;
	struct file *f;
	char path[DIR_PATH_MAX];
	u32 i;

	memset(&s, 0, sizeof(s));
	s.ctx.actor = dir_scan_actor;
	f = filp_open(root, O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(f))
		return;
	iterate_dir(f, &s.ctx);
	filp_close(f, NULL);

	for (i = 0; i < s.n; i++) {
		snprintf(path, sizeof(path), "%s/%s", root, s.name[i]);
		dir_register_path(path);
	}
}

/*
 * Resolve the parents again. A user added since the last pass gets its
 * directories, and a directory already registered is left alone: its record
 * stays for the module's life, because the inode may still be pointing at the
 * copy and an unregistered parent cannot be given one back safely.
 */
void tosya_dir_refresh(void)
{
	mutex_lock(&g_dir_refresh_lock);
	dir_scan_users("/data/user");
	dir_scan_users("/data/user_de");
	mutex_unlock(&g_dir_refresh_lock);
	tosya_status_set_hidden(dir_name_count(), dir_guard_count());
	pr_info("tosya: %u directory(ies) protected, %u hidden name(s)\n",
		dir_guard_count(), dir_name_count());
}

void tosya_dir_names_reset(void)
{
	dir_stage_reset();
}

/*
 * One record of a names stream. caller is 0 for every caller, otherwise an app
 * uid; the app id inside it is what the query is keyed by, exactly as the uid
 * policy is.
 */
int tosya_dir_name_add(u32 op, u32 caller, const u8 *name, u32 len)
{
	u32 app;
	int rc;

	// A names stream is the whole set: END replaces what the kernel holds.
	if (op != KAUX_OP_ADD)
		return -EINVAL;
	if (len == 0 || len > TOSYA_NAME_MAX ||
	    !tosya_package_name_ok(name, len))
		return -EINVAL;
	rc = dir_caller_app_of(caller, &app);
	if (rc != 0)
		return rc;
	return dir_stage_add(app, name, len);
}

int tosya_dir_names_apply(void)
{
	/*
	 * The parents are looked for again here. A module loaded before /data is complete finds only the
	 * directories that exist then, and a stream that arrives later is the moment the rest can be taken:
	 * a parent that is not registered answers walks like any other directory, which is how the
	 * device-encrypted tree stayed unprotected while the credential-encrypted one did not.
	 */
	tosya_dir_refresh();
	return dir_names_apply();
}

u32 tosya_dir_name_count(void)
{
	return dir_name_count();
}

u32 tosya_dir_guard_count(void)
{
	return dir_guard_count();
}

int tosya_dir_init(void)
{
	/*
	 * Resolve d_add() once, before any walk can take the cold path: the
	 * lookup itself runs under g_dir_sem and must not go looking for symbols.
	 */
	if (dir_d_add_get() == NULL)
		pr_warn("tosya: d_add is not resolvable; hidden names will not cache\n");
	tosya_dir_refresh();
	return 0;
}

void tosya_dir_exit(void)
{
	dir_guard_remove_all();
}
