/*
 * Host test for the directory guard of src/dir_hook.c.
 *
 * The block needs an inode and a dcache, so scripts/extract_dir.py lifts it out
 * of the module and this file gives it both. What it pins down is the design's
 * two halves:
 *
 *   - the one walk preparation (tosya_dir_walk_last) probes the fixed run and
 *     reports the entry's stored mask bytes and hash(M), or the original qstr;
 *   - the cold path (the replaced ->lookup) turns a mask back into N, checks
 *     the precomputed hash, and leaves a negative dentry without asking the
 *     filesystem; every other name still reaches the original lookup.
 *
 * The counters are bumped by the block itself under TOSYA_DIR_TEST, so the
 * "same work on both paths" assertions measure the code the kernel runs.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

#define TOSYA_DIR_MAX 8u
#define TOSYA_HIDDEN_MAX 64u
#define TOSYA_NAME_MAX 255u
#define TOSYA_APP_MIN 10000u
#define TOSYA_APP_SPAN 10000u
#define POLICY_ID_NONE 0xffffffffu
#define GFP_KERNEL 0u
#define DCACHE_OP_HASH 0x1000u

struct module;
struct rcu_head {
	int unused;
};
struct dentry;
struct inode;

struct qstr {
	const unsigned char *name;
	u32 len;
	u32 hash;
};
struct dentry_operations {
	int (*d_hash)(const struct dentry *, struct qstr *);
};
struct inode_operations {
	struct dentry *(*lookup)(struct inode *, struct dentry *, unsigned int);
	int (*permission)(struct inode *, int);
	const char *(*get_link)(struct dentry *, struct inode *, void *);
	unsigned long magic; // must survive the copy to the inode
};
struct super_block {
	dev_t s_dev;
};
struct inode {
	const struct inode_operations *i_op;
	struct super_block *i_sb;
	unsigned long i_ino;
	int refs;
};
struct dentry {
	struct qstr d_name;
	struct inode *d_inode;
	struct dentry *d_parent;
	unsigned int d_flags;
	const struct dentry_operations *d_op;
	int refs;
};

#define __rcu
#define unlikely(x) (x)
#define likely(x) (x)
#define MAX_ERRNO 4095
static inline bool is_err(const void *p)
{
	return (unsigned long)p >= (unsigned long)-MAX_ERRNO;
}
#define IS_ERR(p) is_err((const void *)(p))
#define ERR_PTR(e) ((void *)(long)(e))
#define PTR_ERR(p) ((long)(p))
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))

static void *kzalloc(size_t n, int flags)
{
	(void)flags;
	return calloc(1, n);
}
#define kvzalloc(n, flags) kzalloc((n), (flags))
static void kfree_p(const void *p)
{
	free((void *)p);
}
#define kfree(p) kfree_p(p)
#define kvfree(p) kfree_p(p)

static bool try_module_get(struct module *m)
{
	(void)m;
	return true;
}
static void module_put(struct module *m)
{
	(void)m;
}
#define THIS_MODULE ((struct module *)0)
#define noinline __attribute__((noinline))

#define DEFINE_MUTEX(x) int x
#define mutex_lock(x)      \
	do {               \
		(void)(x); \
	} while (0)
#define mutex_unlock(x)    \
	do {               \
		(void)(x); \
	} while (0)
#define DECLARE_RWSEM(x) int x
#define down_read(x)       \
	do {               \
		(void)(x); \
	} while (0)
#define up_read(x)         \
	do {               \
		(void)(x); \
	} while (0)
#define down_write(x)      \
	do {               \
		(void)(x); \
	} while (0)
#define up_write(x)        \
	do {               \
		(void)(x); \
	} while (0)

#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define smp_load_acquire(p) (*(p))
#define smp_store_release(p, v) (*(p) = (v))
#define rcu_read_lock() \
	do {            \
	} while (0)
#define rcu_read_unlock() \
	do {              \
	} while (0)
#define rcu_dereference(p) (p)
#define rcu_assign_pointer(p, v) ((p) = (v))
#define rcu_dereference_protected(p, c) ((void)(c), (p))
#define lockdep_is_held(l) 1
#define kvfree_rcu(p, member) kvfree(p)
#define synchronize_rcu() \
	do {              \
	} while (0)

static int g_warned;
#define pr_warn_once(fmt, ...) \
	do {                   \
		(void)(fmt);   \
		g_warned++;    \
	} while (0)

static u32 g_dir_test_app;

/*
 * The token the masks are derived from. A test changes it to show that a new
 * token gives every name a new mask.
 */
static const u32 g_default_token[4] = { 0x11111111u, 0x22222222u, 0x33333333u,
					0x44444444u };
static u32 g_test_token[4] = { 0x11111111u, 0x22222222u, 0x33333333u,
			       0x44444444u };
void tosya_token_get(u32 out[4]);

/* What the cold path's d_add() did, recorded by the shim below. */
static int g_d_add_calls;
static u32 g_d_add_hash;
static u32 g_d_add_len;
static unsigned char g_d_add_name[TOSYA_NAME_MAX + 1];

#define TOSYA_DIR_TEST 1
static void d_add(struct dentry *dentry, struct inode *inode)
{
	g_d_add_calls++;
	g_d_add_hash = dentry->d_name.hash;
	g_d_add_len = dentry->d_name.len;
	memcpy(g_d_add_name, dentry->d_name.name, dentry->d_name.len);
	g_d_add_name[dentry->d_name.len] = '\0';
	dentry->d_inode = inode;
}

static struct dentry *dget(struct dentry *d)
{
	return d;
}
static void dput(struct dentry *d)
{
}
static struct inode *igrab(struct inode *i)
{
	i->refs++;
	return i;
}
static void iput(struct inode *i)
{
	i->refs--;
}

#include "dir_block.inc"

void tosya_token_get(u32 out[4])
{
	memcpy(out, g_test_token, sizeof(g_test_token));
}

static int g_fail;

#define CHECK(cond, what)                                             \
	do {                                                          \
		if (!(cond)) {                                        \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, \
				__LINE__, what);                      \
			g_fail++;                                     \
		}                                                     \
	} while (0)

#define NPARENT 3

static struct super_block g_sb;
static struct inode g_parent[NPARENT + 1];
static struct dentry g_pdent[NPARENT + 1];
static struct inode_operations g_orig[NPARENT + 1];
static struct inode g_child;
static int g_orig_calls;
static unsigned char g_orig_name[TOSYA_NAME_MAX + 1];
static u32 g_orig_len;
static u32 g_orig_hash;

static int perm_stub(struct inode *inode, int mask)
{
	(void)inode;
	return mask;
}

static const char *link_stub(struct dentry *dentry, struct inode *inode,
			     void *done)
{
	(void)dentry;
	(void)inode;
	(void)done;
	return NULL;
}

/*
 * The filesystem's own ->lookup. Only names the walk did not substitute as a
 * mask reach it, so it is the "visible child" lookup and nothing else.
 */
static struct dentry *orig_lookup(struct inode *dir, struct dentry *dentry,
				  unsigned int flags)
{
	(void)dir;
	(void)flags;
	g_orig_calls++;
	g_orig_len = dentry->d_name.len;
	g_orig_hash = dentry->d_name.hash;
	memcpy(g_orig_name, dentry->d_name.name, dentry->d_name.len);
	g_orig_name[dentry->d_name.len] = '\0';
	dentry->d_inode = &g_child;
	return NULL;
}

static void setup_parents(void)
{
	int i;

	memset(&g_sb, 0, sizeof(g_sb));
	g_sb.s_dev = 0x1234;
	memset(&g_child, 0, sizeof(g_child));
	g_child.i_ino = 4242;
	for (i = 0; i < NPARENT; i++) {
		memset(&g_orig[i], 0, sizeof(g_orig[i]));
		g_orig[i].lookup = orig_lookup;
		g_orig[i].permission = perm_stub;
		g_orig[i].get_link = link_stub;
		g_orig[i].magic = 0xa5a50000ul + (unsigned long)i;

		memset(&g_parent[i], 0, sizeof(g_parent[i]));
		g_parent[i].i_op = &g_orig[i];
		g_parent[i].i_sb = &g_sb;
		g_parent[i].i_ino = 1000ul + (unsigned long)i;
		g_parent[i].refs = 1;

		memset(&g_pdent[i], 0, sizeof(g_pdent[i]));
		g_pdent[i].d_name.name = (const unsigned char *)"parent";
		g_pdent[i].d_name.len = 6;
		g_pdent[i].d_inode = &g_parent[i];
		g_pdent[i].refs = 1;
	}

	// Never registered: its i_op and its lookup must stay exactly as they were.
	memset(&g_orig[NPARENT], 0, sizeof(g_orig[NPARENT]));
	g_orig[NPARENT].lookup = orig_lookup;
	g_orig[NPARENT].magic = 0xdead;
	memset(&g_parent[NPARENT], 0, sizeof(g_parent[NPARENT]));
	g_parent[NPARENT].i_op = &g_orig[NPARENT];
	g_parent[NPARENT].i_sb = &g_sb;
	g_parent[NPARENT].i_ino = 2000;
}

static int register_all(void)
{
	int i, rc = 0;

	down_write(&g_dir_sem);
	mutex_lock(&g_dir_lock);
	for (i = 0; i < NPARENT; i++) {
		rc = dir_guard_add_inode(&g_parent[i], &g_pdent[i]);
		if (rc != 0)
			break;
	}
	mutex_unlock(&g_dir_lock);
	up_write(&g_dir_sem);
	return rc;
}

static void add_name(u32 caller, const char *name)
{
	u32 app = 0;
	int rc = dir_caller_app_of(caller, &app);

	CHECK(rc == 0, "caller maps to an app id");
	if (rc != 0)
		return;
	rc = dir_stage_add(app, (const u8 *)name, (u32)strlen(name));
	CHECK(rc == 0, "name is staged");
}

/* ---- one walk, without and with the cold path -------------------------- */

#define TEST_HASH 0x12345678u

struct walk {
	int hit; /* the preparation selected the mask */
	u32 len;
	u32 hash; /* the qstr hash after the preparation */
	unsigned char name[TOSYA_NAME_MAX + 1];
	int original; /* the qstr still points at the walk's own buffer */
	struct dentry *res;
	int orig_calls;
	int d_add_calls;
	u32 slow_hash;
};

/*
 * The two layers fs/namei.c runs: the preparation lookup_fast's hook makes,
 * then -- when the preparation produced something the (empty) dcache does not
 * have -- __lookup_slow's call into the replaced ->lookup. The dcache is empty
 * here, so every first walk takes the cold path; that is what this checks.
 */
static void walk_one(int parent, const char *name, struct walk *w, int slow)
{
	unsigned char copy[TOSYA_NAME_MAX + 1];
	struct qstr last;
	struct dentry d;
	const u8 *mask_bytes;
	u32 len = (u32)strlen(name);
	u32 mask_hash;

	memset(w, 0, sizeof(*w));
	memcpy(copy, name, len + 1);
	last.name = copy;
	last.len = len;
	last.hash = TEST_HASH;
	w->hit = tosya_dir_walk_last(&last, &mask_bytes, &mask_hash);
	last.name = w->hit ? mask_bytes : last.name;
	last.hash = w->hit ? mask_hash : last.hash;
	w->original = last.name == copy;
	memcpy(w->name, last.name, len);
	w->name[len] = '\0';
	w->len = len;
	w->hash = last.hash;

	if (!slow)
		return;

	memset(&d, 0, sizeof(d));
	d.d_name = last;
	d.d_parent = &g_pdent[parent];
	g_orig_calls = 0;
	g_d_add_calls = 0;
	memset(g_orig_name, 0, sizeof(g_orig_name));
	memset(g_d_add_name, 0, sizeof(g_d_add_name));
	w->res = g_parent[parent].i_op->lookup(&g_parent[parent], &d, 0);
	w->orig_calls = g_orig_calls;
	w->d_add_calls = g_d_add_calls;
	w->slow_hash = d.d_name.hash;
	if (d.d_inode == NULL)
		w->res = NULL;
}

/* Only the preparation lookup_fast's hook makes, without the cold path. */
static void walk_prepare(const char *name, struct walk *w)
{
	walk_one(0, name, w, 0);
}

/* ---- the assertions ---------------------------------------------------- */

static void check_copies(void)
{
	int i;

	for (i = 0; i < NPARENT; i++) {
		CHECK(g_parent[i].i_op != &g_orig[i], "inode has its own copy");
		CHECK(g_parent[i].i_op->lookup == tosya_lookup,
		      "the copy's lookup is the cold path");
		CHECK(g_parent[i].i_op->permission == g_orig[i].permission,
		      "permission is unchanged");
		CHECK(g_parent[i].i_op->get_link == g_orig[i].get_link,
		      "get_link is unchanged");
		CHECK(g_parent[i].i_op->magic == g_orig[i].magic,
		      "the rest of the table is a copy, not a template");
	}
	CHECK(g_parent[NPARENT].i_op == &g_orig[NPARENT],
	      "an unregistered inode keeps its table");
}

static void check_mapping(void)
{
	u32 app = 0;

	CHECK(dir_caller_app_of(10123u, &app) == 0 && app == 123u,
	      "an app uid maps to its app id");
	CHECK(dir_caller_app_of(110123u, &app) == 0 && app == 123u,
	      "a secondary user's app maps to the same app id");
	CHECK(dir_caller_app_of(0u, &app) == 0 && app == TOSYA_APP_SPAN,
	      "caller 0 is the wildcard");
	CHECK(dir_caller_app_of(1000u, &app) != 0, "a system uid is refused");
	CHECK(dir_caller_app_of(90042u, &app) != 0,
	      "an isolated uid is refused");
}

static const struct expect {
	u32 caller;
	const char *name;
	int hidden;
} g_cases[] = {
	{ 10123, "com.hidden.one", 1 },
	{ 10123, "com.hidden.two", 1 },
	{ 10123, "com.hidden.all", 1 },
	{ 10124, "com.hidden.one", 0 },
	{ 10124, "com.hidden.two", 1 },
	{ 10124, "com.hidden.all", 1 },
	{ 10125, "com.hidden.one", 0 },
	{ 10125, "com.hidden.two", 0 },
	{ 10125, "com.hidden.all", 1 },
	{ 10123, "com.visible", 0 },
	{ POLICY_ID_NONE, "com.hidden.one", 0 },
	{ POLICY_ID_NONE, "com.hidden.all", 0 },
};

static void check_matrix(void)
{
	unsigned int k;
	int p;

	for (p = 0; p < NPARENT; p++) {
		for (k = 0; k < sizeof(g_cases) / sizeof(g_cases[0]); k++) {
			const struct expect *e = &g_cases[k];
			struct walk w;
			u32 len = (uint32_t)strlen(e->name);

			if (e->caller == POLICY_ID_NONE) {
				g_dir_test_app = POLICY_ID_NONE;
			} else {
				u32 app = 0;

				CHECK(dir_caller_app_of(e->caller, &app) == 0,
				      "the case names an app");
				g_dir_test_app = app;
			}
			walk_one(p, e->name, &w, 1);
			CHECK(w.len == len, "the qstr length is never changed");
			if (e->hidden) {
				const u32 nidx = dir_hidden_probe(
					g_dir_names, g_dir_test_app,
					(const u8 *)e->name, len,
					dir_hash((const u8 *)e->name, len));
				const struct dir_ent *ne;

				CHECK(nidx != DIR_HIT_NONE,
				      "the hidden name is in the table");
				ne = &g_dir_names->ent[nidx];
				CHECK(w.hash == ne->mask_hash,
				      "the qstr hash is the entry's precomputed mask_hash");
				CHECK(w.hit == 1,
				      "a hidden name is substituted by the walk");
				CHECK(w.original == 0,
				      "the hidden path points at the stored mask bytes");
				CHECK(w.res == NULL && w.d_add_calls == 1,
				      "the cold path leaves one negative dentry");
				CHECK(w.orig_calls == 0,
				      "the filesystem is never asked about a hidden name");
				CHECK(memcmp(w.name,
					     g_dir_names->arena + ne->mask_off,
					     len) == 0,
				      "nd->last.name is the entry's stored mask_bytes");
				CHECK(memcmp(w.name, e->name, len) != 0,
				      "the mask is not the name");
				CHECK(g_d_add_hash == w.hash &&
					      g_d_add_len == len &&
					      memcmp(g_d_add_name, w.name,
						     len) == 0,
				      "the negative dentry is keyed by hash(M) and named M");
			} else {
				CHECK(w.hit == 0,
				      "a name that is not hidden is not substituted");
				CHECK(w.original == 1,
				      "the ordinary path returns the caller's pointer");
				CHECK(w.hash == TEST_HASH,
				      "the ordinary path leaves the qstr hash alone");
				CHECK(memcmp(w.name, e->name, len) == 0,
				      "the ordinary path leaves nd->last.name unchanged");
				CHECK(w.res == NULL && w.d_add_calls == 0,
				      "the cold path does not create a negative entry");
				CHECK(w.orig_calls == 1,
				      "the filesystem is asked about an ordinary name");
				CHECK(g_orig_hash == TEST_HASH &&
					      g_orig_len == len &&
					      memcmp(g_orig_name, e->name,
						     len) == 0,
				      "the original lookup gets the name unchanged");
			}
		}
	}
}

/*
 * The acceptance measurement: the two paths must do the same preparation.
 * "com.hidden.one" and "com.visible.xx" both have 14 bytes, one hits and one
 * misses; the hash traversal and the probe counts have to agree exactly.
 */
static void check_unconditional(void)
{
	struct walk w;
	u32 hc_hidden, hi_hidden, probes_hidden, slots_hidden;
	u32 hc_visible, hi_visible, probes_visible, slots_visible;

	g_dir_test_app = 123;

	g_dir_test_hash_calls = 0;
	g_dir_test_hash_iters = 0;
	g_dir_test_probes = 0;
	g_dir_test_probe_slots = 0;
	walk_prepare("com.hidden.one", &w);
	CHECK(w.hit == 1, "the unconditional measurement hits");
	hc_hidden = g_dir_test_hash_calls;
	hi_hidden = g_dir_test_hash_iters;
	probes_hidden = g_dir_test_probes;
	slots_hidden = g_dir_test_probe_slots;

	g_dir_test_hash_calls = 0;
	g_dir_test_hash_iters = 0;
	g_dir_test_probes = 0;
	g_dir_test_probe_slots = 0;
	walk_prepare("com.visible.xx", &w);
	CHECK(w.hit == 0, "the unconditional measurement misses");
	hc_visible = g_dir_test_hash_calls;
	hi_visible = g_dir_test_hash_iters;
	probes_visible = g_dir_test_probes;
	slots_visible = g_dir_test_probe_slots;

	CHECK(hc_hidden == 1u && hc_visible == 1u,
	      "both paths make one hash traversal");
	CHECK(hi_hidden == 14u && hi_visible == 14u,
	      "both traversals visit the name's bytes");
	CHECK(probes_hidden == 1u && probes_visible == 1u,
	      "both paths make exactly one probe call");
	CHECK(slots_hidden == 2u * DIR_PAIR_PROBES &&
		      slots_visible == 2u * DIR_PAIR_PROBES,
	      "both paths read both fixed probe runs");
	CHECK(hc_hidden == hc_visible && hi_hidden == hi_visible &&
		      probes_hidden == probes_visible &&
		      slots_hidden == slots_visible,
	      "the hidden and ordinary preparations are identical");
	printf("unconditional,hash_calls,hash_iters,probes,slots\n");
	printf("unconditional,hidden,%u,%u,%u,%u\n", hc_hidden, hi_hidden,
	       probes_hidden, slots_hidden);
	printf("unconditional,visible,%u,%u,%u,%u\n", hc_visible, hi_visible,
	       probes_visible, slots_visible);
}

/*
 * The stored mask has the name's length at every length, is not the name, and
 * the hash is the entry's precomputed hash(M).
 */
static void check_mask_lengths(void)
{
	static const char alphabet[] = "com.example.pkg_v1";
	u32 len;

	for (len = 1; len <= 64; len++) {
		char name[TOSYA_NAME_MAX + 1];
		struct walk w;
		u32 i;
		u32 nidx;
		const struct dir_ent *e;

		for (i = 0; i < len; i++)
			name[i] = alphabet[i % (sizeof(alphabet) - 1u)];
		name[len] = '\0';
		g_dir_test_app = 123;
		dir_stage_reset();
		add_name(10123u, name);
		CHECK(dir_names_apply() == 0, "a one-name set is applied");
		walk_one(0, name, &w, 1);
		CHECK(w.hit == 1 && w.d_add_calls == 1 && w.orig_calls == 0,
		      "every length is hidden through the walk");
		CHECK(w.len == len, "the mask has the name's length");
		nidx = dir_hidden_probe(g_dir_names, 123, (const u8 *)name, len,
					dir_hash((const u8 *)name, len));
		CHECK(nidx != DIR_HIT_NONE && g_dir_names->ent[nidx].len == len,
		      "the entry stores a mask of the name's length");
		e = &g_dir_names->ent[nidx];
		CHECK(memcmp(w.name, g_dir_names->arena + e->mask_off, len) ==
			      0,
		      "the walk uses the entry's stored mask_bytes");
		CHECK(memcmp(w.name, name, len) != 0,
		      "the mask is not the name");
		CHECK(w.hash == e->mask_hash,
		      "the hash is the entry's precomputed hash(M)");
	}
}

/*
 * The hash is the entry's precomputed mask_hash, not a value recomputed from
 * the stored mask bytes: replacing the entry's mask_hash after publication
 * changes what the walk puts in nd->last.hash.
 */
static void check_hash_comes_from_the_entry(void)
{
	const char *name = "com.hidden.one";
	struct walk w;
	u32 idx, saved;

	g_dir_test_app = 123;
	dir_stage_reset();
	add_name(10123u, name);
	CHECK(dir_names_apply() == 0, "the hash-source set is applied");
	idx = dir_hidden_probe(g_dir_names, 123, (const u8 *)name, 14,
			       dir_hash((const u8 *)name, 14));
	CHECK(idx != DIR_HIT_NONE, "the hash-source name is in the table");
	saved = g_dir_names->ent[idx].mask_hash;
	g_dir_names->ent[idx].mask_hash = 0xdeadbeefu;
	walk_prepare(name, &w);
	CHECK(w.hit == 1, "the hash-source name is still hidden");
	CHECK(w.hash == 0xdeadbeefu,
	      "nd->last.hash is the entry's mask_hash, not a recomputed value");
	CHECK(w.hash != dir_mask_hash((const u8 *)w.name, w.len),
	      "the table value is what the walk uses");
	printf("table_hash,entry=0xdeadbeef,walk=0x%x,recomputed=0x%x\n",
	       w.hash, dir_mask_hash((const u8 *)w.name, w.len));
	g_dir_names->ent[idx].mask_hash = saved;
}

/* A hit, a miss and an empty set all read the same fixed run. */
static void check_probe_cost(void)
{
	u8 name[32];
	u32 idx;

	dir_stage_reset();
	CHECK(dir_names_apply() == 0, "the empty set is applied");
	g_dir_test_probes = 0;
	g_dir_test_probe_slots = 0;
	idx = dir_hidden_probe(g_dir_names, 123, (const u8 *)"com.hidden.one",
			       14, dir_hash((const u8 *)"com.hidden.one", 14));
	CHECK(idx == DIR_HIT_NONE, "the empty set answers miss");
	CHECK(g_dir_test_probes == 1u &&
		      g_dir_test_probe_slots == 2u * DIR_PAIR_PROBES,
	      "the empty set reads the fixed run");

	dir_stage_reset();
	add_name(10123u, "com.hidden.one");
	CHECK(dir_names_apply() == 0, "the probe-cost set is applied");
	g_dir_test_app = 123;
	memcpy(name, "com.hidden.one", 15);
	g_dir_test_probes = 0;
	g_dir_test_probe_slots = 0;
	idx = dir_hidden_probe(g_dir_names, 123, name, 14, dir_hash(name, 14));
	CHECK(idx == 0, "the hidden name is found");
	CHECK(g_dir_test_probes == 1u &&
		      g_dir_test_probe_slots == 2u * DIR_PAIR_PROBES,
	      "a hit reads the fixed run");
	memcpy(name, "com.visible.xx", 15);
	g_dir_test_probes = 0;
	g_dir_test_probe_slots = 0;
	idx = dir_hidden_probe(g_dir_names, 123, name, 14, dir_hash(name, 14));
	CHECK(idx == DIR_HIT_NONE, "the ordinary name is not found");
	CHECK(g_dir_test_probes == 1u &&
		      g_dir_test_probe_slots == 2u * DIR_PAIR_PROBES,
	      "a miss reads the same fixed run");
}

/* A new token gives every name new stored mask bytes. */
static void check_token(void)
{
	static const u32 other[4] = { 0xdeadbeefu, 0x0badf00du, 0x12345678u,
				      0x9abcdef0u };
	unsigned char first[TOSYA_NAME_MAX + 1];
	struct walk w;
	u32 first_len;

	dir_stage_reset();
	add_name(10123u, "com.hidden.one");
	CHECK(dir_names_apply() == 0, "the token set is applied");
	g_dir_test_app = 123;
	walk_one(0, "com.hidden.one", &w, 1);
	CHECK(w.hit == 1, "the first token hides the name");
	first_len = w.len;
	memcpy(first, w.name, first_len + 1);

	memcpy(g_test_token, other, sizeof(g_test_token));
	dir_stage_reset();
	add_name(10123u, "com.hidden.one");
	CHECK(dir_names_apply() == 0, "the set is applied under a new token");
	walk_one(0, "com.hidden.one", &w, 1);
	CHECK(w.hit == 1, "the new token still hides the name");
	CHECK(!(w.len == first_len && memcmp(w.name, first, first_len) == 0),
	      "a new token gives the name a new mask");
	memcpy(g_test_token, g_default_token, sizeof(g_test_token));
}

int main(void)
{
	u32 app = 0;

	setup_parents();

	CHECK(register_all() == 0, "the parents are registered");
	CHECK(dir_guard_count() == NPARENT, "all parents are protected");
	CHECK(g_dir_pinned, "the module is pinned while a table is installed");
	check_copies();

	// A second registration of the same inode must not add a second record.
	down_write(&g_dir_sem);
	mutex_lock(&g_dir_lock);
	CHECK(dir_guard_add_inode(&g_parent[0], &g_pdent[0]) == 0,
	      "registering a parent twice is idempotent");
	mutex_unlock(&g_dir_lock);
	up_write(&g_dir_sem);
	CHECK(dir_guard_count() == NPARENT, "the count is unchanged");

	check_mapping();

	dir_stage_reset();
	add_name(10123u, "com.hidden.one");
	add_name(10123u, "com.hidden.two");
	add_name(10124u, "com.hidden.two");
	add_name(0u, "com.hidden.all");
	add_name(10123u, "com.hidden.one"); // the same pair again: one name
	CHECK(dir_caller_app_of(10124u, &app) == 0 && app == 124u,
	      "the second caller maps as expected");
	CHECK(dir_names_apply() == 0, "the name set is applied");
	CHECK(dir_name_count() == 3, "duplicates collapse to three names");

	check_matrix();
	check_unconditional();
	check_mask_lengths();
	check_probe_cost();
	check_hash_comes_from_the_entry();
	check_token();

	// A new set replaces the old one.
	dir_stage_reset();
	add_name(10125u, "com.hidden.one");
	CHECK(dir_names_apply() == 0, "the replacement set is applied");
	CHECK(dir_name_count() == 1, "the replacement set has one name");
	g_dir_test_app = 123;
	{
		struct walk w;

		walk_one(0, "com.hidden.one", &w, 1);
		CHECK(w.hit == 0 && w.orig_calls == 1,
		      "a name the new set does not carry is visible");
	}
	g_dir_test_app = 125;
	{
		struct walk w;

		walk_one(0, "com.hidden.one", &w, 1);
		CHECK(w.hit == 1 && w.d_add_calls == 1 && w.orig_calls == 0,
		      "the new caller's hidden name is gone");
	}

	// Clearing the set makes every name visible again.
	dir_stage_reset();
	CHECK(dir_names_apply() == 0, "an empty set is applied");
	CHECK(dir_name_count() == 0, "the set is empty");
	g_dir_test_app = 123;
	{
		struct walk w;

		walk_one(0, "com.hidden.one", &w, 1);
		CHECK(w.hit == 0 && w.orig_calls == 1,
		      "an empty set hides nothing");
	}

	dir_guard_remove_all();
	CHECK(dir_guard_count() == 0, "every parent is released");
	CHECK(!g_dir_pinned, "the module reference is given back");
	{
		int i;

		for (i = 0; i < NPARENT; i++)
			CHECK(g_parent[i].i_op == &g_orig[i],
			      "the original table is back");
	}
	CHECK(g_parent[NPARENT].i_op == &g_orig[NPARENT],
	      "the unregistered inode was never touched");

	(void)g_warned;
	printf("%s\n", g_fail != 0 ? "FAIL" : "PASS");
	return g_fail != 0;
}
