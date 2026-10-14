// SPDX-License-Identifier: GPL-2.0
/*
 * inode_hook.c - naming a child from the apk it opens.
 *
 * The first file of its own code that an isolated child opens is what gives it
 * its identity. Every app that has rules has its base.apk's ->open replaced with
 * a copy of the inode's file_operations that differs in that one member and
 * carries the app id behind it, so the first open of its own code names the
 * whole thread group (tag.c keeps the record).
 *
 * Nothing is looked up on the open path and no reference to the inode is taken:
 * the copy is reached through the inode's own i_fop, so what is in that field is
 * the only thing the hook has to trust, and it checks for its own function
 * before reading anything behind it.
 */
#include <linux/vmalloc.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>

#include "tosya.h"
// KAUX_OP_*: the actions a stream record can carry
#include "kaux.h"
#include <linux/string.h> /* strcmp: a stream entry is claimed by its path */

// the host test has no inodes to shadow
#ifndef TOSYA_HOST_TEST
/* TOSYA_SHADOW_BEGIN: scripts/extract_shadow.py lifts this block into the host test */
// KAUX_OP_*: the actions a stream record carries
#include "kaux.h"
#include <linux/mm.h>
#include <linux/rcupdate.h>

/*
 * One record, and one table inside it, for one file: a record is never given to
 * another file, because the inode it was made for may still point at that table
 * (nothing is holding the inode, on purpose) and every open through it has to
 * keep finding the operations it was made for. Records are freed at unload and
 * not before.
 *
 * Asked from the open path, declared here so the block carries its own dependencies (the host test
 * lifts it out of this file unchanged).
 */
bool tosya_tag_pending_here(void);
void tosya_tag_name(u32 app);

struct tosya_shadow {
	const struct file_operations *orig_fops;
	struct file_operations
		fops; // the module's copy: ->open is the only difference
	int (*orig_open)(struct inode *, struct file *);
	u32 app;
	/*
	 * The numbers a helper names this file by, and nothing else: the table is learned from the
	 * first inode the rule meets, so no path is ever resolved for a push.
	 */
	u32 dev;
	u64 ino;
	/*
	 * A record whose file is gone. It stays allocated -- a task may still be holding the pointer it
	 * read from that inode -- and is reused by the next replacement, so the array is bounded by
	 * TOSYA_APK_MAX records ever installed, not live ones, and the memory is freed at unload:
	 * a record is parked for good, because an inode may still be pointing at its table.
	 */
	bool parked;
};

// cp_new_stat() hands userspace this encoding of s_dev; match it by hand.
u32 tosya_encode_dev(dev_t s_dev)
{
	const u32 major = (u32)(s_dev >> 20) & 0xfffu;
	const u32 minor = (u32)s_dev & 0xfffffu;

	return (minor & 0xffu) | (major << 8) | ((minor & ~0xffu) << 12);
}

static struct tosya_shadow *g_shadow[TOSYA_APK_MAX]; // installed, in use
static u32 g_shadow_n;

static DEFINE_MUTEX(g_shadow_lock);
/*
 * The index the hot paths use: inode creation asks "is this one of ours" for every new inode, so
 * the answer costs the same for a hit and for a miss -- two bucket reads and a scan of the whole
 * stash, which is a fixed four slots. A key has two candidate buckets; an insert that finds both
 * taken moves one of their occupants to its own other bucket, for a bounded number of rounds, and a
 * key that will not settle waits in the stash.
 *
 * Nothing is marked and nothing is removed between pushes: a stream ends with a rebuild that keeps
 * only the records still live, so a table never carries the history of what it held, and the table
 * it replaces is handed to RCU rather than kept.
 */
#define TOSYA_INDEX_MIN_BITS 12u
#define TOSYA_INDEX_MAX_BITS 21u
#define TOSYA_INDEX_ROUNDS 8u
#define TOSYA_INDEX_STASH 4u

struct tosya_index_slot {
	u32 dev;
	u64 ino;
	struct tosya_shadow *s;
};

/*
 * One table is one object, and it never changes after it is published: the size and the slots are
 * read together by callers that take nothing -- every new inode asks whether it is ours, and that
 * is a hot path. A table that has been replaced stays where it is; nothing is handed back to the
 * allocator while a reader may still be walking it.
 */
struct tosya_index {
	u32 bits;
	u32 used;
	struct tosya_index_slot *slot;
	u32 stash_n;
	struct tosya_index_slot stash[TOSYA_INDEX_STASH];
	struct rcu_head rcu;
};

static struct tosya_index __rcu *g_index;

/* How many slot reads one lookup costs, so a test can hold every lookup to one number. */
static unsigned long g_index_reads;
#define INDEX_READ() (g_index_reads++)

static u64 index_hash(u64 dev, u64 ino)
{
	return (u64)dev * 0x9e3779b97f4a7c15ULL ^ (ino + 0x165667b19e3779f9ULL);
}

/* The first candidate bucket. */
static u32 index_bucket(u64 h, u32 bits)
{
	return (u32)(h >> (64 - bits));
}

/* The second: the same hash multiplied again, so the two do not move together. */
static u32 index_other(u64 h, u32 bits)
{
	return (u32)((h * 0x9e3779b97f4a7c15ULL) >> (64 - bits));
}

static struct tosya_index *index_new(u32 bits)
{
	struct tosya_index *ix = kzalloc(sizeof(*ix), GFP_KERNEL);

	if (ix == NULL)
		return NULL;
	ix->slot =
		kvzalloc((size_t)(1u << bits) * sizeof(*ix->slot), GFP_KERNEL);
	if (ix->slot == NULL) {
		kfree(ix);
		return NULL;
	}
	ix->bits = bits;
	return ix;
}

static bool index_insert(struct tosya_index *ix, u32 dev, u64 ino,
			 struct tosya_shadow *s);
static void index_rebuild_locked(void);
static bool index_put(u32 dev, u64 ino, struct tosya_shadow *s);

/*
 * One lookup: the two buckets the key can be in, then every stash slot. Nothing returns early,
 * because the cost is what this table is for -- a hit and a miss have to be the same read.
 */
static struct tosya_shadow *index_lookup(struct tosya_index *ix, u32 dev,
					 u64 ino)
{
	u64 h = index_hash(dev, ino);
	u32 b1 = index_bucket(h, ix->bits);
	u32 b2 = index_other(h, ix->bits);
	struct tosya_shadow *found = NULL;
	u32 i;

	if (b2 == b1)
		b2 = b1 ^ 1u;
	INDEX_READ();
	if (ix->slot[b1].s != NULL && ix->slot[b1].dev == dev &&
	    ix->slot[b1].ino == ino)
		found = ix->slot[b1].s;
	INDEX_READ();
	if (ix->slot[b2].s != NULL && ix->slot[b2].dev == dev &&
	    ix->slot[b2].ino == ino)
		found = ix->slot[b2].s;
	for (i = 0; i < TOSYA_INDEX_STASH; i++) {
		INDEX_READ();
		if (ix->stash[i].s != NULL && ix->stash[i].dev == dev &&
		    ix->stash[i].ino == ino)
			found = ix->stash[i].s;
	}
	return found;
}

static bool index_stash_put(struct tosya_index *ix, u32 dev, u64 ino,
			    struct tosya_shadow *s)
{
	u32 i;

	for (i = 0; i < TOSYA_INDEX_STASH; i++)
		if (ix->stash[i].s == NULL) {
			ix->stash[i].dev = dev;
			ix->stash[i].ino = ino;
			WRITE_ONCE(ix->stash[i].s, s);
			ix->stash_n++;
			return true;
		}
	return false;
}

/*
 * Places one key. Both buckets taken means one occupant moves to its own other bucket, for a
 * bounded number of rounds; a key that will not settle waits in the stash, and a stash that is
 * full is the caller's signal to rebuild.
 */
static bool index_insert(struct tosya_index *ix, u32 dev, u64 ino,
			 struct tosya_shadow *s)
{
	struct tosya_index_slot cur = { .dev = dev, .ino = ino, .s = s };
	u64 h = index_hash(dev, ino);
	u32 b1, b2, i;
	u32 round;

	/*
	 * A key that is already here is replaced, not added again: a file that comes back at the
	 * same inode number is given a table of its own, and the index has to point at the new one.
	 */
	b1 = index_bucket(h, ix->bits);
	b2 = index_other(h, ix->bits);
	if (b2 == b1)
		b2 = b1 ^ 1u;
	for (i = 0; i < 2; i++) {
		struct tosya_index_slot *slot = &ix->slot[i ? b2 : b1];

		if (slot->s != NULL && slot->dev == dev && slot->ino == ino) {
			WRITE_ONCE(slot->s, s);
			return true;
		}
	}
	for (i = 0; i < TOSYA_INDEX_STASH; i++)
		if (ix->stash[i].s != NULL && ix->stash[i].dev == dev &&
		    ix->stash[i].ino == ino) {
			WRITE_ONCE(ix->stash[i].s, s);
			return true;
		}

	for (round = 0; round < TOSYA_INDEX_ROUNDS; round++) {
		b1 = index_bucket(h, ix->bits);
		b2 = index_other(h, ix->bits);

		if (b2 == b1)
			b2 = b1 ^ 1u;
		if (ix->slot[b1].s == NULL) {
			ix->slot[b1] = cur;
			ix->used++;
			return true;
		}
		if (ix->slot[b2].s == NULL) {
			ix->slot[b2] = cur;
			ix->used++;
			return true;
		}
		cur = ix->slot[b1];
		ix->slot[b1].dev = dev;
		ix->slot[b1].ino = ino;
		ix->slot[b1].s = s;
		dev = cur.dev;
		ino = cur.ino;
		s = cur.s;
		h = index_hash(dev, ino);
	}
	return index_stash_put(ix, dev, ino, s);
}

/*
 * A fresh table holding what is live, published in one store. The table it replaces is handed to
 * RCU: a reader that took it may still be in it, and nothing is kept past that grace period.
 */
static void index_rebuild_locked(void)
{
	struct tosya_index *old, *ni;
	u32 bits, i, live = 0;

	old = rcu_dereference_protected(g_index,
					lockdep_is_held(&g_shadow_lock));
	for (i = 0; i < g_shadow_n; i++)
		if (!g_shadow[i]->parked)
			live++;
	bits = TOSYA_INDEX_MIN_BITS;
	while (bits < TOSYA_INDEX_MAX_BITS && (1u << (bits - 1u)) < live * 2u)
		bits++;
	ni = index_new(bits);
	if (ni == NULL)
		return;
	for (i = 0; i < g_shadow_n; i++) {
		if (g_shadow[i]->parked)
			continue;
		if (!index_insert(ni, g_shadow[i]->dev, g_shadow[i]->ino,
				  g_shadow[i]))
			pr_warn_once(
				"tosya: the apk index stash is full; later apks rely on their buckets\n");
	}
	rcu_assign_pointer(g_index, ni);
	if (old != NULL)
		kvfree_rcu(old, rcu);
}

static struct tosya_shadow *index_get(u32 dev, u64 ino)
{
	struct tosya_index *ix;
	struct tosya_shadow *found = NULL;

	rcu_read_lock();
	ix = rcu_dereference(g_index);
	if (ix != NULL)
		found = index_lookup(ix, dev, ino);
	rcu_read_unlock();
	return found;
}

static bool index_put(u32 dev, u64 ino, struct tosya_shadow *s)
{
	struct tosya_index *ix = g_index;

	if (ix == NULL) {
		index_rebuild_locked();
		ix = g_index;
		if (ix == NULL)
			return false;
	}
	if (index_insert(ix, dev, ino, s))
		return true;
	/* The stash is full: one rebuild gives every key a table sized to what is held. */
	index_rebuild_locked();
	ix = g_index;
	return ix != NULL && index_insert(ix, dev, ino, s);
}

static int tosya_shadow_open(struct inode *inode, struct file *file)
{
	const struct file_operations *op = READ_ONCE(inode->i_fop);
	struct tosya_shadow *s;

	/*
	 * What is in i_fop is what this call came through, and there is a record of
	 * ours behind it only when ->open is this function: a filesystem may have put
	 * its own table back since, and then the pointer is not ours to read.
	 */
	if (op == NULL)
		return 0;
	if (op->open != tosya_shadow_open)
		return op->open != NULL ? op->open(inode, file) : 0;
	s = container_of(op, struct tosya_shadow, fops);

	/*
	 * The hot path is this test: a load and a branch that falls through to the
	 * open the inode had before, as a tail call, so the fail path is a handful of
	 * instructions and nothing an attacker does can reach the other one -- only a
	 * task the framework is still setting up is pending.
	 *
	 * The numbers are checked as well, because an inode number is a number and not
	 * a name: a table of ours can outlive the file it was made for, and naming an
	 * app for a file that is not its own is the one thing that could come of that.
	 */
	if (s->dev != tosya_encode_dev(inode->i_sb->s_dev) ||
	    s->ino != inode->i_ino)
		return s->orig_open ? s->orig_open(inode, file) : 0;
	if (tosya_tag_pending_here())
		tosya_tag_name(s->app);
	return s->orig_open ? s->orig_open(inode, file) : 0;
}

// One table per file, told apart by the numbers a helper can name it by.
static struct tosya_shadow *shadow_find(u32 dev, u64 ino)
{
	struct tosya_shadow *s = index_get(dev, ino);

	/*
	 * A parked record is one whose file is gone: the table stays, because an inode may still be
	 * reading through it, but the name is not taken, so a file that comes back -- even at the
	 * same inode number -- is given a record of its own.
	 */
	return (s != NULL && !s->parked) ? s : NULL;
}

/*
 * The table a record answers opens with is made from the file operations of the first inode that
 * carries the rule. A record is named by its numbers and by nothing else, so a push never looks a
 * file up: a path walk there is visible to anything watching the paths, and that visibility is what
 * this design exists to remove.
 *
 * Two callers can arrive here at once -- the cache sweep and the inode-creation hook -- and both
 * would write the same table, so no lock is taken. What matters is that no reader sees a table that
 * is not finished: inode->i_fop is published only after the table is complete.
 */
static void shadow_build(struct tosya_shadow *s,
			 const struct file_operations *cur)
{
	struct file_operations copy = *cur;

	copy.open = tosya_shadow_open;
	copy.owner = THIS_MODULE;
	WRITE_ONCE(s->orig_open, cur->open);
	s->fops = copy;
	smp_wmb();
	WRITE_ONCE(s->orig_fops, cur);
}

/*
 * A record, made from the numbers the userspace half already read. No inode is touched and no path
 * is resolved here; what the file operations are is learned from the first inode the rule meets.
 */
static int shadow_arm(u32 dev, u64 ino, u32 uid)
{
	const u32 app = uid % 100000u;
	struct tosya_shadow *s;

	if (!ino || app < TOSYA_APP_MIN ||
	    app >= TOSYA_APP_MIN + TOSYA_APP_SPAN)
		return -EINVAL;
	if (shadow_find(dev, ino) != NULL)
		return 0; /* this file is already named */
	if (g_shadow_n >= TOSYA_APK_MAX) {
		pr_warn_once(
			"tosya: %u app apk(s) are named and the rest cannot be\n",
			g_shadow_n);
		return -ENOSPC;
	}
	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (s == NULL)
		return -ENOMEM;
	s->app = app - TOSYA_APP_MIN;
	s->dev = dev;
	s->ino = ino;
	g_shadow[g_shadow_n++] = s;
	/*
	 * A record the index did not take is a record nothing will ever look up or sweep:
	 * it would be reported as named while the kernel matches nothing by it. Take it back
	 * out here, so the table and the index say the same thing.
	 */
	if (!index_put(s->dev, s->ino, s)) {
		g_shadow_n--;
		kfree(s);
		return -ENOSPC;
	}
	return 0;
}

__maybe_unused static void shadow_drop_id(u32 dev, u64 ino)
{
	struct tosya_shadow *s = NULL;
	u32 i;

	for (i = 0; i < g_shadow_n; i++)
		if (g_shadow[i]->dev == dev && g_shadow[i]->ino == ino)
			s = g_shadow[i];
	if (s == NULL)
		return;
	/*
	 * Only the module's own table changes here: that inode is the package manager's and it
	 * is on its way out -- the file is gone, which is why the userspace half sent this --
	 * so its i_fop is left alone. The record is parked, and parked is final: the
	 * table belongs to that one file for the rest of the module's life, because the
	 * inode may still be read from and every open through it has to keep finding
	 * the operations it was made for. A file that comes back -- even at the same
	 * inode number -- is given a table of its own.
	 */
	s->parked = true;
	/*
	 * The index is not touched: nothing is removed between pushes, and the rebuild at the end
	 * of the stream is what leaves this record out. Until then it is still found -- which is
	 * what the paragraph above is about.
	 */
}

/*
 * Streaming: one record names one file and carries its generation. ADD goes through
 * shadow_arm, DEL through shadow_drop_id (parking); the two share code, not meaning.
 */
/*
 * Is this inode one of ours? Called with a newly read inode before it is unlocked, so the file
 * system has finished setting i_fop and nothing can open it yet: replacing it here is the one
 * moment with no window and no race.
 */
bool tosya_apk_shadow_apply(struct inode *inode)
{
	const struct file_operations *cur;
	struct tosya_shadow *s;

	if (inode == NULL || g_shadow_n == 0)
		return false;
	if (!S_ISREG(inode->i_mode))
		return false;
	s = index_get(tosya_encode_dev(inode->i_sb->s_dev), inode->i_ino);
	if (s == NULL)
		return false;
	cur = READ_ONCE(inode->i_fop);
	if (cur == NULL || cur == &s->fops)
		return false;
	if (s->orig_fops == NULL)
		shadow_build(s, cur);
	else if (cur != READ_ONCE(s->orig_fops))
		return false; /* another table: never replaced */
	WRITE_ONCE(inode->i_fop, &s->fops);
	return true;
}

/*
 * The rules arrived and the files behind them may already be in the cache. They are asked of the
 * cache, and only of the cache: a file the cache does not hold has no inode to arm, and looking it
 * up by name would instantiate one -- visible to anything watching the paths, which is the thing
 * this design exists to avoid. Such a file is covered by the other half: when something next opens
 * it, the inode is created and unlock_new_inode carries the rule to it.
 *
 * Two things make the cache safe to ask, and both are the callee's doing:
 *   - user_get_super(dev, false) takes the super block's read lock, and drop_super() gives it back;
 *   - ilookup() takes the inode hash lock itself, calls __iget() on what it finds -- so the answer
 *     comes with a reference this call owns -- waits out I_NEW, and retries if the inode was
 *     unhashed in the meantime.
 *
 * What must not be done is grabbing it again, or reading i_count first: an extra reference leaks,
 * and a count read from an inode nobody holds is a read of something that may already be free.
 */
typedef struct super_block *(*tosya_user_get_super_t)(dev_t, bool);
static tosya_user_get_super_t g_user_get_super;

void tosya_apk_shadow_sweep(void)
{
	u32 i;

	if (g_user_get_super == NULL)
		g_user_get_super = (void *)tosya_lookup("user_get_super");
	if (g_user_get_super == NULL)
		return;
	mutex_lock(&g_shadow_lock);
	for (i = 0; i < g_shadow_n; i++) {
		struct tosya_shadow *s = g_shadow[i];
		struct super_block *sb;
		struct inode *inode;

		if (s->parked)
			continue;
		sb = g_user_get_super(new_decode_dev(s->dev), false);
		if (sb == NULL)
			continue;
		inode = ilookup(sb, s->ino);
		if (inode != NULL) {
			/* the reference ilookup answered with is ours to give back */
			tosya_apk_shadow_apply(inode);
			iput(inode);
		}
		drop_super(sb);
	}
	mutex_unlock(&g_shadow_lock);
}

int tosya_apk_stream(u32 op, u32 uid, u32 dev, u64 ino, const char *path,
		     u32 bytes)
{
	int rc;

	(void)bytes;
	(void)path;

	if (op == KAUX_OP_DEL) {
		mutex_lock(&g_shadow_lock);
		shadow_drop_id(dev, ino);
		mutex_unlock(&g_shadow_lock);
		return 0;
	}

	mutex_lock(&g_shadow_lock);
	rc = shadow_arm(dev, ino, uid);
	mutex_unlock(&g_shadow_lock);
	return rc;
}

/*
 * End of a stream: entries outside this generation leave. Parking is leaving -- lookups skip them,
 * and the record itself stays allocated, because an inode may still be pointing at its table: the
 * memory is bounded by TOSYA_APK_MAX and given back at unload.
 */
u32 tosya_apk_stream_finish(void)
{
	u32 i, left = 0, attached = 0;

	tosya_apk_shadow_sweep();

	mutex_lock(&g_shadow_lock);
	/*
	 * The one moment the table is rebuilt: what the stream left out is left out here too, so a
	 * table never carries the history of what it held and the lookup stays two buckets and a
	 * stash. The table it replaces goes to RCU.
	 */
	index_rebuild_locked();
	for (i = 0; i < g_shadow_n; i++)
		if (!g_shadow[i]->parked) {
			left++;
			if (g_shadow[i]->orig_fops != NULL)
				attached++;
		}
	mutex_unlock(&g_shadow_lock);
	pr_info("tosya: apk records: %u active, %u have encountered an inode\n",
		left, attached);
	return left;
}

/*
 * Put every table back, at unload. A record is found by its numbers and only in the inode cache: an
 * inode that is not cached cannot be holding a pointer to that table -- it would have to have been
 * instantiated and armed for that -- so nothing is missed by not looking for it by name.
 *
 * The records themselves are released here. What can still reference one is a file opened through
 * its table, which holds a reference on THIS_MODULE (the owner set in the copy), and module_exit
 * runs only with that count at zero.
 */
void tosya_apk_remove(void)
{
	u32 i, unresolved = 0;

	if (g_user_get_super == NULL)
		g_user_get_super = (void *)tosya_lookup("user_get_super");
	mutex_lock(&g_shadow_lock);
	for (i = 0; i < g_shadow_n; i++) {
		struct tosya_shadow *s = g_shadow[i];
		struct super_block *sb;
		struct inode *inode;

		if (s->orig_fops == NULL || g_user_get_super == NULL) {
			unresolved++;
			continue;
		}
		sb = g_user_get_super(new_decode_dev(s->dev), false);
		if (sb == NULL) {
			unresolved++;
			continue;
		}
		inode = ilookup(sb, s->ino);
		if (inode != NULL) {
			if (READ_ONCE(inode->i_fop) == &s->fops)
				WRITE_ONCE(inode->i_fop, s->orig_fops);
			iput(inode);
		}
		drop_super(sb);
	}
	if (unresolved != 0)
		pr_info("tosya: %u apk record(s) had no inode to put back at unload\n",
			unresolved);
	for (i = 0; i < g_shadow_n; i++) {
		kfree(g_shadow[i]);
		g_shadow[i] = NULL;
	}
	g_shadow_n = 0;
	{
		struct tosya_index *ix = rcu_dereference_protected(
			g_index, lockdep_is_held(&g_shadow_lock));

		rcu_assign_pointer(g_index, NULL);
		/* A reader may still be in it: the table goes after the grace period, not before. */
		synchronize_rcu();
		if (ix != NULL) {
			kvfree(ix->slot);
			kfree(ix);
		}
	}
	mutex_unlock(&g_shadow_lock);
}
/* TOSYA_SHADOW_END */
#endif
