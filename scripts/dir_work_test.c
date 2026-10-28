/*
 * Host test: what one lookup costs, and whether that cost is the same when the
 * name is hidden and when the name does not exist at all.
 *
 * scripts/extract_dir_work.py lifts the directory-guard block out of
 * src/dir_hook.c, so this drives the same preparation the inline lookup_fast
 * hook runs and the same cold path the replaced ->lookup runs. Around them it
 * models the two namei layers (lookup_fast -> dcache probe; on a miss
 * lookup_slow -> i_op->lookup) and a dcache that keys entries by hash and name.
 *
 * Usage: dir_work_test <scenario> [cold|both] [--links N]
 *   cold: the first walk of that name; both: a second walk too, with the dentry
 *   the first one left in the cache (the state a repeated stat() is in).
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
#define TOSYA_HIDDEN_MAX 8192u
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
	unsigned long magic;
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
#define noinline __attribute__((noinline))

/* Every counter this test reports. */
struct work {
	/* the walk preparation (lookup_fast's hook) */
	unsigned long walk_calls;
	unsigned long walk_hits;
	unsigned long hash_calls;
	unsigned long hash_iters;
	unsigned long probe_calls;
	unsigned long probe_slots;
	unsigned long fast_probe; /* dcache lookups made by the fast path */
	unsigned long fast_cached; /* a dentry answered it */
	/* the cold path (the replaced ->lookup) */
	unsigned long slow;
	unsigned long orig_lookup;
	unsigned long negative_add; /* d_add(dentry, NULL) for a mask */
	unsigned long alloc, free;
	unsigned long lock_read, unlock_read;
	unsigned long lock_write, unlock_write;
	unsigned long mutex_lock, mutex_unlock;
	unsigned long rcu_lock, rcu_unlock;
	unsigned long ordered;
};

static struct work g_w;

static void w_reset(void)
{
	memset(&g_w, 0, sizeof(g_w));
}

static void *kzalloc(size_t n, int flags)
{
	(void)flags;
	g_w.alloc++;
	return calloc(1, n);
}
#define kvzalloc(n, flags) kzalloc((n), (flags))
static void kfree_p(const void *p)
{
	if (p != NULL)
		g_w.free++;
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

#define DEFINE_MUTEX(x) int x
#define mutex_lock(x)             \
	do {                      \
		(void)(x);        \
		g_w.mutex_lock++; \
	} while (0)
#define mutex_unlock(x)             \
	do {                        \
		(void)(x);          \
		g_w.mutex_unlock++; \
	} while (0)
#define DECLARE_RWSEM(x) int x
#define down_read(x)             \
	do {                     \
		(void)(x);       \
		g_w.lock_read++; \
	} while (0)
#define up_read(x)                 \
	do {                       \
		(void)(x);         \
		g_w.unlock_read++; \
	} while (0)
#define down_write(x)             \
	do {                      \
		(void)(x);        \
		g_w.lock_write++; \
	} while (0)
#define up_write(x)                 \
	do {                        \
		(void)(x);          \
		g_w.unlock_write++; \
	} while (0)

#define READ_ONCE(x) (g_w.ordered++, (x))
#define WRITE_ONCE(x, v)       \
	do {                   \
		g_w.ordered++; \
		(x) = (v);     \
	} while (0)
#define smp_load_acquire(p) (g_w.ordered++, *(p))
#define smp_store_release(p, v) \
	do {                    \
		g_w.ordered++;  \
		*(p) = (v);     \
	} while (0)
#define rcu_read_lock()         \
	do {                    \
		g_w.rcu_lock++; \
	} while (0)
#define rcu_read_unlock()         \
	do {                      \
		g_w.rcu_unlock++; \
	} while (0)
#define rcu_dereference(p) (g_w.ordered++, (p))
#define rcu_assign_pointer(p, v) \
	do {                     \
		g_w.ordered++;   \
		(p) = (v);       \
	} while (0)
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
static const u32 g_test_token[4] = { 0x11111111u, 0x22222222u, 0x33333333u,
				     0x44444444u };
void tosya_token_get(u32 out[4]);

#define TOSYA_DIR_TEST 1
static void d_add(struct dentry *dentry, struct inode *inode)
{
	g_w.negative_add++;
	dentry->d_inode = inode;
}
static struct dentry *dget(struct dentry *d)
{
	return d;
}
static void dput(struct dentry *d)
{
	(void)d;
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

#include "dir_work_block.inc"

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

/* ---- the parents ------------------------------------------------------- */

#define NPARENT 2
#define PARENT 0

static struct super_block g_sb;
static struct inode g_parent[NPARENT];
static struct dentry g_pdent[NPARENT];
static struct inode_operations g_orig[NPARENT];
static struct inode g_child;
static int g_fs_has_child;

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

static struct dentry *orig_lookup(struct inode *dir, struct dentry *dentry,
				  unsigned int flags)
{
	(void)dir;
	(void)flags;
	g_w.orig_lookup++;
	dentry->d_inode = g_fs_has_child ? &g_child : NULL;
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

/* ---- the dcache the fast path consults --------------------------------- */

#define CACHE_MAX 16

struct cache_ent {
	unsigned char name[TOSYA_NAME_MAX + 1];
	u32 len;
	u32 hash;
	int negative;
};
static struct cache_ent g_cache[CACHE_MAX];
static int g_cache_n;

static int cache_find(const u8 *name, u32 len, u32 hash)
{
	int i;

	for (i = 0; i < g_cache_n; i++)
		if (g_cache[i].len == len && g_cache[i].hash == hash &&
		    memcmp(g_cache[i].name, name, len) == 0)
			return g_cache[i].negative;
	return -1;
}

static void cache_add(const u8 *name, u32 len, u32 hash, int negative)
{
	if (cache_find(name, len, hash) >= 0)
		return;
	if (g_cache_n >= CACHE_MAX)
		return;
	memcpy(g_cache[g_cache_n].name, name, len);
	g_cache[g_cache_n].name[len] = '\0';
	g_cache[g_cache_n].len = len;
	g_cache[g_cache_n].hash = hash;
	g_cache[g_cache_n].negative = negative;
	g_cache_n++;
}

/* ---- one walk of one name ---------------------------------------------- */

#define TEST_HASH 0x12345678u

static int walk(const char *name)
{
	const u32 len = (u32)strlen(name);
	unsigned char dname[TOSYA_NAME_MAX + 1];
	struct qstr last;
	struct dentry d;
	const u8 *mask_bytes;
	u32 mask_hash;
	int hit, cached;

	memcpy(dname, name, len + 1);
	last.name = dname;
	last.len = len;
	last.hash = TEST_HASH;

	/* lookup_fast(): one preparation, then the dcache probe */
	g_w.walk_calls++;
	g_w.hash_calls = g_dir_test_hash_calls;
	g_w.hash_iters = g_dir_test_hash_iters;
	g_w.probe_calls = g_dir_test_probes;
	g_w.probe_slots = g_dir_test_probe_slots;
	hit = tosya_dir_walk_last(&last, &mask_bytes, &mask_hash);
	g_w.walk_hits += hit;
	g_w.hash_calls = g_dir_test_hash_calls - g_w.hash_calls;
	g_w.hash_iters = g_dir_test_hash_iters - g_w.hash_iters;
	g_w.probe_calls = g_dir_test_probes - g_w.probe_calls;
	g_w.probe_slots = g_dir_test_probe_slots - g_w.probe_slots;
	last.name = hit ? mask_bytes : last.name;
	last.hash = hit ? mask_hash : last.hash;
	g_w.fast_probe++;
	cached = cache_find(last.name, last.len, last.hash);
	if (cached >= 0) {
		g_w.fast_cached++;
		return cached ? -ENOENT : 0;
	}

	/* lookup_slow() -> __lookup_slow() -> i_op->lookup */
	g_w.slow++;
	memset(&d, 0, sizeof(d));
	d.d_name = last;
	d.d_parent = &g_pdent[PARENT];
	CHECK(g_parent[PARENT].i_op->lookup(&g_parent[PARENT], &d, 0) == NULL,
	      "the cold path answers without an error");
	cache_add(last.name, last.len, last.hash, d.d_inode == NULL);
	return d.d_inode == NULL ? -ENOENT : 0;
}

/* ---- the scenarios ------------------------------------------------------ */

struct scenario {
	const char *id;
	u32 caller;
	const char *child;
	int fs_has;
	int hidden;
	const char *what;
};

static const struct scenario g_cases[] = {
	{ "absent", 10123, "com.not.there", 0, 0,
	  "the name is in no set and the filesystem does not have it" },
	{ "hidden-own", 10123, "com.hidden.one", 1, 1,
	  "hidden from this caller and the filesystem has it" },
	{ "hidden-own-2", 10123, "com.hidden.two", 1, 1,
	  "a second hidden name" },
	{ "hidden-wild", 10125, "com.hidden.all", 1, 1,
	  "hidden only by the wildcard record (caller 0)" },
	{ "hidden-12", 10123, "com.hidden.x", 1, 1, "hidden at 12 bytes" },
	{ "caller-miss", 10124, "com.hidden.one", 1, 0,
	  "hidden from 123, not from this caller" },
	{ "visible", 10123, "com.visible", 1, 0,
	  "in no set, and the filesystem has it" },
	{ "untagged", POLICY_ID_NONE, "com.hidden.one", 1, 0,
	  "an untagged caller is answered by the filesystem" },
};

static void stage_set(u32 npad)
{
	u32 i;
	char pad[32];

	dir_stage_reset();
	CHECK(dir_stage_add(123u, (const u8 *)"com.hidden.one", 14) == 0,
	      "the first name is staged");
	CHECK(dir_stage_add(123u, (const u8 *)"com.hidden.x", 12) == 0,
	      "a 12-byte name is staged");
	CHECK(dir_stage_add(123u, (const u8 *)"com.hidden.two", 14) == 0,
	      "the second name is staged");
	CHECK(dir_stage_add(TOSYA_APP_SPAN, (const u8 *)"com.hidden.all", 14) ==
		      0,
	      "the wildcard name is staged");
	for (i = 0; i < npad; i++) {
		snprintf(pad, sizeof(pad), "com.pad.%u", i);
		CHECK(dir_stage_add(123u, (const u8 *)pad, (u32)strlen(pad)) ==
			      0,
		      "a padding name is staged");
	}
	CHECK(dir_names_apply() == 0, "the set is applied");
}

static const char *const g_cols[] = {
	"walk_calls",  "walk_hits",   "hash_calls",   "hash_iters",
	"probe_calls", "probe_slots", "fast_probe",   "fast_cached",
	"slow",	       "orig_lookup", "negative_add", "alloc",
	"free",	       "lock_read",   "unlock_read",  "lock_write",
	"mutex_lock",  "rcu_lock",    "rcu_unlock",   "arena_bytes",
};

static void print_header(void)
{
	size_t i;

	printf("header,scenario,phase,rc");
	for (i = 0; i < sizeof(g_cols) / sizeof(g_cols[0]); i++)
		printf(",%s", g_cols[i]);
	printf("\n");
}

static void print_line(const char *id, const char *phase, int rc)
{
	const unsigned long v[] = {
		g_w.walk_calls,	  g_w.walk_hits,
		g_w.hash_calls,	  g_w.hash_iters,
		g_w.probe_calls,  g_w.probe_slots,
		g_w.fast_probe,	  g_w.fast_cached,
		g_w.slow,	  g_w.orig_lookup,
		g_w.negative_add, g_w.alloc,
		g_w.free,	  g_w.lock_read,
		g_w.unlock_read,  g_w.lock_write,
		g_w.mutex_lock,	  g_w.rcu_lock,
		g_w.rcu_unlock,	  (unsigned long)g_dir_names->arena_bytes,
	};
	size_t i;

	printf("csv,%s,%s,%d", id, phase, rc);
	for (i = 0; i < sizeof(v) / sizeof(v[0]); i++)
		printf(",%lu", v[i]);
	printf("\n");
}

int main(int argc, char **argv)
{
	const struct scenario *sc = NULL;
	const char *mode = "both";
	u32 npad = 0;
	size_t i;
	int rc;

	if (argc < 2) {
		fprintf(stderr,
			"usage: %s <scenario|list> [cold|both] [--links N]\n",
			argv[0]);
		return 2;
	}
	for (i = 0; i < sizeof(g_cases) / sizeof(g_cases[0]); i++)
		if (strcmp(argv[1], g_cases[i].id) == 0)
			sc = &g_cases[i];
	if (sc == NULL) {
		for (i = 0; i < sizeof(g_cases) / sizeof(g_cases[0]); i++)
			printf("%s\t%s\n", g_cases[i].id, g_cases[i].what);
		return strcmp(argv[1], "list") == 0 ? 0 : 2;
	}
	if (argc >= 3)
		mode = argv[2];
	for (i = 3; i + 1 < (size_t)argc; i++)
		if (strcmp(argv[i], "--links") == 0)
			npad = (u32)strtoul(argv[i + 1], NULL, 0);

	print_header();
	setup_parents();
	w_reset();
	CHECK(register_all() == 0, "the parents are registered");
	CHECK(dir_guard_count() == NPARENT, "all parents are protected");
	stage_set(npad);
	printf("setup,parents=%u,names=%u,guards=%u,alloc=%lu\n", NPARENT,
	       dir_name_count(), dir_guard_count(), g_w.alloc);

	if (sc->caller == POLICY_ID_NONE)
		g_dir_test_app = POLICY_ID_NONE;
	else {
		u32 app = 0;

		CHECK(dir_caller_app_of(sc->caller, &app) == 0,
		      "the case names an app");
		g_dir_test_app = app;
	}
	g_fs_has_child = sc->fs_has;

	const int want = (sc->hidden || !sc->fs_has) ? -ENOENT : 0;

	/* the first walk of the name: nothing for it in the cache */
	g_dir_test_hash_calls = 0;
	g_dir_test_hash_iters = 0;
	g_dir_test_probes = 0;
	g_dir_test_probe_slots = 0;
	w_reset();
	rc = walk(sc->child);
	print_line(sc->id, "cold", rc);
	CHECK(rc == want, "the first walk answers what the case expects");
	CHECK(g_cache_n >= 1, "the walk left a dentry behind");
	CHECK(g_w.walk_calls == 1u, "one preparation");
	CHECK(g_w.hash_calls == 1u &&
		      g_w.hash_iters == (unsigned long)strlen(sc->child),
	      "one hash traversal of the name on both paths");
	CHECK(g_w.probe_calls == 1u && g_w.probe_slots == 2u * DIR_PAIR_PROBES,
	      "one fixed probe run on both paths");
	if (sc->hidden) {
		CHECK(g_w.walk_hits == 1u,
		      "the preparation substituted a hidden name");
		CHECK(g_w.orig_lookup == 0u,
		      "the filesystem is never asked about a hidden name");
		CHECK(g_w.negative_add == 1u,
		      "the cold path left one negative entry");
		CHECK(g_w.slow == 1u, "the first walk took the cold path");
	} else {
		CHECK(g_w.walk_hits == 0u,
		      "the preparation left the name alone");
		CHECK(g_w.orig_lookup == 1u,
		      "the filesystem was asked about the name");
		CHECK(g_w.negative_add == 0u,
		      "the cold path added nothing of its own");
	}

	if (strcmp(mode, "both") == 0) {
		/* the second walk: the dentry the first one left answers it */
		g_dir_test_hash_calls = 0;
		g_dir_test_hash_iters = 0;
		g_dir_test_probes = 0;
		g_dir_test_probe_slots = 0;
		w_reset();
		rc = walk(sc->child);
		print_line(sc->id, "warm", rc);
		CHECK(rc == want, "the second walk answers the same");
		CHECK(g_w.fast_cached == 1u,
		      "the dentry the first walk left answers the probe");
		CHECK(g_w.slow == 0u,
		      "the second walk does not reach the cold path");
		CHECK(g_w.orig_lookup == 0u,
		      "the second walk asks the filesystem nothing");
		CHECK(g_w.walk_hits == (sc->hidden ? 1u : 0u),
		      "the preparation is the same on every walk");
	}

	dir_guard_remove_all();
	(void)g_warned;
	printf("%s\n", g_fail != 0 ? "FAIL" : "OK");
	return g_fail != 0;
}
