/* Host test for the inode shadow records of src/policy.c.
 *
 * The block is kernel-only (it needs inodes), so scripts/extract_shadow.py lifts it
 * out of the file and this drives it. What the scenarios pin down is what went
 * wrong in it: an inode the package manager let go of while its fields were being
 * read, a table handed to a file it was not made for, an open that chained to
 * itself, and a record installed even though its path could not be stored. Run
 * under ASan on purpose -- three of those were use-after-free or type confusion,
 * which a plain run does not show.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

// What the block expects from the kernel.
#define TOSYA_APK_MAX 16
#define TOSYA_APP_MIN 10000u
#define TOSYA_APP_SPAN 10000u
#define I_NEW 1u
#define I_FREEING 2u
#define I_WILL_FREE 4u
#define GFP_KERNEL 0u
#define __maybe_unused
#define __nocfi
#define DEFINE_MUTEX(x) int x
// The table lock is real here, and it aborts when one thread takes it twice: the kernel's mutex would
// wait forever there, and a test that hangs says nothing.
static pthread_mutex_t g_host_lock = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local int g_host_locked;
static void host_mutex_lock(int *lock)
{
	(void)lock;
	if (g_host_locked) {
		fputs("shadow: one thread took the table lock twice\n", stderr);
		abort();
	}
	assert(pthread_mutex_lock(&g_host_lock) == 0);
	g_host_locked = 1;
}
static void host_mutex_unlock(int *lock)
{
	(void)lock;
	g_host_locked = 0;
	assert(pthread_mutex_unlock(&g_host_lock) == 0);
}
#define mutex_lock(x) host_mutex_lock(x)
#define mutex_unlock(x) host_mutex_unlock(x)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#define TOSYA_DEBUG_ON() 0
#define pr_info(...) ((void)0)
#define pr_info_once(...) ((void)0)
#define pr_warn(...) ((void)0)
#define atomic_read(p) (*(p))
#define i_size_read(p) 0LL

struct module;
struct inode;
struct file;

struct file_operations {
	struct module *owner;
	int (*open)(struct inode *, struct file *);
	int (*read_iter)(struct file *);
};

struct super_block {
	dev_t s_dev;
};

struct inode {
	const struct file_operations *i_fop;
	struct super_block *i_sb;
	unsigned long i_ino;
	unsigned long i_state;
	int i_count;
	unsigned int i_mode; /* S_ISREG is asked of it */
};

struct file {
	const struct file_operations *f_op;
};

struct dentry {
	struct inode *inode;
	struct dentry *d_parent;
	struct {
		const char *name;
	} d_name;
};

struct path {
	struct dentry *dentry;
};

#define d_backing_inode(d) ((d)->inode)

/* The module a table belongs to: fops_get() takes a reference on its owner, and the
 * block has to name this module as the owner of the copy it installs. */
static int g_module;
#define THIS_MODULE ((struct module *)&g_module)

static void *tosya_kzalloc(size_t bytes)
{
	return calloc(1, bytes);
}

/* The block allocates through the shim's kzalloc/kfree (linux/slab.h, pulled in by the block's
 * own include of linux/mm.h); these two are only for what this file builds by hand. */

/* igrab() refuses an inode that is being freed -- that is what makes reading its
 * fields safe -- and iput() gives the reference back; the last one evicts the
 * inode the way the kernel does. */
static struct inode *igrab(struct inode *inode)
{
	if (inode == NULL || (inode->i_state & (I_FREEING | I_WILL_FREE)))
		return NULL;
	inode->i_count++;
	return inode;
}

static void iput(struct inode *inode)
{
	if (inode == NULL)
		return;
	if (--inode->i_count == 0)
		free(inode);
}

static int open_a(struct inode *inode, struct file *file);
static int open_b(struct inode *inode, struct file *file);
static int read_a(struct file *file)
{
	(void)file;
	return 111;
}
static int read_b(struct file *file)
{
	(void)file;
	return 222;
}

static const struct file_operations ops_a = { .open = open_a,
					      .read_iter = read_a };
static const struct file_operations ops_b = { .open = open_b,
					      .read_iter = read_b };

static struct inode *g_a;
static struct inode *g_b;
static struct dentry d_a;
static struct dentry d_b;
static struct super_block g_sb = { .s_dev = 1 };

static int open_a(struct inode *inode, struct file *file)
{
	(void)inode;
	(void)file;
	return 11;
}

static int open_b(struct inode *inode, struct file *file)
{
	(void)inode;
	(void)file;
	return 22;
}

static const char *kApkA = "/data/app/~~a/com.a/base.apk";
static const char *kApkB = "/data/app/~~b/com.b/base.apk";

static int fake_kern_path(const char *name, unsigned int flags, struct path *p)
{
	(void)flags;
	if (!strcmp(name, kApkA))
		p->dentry = &d_a;
	else if (!strcmp(name, kApkB))
		p->dentry = &d_b;
	else
		return -ENOENT;
	if (p->dentry->inode == NULL)
		return -ENOENT;
	p->dentry->inode->i_count++; /* the reference the dentry holds for us */
	return 0;
}

/* What a dentry reference keeps: d_delete() takes the inode out of the dentry and
 * lets it go, and that is the case the block has to survive. */
static void path_put(struct path *p)
{
	iput(p->dentry->inode);
}

static struct super_block *host_user_get_super(dev_t dev, bool rw);

static unsigned long tosya_lookup(const char *name)
{
	/* The block resolves the super block helper through this name, so the host hands it its own:
	 * that is what lets the sweep put a file back and the unload path hand every record away. */
	if (strcmp(name, "user_get_super") == 0)
		return (unsigned long)&host_user_get_super;
	return (unsigned long)fake_kern_path;
}

static void tosya_status_set_apks(unsigned int inodes, unsigned int offered,
				  unsigned int failed)
{
	(void)inodes;
	(void)offered;
	(void)failed;
}

/* count is the number of references the inode starts with: the lookup takes one of
 * its own, and anything above that stands for whoever else still holds it (the
 * package manager's inode cache). */
static struct inode *new_inode(const struct file_operations *ops,
			       unsigned long ino, int count)
{
	struct inode *inode = tosya_kzalloc(sizeof(*inode));

	assert(inode != NULL);
	inode->i_fop = ops;
	inode->i_sb = &g_sb;
	inode->i_ino = ino;
	inode->i_count = count;
	// A regular file: the shadow rule only applies to those (S_ISREG is asked of it).
	inode->i_mode = 0100644;
	return inode;
}

// held = how many references the file has besides the one the lookup takes.
void tosya_apk_remove(void);

static void setup_a(int held)
{
	/*
	 * The world every scenario starts in: what the last one left is given back first, tables and
	 * all, so a record from it cannot answer for this one.
	 */
	tosya_apk_remove();
	g_a = new_inode(&ops_a, 100, 1 + held);
	d_a.inode = g_a;
}

static void setup_b(int held)
{
	g_b = new_inode(&ops_b, 200, 1 + held);
	d_b.inode = g_b;
}

/*
 * The barrier and lock seams the block asks about, which one thread would not need and the
 * contention scenario does. RCU is not among them: it comes from the stub, where a reader holds
 * the read side for as long as it is in a table.
 */
#define smp_wmb() ((void)0)
#define lockdep_is_held(lock) (1)
#define pr_warn_once(...) ((void)0)
#define S_ISREG(m) (((m) & 0170000) == 0100000)
#define new_decode_dev(dev) (dev)

/* What the block asks of the kernel around the table it installs: the lookup helper it calls under
 * the super block lock, and the index it keeps for the files it shadowed. The host has no VFS, so
 * these answer with the one superblock and the two inodes the scenarios build; the super block
 * seam itself (g_user_get_super) is resolved at load time and stays NULL here, which the block
 * handles by leaving the sweep alone. */
typedef struct super_block *(*tosya_user_get_super_t)(dev_t dev, bool rw);
struct tosya_index;
static struct tosya_index *g_index;

static struct inode *ilookup(struct super_block *sb, unsigned long ino)
{
	if (sb != &g_sb)
		return NULL;
	if (ino == 100)
		return g_a;
	if (ino == 200)
		return g_b;
	return NULL;
}

static void drop_super(struct super_block *sb)
{
	(void)sb;
}

#include "shadow_block.inc"

// What the kernel's user_get_super does for this build's single super block.
static struct super_block *host_user_get_super(dev_t dev, bool rw)
{
	(void)rw;
	return dev == g_sb.s_dev ? &g_sb : NULL;
}

/* The block asks the tag record two questions (see tag.c): nothing here is
 * waiting for a name, and the name itself is what the test that follows checks
 * by hand rather than through the hook. */
bool tosya_tag_pending_here(void)
{
	return false;
}

void tosya_tag_name(u32 app)
{
	(void)app;
}

// A file opened through a table.
static int open_through(const struct file_operations *fops, struct inode *inode)
{
	struct file file = { .f_op = fops };

	return fops->open(inode, &file);
}

/* The inode the lookup hands over is the one the package manager evicts while its
 * fields are still being read: without a reference of our own that read is a
 * use-after-free, which is what the sanitizer is here for. The record still has to
 * end up installed and complete. */
static void scenario_early_put(void)
{
	setup_a(0);
	assert(shadow_arm(tosya_encode_dev(g_sb.s_dev), 100, 10123) == 0);
	// The table is built when the rule first meets the file, which is what the inode hook does.
	tosya_apk_shadow_apply(g_a);
	assert(g_shadow_n == 1);
	assert(!g_shadow[0]->parked);
	assert(g_shadow[0]->dev == tosya_encode_dev(g_sb.s_dev));
	assert(g_shadow[0]->ino == 100);
	assert(g_shadow[0]->app == 123);
	assert(g_shadow[0]->fops.owner == THIS_MODULE);
	assert(g_shadow[0]->orig_open == open_a);
}

/* A table belongs to the file it was made for: the second replacement must not
 * touch the first one's, or an inode that still points at it dispatches into
 * another filesystem's operations. */
static void scenario_no_reuse(void)
{
	setup_a(1);
	setup_b(0);
	assert(shadow_arm(tosya_encode_dev(g_sb.s_dev), 100, 10123) == 0);
	tosya_apk_shadow_apply(g_a);
	shadow_drop_id(tosya_encode_dev(g_sb.s_dev), 100);
	assert(g_shadow[0]->parked);

	assert(shadow_arm(tosya_encode_dev(g_sb.s_dev), 200, 10456) == 0);
	tosya_apk_shadow_apply(g_b);
	assert(g_shadow_n == 2);
	assert(!g_shadow[1]->parked);
	assert(g_shadow[1]->ino == 200);
	assert(open_through(&g_shadow[1]->fops, g_b) == 22);

	// The first file still finds the operations it was made for.
	assert(g_shadow[0]->orig_open == open_a);
	assert(open_through(&g_shadow[0]->fops, g_a) == 11);
	assert(g_shadow[0]->fops.read_iter(NULL) == 111);
}

/* A file that comes back after being dropped is given a table of its own, and that
 * table has to chain to the file's own open -- chaining to this module's would call
 * itself until the stack is gone. */
static void scenario_readd(void)
{
	setup_a(1);
	assert(shadow_arm(tosya_encode_dev(g_sb.s_dev), 100, 10123) == 0);
	tosya_apk_shadow_apply(g_a);
	shadow_drop_id(tosya_encode_dev(g_sb.s_dev), 100);
	/* Putting the file back is the sweep's work in the kernel, and the host has no cache to
	 * sweep: it happens here so that the second table is built from the file's own operations. */
	g_a->i_fop = &ops_a;
	assert(shadow_arm(tosya_encode_dev(g_sb.s_dev), 100, 10123) == 0);
	tosya_apk_shadow_apply(g_a);
	assert(g_shadow_n == 2);
	assert(g_shadow[1]->orig_open != tosya_shadow_open);
	assert(g_shadow[1]->orig_open == open_a);
	assert(open_through(&g_shadow[1]->fops, g_a) == 11);
}

// Unloading puts every file back and gives the records away.
static void scenario_remove(void)
{
	setup_a(1);
	assert(shadow_arm(tosya_encode_dev(g_sb.s_dev), 100, 10123) == 0);
	tosya_apk_shadow_apply(g_a);
	assert(g_a->i_fop == &g_shadow[0]->fops);
	tosya_apk_remove();
	assert(g_shadow_n == 0);
	assert(g_a->i_fop == &ops_a);
}

/*
 * A lookup costs the same whatever it finds: two bucket reads. The number is the design and not a
 * measurement, so it is asserted rather than described.
 */
static void scenario_reads(void)
{
	unsigned long first, again;

	setup_a(1);
	assert(shadow_arm(tosya_encode_dev(g_sb.s_dev), 100, 10123) == 0);
	assert(shadow_arm(tosya_encode_dev(g_sb.s_dev), 101, 10123) == 0);
	assert(shadow_arm(tosya_encode_dev(g_sb.s_dev), 102, 10124) == 0);
	/*
	 * A record is in the table a reader sees once the push has put it there: that is what keeps
	 * the published table out of a writer's reach, and what these lookups are read through.
	 */
	(void)tosya_apk_stream_finish();

	g_index_reads = 0;
	assert(shadow_find(tosya_encode_dev(g_sb.s_dev), 100) != NULL);
	first = g_index_reads;
	assert(first == 2);
	g_index_reads = 0;
	assert(shadow_find(tosya_encode_dev(g_sb.s_dev), 100) != NULL);
	again = g_index_reads;
	assert(first == again);
	g_index_reads = 0;
	assert(shadow_find(tosya_encode_dev(g_sb.s_dev), 999) == NULL);
	assert(g_index_reads == first);
	g_index_reads = 0;
	assert(shadow_find(tosya_encode_dev(g_sb.s_dev) + 7u, 100) == NULL);
	assert(g_index_reads == first);
	fprintf(stderr,
		"shadow: %lu read(s) per lookup, hit and miss alike PASS\n",
		first);
}

/*
 * A record whose inode is gone is given back at the next push: the inode cache reclaimed it, so
 * nothing can reach the record through it, and the array it lives in stops growing with the
 * churn of installs and removals.
 */
static void scenario_reclaim(void)
{
	setup_a(1);
	assert(shadow_arm(tosya_encode_dev(g_sb.s_dev), 100, 10123) == 0);
	tosya_apk_shadow_apply(g_a);
	assert(g_shadow_n == 1);

	// The inode cache gives the inode up: the hook marks the record before the original runs.
	tosya_apk_shadow_reclaim(g_a);
	assert(g_shadow[0]->reclaimed);
	assert(shadow_find(tosya_encode_dev(g_sb.s_dev), 100) == NULL);

	assert(tosya_apk_stream_finish() == 0);
	assert(g_shadow_n == 0);
	assert(index_get(tosya_encode_dev(g_sb.s_dev), 100) == NULL);

	// The file coming back is a new inode and a new record, not the freed one.
	assert(shadow_arm(tosya_encode_dev(g_sb.s_dev), 100, 10123) == 0);
	assert(g_shadow_n == 1);
	assert(!g_shadow[0]->reclaimed);
	tosya_apk_remove();
	assert(g_shadow_n == 0);
	fprintf(stderr, "shadow: reclaim PASS\n");
}

/*
 * Readers and a writer at once. The readers only ever take the read side and the writer only ever
 * takes the mutex and the write side, so a deadlock here is a lock order that does not exist, and a
 * use-after-free is a record freed while a reader could still be inside it.
 */
static void *reader_thread(void *arg)
{
	u32 dev = tosya_encode_dev(g_sb.s_dev);
	int i;

	(void)arg;
	for (i = 0; i < 40000; i++)
		(void)shadow_find(dev, (u64)(100 + (i % 8)));
	return NULL;
}

/*
 * A push that ends while the files it names are in the cache: the sweep arms them holding the table
 * lock, so the lookup inside it must not take that lock again.
 */
static void scenario_sweep_cached(void)
{
	u32 dev = tosya_encode_dev(g_sb.s_dev);

	setup_a(1);
	assert(shadow_arm(dev, 100, 10123) == 0);
	assert(g_staging != NULL);
	assert(tosya_apk_stream_finish() == 1);
	assert(g_a->i_fop == &g_shadow[0]->fops);
	assert(open_through(&g_shadow[0]->fops, g_a) == 11);
	tosya_apk_remove();
	fprintf(stderr, "shadow: sweep-cached PASS\n");
}

/*
 * What a lookup costs, hit and miss alike: the scenario next door counts the reads, and this one is
 * the number, measured in batches so the clock is not part of it.
 */
#define BENCH_ROUNDS 200
#define BENCH_PER_ROUND 2000
#define BENCH_REPS 5

/*
 * Picoseconds per iteration, best of five rounds of two thousand: the clock is outside the loop and
 * each body is passed in, so no call of the benchmark's own is part of the answer. The loop carries
 * a compiler barrier, without which the work is hoisted out of a loop that writes nothing it reads.
 */
#define BENCH_PS(body)                                                                                      \
	do {                                                                                                \
		struct timespec a, b;                                                                       \
		u64 total = 0;                                                                              \
		int r, i;                                                                                   \
		volatile int sink = 0;                                                                      \
                                                                                                            \
		for (r = 0; r < BENCH_ROUNDS; r++) {                                                        \
			clock_gettime(CLOCK_MONOTONIC, &a);                                                 \
			for (i = 0; i < BENCH_PER_ROUND; i++) {                                             \
				/* The loop has to do the work every time: without this the compiler hoists
				 * a lookup that only reads what the loop never writes. */ \
				__asm__ __volatile__("" ::: "memory");                                      \
				body;                                                                       \
			}                                                                                   \
			clock_gettime(CLOCK_MONOTONIC, &b);                                                 \
			total += (u64)(b.tv_sec - a.tv_sec) * 1000000000ull +                               \
				 (u64)(b.tv_nsec - a.tv_nsec);                                              \
		}                                                                                           \
		(void)sink;                                                                                 \
		ret = total * 1000ull / (BENCH_ROUNDS * BENCH_PER_ROUND);                                   \
	} while (0)

// Nothing at all: the loop, so the rest can be read against it.
static u64 bench_loop(void)
{
	u64 ret;

	BENCH_PS(sink += i & 1);
	return ret;
}

// What this machine spends on the harness itself: the read side here is a pthread lock.
static u64 bench_rcu(void)
{
	u64 ret;

	BENCH_PS(rcu_read_lock(); rcu_read_unlock());
	return ret;
}

// The table alone: two slot reads and the hash, with no read side and no call around it.
static u64 bench_table(u32 dev, u64 ino)
{
	u64 ret;

	BENCH_PS(sink += index_lookup(g_index, dev, ino) != NULL);
	return ret;
}

// What a caller of the block pays, read side included.
static u64 bench_find(u32 dev, u64 ino)
{
	u64 ret;

	BENCH_PS(sink += shadow_find(dev, ino) != NULL);
	return ret;
}

static void scenario_timing(void)
{
	u32 dev = tosya_encode_dev(g_sb.s_dev);
	u64 loop, rcu, hit, miss, find_hit, find_miss;

	setup_a(1);
	assert(shadow_arm(dev, 100, 10123) == 0);
	// Published, which is the state a lookup is asked in almost every time.
	(void)tosya_apk_stream_finish();
	loop = bench_loop();
	rcu = bench_rcu();
	hit = bench_table(dev, 100);
	miss = bench_table(dev, 999999);
	find_hit = bench_find(dev, 100);
	find_miss = bench_find(dev, 999999);
	fprintf(stderr,
		"shadow: %llu ps loop, %llu ps rcu, table %llu/%llu ps hit/miss, find %llu/%llu",
		(unsigned long long)loop, (unsigned long long)rcu,
		(unsigned long long)hit, (unsigned long long)miss,
		(unsigned long long)find_hit, (unsigned long long)find_miss);
	puts("");
	fprintf(stderr,
		"shadow: the table is %lld ps a lookup, the two differ by %lld ps",
		(long long)(hit - loop), (long long)hit - (long long)miss);
	puts("");
	tosya_apk_remove();
	puts("shadow: timing PASS");
}

static void scenario_contend(void)
{
	pthread_t th[6];
	u32 dev = tosya_encode_dev(g_sb.s_dev);
	int i, t;

	setup_a(1);
	for (i = 0; i < 8; i++)
		assert(shadow_arm(dev, (u64)(100 + i), 10123) == 0);
	for (t = 0; t < 6; t++)
		assert(pthread_create(&th[t], NULL, reader_thread, NULL) == 0);
	for (i = 0; i < 200; i++) {
		tosya_apk_shadow_apply(g_a);
		tosya_apk_shadow_reclaim(g_a);
		/*
		 * The inode cache gives the inode up here, which in the kernel means the inode itself
		 * goes with it: what is left of it in this test has to stop pointing at the record the
		 * reclaim just marked, or the next round reads a table that is on its way out.
		 */
		g_a->i_fop = &ops_a;
		(void)tosya_apk_stream_finish();
		assert(shadow_arm(dev, 100, 10123) == 0);
	}
	for (t = 0; t < 6; t++)
		assert(pthread_join(th[t], NULL) == 0);
	tosya_apk_remove();
	assert(g_shadow_n == 0);
	fprintf(stderr, "shadow: contend PASS\n");
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr,
			"usage: %s <early-put|no-reuse|readd|remove|reads|reclaim|sweep-cached|timing|contend>\n",
			argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "early-put"))
		scenario_early_put();
	else if (!strcmp(argv[1], "no-reuse"))
		scenario_no_reuse();
	else if (!strcmp(argv[1], "readd"))
		scenario_readd();
	else if (!strcmp(argv[1], "remove"))
		scenario_remove();
	else if (!strcmp(argv[1], "reads"))
		scenario_reads();
	else if (!strcmp(argv[1], "reclaim"))
		scenario_reclaim();
	else if (!strcmp(argv[1], "sweep-cached"))
		scenario_sweep_cached();
	else if (!strcmp(argv[1], "timing"))
		scenario_timing();
	else if (!strcmp(argv[1], "contend"))
		scenario_contend();
	else
		return 2;
	printf("shadow: %s PASS\n", argv[1]);
	return 0;
}
