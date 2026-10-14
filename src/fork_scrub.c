/*
 * Taking the names out of the parent, after the fork it asked for is done.
 *
 * The arguments of a start are made into Java Strings in the process that parses them -- the main
 * zygote on the fork path, and the pooled child (A17 forks repeatedly from one such child) on the
 * usap path. That process then forks, and everything it forks -- apps, the next pool child, an
 * isolated process -- inherits those Strings through copy-on-write. So the cleanup runs in the
 * parent every time it forks, before it can serve the next command.
 *
 * Working in the parent is also what keeps the child working: the child has to read its own
 * arguments, and the write here splits the page, so the parent gets a clean copy and the child
 * keeps the text it was given.
 *
 * Only pages this process wrote since the last look are looked at: the hardware keeps that fact in
 * the dirty bit. All of them are taken, in rounds, with no cap -- a page that is not taken stays
 * dirty and is seen again next time. A page is only allowed to lose its dirty bit after it has
 * been read whole and compared, and a page that is written over is written through a proper
 * mapping, never through one shared with a child.
 */
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/pagewalk.h>
#include <linux/ptrace.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uidgid.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "tosya.h"

#define TOSYA_FIRST_APP_UID 10000u

/* One round takes this many pages; the next round takes the next ones. Nothing is dropped. */
#define TOSYA_BATCH_MAX 2048u
/* A guarded loop: every round has to make progress, and this is only a backstop. */
#define TOSYA_MAX_ROUNDS 16u

/* kmap_local_page arrived in 5.11; before that an atomic mapping is the one that may be
 * used for a page taken by get_user_pages. */
static inline void *tosya_map_page(struct page *page)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	return kmap_local_page(page);
#else
	return kmap_atomic(page);
#endif
}

static inline void tosya_unmap_page(void *base)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	kunmap_local(base);
#else
	kunmap_atomic(base);
#endif
}

/* The locked argument this call used to carry went away in 6.5. */
static inline int tosya_get_page(struct mm_struct *mm, unsigned long addr,
				 struct page **page, bool writable)
{
	unsigned int flags = writable ? FOLL_WRITE : 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
	return get_user_pages_remote(mm, addr, 1, flags, page, NULL);
#else
	return get_user_pages_remote(mm, addr, 1, flags, page, NULL, NULL);
#endif
}

/* One read, one answer: the list is copied out at a fixed size, so there is no "how big is
 * it" step that can disagree with the copy that follows. */
#define TOSYA_NAMES_MAX (8u * 1024u)
#define TOSYA_TOKEN_MAX 64u

/* The shapes a name is carried in. Only what is recognised byte for byte is written over. */
static const char *const tosya_prefixes[] = {
	"--package-name=",
	"--nice-name=",
	"--pkg-data-info-map=",
	"--app-data-dir=/data/user/0/",
	"--app-data-dir=/data/user_de/0/",
	"--app-data-dir=/data/data/",
	"/data/user/0/",
	"/data/user_de/0/",
};

static inline bool tosya_name_char(u8 c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '_' || c == '.';
}

/*
 * The text that stands in for a run: letters and digits, both cases, expanded from the record's
 * seed. No shape of its own -- it cannot be read as an argument, a path or a package name.
 */
static void tosya_fill(u8 *at, u32 len, u32 seed)
{
	static const char alphabet[] =
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	u32 state = seed | 1u;
	u32 i;

	for (i = 0; i < len; ++i) {
		state ^= state << 13;
		state ^= state >> 17;
		state ^= state << 5;
		at[i] = alphabet[state % 62u];
	}
}

/* The recognised prefix ending right at @at, or zero when there is none. */
static u32 tosya_prefix_at(const u8 *page, u32 at)
{
	u32 best = 0;
	u32 i;

	for (i = 0; i < ARRAY_SIZE(tosya_prefixes); ++i) {
		u32 len = strlen(tosya_prefixes[i]);

		if (len > best && at >= len &&
		    memcmp(page + at - len, tosya_prefixes[i], len) == 0)
			best = len;
	}
	return best;
}

/* One page of the parent: every dot is an anchor, every name is a candidate. */
static u32 tosya_scrub_page(u8 *page, u32 len, const char *names, u32 bytes,
			    bool write_over)
{
	u32 hits = 0;
	u32 i;

	for (i = 0; i < len; ++i) {
		u32 start, end, token;

		if (page[i] != '.')
			continue;
		start = i;
		while (start > 0 && tosya_name_char(page[start - 1]))
			--start;
		end = i + 1;
		while (end < len && tosya_name_char(page[end]))
			++end;
		token = end - start;
		if (token < 4 || token > TOSYA_TOKEN_MAX)
			continue;

		{
			u32 seed = 0;

			/* The tree is walked over the token once: the cost follows its length. */
			if (token >= 4 && tosya_names_trie_match(page + start, token, &seed)) {
				u32 take = tosya_prefix_at(page, start);

				if (take != 0) {
					if (write_over)
						tosya_fill(page + start - take, take + token, seed);
					++hits;
				}
			}
		}	}
	return hits;
}

/* One 4K page, or one huge page the walk reported whole. Nothing here is a cap: a batch that
 * fills up is followed by another round, and a page that is not taken stays dirty for next time. */
struct tosya_entry {
	unsigned long addr;
	unsigned long size;
};

struct tosya_scan {
	struct tosya_entry e[TOSYA_BATCH_MAX];
	u32 n;
	bool full;
};

/*
 * Only the zygote, and what the zygote forks.
 *
 * What is being taken out are the arguments of an app start, and the only thing that carries
 * them is that lineage: the main zygote, the pooled children it pre-forks (their names come from
 * the zygote, and the A17 fork server is one of them), the webview zygote. Any other root process
 * -- a shell, a daemon, a permission helper -- may hold the very same names for its own work, and
 * taking them away from it is how a tool stops working. So the parent has to be one of these.
 *
 * A name an app can set itself is not a way out of this: an app that calls itself a zygote only
 * has its own memory rewritten, which hides nothing and breaks nothing but itself.
 */
/* The comm of the process, not of the thread: a fork is often issued by a worker thread,
 * whose own name says nothing about what process it belongs to. */
/*
 * The zygote family runs /system/bin/app_process and never execs anything else, so the executable
 * of the forking task is what says "an app is being made" -- not its comm (a thread's name), not
 * its uid alone (su is root too), and not the last path component (a file may be named anything).
 * Root is still required beside it, and an app can be neither.
 */
/*
 * Which task is the one that starts apps.
 *
 * Not a name and not an executable: the sockets. The child closes the zygote's server socket before
 * it is specialized (ZygoteConnection.closeServerSocket), the pool processes keep theirs and accept
 * on it, and nothing else on the system holds one -- a shell, su or an app that forks does not. The
 * identities are handed over at runtime, because only the userspace half knows which inode its
 * sockets have.
 */
#define TOSYA_ZYGOTE_SOCKETS_MAX 8u
static u32 g_socket_dev[TOSYA_ZYGOTE_SOCKETS_MAX];
static u64 g_socket_ino[TOSYA_ZYGOTE_SOCKETS_MAX];
static u32 g_socket_n;

void tosya_zygote_sockets_set(const u32 *pairs, u32 npairs)
{
	u32 i, n = min(npairs, TOSYA_ZYGOTE_SOCKETS_MAX);

	for (i = 0; i < n; i++) {
		g_socket_dev[i] = pairs[i * 3u];
		g_socket_ino[i] = (u64)pairs[i * 3u + 1u] | ((u64)pairs[i * 3u + 2u] << 32);
	}
	WRITE_ONCE(g_socket_n, n);
	pr_info("tosya: %u socket(s) say which task starts apps\n", n);
}

static bool tosya_holds_a_zygote_socket(void)
{
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	unsigned int max, i;
	u32 n, k;

	n = READ_ONCE(g_socket_n);
	if (n == 0 || files == NULL)
		return false;
	rcu_read_lock();
	fdt = files_fdtable(files);
	max = fdt->max_fds;
	for (i = 0; i < max; i++) {
		struct file *file = rcu_dereference(fdt->fd[i]);
		struct inode *inode;
		u32 dev;
		u64 ino;

		if (file == NULL)
			continue;
		inode = file_inode(file);
		if (inode == NULL || !S_ISSOCK(inode->i_mode))
			continue;
		dev = tosya_encode_dev(inode->i_sb->s_dev);
		ino = inode->i_ino;
		for (k = 0; k < n; k++)
			if ((g_socket_dev[k] == 0u || g_socket_dev[k] == dev) &&
			    g_socket_ino[k] == ino) {
				rcu_read_unlock();
				return true;
			}
	}
	rcu_read_unlock();
	return false;
}

/*
 * The answer is per task and does not change while it lives, so it is remembered: a task that
 * forks twice pays for the walk once. A stale entry cannot lie, because a task is recognised by
 * the pair of its address and the moment it started.
 */
#define TOSYA_FORKERS 64u
struct tosya_forker {
	struct task_struct *task;
	u64 start;
	bool forker;
};
static struct tosya_forker g_forkers[TOSYA_FORKERS];
static DEFINE_SPINLOCK(g_forkers_lock);
static u32 g_forkers_next;

static bool tosya_parent_starts_apps(void)
{
	struct task_struct *self = current;
	u64 start = self->start_boottime;
	u32 i, slot = TOSYA_FORKERS;
	bool answer;

	spin_lock(&g_forkers_lock);
	for (i = 0; i < TOSYA_FORKERS; i++) {
		if (g_forkers[i].task == self && g_forkers[i].start == start) {
			answer = g_forkers[i].forker;
			spin_unlock(&g_forkers_lock);
			return answer;
		}
		if (g_forkers[i].task == NULL && slot == TOSYA_FORKERS)
			slot = i;
	}
	if (slot == TOSYA_FORKERS)
		slot = g_forkers_next++ % TOSYA_FORKERS;
	spin_unlock(&g_forkers_lock);

	answer = tosya_holds_a_zygote_socket();

	spin_lock(&g_forkers_lock);
	g_forkers[slot].task = self;
	g_forkers[slot].start = start;
	g_forkers[slot].forker = answer;
	spin_unlock(&g_forkers_lock);
	return answer;
}


static bool tosya_scannable(struct vm_area_struct *vma)
{
	return vma != NULL && vma_is_anonymous(vma) && !(vma->vm_flags & VM_SHARED);
}

static int tosya_collect_pte(pte_t *pte, unsigned long addr, unsigned long next,
			     struct mm_walk *walk)
{
	struct tosya_scan *s = walk->private;
	pte_t val = *pte;

	(void)next;
	if (!tosya_scannable(walk->vma) || !pte_present(val) || !pte_dirty(val))
		return 0;
	if (s->n >= TOSYA_BATCH_MAX) {
		s->full = true;
		return 1;
	}
	s->e[s->n].addr = addr;
	s->e[s->n].size = PAGE_SIZE;
	s->n++;
	return 0;
}

/* A huge page carries one dirty bit for the whole of it, so the whole of it has to be looked at.
 * Reading it splits nothing; only a page that really holds a name is ever written to. */
static int tosya_collect_pmd(pmd_t *pmd, unsigned long addr, unsigned long next,
			     struct mm_walk *walk)
{
	struct tosya_scan *s = walk->private;
	pmd_t val = *pmd;

	if (!tosya_scannable(walk->vma) || !pmd_present(val) || !pmd_trans_huge(val) ||
	    !pmd_dirty(val))
		return 0;
	if (s->n >= TOSYA_BATCH_MAX) {
		s->full = true;
		return 1;
	}
	s->e[s->n].addr = addr;
	s->e[s->n].size = next - addr;
	s->n++;
	return 0;
}

static const struct mm_walk_ops tosya_collect_ops = {
	.pmd_entry = tosya_collect_pmd,
	.pte_entry = tosya_collect_pte,
};

/*
 * Taking the dirty bit away. An entry that is still dirty in the TLB would keep a later write from
 * setting it in memory, and a page written after this would then look clean at the next fork --
 * which is the one thing that must not happen. flush_tlb_* is not exported to modules, so the
 * invalidation is written out here; the only context this mm can be live in is this one, and it
 * covers every ASID, so no mm state is needed.
 */
static inline void tosya_tlb_va(unsigned long addr)
{
	asm volatile("dsb ish\n\ttlbi vaae1is, %0\n\tdsb ish\n\tisb" ::
		     "r"(addr >> PAGE_SHIFT) : "memory");
}

static int tosya_clean_pte(pte_t *pte, unsigned long addr, unsigned long next,
			   struct mm_walk *walk)
{
	pte_t val = *pte;

	(void)next;
	if (pte_present(val) && pte_dirty(val)) {
		set_pte_at(walk->mm, addr, pte, pte_mkclean(val));
		tosya_tlb_va(addr);
	}
	return 0;
}

static int tosya_clean_pmd(pmd_t *pmd, unsigned long addr, unsigned long next,
			   struct mm_walk *walk)
{
	pmd_t val = *pmd;

	(void)next;
	if (pmd_present(val) && pmd_trans_huge(val) && pmd_dirty(val)) {
		set_pmd_at(walk->mm, addr, pmd, pmd_mkclean(val));
		tosya_tlb_va(addr);
	}
	return 0;
}

static const struct mm_walk_ops tosya_clean_ops = {
	.pmd_entry = tosya_clean_pmd,
	.pte_entry = tosya_clean_pte,
};

/* From 6.1 on the walk expects the caller to hold mmap_lock for read; before that it takes the
 * lock itself, so taking it here as well would put two readers on one lock. */
static void tosya_walk(struct mm_struct *mm, unsigned long start, unsigned long end,
		       const struct mm_walk_ops *ops, void *private)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	mmap_read_lock(mm);
	walk_page_range(mm, start, end, ops, private);
	mmap_read_unlock(mm);
#else
	walk_page_range(mm, start, end, ops, private);
#endif
}

/* A read-only look at one page. Nothing is written, so a page shared with a child stays shared. */
static u32 tosya_read_scan(struct mm_struct *mm, unsigned long addr, char *names, u32 bytes)
{
	struct page *page = NULL;
	u8 *base;
	u32 hits;

	if (tosya_get_page(mm, addr, &page, false) != 1)
		return U32_MAX; /* nothing was read, so nothing may be cleared */
	base = tosya_map_page(page);
	hits = tosya_scrub_page(base, PAGE_SIZE, names, bytes, false);
	tosya_unmap_page(base);
	put_page(page);
	return hits;
}

/* The write. FOLL_WRITE is what breaks a shared copy-on-write page properly, so the write lands
 * in the parent's own page: the parent is left clean and the child keeps what it was given. */
static bool tosya_write_scan(struct mm_struct *mm, unsigned long addr, char *names, u32 bytes)
{
	struct page *page = NULL;
	u8 *base;

	if (tosya_get_page(mm, addr, &page, true) != 1)
		return false;
	base = tosya_map_page(page);
	tosya_scrub_page(base, PAGE_SIZE, names, bytes, true);
	tosya_unmap_page(base);
	set_page_dirty(page);
	put_page(page);
	return true;
}



/*
 * The cleanup itself, called from the forking system call once it has returned, with the pid it
 * returned. The work is on the parent's own memory, which is what later children inherit.
 */
unsigned int tosya_scrub_in_place, tosya_scrub_runs, tosya_scrub_hits, tosya_scrub_names;

void tosya_fork_scrub(long pid)
{
	struct mm_struct *mm = current->mm;
	const struct cred *cred = current_cred();
	struct task_struct *child;
	struct tosya_scan *scan;
	char *names = NULL;
	unsigned long addr, next, end;
	u32 bytes = 0, round, i, hits = 0, cand = 0, took = 0;

	/* Entered at all? That alone separates "the hook never fires" from everything else.
	 * Only the lineage is counted and reported: this hook sits in a path every fork in the
	 * kernel goes through, so the first few callers are usually other processes. */
	/* Count only once there is a list to look for: before that every fork is expected to
	 * find nothing, and the first eight reports would be spent there. */
	/* The window opens when a list exists, not when the process starts: before that every
	 * fork has nothing to find and would spend the reports on itself. */

	/* A mask, not a branch: an app cannot make any of these true for its own forks. */
	/*
	 * The first test is the only one a non-root caller is ever subject to, and it takes the
	 * same path for every one of them: one compare and back out. Nothing past this line runs
	 * for a process that is not root, so nothing past it can be observed from one. Root needs
	 * no such care, so the rest is ordinary filtering.
	 */
	if (__kuid_val(cred->euid) != 0)
		return;
	if (mm == NULL)
		return;
	if (!tosya_parent_starts_apps())
		return;
	if (pid <= 0)
		return;
	rcu_read_lock();
	child = pid_task(find_vpid((pid_t)pid), PIDTYPE_PID);
	if (child == NULL || child->mm == NULL) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	/* Presence only: the names themselves live in the tree. */
	tosya_scrub_names = tosya_names_bytes();
	if (tosya_scrub_names == 0)
		return;
	if (bytes == 0) {
		kfree(names);
		return;
	}

	scan = kvzalloc(sizeof(*scan), GFP_KERNEL);
	if (scan == NULL) {
		kfree(names);
		return;
	}

	for (round = 0; round < TOSYA_MAX_ROUNDS; ++round) {
		u32 done = 0, stuck = 0;

		scan->n = 0;
		scan->full = false;
		tosya_walk(mm, 0, TASK_SIZE, &tosya_collect_ops, scan);
		if (scan->n == 0)
			break;
		cand += scan->n;

		for (i = 0; i < scan->n; ++i) {
			end = scan->e[i].addr + scan->e[i].size;
			for (addr = scan->e[i].addr; addr < end; addr = next) {
				u32 h;

				next = (addr + PAGE_SIZE) & PAGE_MASK;
				if (next > end)
					next = end;
				h = tosya_read_scan(mm, addr, names, bytes);
				if (h == U32_MAX) {
					/* It could not be read: it keeps its dirty bit and is
					 * simply met again next time. */
					stuck++;
					continue;
				}
				if (h != 0) {
					if (tosya_write_scan(mm, addr, names, bytes))
						hits += h;
					else
						stuck++;
				}
				/* Read whole and compared: now, and only now, it may lose the
				 * dirty bit. */
				tosya_walk(mm, addr, addr + PAGE_SIZE, &tosya_clean_ops, NULL);
				done++;
			}
		}
		took += done;

		/* A round that cannot move anything stops the loop; what it could not read is
		 * still dirty, so the next fork tries it again. */
		if (done == 0 || !scan->full)
			break;
	}


	tosya_scrub_runs++;
	tosya_scrub_hits += hits;
	kvfree(scan);
	kfree(names);
}
