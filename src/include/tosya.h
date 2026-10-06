/* SPDX-License-Identifier: GPL-2.0 */
// tosya: kernel-side uid existence guard (userspace-resolved policy).
#ifndef TOSYA_H
#define TOSYA_H

#include <linux/jump_label.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/uidgid.h>

// more than the host test's largest policy carries
#define POLICY_MAX_PAIRS 65536

/*
 * Two tables. The target table is read on every query and is indexed like the
 * kernel's own uidhash (8 bucket pointers per line), with the masks of a whole
 * line read either way; the caller table is matched by uid and its cost may
 * differ between callers. A target's mask is a bitmap over dense hider ids, so
 * a target can be hidden from any subset of the policy's callers and the caller
 * count is limited only by POLICY_MAX_CALLERS. A line holds POLICY_WAY target slots and
 * POLICY_CLINE_WAY caller slots.
 */
#define POLICY_WAY 8
/* How many lines one target may be placed after its own. Probing across lines rather
 * than across the slots of a single line is what keeps the table small: the line count
 * then follows the number of targets instead of the worst collision on one line, which
 * is what needed 32768 lines (2 MB) for 24000 targets where 4096 (256 KB) do. */
#define POLICY_PROBE_MAX 4
// caller slots per 64-byte line
#define POLICY_CLINE_WAY 8
#define POLICY_MIN_LINES 16
// 8 slots a line, so this covers ~260k targets
#define POLICY_MAX_LINES 32768
#define POLICY_MAX_CALLERS 4096
#define POLICY_REPL_BITS 12
/*
 * The first uid a hidden target may be replaced with. Two properties matter, and the
 * second is about what a caller can measure: the value has to hash into the same
 * uidhash bucket as the target, so the syscalls that go through find_user() walk the
 * chain they would for the target itself, and it has to be a value the kernel rejects
 * as cheaply as any ordinary uid that does not exist. The window is low for the second
 * one: on a device, getpriority(PRIO_USER, x) costs about 10 ns more to answer for
 * x = 0x40000000 than for x = 10500, and that difference is exactly the timing signal
 * between "hidden" and "no such uid" that uidbench measures. 20001..24096 (the window
 * is POLICY_REPL_MAX wide) is not inside any uid range Android hands out -- apps are
 * 10000..19999 per user, isolated children 90000..98999 -- so make_replace() can take
 * its candidate arithmetically for the hash the kernel uses (make_replace() in policy.c)
 * and never has to ask the kernel whether one is free.
 */
#define POLICY_REPL_BASE 20001u
#define POLICY_REPL_MAX (1u << POLICY_REPL_BITS)
#define POLICY_ID_NONE 0xffffffffu
// app uids: 10000 + appid + user * 100000
#define POLICY_APP_ID_MIN 10000u
#define POLICY_APP_ID_SPAN 10000u
// slot flag: "hide from any caller"
#define POLICY_WILD_FLAG (1u << 15)

/*
 * The uid hash is not hardcoded here on purpose: policy.c reads the formula the
 * running kernel uses back from find_user() at policy-apply time.
 */

struct uid_pair { // 8 bytes: POLICY_WAY of them fill one cache line
	u32 target;
	u16 repl_k;
	/* Which of the interned caller masks this slot uses. The same set of callers
	 * hides target after target, so the mask a slot needs is shared rather than
	 * stored per slot; zero is the empty mask. */
	u16 mask_id;
};

void policy_apply(const u32 *pairs, u32 npairs);

/*
 * Diagnostics sit behind a static key: when it is off the branch is patched to
 * a NOP, so a release build carries none of it. The module parameter turns it
 * on at load and the work item below turns it off again, so a diagnostic run
 * pays for itself only while it is running.
 */
extern struct static_key_false tosya_debug_key;
#define TOSYA_DEBUG_ON() static_branch_unlikely(&tosya_debug_key)
void tosya_debug_init(bool on);

// 0 = not hidden; otherwise the same-bucket replacement uid
// Explicit identity: the self-check in policy_apply() and the host test.
u32 policy_lookup_as(uid_t caller, uid_t target);

/*
 * Identity tag: the app id a process was born with, kept in the free high bits
 * of thread_info.flags (bits 40..55, zero = untagged). It is written at the two
 * moments an identity is created - zygote handing an app uid to a fresh
 * process, and app_zygote handing an isolated uid to one - and never rewritten
 * or cleared afterwards, while fork copies it, so an isolated or app_zygote
 * child keeps answering as the app it came from. That is what makes the caller
 * identity unforgeable: setuid() can no longer pick which hiding rules apply.
 * Only the app id is stored, because the policy is keyed by app id anyway.
 *
 * The name a task carries sits in bits 40..53: an app id is below 10000, so
 * fourteen bits hold one plus its offset. The window bit is above that field,
 * not inside it -- a tag with the top bit set would read back as "still
 * waiting" and the task would be renamed on every file it opened.
 */
#define TOSYA_TAG_SHIFT 40
#define TOSYA_TAG_MASK 0x3fffUL
#define TOSYA_APP_MIN POLICY_APP_ID_MIN
#define TOSYA_APP_SPAN POLICY_APP_ID_SPAN
// app_zygote children are 90000-98999 too
#define TOSYA_ISOLATED_START 90000u

/*
 * Isolated children are marked before they can be named: the flag sits above
 * the identity inside the same field so the hot path tests it with a single
 * AND, without shifting the field out first (an app id plus one never reaches
 * bit 55).
 */
#define TOSYA_TAG_PENDING (1UL << 55)

/*
 * App apks whose open is replaced. 10000 was one user's app-id range, and that is no longer the
 * whole set: every extracted native library is an entry too (its open is what names a native
 * isolated child), and a real device carries a few thousand of those. 65536 holds both with room.
 */
#define TOSYA_APK_MAX 65536

/*
 * Streaming upload entry points (used by netlink.c): one record lands one file, gen is
 * the generation of this upload. finish parks every entry outside that generation and
 * returns how many stayed.
 */
int tosya_apk_stream(u32 op, u32 uid, u32 dev, u64 ino, const char *path,
		     u32 bytes);
u32 tosya_apk_stream_finish(void);

void tosya_tag_name(u32 app);
void tosya_tag_close(void);
bool tosya_tag_pending_here(void);

struct pt_regs;

typedef long (*tosya_syscall_t)(const struct pt_regs *);

#include <linux/rcupdate.h>

/*
 * What the query reads before it decides: the caller's own entry in the snapshot that is published
 * right now, and whether that snapshot carries a wildcard (a pair whose caller has no rules of its
 * own). Both live inside the snapshot, so a query still reads one consistent whole.
 */
struct policy_hot {
	const u16 *cid;
	u32 wild;
};

struct policy;

/* The published snapshot. struct policy_hot is its first member, so the inlined half can read the
 * two words it needs out of the same pointer the walk uses: one swap, one consistent whole. */
extern struct policy *g_pol __rcu;

u32 policy_lookup_slow(uid_t target, u32 app);
void policy_tagless_note(void);

// App id to hider id, shared by both halves so there is one implementation of it.
static __always_inline u32 policy_cid_hot(const struct policy_hot *hot, u32 app)
{
	const u32 id = (app < TOSYA_APP_SPAN) ? hot->cid[app] : 0xffffu;

	return (id != 0xffffu) ? id : POLICY_ID_NONE;
}

/*
 * The caller tag: the app id + 1 in the upper bits of thread_info->flags, or 0 when the process was
 * never tagged. Four instructions and no branches, so the inlined half of the query reads it directly
 * instead of paying a call for it.
 */
static __always_inline u32 tosya_tag_app(void)
{
	return (u32)((task_thread_info(current)->flags >> TOSYA_TAG_SHIFT) &
		     TOSYA_TAG_MASK);
}

/*
 * The half of the query that every hooked wrapper runs. A caller with no rules of its own is answered
 * here, inside the wrapper: that is what a hooked syscall costs for everyone who is not being lied to.
 * The walk for the callers that have rules is out of line. What is read on the way out is the caller's
 * identity and the policy, never the answer, so a target that is hidden and one that was never
 * configured leave through the same instructions with one register different.
 */
static __always_inline u32 policy_query(uid_t target)
{
	const u32 tag_app = tosya_tag_app();
	const u32 app =
		tag_app -
		1u; // the tag carries the app id + 1; the tables are indexed by the id
	struct policy_hot *hot;
	u32 cid;

	if (unlikely(tag_app == 0)) {
		policy_tagless_note();
		return 0;
	}
	if ((u32)target % 100000u == app)
		return 0;
	rcu_read_lock();
	// struct policy_hot is the first member of the snapshot, so this is the same object.
	hot = (struct policy_hot *)rcu_dereference(g_pol);
	cid = policy_cid_hot(hot, app);
	if (likely(cid == POLICY_ID_NONE && !hot->wild)) {
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();
	return policy_lookup_slow(target, app);
}

void tosya_status_add_flags(unsigned int flags);
void tosya_status_set_hooks_expected(unsigned int native, unsigned int compat);
void tosya_status_add_hooks(unsigned int native, unsigned int compat);
void tosya_status_add_hooks_expected(unsigned int native, unsigned int compat);

// The first bytes of a symbol about to be copied, when the debug key is on.
void tosya_debug_dump(const char *name, unsigned long addr, unsigned long size);

static __always_inline u64 tosya_select(u64 when_true, u64 when_false,
					u32 nonzero)
{
#if defined(__aarch64__)
	u64 out;

	asm("cmp\t%w3, #0\n\tcsel\t%0, %1, %2, ne"
	    : "=r"(out)
	    : "r"(when_true), "r"(when_false), "r"(nonzero)
	    : "cc");
	return out;
#else
	/* The host test and the userspace model compile this file too. A real branch is fine
	 * there: nothing is timed, and x86 is not the target. */
	return nonzero ? when_true : when_false;
#endif
}

int tosya_apk_apply(const u32 *blob,
		    u32 n); // n * (st_dev, ino_lo, ino_hi, uid)
/*
 * blob: u32 n, then n * (action, uid, off, len), then the paths those offsets
 * point into. action 0 replaces the open of the base.apk at that path, 1 puts
 * it back, so the userspace half can send only what changed. A replaced inode names a
 * waiting isolated child from the app the apk belongs to.
 */
int tosya_apk_apply(const u32 *blob, u32 len);
void tosya_apk_remove(void); // put every inode back (module exit)
void tosya_tag_adopt(u32 old_uid, u32 new_uid);
void tosya_tag_prime(void);
bool tosya_tag_isset(void);
void tosya_tag_note(u32 before_sid, u32 after_sid, u32 old_uid, u32 new_uid);

/*
 * The setuid hook (see lsm.c): where the kernel hands both creds over at the
 * commit, the syscall table is not touched for the id setters at all. Returns
 * non-zero when the syscall table has to keep them.
 */
int tosya_lsm_install(void);
void tosya_lsm_remove(void);

/*
 * The status the userspace half reads over netlink (include/kaux.h). hooks.c owns it,
 * lsm.c and the hook table fill it in as they go.
 */
struct kaux_status;
void tosya_status_get(struct kaux_status *out);
void tosya_status_set_hooks(unsigned int native, unsigned int compat);
void tosya_status_set_uid_tier(const char *name);
void tosya_status_set_setuid_tier(const char *name);
void tosya_status_set_apks(unsigned int inodes, unsigned int expected,
			   unsigned int failed);
void tosya_status_note(int error);

int policy_init(void);
void policy_free(void);

int hooks_install(void);
void hooks_remove(void);

/* Bulk writes for unpublished clones and legacy data slots, not live entry
 * instructions. A failed bulk write can have changed a prefix. */
int tosya_patch_text(void *dst, const void *src, size_t len, bool sync);
/* Compare and publish one aligned kernel instruction while CPUs are stopped.
 * A nonzero return means this operation did not change the instruction. */
int tosya_patch_insn(void *dst, u32 expected, u32 replacement);
bool tosya_inline_active(void);

// Read kernel text through the nofault copy, for diagnostics only.
bool tosya_read(const void *src, void *dst, size_t len);
int tosya_patch_init(void);
unsigned long tosya_lookup(const char *name);

/*
 * A symbol's address and its extent: the following symbol bounds it, which is
 * what copying a whole function needs to know.
 */
bool tosya_symbol_range(const char *name, unsigned long *addr,
			unsigned long *size);

/*
 * The address just past that symbol: the end of its body in kallsyms, which is
 * what a scan for a call site inside it has to stay within. Zero when the symbol
 * or its follower is unknown.
 */
unsigned long tosya_lookup_raw(const char *name);

/*
 * aarch64 branch helpers, kept inline so the host test can check the encoder: a
 * direct branch is 26 bits of word offset, i.e. +/-128 MB, which is exactly the
 * reach that decides whether a module can call into the kernel image.
 */
#define ARM64_B 0x14000000u
#define ARM64_BL 0x94000000u

static inline bool arm64_is_bl(u32 insn)
{
	return (insn & 0xFC000000u) == ARM64_BL;
}

static inline u32 arm64_branch(u32 op, unsigned long from, unsigned long to)
{
	long off = (long)(to - from);

	if ((off & 3) || off < -(1L << 27) || off >= (1L << 27))
		return 0;
	return op | (((u32)(off >> 2)) & 0x03FFFFFFu);
}

static inline unsigned long arm64_bl_target(unsigned long pc, u32 insn)
{
	long off = (long)(insn & 0x03FFFFFFu) << 2;

	return (unsigned long)((long)pc + ((off ^ (1L << 27)) - (1L << 27)));
}

int netlink_init(void);
void netlink_exit(void);

#endif
