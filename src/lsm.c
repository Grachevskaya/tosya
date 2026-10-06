// SPDX-License-Identifier: GPL-2.0
/*
 * lsm.c - watch a task's identity change where the kernel commits it.
 *
 * The id setters are hooked where the kernel commits the change: the LSM hook the
 * setuid family calls with both creds in hand. It costs one indirect call on a
 * path that is doing real work anyway, and there is no need to sample the fsuid
 * before and after the call to see what happened.
 *
 * The hook heads are resolved by name, because they are not exported; the entry
 * already sitting in a head has its function pointer replaced by this module's,
 * which runs first and calls what it replaced. Nothing is added to or taken out
 * of a list an LSM registered, so the shape of every hook list is left exactly
 * as it was, and unloading puts the pointer back.
 *
 * Only the setuid hook is taken. The gid setters ran the same code, but a gid
 * change does not move the fsuid, so that path only ever saw a value that had not
 * changed and had nothing to record.
 */
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/version.h>

#include <linux/string.h>

#include "tosya.h"
#include "kaux.h"
#include "tier.h"
/*
 * Both generations live in this header: the list of hooks with a function
 * pointer each up to 6.11, and the per-hook static call table from 6.12 on. It
 * has to be included before the branch, because the second generation's types
 * are needed to even declare the state below.
 */
#include <linux/lsm_hooks.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)

typedef int (*tosya_setid_fn)(struct cred *new, const struct cred *old,
			      int flags);

static struct security_hook_list *g_node; // ours, when no LSM had the hook
static void *g_orig; // what the pointer held before
static void **g_slot; // the function pointer that was patched

static int tosya_fix_setuid(struct cred *new, const struct cred *old,
			    int flags);

/*
 * The call back into the replaced function, from a function that is itself
 * reached through an indirect call: on a pre-kCFI kernel both ends of that are
 * checked, so this is marked __nocfi.
 */
static noinline int __nocfi tosya_orig_setuid(struct cred *new,
					      const struct cred *old, int flags)
{
	return ((tosya_setid_fn)g_orig)(new, old, flags);
}

static int tosya_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	const u32 before = (u32)__kuid_val(old->fsuid);
	const u32 after = (u32)__kuid_val(new->fsuid);
	const bool interesting = before == 0 ||
				 (before % 100000u) >= TOSYA_APP_MIN;
	int ret;

	/*
	 * A task that is named already is done: its name came from the one
	 * transition that gave it its identity, and nothing after that may change
	 * it or report it a second time. The hook is called for every id change, so
	 * this is what keeps a process that changes ids repeatedly quiet.
	 */
	if (tosya_tag_isset())
		return tosya_orig_setuid(new, old, flags);

	ret = tosya_orig_setuid(new, old, flags);
	/*
	 * Both ends of the transition are handed over, so nothing has to be sampled
	 * around a call. A transition the kernel refused is not one, and only a
	 * change that lands on an app uid or an isolated uid says anything.
	 */
	if (ret == 0 && interesting && (after % 100000u) >= TOSYA_APP_MIN) {
		tosya_tag_adopt(before, after);
		tosya_tag_note(0, 0, before, after);
	}
	return ret;
}

/*
 * The function that implements the hook on this kernel is resolved by name and
 * then looked for in the list, so that what gets replaced is exactly the
 * implementation that was resolved, and not whichever entry happens to sit
 * first. On a pre-kCFI kernel the table holds the plain symbol while a call site
 * reaches the jump-table one, so both spellings are accepted.
 */
static const char *g_target_name;

/*
 * What implements the hook. commoncap has cap_task_fix_setuid in every kernel
 * this module is built for, and it is the one that has to keep running;
 * safesetid is the only other implementation. SELinux does not implement
 * task_fix_setuid, so it is not in the list.
 */
static const char *const tosya_target_names[] = {
	"cap_task_fix_setuid",
	"safesetid_task_fix_setuid",
};

static void *tosya_resolve_target(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(tosya_target_names); i++) {
		/* the spelling a table holds: jump-table entry before 6.1, plain
		 * symbol from there on */
		unsigned long addr = tosya_lookup(tosya_target_names[i]);
		unsigned long plain;

		if (!addr) {
			plain = tosya_lookup_raw(tosya_target_names[i]);
			addr = plain;
		}
		if (addr) {
			g_target_name = tosya_target_names[i];
			return (void *)addr;
		}
	}
	return NULL;
}

static int tosya_lsm_install_hook(void)
{
	unsigned long heads_addr = tosya_lookup("security_hook_heads");
	struct hlist_head *head;
	struct security_hook_list *e;
	void *target = tosya_resolve_target();
	void *ours = (void *)tosya_fix_setuid;
	void **slot = NULL;

	if (!heads_addr)
		return -ENOENT;
	head = (struct hlist_head *)(heads_addr +
				     offsetof(struct security_hook_heads,
					      task_fix_setuid));

	if (target) {
		hlist_for_each_entry(e, head, list) {
			void **s = (void **)&e->hook.task_fix_setuid;

			if (READ_ONCE(*s) == target) {
				slot = s;
				break;
			}
		}
		if (!slot)
			return -ENOENT;
		g_orig = *slot;
		if (tosya_patch_text(slot, &ours, sizeof(ours), true) ||
		    *slot != ours) {
			g_orig = NULL;
			return -EIO;
		}
		smp_wmb();
		g_slot = slot;
		pr_info("tosya: task_fix_setuid taken over (%s)\n",
			g_target_name ? g_target_name : "?");
		if (TOSYA_DEBUG_ON())
			pr_info("tosya:   the slot held %px\n", g_orig);
		return 0;
	}
	pr_info("tosya: no cap_task_fix_setuid or safesetid_task_fix_setuid; taking the chain head\n");

	hlist_for_each_entry(e, head, list) {
		void **s = (void **)&e->hook.task_fix_setuid;

		if (READ_ONCE(*s)) {
			slot = s;
			break;
		}
	}
	if (slot) {
		g_orig = *slot;
		if (tosya_patch_text(slot, &ours, sizeof(ours), true) ||
		    *slot != ours) {
			g_orig = NULL;
			return -EIO;
		}
		smp_wmb();
		g_slot = slot;
		pr_info("tosya: task_fix_setuid taken over (chain head, entry of %s)\n",
			e->lsm ? e->lsm : "?");
		if (TOSYA_DEBUG_ON())
			pr_info("tosya:   the slot held %px\n", g_orig);
		return 0;
	}

	/*
	 * No LSM implements the hook on this kernel, so the module brings its own
	 * entry and the head points at it. The entry is this module's memory, so
	 * only the head's first pointer has to be patched -- and the head is empty,
	 * so there is no other entry whose pprev would have to be kept in step.
	 */
	g_node = kzalloc(sizeof(*g_node), GFP_KERNEL);
	if (!g_node)
		return -ENOMEM;
	g_node->hook.task_fix_setuid = tosya_fix_setuid;
	g_node->lsm = "tosya";
	INIT_HLIST_NODE(&g_node->list);
	g_node->head = head;

	{
		void *first = &g_node->list;
		void **slot = (void **)&head->first;

		if (tosya_patch_text(slot, &first, sizeof(first), true) ||
		    *slot != first) {
			kfree(g_node);
			g_node = NULL;
			return -EIO;
		}
		g_slot = slot;
		pr_info("tosya: task_fix_setuid installed (no LSM had it)\n");
	}
	return 0;
}

void tosya_lsm_remove(void)
{
	void *nul = NULL;

	if (!g_slot)
		return;
	/*
	 * Another patcher may have taken this slot since -- KernelSU takes a hook
	 * the same way -- and what would be written back is then either its work or,
	 * worse, an address inside a module that has already gone. A hook that is no
	 * longer this module's is left where it is.
	 */
	if (READ_ONCE(*g_slot) != (void *)tosya_fix_setuid) {
		pr_warn("tosya: the setuid hook is no longer ours; leaving it alone\n");
		return;
	}
	if (g_node) {
		if (tosya_patch_text(g_slot, &nul, sizeof(nul), true) ||
		    READ_ONCE(*g_slot) != NULL)
			pr_emerg(
				"tosya: the setuid hook slot still points at this module\n");
		kfree(g_node);
		g_node = NULL;
	} else if (g_orig) {
		if (tosya_patch_text(g_slot, &g_orig, sizeof(g_orig), true) ||
		    READ_ONCE(*g_slot) != g_orig)
			pr_emerg(
				"tosya: the setuid hook slot still points at this module\n");
	}
	smp_wmb();
	/*
	 * A task may be inside the replaced function right now: the hook is called
	 * under RCU, so waiting for a grace period is what makes sure none of them
	 * is still on its way through code this module is about to give up.
	 */
	synchronize_rcu();
	g_slot = NULL;
	g_orig = NULL;
}

int tosya_lsm_install(void)
{
	const int ret = tosya_lsm_install_hook();

	char name[32];

	if (ret) {
		tosya_status_note(ret);
		return ret;
	}
	strscpy(name, "lsm: ", sizeof(name));
	strlcat(name, g_target_name ? g_target_name : "chain head",
		sizeof(name));
	tosya_status_set_setuid_tier(name);
	return 0;
}

// >= 6.12: every hook sits behind its own static call
#else

/*
 * From 6.12 a hook is not a function pointer in a list any more: each hook owns
 * an array of static calls, one slot per registered LSM, and the call site is a
 * patched branch. The table that holds them is built at boot and is read-only
 * afterwards, so the slot is found by walking it, and both the slot's own
 * function pointer and the static call behind it have to be moved together,
 * including the rollback when the second half fails.
 */
typedef int (*tosya_kallsyms_size_t)(unsigned long addr,
				     unsigned long *symbolsize,
				     unsigned long *offset);

static struct lsm_static_call *g_scall;
static void **g_slot;
static void *g_orig;

typedef void (*tosya_scall_update_t)(struct static_call_key *key, void *tramp,
				     void *func);
typedef int (*tosya_setid_fn)(struct cred *new, const struct cred *old,
			      int flags);

static unsigned long g_scall_update_addr;

/*
 * Returns what the call returned, which is nothing: __static_call_update() is
 * void, so the check at the call sites is a shape to keep the two halves of the
 * update together, not a test that can fail today.
 */
static noinline int __nocfi tosya_scall_update(struct static_call_key *key,
					       void *tramp, void *func)
{
	((tosya_scall_update_t)g_scall_update_addr)(key, tramp, func);
	return 0;
}

/*
 * Where the static call points right now. __static_call_update() returns nothing,
 * so an update that did not take effect would be taken for one -- and the call
 * site it patched is exactly what keeps calling this module after the module is
 * gone. The low bits of the stored pointer carry the static call's return-type
 * tag, so both sides are masked before the comparison.
 */
static void *tosya_scall_target(const struct lsm_static_call *scall)
{
	const unsigned long f = READ_ONCE(*(const unsigned long *)scall->key);

	return (void *)(f & ~7ul);
}

#define TOSYA_SCALL_MASK(v) ((void *)((unsigned long)(v) & ~7ul))

/*
 * The implementation that was in the slot before this module took it. It has to
 * keep running: SELinux's task_fix_setuid is what relabels the cred, and a hook
 * this module replaced is a hook it is responsible for.
 */
static noinline int __nocfi tosya_orig_setuid(struct cred *new,
					      const struct cred *old, int flags)
{
	return ((tosya_setid_fn)g_orig)(new, old, flags);
}

static int tosya_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	const u32 before = (u32)__kuid_val(old->fsuid);
	const u32 after = (u32)__kuid_val(new->fsuid);
	const bool interesting = before == 0 ||
				 (before % 100000u) >= TOSYA_APP_MIN;
	int ret;

	if (tosya_tag_isset())
		return tosya_orig_setuid(new, old, flags);

	ret = tosya_orig_setuid(new, old, flags);
	if (ret == 0 && interesting && (after % 100000u) >= TOSYA_APP_MIN) {
		tosya_tag_adopt(before, after);
		tosya_tag_note(0, 0, before, after);
	}
	return ret;
}

static int tosya_lsm_install_hook(void)
{
	unsigned long table = tosya_lookup("static_calls_table");
	unsigned long cnt_addr = tosya_lookup("lsm_active_cnt");
	size_t size = sizeof(struct lsm_static_calls_table);
	size_t count, i;
	struct lsm_static_call *scalls;
	void *size_fn;
	void *target;
	void *ours = (void *)tosya_fix_setuid;

	g_scall_update_addr = tosya_lookup_raw("__static_call_update");
	if (!table || !g_scall_update_addr)
		return -ENOSYS;
	/* lsm_active_cnt bounds how many slots the framework fills; it is read for the
	 * log and is not required, because the table's own size is known at compile
	 * time and the walk is bounded by that. */
	if (cnt_addr && TOSYA_DEBUG_ON())
		pr_info("tosya: lsm_active_cnt=%u\n", *(u32 *)cnt_addr);

	/* the implementations that exist: commoncap has one on every kernel this
	 * module is built for, safesetid is the only other (see the list above) */
	target = (void *)tosya_lookup("cap_task_fix_setuid");
	if (!target)
		target = (void *)tosya_lookup_raw("cap_task_fix_setuid");
	if (!target)
		target = (void *)tosya_lookup("safesetid_task_fix_setuid");
	if (!target)
		return -ENOENT;

	count = size / sizeof(struct lsm_static_call);
	/*
	 * A vendor can change MAX_LSM_COUNT, and then the table's own size is the truth
	 * rather than this build's count: take it from kallsyms when that can be reached
	 * (KernelSU reads it the same way) and keep the compile-time count when it cannot.
	 */
	size_fn = (void *)tosya_lookup("kallsyms_lookup_size_offset");
	if (size_fn) {
		unsigned long sym_size = size;

		if (((tosya_kallsyms_size_t)size_fn)(table, &sym_size, NULL) &&
		    sym_size >= sizeof(struct lsm_static_call))
			count = sym_size / sizeof(struct lsm_static_call);
	}
	scalls = (struct lsm_static_call *)table;
	for (i = 0; i < count; i++) {
		struct lsm_static_call *scall = &scalls[i];
		struct security_hook_list *e = READ_ONCE(scall->hl);
		void **slot;

		if (!e || !scall->key)
			continue;
		slot = (void **)((char *)e + offsetof(struct security_hook_list,
						      hook.task_fix_setuid));
		if (READ_ONCE(*slot) != target)
			continue;

		/* the slot can already be reached before the static call is moved, so
		 * the function it chains to is in place first */
		g_scall = scall;
		g_slot = slot;
		g_orig = target;
		if (tosya_patch_text(slot, &ours, sizeof(ours), true)) {
			g_scall = NULL;
			g_slot = NULL;
			g_orig = NULL;
			return -EIO;
		}
		if (tosya_scall_update(scall->key, scall->trampoline, ours)) {
			tosya_patch_text(slot, &target, sizeof(target), true);
			g_scall = NULL;
			g_slot = NULL;
			g_orig = NULL;
			return -EIO;
		}
		static_branch_enable(scall->active);
		smp_wmb();
		pr_info("tosya: task_fix_setuid taken over (static call)\n");
		if (TOSYA_DEBUG_ON())
			pr_info("tosya:   the slot held %px\n", g_orig);
		return 0;
	}
	return -ENOENT;
}

void tosya_lsm_remove(void)
{
	if (!g_slot)
		return;
	/* see tosya_lsm_remove() above: a slot that is no longer ours is left
	 * alone, and so is the static call behind it */
	if (READ_ONCE(*g_slot) != (void *)tosya_fix_setuid) {
		pr_warn("tosya: the setuid hook is no longer ours; leaving it alone\n");
		return;
	}
	if (tosya_scall_update(g_scall->key, g_scall->trampoline, g_orig)) {
		pr_warn("tosya: could not put the static call back\n");
		return;
	}
	/*
	 * Read it back: this is the call site that would otherwise enter this module
	 * after its text is gone, and the update above reports nothing when it does not
	 * take (__static_call_update() is void). One retry, then it says so: with a
	 * working update this cannot happen, and when it does, the reason has to be in
	 * the log rather than in a crash.
	 */
	if (tosya_scall_target(g_scall) != TOSYA_SCALL_MASK(g_orig)) {
		pr_warn("tosya: the static call did not take the old target back; retrying\n");
		tosya_scall_update(g_scall->key, g_scall->trampoline, g_orig);
		if (tosya_scall_target(g_scall) != TOSYA_SCALL_MASK(g_orig))
			pr_emerg(
				"tosya: the setuid static call still points at this module\n");
	}
	tosya_patch_text(g_slot, &g_orig, sizeof(g_orig), true);
	smp_wmb();
	synchronize_rcu();
	g_scall = NULL;
	g_slot = NULL;
	g_orig = NULL;
}

int tosya_lsm_install(void)
{
	const int ret = tosya_lsm_install_hook();

	char name[32];

	if (ret) {
		tosya_status_note(ret);
		return ret;
	}
	strscpy(name, "lsm: ", sizeof(name));
	strlcat(name, "cap_task_fix_setuid", sizeof(name));
	tosya_status_set_setuid_tier(name);
	return 0;
}

#endif

/*
 * The LSM mechanism of the setuid family: the kernel hands task_fix_setuid both
 * creds at the commit, and taking that hook is the least trouble of the three
 * when it can be taken (inline_hooks.c is the one that runs first, and
 * table_hooks.c the one behind this).
 */
TOSYA_TIER(tosya_tier_setuid_lsm, TOSYA_TIER_SETUID, "lsm",
	   "lsm task_fix_setuid", 20, tosya_lsm_install, tosya_lsm_remove);
