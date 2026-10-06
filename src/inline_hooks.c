// SPDX-License-Identifier: GPL-2.0
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/uidgid.h>
#include <linux/user.h>

#include "tosya.h"
#include "kaux.h"
#include "inline.h"
#include "inline_entry.h"
#include "inline_alloc.h"
#include "tier.h"

#define TOSYA_INLINE_STORAGE_SIZE 16
#define TOSYA_BTI_JC 0xd50324dfu
#define TOSYA_PACIASP 0xd503233fu
#define TOSYA_PACIBSP 0xd503237fu

// Assembly objects have instruction alignment, not unsigned-long alignment.
extern u32 g_find_user_copy[], g_setuid_copy[];
/* Typed function aliases at the same RX addresses: direct calls need no CFI
 * bypass or extra C bridge frame. The object aliases are only for text writes.
 */
extern struct user_struct *tosya_find_user_orig(kuid_t uid);
extern int tosya_setuid_orig(struct cred *new, const struct cred *old,
			     int flags);
extern struct user_struct *tosya_find_user_stub(kuid_t uid);
extern struct user_struct *tosya_find_user_pacia_stub(kuid_t uid);
extern struct user_struct *tosya_find_user_pacib_stub(kuid_t uid);
extern int tosya_setuid_stub(struct cred *, const struct cred *, int);
extern int tosya_setuid_pacia_stub(struct cred *, const struct cred *, int);
extern int tosya_setuid_pacib_stub(struct cred *, const struct cred *, int);
struct user_struct *tosya_find_user_hook(kuid_t uid);
int tosya_setuid_inline_hook(struct cred *, const struct cred *, int);

// RX storage avoids STRICT_MODULE_RWX rejecting writable executable arrays.
#define TOSYA_ASM_STUB(name, auth, hook)                                \
	".balign 4\n.global " name "\n.type " name ", %function\n" name \
	":\n\tbti jc\n" auth "\tb " hook "\n"                           \
	".size " name ", . - " name "\n"
#define TOSYA_ASM_COPY(name, original)                                         \
	".balign 16\n.global " name "\n.type " name ", %object\n"              \
	".global " original "\n.type " original ", %function\n" name           \
	":\n" original ":\n\t.space " __stringify(                             \
		TOSYA_INLINE_STORAGE_SIZE) ", 0\n"                             \
					   ".size " name ", . - " name "\n"    \
					   ".size " original ", . - " original \
					   "\n"
asm(".pushsection \".text.tosya_inline\",\"ax\"\n" TOSYA_ASM_COPY(
	"g_find_user_copy",
	"tosya_find_user_orig") TOSYA_ASM_STUB("tosya_find_user_stub", "",
					       "tosya_find_user_hook")
	    TOSYA_ASM_STUB(
		    "tosya_find_user_pacia_stub", "\tautiasp\n",
		    "tosya_find_user_hook") TOSYA_ASM_STUB("tosya_find_user_pacib_stub",
							   "\tautibsp\n",
							   "tosya_find_user_hook")
		    TOSYA_ASM_COPY("g_setuid_copy", "tosya_setuid_orig") TOSYA_ASM_STUB(
			    "tosya_setuid_stub", "", "tosya_setuid_inline_hook")
			    TOSYA_ASM_STUB("tosya_setuid_pacia_stub",
					   "\tautiasp\n",
					   "tosya_setuid_inline_hook")
				    TOSYA_ASM_STUB(
					    "tosya_setuid_pacib_stub",
					    "\tautibsp\n",
					    "tosya_setuid_inline_hook") ".popsection\n");

__attribute__((hot)) noinline struct user_struct *
tosya_find_user_hook(kuid_t uid)
{
	const u32 replacement = policy_query((u32)__kuid_val(uid));
	const u32 query =
		(u32)tosya_select(replacement, __kuid_val(uid), replacement);
	struct user_struct *real = tosya_find_user_orig(KUIDT_INIT(query));
	struct user_struct *drop =
		(struct user_struct *)(unsigned long)tosya_select(
			(unsigned long)real, 0, replacement);

	/* A hidden target normally does one native miss in its own hash bucket,
	 * without incrementing and then dropping the real target's reference.
	 * A replacement UID may have become live since policy_apply: never return
	 * that unrelated user or leak its reference. This is not a constant-time
	 * guarantee; hash detection and bucket population still matter. */
	if (unlikely(drop)) {
		free_uid(drop);
		return NULL;
	}
	return real;
}

__attribute__((hot)) noinline int
tosya_setuid_inline_hook(struct cred *new, const struct cred *old, int flags)
{
	const u32 before = (u32)__kuid_val(old->fsuid);
	const u32 after = (u32)__kuid_val(new->fsuid);
	const bool interesting = before == 0 ||
				 (before % 100000u) >= TOSYA_APP_MIN;
	int ret;

	if (tosya_tag_isset())
		return tosya_setuid_orig(new, old, flags);
	ret = tosya_setuid_orig(new, old, flags);
	/* This observes the capability/LSM callback, before commit_creds. It
	 * preserves the upstream tagging contract, not a post-commit guarantee. */
	if (ret == 0 && interesting && (after % 100000u) >= TOSYA_APP_MIN) {
		tosya_tag_adopt(before, after);
		tosya_tag_note(0, 0, before, after);
	}
	return ret;
}

struct tosya_inline_hook {
	const char *name;
	u32 *copy;
	unsigned long
		hook; // the C handler, when the stub would only be a landing pad
	unsigned long stub, pacia_stub, pacib_stub;
	unsigned long site;
	u32 saved;
	bool installed;
	struct tosya_inline_region region;
};

static struct tosya_inline_hook g_find_user = {
	.name = "find_user",
	.copy = g_find_user_copy,
	.hook = (unsigned long)tosya_find_user_hook,
	.stub = (unsigned long)tosya_find_user_stub,
	.pacia_stub = (unsigned long)tosya_find_user_pacia_stub,
	.pacib_stub = (unsigned long)tosya_find_user_pacib_stub,
};
static struct tosya_inline_hook g_setuid = {
	.name = "cap_task_fix_setuid",
	.copy = g_setuid_copy,
	.hook = (unsigned long)tosya_setuid_inline_hook,
	.stub = (unsigned long)tosya_setuid_stub,
	.pacia_stub = (unsigned long)tosya_setuid_pacia_stub,
	.pacib_stub = (unsigned long)tosya_setuid_pacib_stub,
};

bool tosya_inline_active(void)
{
	return g_find_user.installed || g_setuid.installed;
}

static int inline_errno(int rc)
{
	switch (rc) {
	case TOSYA_INLINE_ESIZE:
		return -E2BIG;
	case TOSYA_INLINE_EINSN:
		return -EOPNOTSUPP;
	case TOSYA_INLINE_ERANGE:
		return -ERANGE;
	default:
		return -EINVAL;
	}
}

/* Called only during serialized module initialization. Nothing can enter the
 * scratch/trampoline while it is being constructed. Only the displaced entry
 * instructions are copied; the rest runs at its original kernel address. */
static int inline_install(struct tosya_inline_hook *hook)
{
	static u32 source[TOSYA_INLINE_MAX_SOURCE / TOSYA_INLINE_INSN];
	static u32 scratch[TOSYA_INLINE_STORAGE_SIZE / TOSYA_INLINE_INSN];
	unsigned long addr = 0, size = 0, stub = hook->stub;
	size_t written = 0, skip = 0;
	u32 patch;
	bool distant = false;
	int rc;

	BUILD_BUG_ON(TOSYA_INLINE_TRAMPOLINE_MAX + TOSYA_INLINE_INSN >
		     TOSYA_INLINE_STORAGE_SIZE);
	BUILD_BUG_ON(TOSYA_INLINE_VENEER_SIZE > TOSYA_INLINE_STORAGE_SIZE);
	if (hook->installed)
		return 0;
	if (!tosya_symbol_range(hook->name, &addr, &size))
		return -ENOENT;
	if ((addr & 3) || (size & 3) || size < TOSYA_INLINE_INSN ||
	    size > sizeof(source))
		return -E2BIG;
	if (!tosya_read((const void *)addr, source, size))
		return -EFAULT;
	tosya_debug_dump(hook->name, addr, size);

	/* Preserve explicit BTI landing pads. PAC*SP is also a landing pad: if
	 * first, leave it in place and undo precisely that signing in the stub,
	 * before a C prologue changes SP or signs its own return address. */
	if ((source[0] & 0xffffff3fu) == 0xd503241fu) {
		skip = TOSYA_INLINE_INSN;
		stub = hook->hook;
	} else if (source[0] == TOSYA_PACIASP || source[0] == TOSYA_PACIBSP) {
		skip = TOSYA_INLINE_INSN;
		stub = source[0] == TOSYA_PACIASP ? hook->pacia_stub :
						    hook->pacib_stub;
	}
	if (size < skip + TOSYA_INLINE_INSN)
		return -EINVAL;
	rc = tosya_inline_entry(&patch, sizeof(patch), addr + skip, stub);
	if (rc != TOSYA_INLINE_ENTRY && rc != TOSYA_INLINE_ERANGE)
		return inline_errno(rc);
	distant = rc == TOSYA_INLINE_ERANGE;

	/* The original may only be directly called and have no BTI of its own.
	 * The helper can call this copy indirectly, so give it a known landing. */
	if (!distant) {
		rc = tosya_inline_trampoline(scratch, sizeof(scratch), source,
					     addr, (unsigned long)hook->copy,
					     size, skip, &written);
		if (rc != TOSYA_INLINE_OK)
			return inline_errno(rc);
	}
	if (distant) {
		u32 *entry, *original;
		size_t original_len;

		/* Keep the kernel entry a single B. Only a private allocation holds
		 * long veneers; no extra live instructions are overwritten. Each
		 * hook owns its page, retained forever once the entry is published.
		 */
		rc = tosya_inline_alloc(&hook->region, addr);
		if (rc)
			return rc;
		entry = hook->region.addr;
		original = entry +
			   TOSYA_INLINE_ISLAND_TRAMPOLINE / TOSYA_INLINE_INSN;
		rc = tosya_inline_entry(&patch, sizeof(patch), addr + skip,
					(unsigned long)entry);
		if (rc != TOSYA_INLINE_ENTRY) {
			rc = inline_errno(rc);
			goto free_region;
		}
		original[0] = TOSYA_BTI_JC;
		rc = tosya_inline_trampoline(
			original + 1,
			TOSYA_INLINE_STORAGE_SIZE - TOSYA_INLINE_INSN, source,
			addr, (unsigned long)(original + 1), size, skip,
			&original_len);
		if (rc != TOSYA_INLINE_OK) {
			rc = inline_errno(rc);
			goto free_region;
		}
		rc = tosya_inline_veneer(entry, TOSYA_INLINE_ISLAND_TRAMPOLINE,
					 stub, 1);
		if (rc != TOSYA_INLINE_LANDING_VENEER_SIZE) {
			rc = inline_errno(rc);
			goto free_region;
		}
		/* The typed alias is still reached by a direct BL. Its private
		 * veneer preserves LR, arguments, NZCV and SCS; IP0 is ABI scratch.
		 * The island original trampoline resumes the body with a direct B.
		 */
		rc = tosya_inline_veneer(scratch, sizeof(scratch),
					 (unsigned long)original, 0);
		if (rc != TOSYA_INLINE_VENEER_SIZE) {
			rc = inline_errno(rc);
			goto free_region;
		}
		written = TOSYA_INLINE_VENEER_SIZE;
		rc = tosya_inline_seal(&hook->region);
		if (rc)
			goto free_region;
	}
	rc = tosya_patch_text(hook->copy, scratch, written, true);
	if (rc)
		goto free_region;
	if (memcmp(hook->copy, scratch, written)) {
		rc = -EIO;
		goto free_region;
	}
	if (memcmp((const void *)addr, source, size)) {
		rc = -EBUSY;
		goto free_region;
	}

	hook->site = addr + skip;
	hook->saved = source[skip / TOSYA_INLINE_INSN];
	/* Hold a real module reference BEFORE the kernel can branch into this module.
	 * tosya_init must never return an error after a successful publication:
	 * module-loader init failure frees even a module with outstanding refs. */
	if (!try_module_get(THIS_MODULE)) {
		rc = -ENODEV;
		goto free_region;
	}
	rc = tosya_patch_insn((void *)hook->site, hook->saved, patch);
	if (rc) {
		// The single-word patch API guarantees failure leaves it unchanged.
		module_put(THIS_MODULE);
		goto free_region;
	}
	hook->installed = true;
	if (distant)
		hook->region.published = true;
	if (distant)
		pr_info("tosya: inline %s near island at %px, %zu bytes RO/X\n",
			hook->name, hook->region.addr, hook->region.size);
	pr_info("tosya: inline %s: %zu-byte %s, one B, pinned until reboot\n",
		hook->name, written,
		distant ? "original-call veneer via near island" :
			  "entry trampoline");
	return 0;

free_region:
	tosya_inline_free(&hook->region);
	return rc;
}

static int find_user_hook_install(void)
{
	int rc = inline_install(&g_find_user);

	if (rc)
		tosya_status_note(rc);
	return rc;
}

static int setuid_inline_install(void)
{
	int rc = inline_install(&g_setuid);

	// Preserve the upstream symbol fallback when capability's body is absent.
	if (rc == -ENOENT && !strcmp(g_setuid.name, "cap_task_fix_setuid")) {
		g_setuid.name = "safesetid_task_fix_setuid";
		rc = inline_install(&g_setuid);
	}
	if (rc) {
		tosya_status_note(rc);
		return rc;
	}
	return 0;
}

static int uid_inline_install(void)
{
	int rc = find_user_hook_install();

	if (!rc) {
		tosya_status_set_hooks_expected(0, 0);
	}
	return rc;
}

static void inline_remove(void)
{
	/* Normally unreachable: successful publication retains a module ref.
	 * Tier teardown also refuses while either permanent inline tier is live. */
	WARN_ON_ONCE(tosya_inline_active());
}

TOSYA_TIER(tosya_tier_uid_inline, TOSYA_TIER_UID, "inline", "inline find_user",
	   10, uid_inline_install, inline_remove);
TOSYA_TIER(tosya_tier_setuid_inline, TOSYA_TIER_SETUID, "inline",
	   "inline cap_task_fix_setuid", 10, setuid_inline_install,
	   inline_remove);
