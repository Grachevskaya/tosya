// SPDX-License-Identifier: GPL-2.0
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/string.h>
#include <linux/uidgid.h>
#include <linux/user.h>

#include "tosya.h"
#include "kaux.h"
#include "inline.h"
#include "inline_entry.h"
#include "inline_alloc.h"
#include "tier.h"
#include <linux/namei.h>

// Displaced prefix plus the veneer that returns from it.
#define TOSYA_INLINE_STORAGE_SIZE 64
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
	"g_unlock_inode_copy",
	"tosya_unlock_inode_orig") TOSYA_ASM_STUB("tosya_unlock_inode_stub", "",
						  "tosya_unlock_inode_hook")
	    TOSYA_ASM_STUB(
		    "tosya_unlock_inode_pacia_stub", "\tautiasp\n",
		    "tosya_unlock_inode_hook") TOSYA_ASM_STUB("tosya_unlock_inode_pacib_stub",
							      "\tautibsp\n",
							      "tosya_unlock_inode_hook")
		    TOSYA_ASM_COPY("g_find_user_copy", "tosya_find_user_orig") TOSYA_ASM_STUB(
			    "tosya_find_user_stub", "",
			    "tosya_find_user_hook") TOSYA_ASM_STUB("tosya_find_user_pacia_stub",
								   "\tautiasp\n",
								   "tosya_find_user_hook")
			    TOSYA_ASM_STUB(
				    "tosya_find_user_pacib_stub", "\tautibsp\n",
				    "tosya_find_user_hook") TOSYA_ASM_COPY("g_setuid_copy",
									   "tosya_setuid_orig")
				    TOSYA_ASM_STUB("tosya_setuid_stub", "",
						   "tosya_setuid_inline_hook")
					    TOSYA_ASM_STUB(
						    "tosya_setuid_pacia_stub",
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
	bool allow_indirect; // a hook whose target has an indirect call the prefix never moves
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
	static u32 source[TOSYA_INLINE_MAX_FUNC / TOSYA_INLINE_INSN];
	static u32 scratch[TOSYA_INLINE_STORAGE_SIZE / TOSYA_INLINE_INSN];
	unsigned long addr = 0, size = 0, stub = hook->stub;
	size_t written = 0, skip = 0;
	u32 patch;
	bool distant = false;
	int rc;

	BUILD_BUG_ON(TOSYA_INLINE_TRAMPOLINE_MAX + TOSYA_INLINE_INSN >
		     TOSYA_INLINE_STORAGE_SIZE);
	BUILD_BUG_ON(TOSYA_INLINE_VENEER_SIZE > TOSYA_INLINE_STORAGE_SIZE);
	BUILD_BUG_ON(2 * TOSYA_INLINE_INSN + TOSYA_INLINE_TRAMPOLINE_MAX >
		     TOSYA_INLINE_STORAGE_SIZE);
	if (hook->installed)
		return 0;
	if (!tosya_symbol_range(hook->name, &addr, &size))
		return -ENOENT;
	/* The size is the distance to the next symbol, which can be a section boundary far past
	 * the function. It bounds the read and the scan and nothing else, so it is clamped
	 * first: what is left is the real end of the function, found by the scan itself. */
	if (size > TOSYA_INLINE_MAX_FUNC)
		size = TOSYA_INLINE_MAX_FUNC;
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
					     size, skip, &written,
					     hook->allow_indirect);
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
			&original_len, hook->allow_indirect);
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

/*
 * The fork cleanup used to live here: a wake_up_new_task hook that took a hidden package's start
 * arguments out of the parent's heap right after a fork, so the next process forked out of the
 * zygote would not inherit them. The platform's own USAP pool does that job from the other side
 * now -- a pool clone reads the start command itself and becomes the app, so the zygote never holds
 * it at all -- and this module asks for that pool instead. The hook, its module parameter and the
 * counters it used to move went with it.
 */

/*
 * The inode cache. A shadow lives in the inode's i_fop, and an inode can be reclaimed, so the
 * replacement has to be put back when one is built again -- and this is where that happens: every
 * newly read inode passes here, with its file operations already set by the file system and not
 * yet unlocked, so the swap is made before anything can open it.
 */
extern u32 g_evict_inode_copy[];
extern void tosya_evict_inode_orig(struct inode *inode);
extern void tosya_evict_inode_stub(struct inode *inode);
extern void tosya_evict_inode_pacia_stub(struct inode *inode);
extern void tosya_evict_inode_pacib_stub(struct inode *inode);
void tosya_evict_inode_hook(struct inode *inode);

/*
 * The inode is being reclaimed. Its i_fop is one of the fields the file system is about to take
 * apart, so the record it carries is marked before the original runs, not after.
 */
asm(".pushsection \".text.tosya_inline\",\"ax\"\n" TOSYA_ASM_COPY(
	"g_evict_inode_copy",
	"tosya_evict_inode_orig") TOSYA_ASM_STUB("tosya_evict_inode_stub", "",
						 "tosya_evict_inode_hook")
	    TOSYA_ASM_STUB("tosya_evict_inode_pacia_stub", "\tautiasp\n",
			   "tosya_evict_inode_hook")
		    TOSYA_ASM_STUB("tosya_evict_inode_pacib_stub",
				   "\tautibsp\n",
				   "tosya_evict_inode_hook") "\n.popsection\n");

static struct tosya_inline_hook g_evict_inode = {
	.name = "evict_inode",
	.copy = g_evict_inode_copy,
	.hook = (unsigned long)tosya_evict_inode_hook,
	.stub = (unsigned long)tosya_evict_inode_stub,
	.pacia_stub = (unsigned long)tosya_evict_inode_pacia_stub,
	.pacib_stub = (unsigned long)tosya_evict_inode_pacib_stub,
};

noinline void tosya_evict_inode_hook(struct inode *inode)
{
	tosya_apk_shadow_reclaim(inode);
	tosya_evict_inode_orig(inode);
}

int tosya_evict_inode_install(void)
{
	int rc = inline_install(&g_evict_inode);

	if (rc == 0)
		pr_info("tosya: a reclaimed inode gives its record back\n");
	return rc;
}

extern u32 g_unlock_inode_copy[];
extern void tosya_unlock_inode_orig(struct inode *inode);
extern void tosya_unlock_inode_stub(struct inode *inode);
extern void tosya_unlock_inode_pacia_stub(struct inode *inode);
extern void tosya_unlock_inode_pacib_stub(struct inode *inode);
void tosya_unlock_inode_hook(struct inode *inode);

extern u32 g_lookup_fast_copy[];
extern struct dentry *tosya_lookup_fast_orig(void *nd);
extern struct dentry *tosya_lookup_fast_stub(void *nd);
extern struct dentry *tosya_lookup_fast_pacia_stub(void *nd);
extern struct dentry *tosya_lookup_fast_pacib_stub(void *nd);
struct dentry *tosya_lookup_fast_hook(void *nd);

/*
 * The copy of the displaced lookup_fast() prefix and the stubs that enter the C
 * hook. The copy is the original-call alias; the three stubs differ only in
 * whether they undo a signing instruction the entry left in place.
 */
asm(".pushsection \".text.tosya_inline\",\"ax\"\n" TOSYA_ASM_COPY(
	"g_lookup_fast_copy",
	"tosya_lookup_fast_orig") TOSYA_ASM_STUB("tosya_lookup_fast_stub", "",
						 "tosya_lookup_fast_hook")
	    TOSYA_ASM_STUB("tosya_lookup_fast_pacia_stub", "\tautiasp\n",
			   "tosya_lookup_fast_hook")
		    TOSYA_ASM_STUB("tosya_lookup_fast_pacib_stub",
				   "\tautibsp\n",
				   "tosya_lookup_fast_hook") "\n.popsection\n");

/*
 * A64 pieces used to find nd->last in the running kernel. struct nameidata is
 * private to fs/namei.c, so its layout is not in any header this module may
 * include. The function itself says where the qstr is: lookup_fast() passes
 * &nd->last as the second argument of __d_lookup_rcu()/__d_lookup(), and it
 * reads nd->flags (four pointers and two qstrs further on) on the same entry
 * path. Both facts are checked before the entry is patched; an offset that
 * cannot be confirmed refuses the hook instead of guessing.
 */
#define TOSYA_A64_ADD_IMM 0x91000000u
#define TOSYA_A64_ADD_IMM_MASK 0xff000000u
#define TOSYA_A64_MOV_X 0xaa0003e0u
#define TOSYA_A64_MOV_X_MASK 0xffe0ffe0u
#define TOSYA_A64_BL 0x94000000u
#define TOSYA_A64_BL_MASK 0xfc000000u
#define TOSYA_A64_LDRB_IMM 0x39400000u
#define TOSYA_A64_LDRW_IMM 0xb9400000u
#define TOSYA_A64_LDR_IMM_MASK 0xffc00000u

static long tosya_sx26(u32 value)
{
	return (long)(value & 0x01ffffffu) - (long)(value & 0x02000000u);
}

/*
 * The alias set starts with x0 (the nd argument). A register that received x0,
 * or an alias of it, joins the set; every other write removes the destination.
 * ADD (immediate) into x1 from the set is the qstr pointer; a BL to one of the
 * two dcache lookups consumes that pointer.
 */
static bool tosya_nd_last_offset(u32 *out)
{
	unsigned long addr, size, dlookup, dlookup_rcu;
	/* Installation is serialized module init; the snapshot need not be on stack. */
	static u32 source[TOSYA_INLINE_MAX_FUNC / TOSYA_INLINE_INSN];
	u32 alias, x1_off;
	size_t words, i;
	bool found = false;
	u32 off = 0;

	if (!tosya_symbol_range("lookup_fast", &addr, &size))
		return false;
	if (size > TOSYA_INLINE_MAX_FUNC)
		size = TOSYA_INLINE_MAX_FUNC;
	size &= ~(unsigned long)(TOSYA_INLINE_INSN - 1u);
	if (size < 8u * TOSYA_INLINE_INSN ||
	    !tosya_read((const void *)addr, source, size))
		return false;
	/*
	 * The BL target is the function body, never the pre-kCFI jump-table
	 * veneer: use the raw lookup, not tosya_sym()'s callable-address one.
	 */
	dlookup = tosya_lookup_raw("__d_lookup");
	dlookup_rcu = tosya_lookup_raw("__d_lookup_rcu");
	words = size / TOSYA_INLINE_INSN;

	alias = 1u;
	x1_off = ~0u;
	for (i = 0; i < words; i++) {
		const u32 insn = source[i];
		const u32 rd = insn & 31u;
		const u32 rn = (insn >> 5) & 31u;

		if ((insn & TOSYA_A64_MOV_X_MASK) == TOSYA_A64_MOV_X) {
			const u32 rm = (insn >> 16) & 31u;

			if (alias & (1u << rm)) {
				alias |= 1u << rd;
				if (rd == 1u)
					x1_off = 0;
			} else {
				alias &= ~(1u << rd);
				if (rd == 1u)
					x1_off = ~0u;
			}
			continue;
		}
		if ((insn & TOSYA_A64_ADD_IMM_MASK) == TOSYA_A64_ADD_IMM &&
		    !(insn & (1u << 22))) {
			const u32 imm = (insn >> 10) & 0xfffu;

			if (alias & (1u << rn)) {
				alias |= 1u << rd;
				if (rd == 1u)
					x1_off = imm;
			} else {
				alias &= ~(1u << rd);
				if (rd == 1u)
					x1_off = ~0u;
			}
			continue;
		}
		if ((insn & TOSYA_A64_BL_MASK) == TOSYA_A64_BL) {
			const long delta = tosya_sx26(insn & 0x03ffffffu) *
					   (long)TOSYA_INLINE_INSN;
			const unsigned long target = addr +
						     i * TOSYA_INLINE_INSN +
						     (unsigned long)delta;

			if ((target == dlookup || target == dlookup_rcu) &&
			    x1_off != ~0u && x1_off >= 8u && x1_off <= 512u &&
			    !(x1_off & 7u)) {
				off = x1_off;
				found = true;
			}
			continue;
		}
		if (rd != 31u) {
			alias &= ~(1u << rd);
			if (rd == 1u)
				x1_off = ~0u;
		}
	}

	/*
	 * The second fact: the same nd has a flags word just past the qstr, at
	 * nd + off + 0x28 (path, qstr, root and the inode pointer fill 0x38
	 * bytes), and lookup_fast() reads it as a byte. Requiring that load makes
	 * a chance ADD of some other constant unusable.
	 */
	alias = 1u;
	for (i = 0; found && i < words; i++) {
		const u32 insn = source[i];
		const u32 rd = insn & 31u;
		const u32 rn = (insn >> 5) & 31u;

		if ((insn & TOSYA_A64_MOV_X_MASK) == TOSYA_A64_MOV_X) {
			const u32 rm = (insn >> 16) & 31u;

			if (alias & (1u << rm))
				alias |= 1u << rd;
			else
				alias &= ~(1u << rd);
			continue;
		}
		if ((insn & TOSYA_A64_LDR_IMM_MASK) == TOSYA_A64_LDRB_IMM ||
		    (insn & TOSYA_A64_LDR_IMM_MASK) == TOSYA_A64_LDRW_IMM) {
			const u32 imm = (insn >> 10) & 0xfffu;

			if ((alias & (1u << rn)) &&
			    (imm == off + 0x28u || imm == off + 0x29u))
				goto confirmed;
		}
		if (rd != 31u)
			alias &= ~(1u << rd);
	}
	return false;

confirmed:
	*out = off;
	pr_info("tosya: lookup_fast's nd->last is at +%#x (checked against nd->flags)\n",
		off);
	return true;
}

static u32 g_nd_last_off;

/*
 * The one walk hook. lookup_fast(nd) is the point where the VFS is about to ask
 * the dcache for nd->last; before it does, this hook asks the published set:
 *
 *   - dir_hidden_probe() reads its fixed number of pair slots, the same run for
 *     every name;
 *   - two conditional selects then take the entry's stored mask bytes and
 *     precomputed hash(M), or leave the original bytes and hash in place.
 *
 * There is no allocation, no lock and no scratch buffer: the mask bytes live in
 * the published set, and replaced sets are retained so the pointer in nd->last
 * stays valid when lookup_slow() reads it after the hook has returned.
 */
noinline struct dentry *tosya_lookup_fast_hook(void *nd)
{
	struct qstr *last = (struct qstr *)((u8 *)nd + g_nd_last_off);
	struct qstr asked = *last;
	const u8 *mask_bytes;
	u32 mask_hash;
	bool hit;

	hit = tosya_dir_walk_last(&asked, &mask_bytes, &mask_hash);
	last->name = hit ? mask_bytes : last->name;
	last->hash = hit ? mask_hash : last->hash;
	return tosya_lookup_fast_orig(nd);
}

static struct tosya_inline_hook g_lookup_fast = {
	.name = "lookup_fast",
	.allow_indirect = true,
	.copy = g_lookup_fast_copy,
	.hook = (unsigned long)tosya_lookup_fast_hook,
	.stub = (unsigned long)tosya_lookup_fast_stub,
	.pacia_stub = (unsigned long)tosya_lookup_fast_pacia_stub,
	.pacib_stub = (unsigned long)tosya_lookup_fast_pacib_stub,
};

int tosya_lookup_fast_install(void)
{
	u32 off;

	if (!tosya_nd_last_offset(&off)) {
		pr_warn("tosya: lookup_fast's nameidata layout cannot be confirmed; the walk is not filtered\n");
		return -EOPNOTSUPP;
	}
	g_nd_last_off = off;
	return inline_install(&g_lookup_fast);
}

static struct tosya_inline_hook g_unlock_inode = {
	.name = "unlock_new_inode",
	.copy = g_unlock_inode_copy,
	.hook = (unsigned long)tosya_unlock_inode_hook,
	.stub = (unsigned long)tosya_unlock_inode_stub,
	.pacia_stub = (unsigned long)tosya_unlock_inode_pacia_stub,
	.pacib_stub = (unsigned long)tosya_unlock_inode_pacib_stub,
};

__attribute__((hot)) noinline void tosya_unlock_inode_hook(struct inode *inode)
{
	/*
	 * After the original, never before: while I_NEW is still set the file system has not
	 * finished with the inode, and a write into i_fop there races its own -- the one window
	 * the shadow code refuses everywhere else.
	 */
	tosya_unlock_inode_orig(inode);
	tosya_apk_shadow_apply(inode);
}

int tosya_unlock_inode_install(void)
{
	int rc = inline_install(&g_unlock_inode);

	if (rc == 0)
		pr_info("tosya: a new inode is shadowed before it is seen\n");
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
