// SPDX-License-Identifier: GPL-2.0
/*
 * policy.c - the (caller, target) pairs computed in userspace.
 *
 * The lookup must not reveal whether a uid is hidden:
 *  - the target's line is the kernel's own uidhash bucket line (8 bucket
 * pointers per line), read in full, and the caller's own word of the mask of every
 * probed slot: which words those are follows from (caller, target) and from the
 * policy, and never from the answer, so a hidden target and one that was never
 * configured read the same addresses the same number of times;
 *  - the replacement uid hashes into the same bucket as the target
 * (make_replace()), so find_user() walks the same chain as for a uid that does
 * not exist at all;
 *  - the caller is matched by uid in its own table: its cost may differ between
 * callers, but not for one caller.
 */
#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
/*
 * The DDK ships a trimmed header set, so this is declared here: the symbol
 * itself is exported (Module.symvers), it is only the declaration that lives in
 * linux/security.h.
 */
#ifndef TOSYA_HOST_BUILD
struct cred;
#endif
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/user.h>

#include "tosya.h"

/*
 * One immutable policy snapshot behind an RCU pointer: a query reads the
 * pointer once and then only touches that snapshot, so it needs no lock and can
 * never see a half-applied policy (a pile of independent globals would have
 * needed the lock just to read them consistently). policy_apply() builds a
 * fresh snapshot with plain stores and publishes it with a single pointer swap;
 * the snapshot it replaced is freed after a grace period.
 */
struct policy {
	// What the inlined half of the query reads; filled in by policy_publish().
	struct policy_hot hot;
	struct uid_pair *tgt;
	/* One entry per distinct caller mask, `nmask_words` words each; a slot names
	 * its mask with mask_id. Keeping the masks themselves in the slots is what
	 * made a policy of a few tens of thousands of pairs pay for tens of megabytes
	 * of table that no cache could hold. */
	u64 *mask_pool;
	u16 *cid;
	u32 nprobe, nlines, shift, nmask_words, npairs, ncallers, mirror;
	/* Set when any pair is caller 0: a wildcard hides a target from a caller
	 * that has no rules of its own, so the lookup cannot take its "no rules"
	 * shortcut on a snapshot that carries one. */
	u32 wild;
};

/*
 * Zeroed stand-in tables, installed by policy_reset(): a lookup with no policy
 * loaded reads them and matches nothing (target 0, no mask bits, caller uid 0),
 * so the hot path needs no "is a policy loaded?" branch and no NULL check.
 */
static struct uid_pair dummy_tgt[POLICY_MIN_LINES * POLICY_WAY];
static u64 dummy_mask_pool[POLICY_MIN_LINES * POLICY_WAY];
static u16 dummy_cid[POLICY_APP_ID_SPAN];

// The empty snapshot a query starts on, so the hot path needs no NULL check.
static struct policy g_empty = {
	.hot = { .cid = dummy_cid, .wild = 0 },
	.tgt = dummy_tgt,
	.mask_pool = dummy_mask_pool,
	.cid = dummy_cid,
	.nprobe = POLICY_WAY,
	.nlines = POLICY_MIN_LINES,
	.shift = 32 - 4,
	.nmask_words = 1,
	.mirror = 0,
};

/* The published snapshot: one pointer swap, so a query reads a consistent
 * whole. */
struct policy *g_pol __rcu = &g_empty;

struct apply_pair {
	u32 caller;
	u32 target;
};

static u32 policy_hash(u32 caller, u32 target, u32 shift);
static u32 policy_index_mode(u32 target, u32 mirror, u32 shift);
static u32 policy_subslot(u32 target);

static void sort_pairs(struct apply_pair *a, u32 n)
{
	u32 i, j;

	for (i = 1; i < n; i++) {
		struct apply_pair key = a[i];

		for (j = i; j > 0; j--) {
			struct apply_pair *p = &a[j - 1];

			if (p->target < key.target)
				break;
			if (p->target == key.target && p->caller <= key.caller)
				break;
			a[j] = *p;
		}
		a[j] = key;
	}
}
/*
 * Read the uid hash formula out of find_user()'s own code: __uidhashfn
 * (((uid >> bits) + uid) & (SZ - 1)) or hash_32 (uid * 0x61c88647 >> (32 -
 * bits)).
 */
#define UID_HASH_BASE 0x40000000u
#define UID_HASH_GOLDEN 0x61c88647u

struct uid_hash {
	u8 bits;
	u8 shift;
	bool multiply;
};

// Assumed until detect_uid_hash() says otherwise; logged either way.
static struct uid_hash g_hash = { .bits = 7, .shift = 25, .multiply = false };

static u32 uid_hash_apply(const struct uid_hash *h, u32 uid)
{
	if (h->multiply)
		// hash_32 truncates the product before extracting its high bits.
		return (u32)(uid * UID_HASH_GOLDEN) >> h->shift;

	return ((uid >> h->bits) + uid) & ((1u << h->bits) - 1);
}

static bool uid_hash_bits_ok(u32 bits)
{
	return bits == 3 || bits == 7 || bits == 8;
}

/*
 * Scan find_user() for one of the two instruction patterns. aarch64:
 *   lsr wA, wB, #BITS UBFM 32-bit with imms = 31
 *   add wC, w?, w?                     one operand is wA
 *   movz wD, #0x8647
 *   movk wD, #0x61c8, lsl #16
 *   lsr wD, wD, #32-BITS
 */
static bool detect_uid_hash(struct uid_hash *out)
{
	const u32 *code = (const u32 *)find_user;
	u32 i;

	for (i = 0; i + 4 < 128; i++) {
		u32 w0 = READ_ONCE(code[i]);

		/*
     * __uidhashfn: clang emits it as one ADD with a shifted operand
     *   add wA, wN, wN, lsr #BITS      (Rn == Rm, shift = LSR)
     *   and wA, wA, #(SZ-1)
     */
		if ((w0 & 0xFFE00000u) == 0x0B400000u &&
		    ((w0 >> 5) & 0x1Fu) == ((w0 >> 16) & 0x1Fu)) {
			u32 bits = (w0 >> 10) & 0x3Fu;

			if (uid_hash_bits_ok(bits)) {
				out->bits = (u8)bits;
				out->shift = (u8)(32 - bits);
				out->multiply = false;
				return true;
			}
		}

		// movz wD, #0x8647
		if ((w0 & 0xFF800000u) != 0x52800000u ||
		    ((w0 >> 5) & 0xFFFFu) != 0x8647u ||
		    ((w0 >> 21) & 0x3u) != 0u)
			continue;

		/*
     * hash_32: movz #0x8647 ... movk #0x61c8, lsl #16 ... umull / mul ...
     *          lsr #(32 - BITS)   or ubfx #(32 - BITS), #32
     *
     * The two halves of the constant can be separated by a BTI/hint
     * (clang 14 inserts one), and the bucket extraction can be a UBFX
     * when the result also feeds the array index.
     */
		{
			u32 j, m;

			for (j = 1; j < 6; j++) {
				u32 wj = READ_ONCE(code[i + j]);

				if ((wj & 0xFF800000u) != 0x72800000u ||
				    ((wj >> 5) & 0xFFFFu) != 0x61c8u ||
				    ((wj >> 21) & 0x3u) != 1u)
					continue;

				for (m = j + 1; m < j + 10; m++) {
					u32 wk = READ_ONCE(code[i + m]);
					u32 lsb, imms;

					if (!((wk & 0xFFC00000u) ==
						      0x53000000u ||
					      (wk & 0xFFC00000u) ==
						      0xD3400000u))
						continue;
					lsb = (wk >> 16) & 0x3Fu;
					imms = (wk >> 10) & 0x3Fu;
					// lsr (32/64-bit) or ubfx covering the whole word
					if (imms != 31u && imms != 63u &&
					    imms != (lsb + 31u))
						continue;
					if (lsb < 24 || lsb > 29 ||
					    !uid_hash_bits_ok(32 - lsb))
						continue;
					out->bits = (u8)(32 - lsb);
					out->shift = (u8)lsb;
					out->multiply = true;
					return true;
				}
				break; // constant found, its high half is unique
			}
		}
	}

	return false;
}

static u32 make_replace(u32 target)
{
	const u32 bucket = uid_hash_apply(&g_hash, target);
	const u32 h = (POLICY_REPL_BASE >> g_hash.bits) + 1u;

	return (h << g_hash.bits) + ((bucket - h) & ((1u << g_hash.bits) - 1u));
}

struct layout {
	struct uid_pair *tgt;
	u64 *masks;
	u16 *cid;
	u32 nlines, shift, nclines, cshift, nmask_words, ntargets, nmasks,
		mirror, probe;
};
/*
 * The buffers a layout is built in, kept between applies: they have the same size every
 * time -- the most a policy can need -- and allocating and zeroing half a megabyte per
 * apply would be work for nothing. One set is enough because applies are
 * serialised: the module applies them from one netlink command under g_apply_lock, and the
 * published snapshot is a separate allocation. policy_free() gives them back at unload.
 */
static u8 *g_used;
static u64 *g_scratch;
static u32 *g_mhash;
static u32 g_mhash_size;

/* distinct callers of the policy -> dense hider ids; -1 if there are too many
 *
 * The hider table: one id per app, never per uid. A policy carries every user's
 * uids -- the userspace half expands them -- and both lookups (the tag one and
 * policy_lookup_as) identify the caller by the app id inside its uid, so keying
 * this by the full uid would leave the first user's masks under an id nobody
 * asks for, and that user's pairs would not be hidden.
 */
static int build_hiders(struct apply_pair *p, u32 n, u32 *hid)
{
	u32 i, j, nh = 0;

	for (i = 0; i < n; i++) {
		u32 c = p[i].caller % 100000u;

		if (c == 0) // caller==0 hides from everyone, no id needed
			continue;
		for (j = 0; j < nh; j++)
			if (hid[j] == c)
				break;
		if (j < nh)
			continue;
		if (nh == POLICY_MAX_CALLERS)
			return -1;
		hid[nh++] = c;
	}
	return (int)nh;
}

// the caller table: one u16 per app id, 0xffff = not a hider
static int layout_cids(struct layout *l, const u32 *hid, u32 nh)
{
	u32 i;

	l->cid = kmalloc_array(POLICY_APP_ID_SPAN, sizeof(*l->cid), GFP_KERNEL);
	if (!l->cid)
		return -1;
	for (i = 0; i < POLICY_APP_ID_SPAN; i++)
		l->cid[i] = 0xffffu;
	for (i = 0; i < nh; i++) {
		u32 app = hid[i] % 100000u;

		if (app < POLICY_APP_ID_MIN ||
		    app >= POLICY_APP_ID_MIN + POLICY_APP_ID_SPAN) {
			pr_warn("tosya: caller %u is not an app uid; it cannot be matched\n",
				hid[i]);
			continue;
		}
		l->cid[app - POLICY_APP_ID_MIN] = (u16)i;
	}
	return 0;
}
static u32 probe_for(u32 maxdist)
{
	return maxdist ? (maxdist < 2 ? 2 : POLICY_PROBE_MAX) : 1;
}

/*
 * Place every distinct target the way the real layout will, and report how far it had to
 * walk: the target goes into its own slot of its own line, or of the lines that follow,
 * up to POLICY_PROBE_MAX of them. One byte per cell is enough to know -- and a cell is
 * one slot of one line, because that is what the query reads now.
 */
static bool trial_fit(const struct apply_pair *p, u32 n, u8 *used, u32 nlines,
		      u32 shift, u32 mirror, u32 *maxdist)
{
	u32 i, dist = 0;

	memset(used, 0, (size_t)nlines * POLICY_WAY);
	for (i = 0; i < n; i++) {
		u32 t = p[i].target, k;

		if (i && p[i - 1].target == t)
			continue;
		{
			u32 unit = policy_index_mode(t, mirror, shift) &
				   (nlines - 1);
			u32 sub = policy_subslot(t);

			for (k = 0; k < POLICY_PROBE_MAX; k++) {
				u8 *cell = &used[(size_t)((unit + k) &
							  (nlines - 1)) *
							 POLICY_WAY +
						 sub];

				if (!*cell) {
					*cell = 1;
					if (k > dist)
						dist = k;
					break;
				}
			}
			if (k == POLICY_PROBE_MAX)
				return false;
		}
	}
	*maxdist = dist;
	return true;
}

/* target slots and their masks, on the kernel's own bucket lines when it fits
 *
 * Find or add a caller mask. One mask per slot would be nlines x POLICY_WAY of
 * them, nmask_words wide each: tens of megabytes of table for a policy of
 * 24000 pairs and 600 callers for the handful of distinct caller sets it
 *  has, every query reading from memory no cache could hold.
 *
 * Interning makes the allocation and the working set proportional to the number of
 * *different* sets. A hash finds a candidate and the comparison is a full memcmp:
 * a collision that was believed would hide a target from a caller that was never
 * configured to see it hidden.
 */
static u16 tosya_mask_intern(u64 *pool, u32 *hash, u32 hsize, u32 *npool,
			     const u64 *bits, u32 mw)
{
	u32 h = 0, i;
	u32 slot;

	for (i = 0; i < mw; i++)
		h = (h ^ (u32)bits[i] ^ (u32)(bits[i] >> 32)) * 2654435761u;
	h &= hsize - 1;
	for (;;) {
		slot = hash[h];
		if (slot == 0xffffffffu) {
			const u32 use = (*npool)++;

			if (use > 0xfffeu)
				return 0xffffu; // more distinct masks than a slot id can name
			memcpy(&pool[(size_t)use * mw], bits,
			       (size_t)mw * sizeof(u64));
			hash[h] = use;
			return (u16)use;
		}
		if (!memcmp(&pool[(size_t)slot * mw], bits,
			    (size_t)mw * sizeof(u64)))
			return (u16)slot;
		h = (h + 1) & (hsize - 1);
	}
}

static int layout_targets(struct layout *l, struct apply_pair *p, u32 n,
			  const u32 *hid, u32 nh)
{
	struct uid_pair *tgt;
	u64 *masks; // the interned caller masks, nmask_words each
	u64 *scratch; // the mask of the target being laid out
	u32 *mhash; // mask -> pool slot, for finding an equal one again
	u8 *used;
	u32 i, j, k, nlines, shift, mirror, nt = 0, maxdist = 0, hsize,
					    npool = 1;
	size_t last = 0;

	_Static_assert(POLICY_WAY <= 8, "one byte of slots per line");

	/*
	 * Where the line search starts: the smallest line count that could hold this many
	 * targets at all. A line carries one target per slot, and a slot serves at most
	 * POLICY_PROBE_MAX targets (its own line and the ones that follow), so the floor is
	 * the target count over POLICY_WAY * POLICY_PROBE_MAX, rounded up to a power of two
	 * and grown by the fit search when the targets do not spread out evenly.
	 */
	{
		u32 nt_seen = 0;

		for (i = 0; i < n; i++) {
			if (i && p[i - 1].target == p[i].target)
				continue;
			nt_seen++;
		}

		/*
		 * keep the starting count a power of two and never below the floor above: the
		 * hash needs a mask, and a layout that cannot fit is only worth trying from
		 * there.
		 */
		for (nlines = POLICY_MIN_LINES;
		     nlines < (nt_seen + POLICY_WAY * POLICY_PROBE_MAX - 1u) /
				      (POLICY_WAY * POLICY_PROBE_MAX) &&
		     nlines < POLICY_MAX_LINES;
		     nlines <<= 1)
			;
	}
	if (g_used == NULL)
		g_used = kcalloc((size_t)POLICY_MAX_LINES * POLICY_WAY,
				 sizeof(*g_used), GFP_KERNEL);
	if (g_used == NULL)
		return -1;
	used = g_used;
	for (;;) {
		u32 dist_own = 0, dist_mine = 0;
		bool fit_own, fit_mine;

		shift = 32 - ilog2(nlines);
		fit_own = trial_fit(p, n, used, nlines, shift, 1, &dist_own);
		fit_mine = trial_fit(p, n, used, nlines, shift, 0, &dist_mine);
		if (fit_own || fit_mine) {
			mirror = fit_own && (!fit_mine ||
					     probe_for(dist_own) <=
						     probe_for(dist_mine)) ?
					 1 :
					 0;
			break;
		}
		if (nlines >= POLICY_MAX_LINES) {
			pr_warn("tosya: policy fits no line layout\n");
			return -1;
		}
		nlines <<= 1;
	}

	tgt = kcalloc((size_t)nlines * POLICY_WAY, sizeof(*tgt), GFP_KERNEL);
	/*
	 * One entry per distinct mask, with pool[0] the empty one so a slot that names
	 * no mask reads zeros. The allocation follows the targets, not the lines: the
	 * table can be sparse, the masks cannot.
	 */
	hsize = 16;
	while (hsize < (u32)n * 2u && hsize < (1u << 17))
		hsize <<= 1;
	// Slot zero is a complete empty mask, including every caller word.
	masks = kcalloc(((size_t)n + 1u) * l->nmask_words, sizeof(*masks),
			GFP_KERNEL);
	if (g_scratch == NULL)
		g_scratch = kcalloc(POLICY_MAX_CALLERS / 64 + 1u,
				    sizeof(*g_scratch), GFP_KERNEL);
	if (g_mhash == NULL || g_mhash_size < hsize) {
		kfree(g_mhash);
		g_mhash = kmalloc_array(hsize, sizeof(*g_mhash), GFP_KERNEL);
		g_mhash_size = g_mhash ? hsize : 0;
	}
	scratch = g_scratch;
	mhash = g_mhash;
	if (!tgt || !masks || !scratch || !mhash)
		goto fail;
	/* the buffer is reused, so the first target has to start from zeros: only the
	 * targets after it clear it themselves */
	memset(scratch, 0, (size_t)l->nmask_words * sizeof(*scratch));
	for (j = 0; j < hsize; j++)
		mhash[j] = 0xffffffffu;

	for (i = 0; i <= n; i++) {
		u32 t, c, app;

		if (i == n || (i && p[i - 1].target != p[i].target)) {
			const u16 id = tosya_mask_intern(masks, mhash, hsize,
							 &npool, scratch,
							 l->nmask_words);

			if (id == 0xffffu) {
				pr_warn("tosya: more than 65534 distinct caller masks; policy refused\n");
				goto fail;
			}
			tgt[last].mask_id = id;
			if (i == n)
				break;
			memset(scratch, 0,
			       (size_t)l->nmask_words * sizeof(*scratch));
		}
		t = p[i].target;
		c = p[i].caller;
		if (i == 0 || p[i - 1].target != t) {
			u32 unit = policy_index_mode(t, mirror, shift) &
				   (nlines - 1),
			    placed = 0;
			u32 sub = policy_subslot(t);

			for (k = 0; k < POLICY_PROBE_MAX; k++) {
				const u32 line = (unit + k) & (nlines - 1);
				struct uid_pair *s =
					&tgt[(size_t)line * POLICY_WAY + sub];

				if (!s->target) {
					s->target = t;
					s->repl_k =
						(make_replace(t) -
						 POLICY_REPL_BASE) &
						((1u << POLICY_REPL_BITS) - 1);
					last = (size_t)line * POLICY_WAY + sub;
					if (k > maxdist)
						maxdist = k;
					placed = 1;
					nt++;
					break;
				}
			}
			if (!placed)
				goto fail;
		}

		/*
		 * The hider table is keyed by app id, not by uid: a policy carries
		 * every user's uids and the lookups identify the caller by the app
		 * id inside its uid, so comparing the full uid here would leave the
		 * second user's pairs with no mask bit at all.
		 */
		app = c % 100000u;
		if (app == 0) {
			tgt[last].repl_k |= POLICY_WILD_FLAG;
			continue;
		}
		for (j = 0; j < nh; j++)
			if (hid[j] == app)
				break;
		if (j < nh)
			scratch[j >> 6] |= 1ULL << (j & 63);
	}

	l->tgt = tgt;
	l->masks = masks;
	l->nmasks = npool;
	l->nlines = nlines;
	l->shift = shift;
	l->mirror = mirror;
	l->ntargets = nt;
	l->probe = probe_for(maxdist);
	return 0;

fail:
	kfree(masks);
	kfree(tgt);
	return -1;
}

static void policy_release(struct policy *p)
{
	if (!p || p == &g_empty)
		return;
	kfree(p->tgt);
	kfree(p->mask_pool);
	kfree(p->cid);
	kfree(p);
}

/*
 * Publish a snapshot: one store makes it visible, and the snapshot it replaced
 * is only freed once every query that could still be inside it has finished.
 */
static void policy_publish(struct policy *np)
{
	struct policy *old;

	// The inlined half reads these out of the snapshot the swap publishes.
	np->hot.cid = np->cid;
	np->hot.wild = np->wild;
	old = xchg(&g_pol, np);
	synchronize_rcu();
	policy_release(old);
}

void policy_apply(const u32 *pairs, u32 npairs)
{
	struct policy *np;
	struct layout l = {};
	struct apply_pair *tmp;
	u32 *hid;
	u32 i, n = 0, wild = 0;
	int nh, ok = 0;

	np = kzalloc(sizeof(*np), GFP_KERNEL);
	if (!np)
		return;

	tmp = kcalloc(POLICY_MAX_PAIRS, sizeof(*tmp), GFP_KERNEL);
	hid = kcalloc(POLICY_MAX_CALLERS, sizeof(*hid), GFP_KERNEL);
	if (!tmp || !hid)
		goto out;

	for (i = 0; i < npairs && n < POLICY_MAX_PAIRS; i++) {
		u32 target = pairs[2 * i + 1];

		if (target < 10000) // never hide target 0 or system uids
			continue;
		if (pairs[2 * i] == 0) // caller 0: hide from everyone
			wild = 1;
		tmp[n].caller = pairs[2 * i];
		tmp[n].target = target;
		n++;
	}

	/* No target remains after filtering: publish the existing empty snapshot.
	 * The target builder requires at least one target before interning a mask. */
	if (!n) {
		policy_publish(&g_empty);
		pr_info("tosya: cleared policy\n");
		goto out;
	}

	if (n) {
		struct uid_hash h;

		if (detect_uid_hash(&h))
			g_hash = h;
		pr_info("tosya: uid hash = %s bits=%u\n",
			g_hash.multiply ? "hash_32" : "__uidhashfn",
			g_hash.bits);
		if (g_hash.multiply)
			pr_warn("tosya: this kernel hashes uids in a form this module does not model; targets are still hidden, but a hidden lookup will not share a bucket with an absent uid\n");
	}

	sort_pairs(tmp, n);

	nh = build_hiders(tmp, n, hid);
	if (nh < 0)
		pr_err("tosya: more than %u callers; keeping previous policy\n",
		       POLICY_MAX_CALLERS);
	else if (layout_cids(&l, hid, (u32)nh))
		pr_err("tosya: cannot lay out %d caller(s); keeping previous policy\n",
		       nh);
	else {
		l.nmask_words = nh ? ((u32)nh + 63) / 64 : 1;
		if (layout_targets(&l, tmp, n, hid, (u32)nh))
			pr_err("tosya: cannot lay out %u pair(s); keeping previous policy\n",
			       n);
		else
			ok = 1;
	}

	if (ok) {
		np->tgt = l.tgt;
		np->mask_pool = l.masks;
		np->cid = l.cid;
		np->nprobe = l.probe;
		np->nlines = l.nlines;
		np->shift = l.shift;
		np->nmask_words = l.nmask_words;
		np->npairs = n;
		np->ncallers = nh > 0 ? (u32)nh : 0;
		np->mirror = l.mirror;
		np->wild = wild;
		l.tgt = NULL;
		l.masks = NULL;
		l.cid = NULL;
	}

	/* Publish first, so the self-check answers through the snapshot a caller
   * would see. */
	if (ok)
		policy_publish(np);

	if (ok) {
		u32 checked = 0, hits = 0;

		// answer every configured pair from the table that is now live
		for (i = 0; i < n; i++) {
			if (tmp[i].caller == 0)
				continue;
			/*
			 * A caller asking about itself is answered 0 by the hot path on
			 * purpose, and the userspace half never emits such a pair: counting it here
			 * would report a policy that is in fact complete as broken.
			 */
			if (tmp[i].caller % 100000u == tmp[i].target % 100000u)
				continue;
			checked++;
			if (policy_lookup_as((uid_t)tmp[i].caller,
					     (uid_t)tmp[i].target))
				hits++;
		}
		if (hits != checked)
			pr_err("tosya: self-check FAILED: %u/%u pairs match\n",
			       hits, checked);
		else
			pr_info("tosya: self-check: %u/%u pairs match\n", hits,
				checked);
	}

out:
	kfree(l.masks);
	kfree(l.tgt);
	kfree(l.cid);
	kfree(hid);
	kfree(tmp);

	/* A layout that failed never filled np in, and the caller has already said why: only a
	 * policy that is live has fields worth printing. */
	if (!ok) {
		kfree(np);
		return;
	}

	pr_info("tosya: injected %u pair(s), %u caller(s), %u line(s), %u mask word(s) in %u mask(s), probe %u, %s layout\n",
		npairs, np->ncallers, np->nlines, np->nmask_words, l.nmasks,
		np->nprobe, np->mirror ? "uid-hash" : "own-hash");
}

/*
 * One line, and it is the line the kernel's own uid hash lands on.
 *
 * uidhash_table[] stores 8 bucket pointers per 64-byte line and hashes uids
 * with a formula read back from find_user() at apply time, so the line index
 * `uid_hash(target) >> 3` is exactly the line the kernel's own bucket lookup
 * touches for that uid: a cache observer sees the rhythm the kernel produces by
 * itself (continuous app uids cluster on the same few lines in the kernel too),
 * absolute positions stay unknown to userspace (kernel KASLR), and which slot
 * of the line a target occupies never changes the cache set because the whole
 * line is read.
 *
 * What no dynamic policy hook can remove is stated plainly: consulting a policy
 * costs two cache lines per query -- the target's line and the fixed caller
 * table.
 *
 * The table line itself is the top bits of a 64-bit product, always in [0, 2^(32 - shift)); the
 * multiplier is 64-bit on purpose, because with a 32-bit one the high bits stay zero for small
 * uids.
 */
static u32 hash_line(u64 key, u32 shift)
{
	key *= 0x9E3779B97F4A7C15ULL;
	return (u32)(key >> (32 + shift));
}

/* target table: keyed by the pair, so different callers do not share a line
 * layout */
static u32 policy_hash(u32 caller, u32 target, u32 shift)
{
	return hash_line(((u64)target << 32) | caller, shift);
}

// the kernel's uid hash, branch-free for both detected variants
static u32 policy_bucket(u32 target, u32 bits, u32 multiply)
{
	u32 hfn = ((target >> bits) + target) & ((1u << bits) - 1);
	u32 h32 = (u32)(target * UID_HASH_GOLDEN) >> (32 - bits);
	u32 sel = (u32)0 - multiply;

	return (hfn & ~sel) | (h32 & sel);
}

/*
 * Sub-index inside the line: the low bits of the kernel's own uid hash.
 * Deterministic and content-independent, so the probe sequence depends only on
 * the target, and the placement starts there -- which keeps the probe distance,
 * and therefore g_probe, tiny.
 */
static u32 policy_subslot(u32 target)
{
	return policy_bucket(target, g_hash.bits, (u32)g_hash.multiply) &
	       (POLICY_WAY - 1);
}

// the line the kernel's bucket lookup touches for this uid
static u32 policy_index_mirror(u32 target)
{
	return policy_bucket(target, g_hash.bits, (u32)g_hash.multiply) >> 3;
}

static u32 policy_index_own(u32 target, u32 shift)
{
	return policy_hash(0, target, shift);
}

/* apply-time helper: the line of the mode being laid out, blended branch-free
 */
static u32 policy_index_mode(u32 target, u32 mirror, u32 shift)
{
	u32 mir = policy_index_mirror(target);
	u32 own = policy_index_own(target, shift);
	u32 m = (u32)0 - mirror;

	return (mir & m) | (own & ~m);
}

/*
 * The layout, in one place.
 *
 * A target occupies one line: the index is the top bits of a 64-bit product of the uid, and the
 * line is read in full, so which slot of it a target sits in never changes what a query touches.
 * The caller is matched exactly -- the caller table builds a one-hot word, so a caller that is not
 * in the policy gets a zero and cannot match a target's mask by accident, which a shared mask bit
 * would do. Masks are interned, one entry per distinct set of callers: one per slot would be tens of
 * megabytes for the handful of sets a policy has. Cost is fixed: POLICY_WAY slot loads plus
 * POLICY_CALLERS comparisons from fixed offsets, no loop over data, no data branch, and the table
 * (16 lines = 1 KB at 7 hash bits) stays in L1. A policy that does not fit the pooled layout falls
 * back to a hash over a table sized from the target count, blended branch-free.
 *
 * The identity tag and the window bit live in the high bits of thread_info.flags, the same word as
 * the TIF_* bits the rest of the kernel updates with set_bit()/clear_bit(): a read-modify-write of
 * the module's own would lose a TIF_* bit set in between, so the word moves with a compare-and-swap. A task
 * that is named keeps its name -- the naming runs on another thread of the same group, and every
 * hiding rule hangs on that name -- and a task that already carries one is never re-tagged.
 * Security hooks are reached by writing out the declaration this module is built against and
 * choosing it by version, never by resolving a symbol by name and never through a function pointer:
 * on GKI a mismatched indirect call is a KCFI failure, which is a panic.
 *
 * The count of entries lives inside the published object. Two separate globals, a pointer and a
 * length, can be seen mismatched and a reader then walks past the end of a shorter array: one
 * pointer, one object, one store.
 *
 * The hot path is __always_inline so the syscall wrappers, which all reach it through uid_hook(),
 * each get a copy instead of paying a call, a prologue and register saves.
 */
static __always_inline u32 policy_cid_by_app(u32 app, const struct policy *p)
{
	return policy_cid_hot(&p->hot, app);
}

/*
 * The caller's own word of the mask, and nothing else. Which word that is follows from
 * the caller (its cid), never from the answer, and the answer is one bit of the word
 * that was read either way -- so this is the same load for a hidden target as for one
 * that was never configured, which is the whole point of the layout.
 *
 * Reading the mask out in full keeps the load count equal too, and costs nmask_words loads
 * per probed slot: ten for a policy with 600 callers, twenty for the two slots a policy that
 * size probes.
 */
static u32 mask_bit(const u64 *m, u32 cid)
{
	const u32 w = (cid == POLICY_ID_NONE) ? 0 : (cid >> 6);

	return (u32)((m[w] >> (cid & 63)) & 1);
}

/*
 * A select the compiler cannot undo. "?:" and the mask that means the same thing both get
 * turned back into a branch when the compiler thinks that is cheaper, and a branch on the
 * answer is exactly what must not exist here: a predictor can learn it and a clock can see
 * it. cmp + csel, two instructions, the same two whatever the answer is.
 */
noinline u32 policy_lookup_slow(uid_t target, u32 app)
{
	const struct policy *p;
	u32 t = (u32)target;
	u32 cid, repl = 0, hit = 0, wild = 0, rk = 0, k, unit, sub, eq, bit, h;
	const struct uid_pair *sl;
	rcu_read_lock();
	p = rcu_dereference(g_pol);

	/* The tag is the identity, so this is one table load and a csel - no uid
   * involved. */
	cid = policy_cid_by_app(app, p);
	/*
	 * A caller with no rules is answered here: the hash and the masks below can
	 * only turn this into a zero, and most callers are in that state, so the cost
	 * a hooked syscall adds is the lookup and not the whole hot path.
	 */
	if (cid == POLICY_ID_NONE && !p->wild) {
		rcu_read_unlock();
		return 0;
	}
	/*
   * One hash for both the line and the slot inside it: the kernel's own uid
   * hash gives the bucket line directly (8 buckets per line) and its low bits
   * give the starting slot, so the hot path hashes the target once instead of
   * twice.
   */
	h = policy_bucket(t, g_hash.bits, (u32)g_hash.multiply);
	sub = h & (POLICY_WAY - 1);
	{
		u32 mir = h >> 3, own = policy_index_own(t, p->shift),
		    m = (u32)0 - p->mirror;

		unit = (mir & m) | (own & ~m);
	}
	sl = &p->tgt[(size_t)unit * POLICY_WAY + sub];
	if (p->nprobe == 1) {
		eq = (sl->target == t);
		bit = mask_bit(
			&p->mask_pool[(size_t)sl->mask_id * p->nmask_words],
			cid);
		hit = eq & bit & (cid != POLICY_ID_NONE);
		wild = eq & ((u32)sl->repl_k >> 15);
		rk = eq ? ((u32)sl->repl_k & ((1u << POLICY_REPL_BITS) - 1)) :
			  0;
	} else {
		for (k = 0; k < p->nprobe; k++) {
			const u32 line = (unit + k) & (p->nlines - 1);

			sl = &p->tgt[(size_t)line * POLICY_WAY + sub];
			eq = (sl->target == t);
			bit = mask_bit(&p->mask_pool[(size_t)sl->mask_id *
						     p->nmask_words],
				       cid);
			hit |= eq & bit & (cid != POLICY_ID_NONE);
			wild |= eq & ((u32)sl->repl_k >> 15);
			rk |= eq ? ((u32)sl->repl_k &
				    ((1u << POLICY_REPL_BITS) - 1)) :
				   0;
		}
	}

	/*
	 * A select, not a branch: the answer steers a register and never the instruction
	 * stream, so a hidden target and one that was never configured run the same code
	 * with a different value in one register. Written as a mask because the compiler
	 * is happy to turn "?:" into a branch here (it did: cbz on hit|wild), and a branch
	 * on the answer is a branch a predictor can learn and a clock can see.
	 */
	repl = (u32)tosya_select((u64)(POLICY_REPL_BASE + rk), (u64)0,
				 hit | wild);
	rcu_read_unlock();

	return repl;
}

/*
 * The hook path. The identity is the task tag: a process zygote did not hand an
 * app uid to has no hiding rules of its own, and a tagged one answers as the
 * app it was born as however often it changes uid afterwards. The caller
 * argument is deliberately ignored.
 *
 * The lookup. The tag is the only identity source: it is written where an
 * identity is created, so an untagged process is one that already existed when
 * the module was loaded, and it gets no rules at all rather than an identity
 * derived from a uid that anything could have changed.
 *
 * The inode side -- the base.apk whose ->open is replaced so the first file of
 * its own code that an isolated child opens names it -- is in inode_hook.c.
 *
 * The cold paths are kept out of line so the query itself stays small enough to inline, and the
 * one below is where the wait for a name ends: an isolated child that is still unnamed but already
 * asking questions means its own code is running, so it answers as an app without rules from here
 * on, deterministically and with no deadline. tosya_tag_close() itself is provided by hooks.c and
 * stubbed out by the host test.
 */
void tosya_tag_close(void);

static noinline void tosya_close_pending(void)
{
	tosya_tag_close();
}

static noinline void tosya_warn_untagged(void)
{
	static bool warned;

	if (!warned && TOSYA_DEBUG_ON()) {
		warned = true;
		pr_info("tosya: untagged caller uid %u flags %lx comm %s\n",
			(u32)__kuid_val(current_fsuid()),
			(unsigned long)task_thread_info(current)->flags,
			current->comm);
	}
}

/*
 * The two log paths of a caller with no tag, out of line: they are taken once per process at most,
 * and leaving them in the wrapper would push a few hundred instructions into twelve of them.
 */
void noinline policy_tagless_note(void)
{
	if (tosya_tag_pending_here())
		tosya_close_pending();
	else
		tosya_warn_untagged();
}

/*
 * Explicit identity, for the self-check in policy_apply() and for the host
 * test: caller is a uid, and the range rules are applied here.
 */
u32 policy_lookup_as(uid_t caller, uid_t target)
{
	const u32 off = ((u32)caller % 100000u);

	if (off <= 1000u || (u32)caller == (u32)target)
		return 0;
	if (off < POLICY_APP_ID_MIN ||
	    off >= POLICY_APP_ID_MIN + POLICY_APP_ID_SPAN)
		return 0;
	return policy_lookup_slow(target, off - POLICY_APP_ID_MIN);
}

static void policy_reset(void)
{
	policy_publish(&g_empty);
}

int policy_init(void)
{
	policy_reset();
	return 0;
}

void policy_free(void)
{
	policy_publish(&g_empty);
	kfree(g_mhash);
	kfree(g_scratch);
	kfree(g_used);
	g_mhash = NULL;
	g_scratch = NULL;
	g_used = NULL;
	g_mhash_size = 0;
}
