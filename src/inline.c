// SPDX-License-Identifier: GPL-2.0
/*
 * Relocate a bounded A64 function without changing the order of its operations.
 * Every source instruction has a destination slot. ADRP keeps its original page
 * value; its consumers are never folded or moved. Branches use that complete
 * layout, including ordinary B and branches into ADRP consumers.
 */
#include "include/inline.h"

#define TOSYA_B 0x14000000u
#define TOSYA_BL 0x94000000u
#define TOSYA_ADRP 0x90000000u
#define TOSYA_ADR 0x10000000u
#define TOSYA_INSNS (TOSYA_INLINE_MAX_SOURCE / TOSYA_INLINE_INSN)

#ifdef TOSYA_INLINE_DEBUG
unsigned int tosya_inline_dbg_insn;
unsigned int tosya_inline_dbg_index;
unsigned int tosya_inline_dbg_stage;
#endif

static long tosya_sx(unsigned int value, unsigned int bits)
{
	const unsigned int sign = 1u << (bits - 1);

	return (long)(value & (sign - 1)) - (long)(value & sign);
}

// Unsigned VA arithmetic also works in the upper half of the address space.
static int tosya_displacement(unsigned long site, unsigned long target,
			      unsigned int shift, unsigned int bits, long *imm)
{
	const unsigned long unit = 1UL << shift;
	const unsigned long limit = 1UL << (bits - 1);
	unsigned long distance;

	if ((site | target) & (unit - 1))
		return TOSYA_INLINE_ERANGE;
	if (target >= site) {
		distance = (target - site) >> shift;
		if (distance >= limit)
			return TOSYA_INLINE_ERANGE;
		*imm = (long)distance;
	} else {
		distance = (site - target) >> shift;
		if (distance > limit)
			return TOSYA_INLINE_ERANGE;
		*imm = -(long)distance;
	}
	return TOSYA_INLINE_OK;
}

static unsigned long tosya_adrp_value(unsigned int insn, unsigned long va)
{
	const long imm = tosya_sx(
		((insn >> 5) & 0x7ffffu) << 2 | ((insn >> 29) & 3u), 21);

	return (va & ~0xfffUL) + (unsigned long)(imm * 4096);
}

static int tosya_adrp_encode(unsigned int *out, unsigned int rd,
			     unsigned long page, unsigned long va)
{
	long imm;

	if (tosya_displacement(va & ~0xfffUL, page, 12, 21, &imm))
		return TOSYA_INLINE_ERANGE;
	*out = TOSYA_ADRP | (((unsigned int)imm & 3u) << 29) |
	       ((((unsigned int)imm >> 2) & 0x7ffffu) << 5) | rd;
	return TOSYA_INLINE_OK;
}

static void tosya_mov_imm(unsigned int *out, unsigned int rd,
			  unsigned long value)
{
	unsigned int k;

	for (k = 0; k < 4; k++)
		out[k] = (k ? 0xf2800000u : 0xd2800000u) | (k << 21) |
			 ((unsigned int)((value >> (16 * k)) & 0xffffu) << 5) |
			 rd;
}

// All immediate branch classes; bit 4 of B.cond is FEAT_HBC's BC.cond.
static unsigned int tosya_branch_bits(unsigned int insn)
{
	if ((insn & 0x7c000000u) == TOSYA_B)
		return 26;
	if ((insn & 0xff000000u) == 0x54000000u ||
	    (insn & 0x7e000000u) == 0x34000000u)
		return 19;
	if ((insn & 0x7e000000u) == 0x36000000u)
		return 14;
	return 0;
}

static unsigned long tosya_branch_target(unsigned int insn, unsigned int bits,
					 unsigned long va)
{
	const unsigned int field = bits == 26 ? insn : insn >> 5;
	const long offset = tosya_sx(field & ((1u << bits) - 1u), bits) * 4;

	return va + (unsigned long)offset;
}

struct tosya_layout {
	unsigned short out[TOSYA_INSNS]; // byte offsets; no consumed instructions
	size_t size;
};

static int tosya_plan(const unsigned int *src, unsigned int words,
		      unsigned long from_va, unsigned long to_va,
		      struct tosya_layout *lay)
{
	unsigned int i;
	size_t at = 0;

	for (i = 0; i < words; i++) {
		const unsigned int insn = src[i];
		unsigned int encoded;

		lay->out[i] = (unsigned short)at;
#ifdef TOSYA_INLINE_DEBUG
		tosya_inline_dbg_insn = insn;
		tosya_inline_dbg_index = i;
		tosya_inline_dbg_stage = 1;
#endif
		if ((insn & 0x9f000000u) == TOSYA_ADRP) {
			const unsigned long page =
				tosya_adrp_value(insn, from_va + i * 4UL);

			at += tosya_adrp_encode(&encoded, insn & 31u, page,
						to_va + at) ?
				      16 :
				      4;
			continue;
		}
		/* Entire load-register-literal class: LDR W/X/S/D/Q, LDRSW,
		 * PRFM, and reserved members. ADR is also refused. These must
		 * not silently keep a PC-relative operand from the original.
		 * Exception-generating instructions (BRK/HLT/SVC/etc.) are
		 * also refused: BUG/exception metadata names original PCs. */
		if ((insn & 0x3b000000u) == 0x18000000u ||
		    (insn & 0x9f000000u) == TOSYA_ADR ||
		    (insn & 0xff000000u) == 0xd4000000u)
			return TOSYA_INLINE_EINSN;
		at += TOSYA_INLINE_INSN;
	}
	lay->size = at;
	return TOSYA_INLINE_OK;
}

static int tosya_branch_encode(unsigned int *out, unsigned int insn,
			       unsigned int bits, unsigned long va,
			       unsigned long target)
{
	const unsigned int shift = bits == 26 ? 0 : 5;
	const unsigned int mask = (1u << bits) - 1u;
	long imm;

	if (tosya_displacement(va, target, 2, bits, &imm))
		return TOSYA_INLINE_ERANGE;
	*out = (insn & ~(mask << shift)) |
	       (((unsigned int)imm & mask) << shift);
	return TOSYA_INLINE_OK;
}

int tosya_inline_entry(void *out, size_t out_size, unsigned long site_va,
		       unsigned long hook_va)
{
	unsigned int encoded;

	if (!out || out_size < TOSYA_INLINE_ENTRY)
		return TOSYA_INLINE_ESIZE;
	if (tosya_branch_encode(&encoded, TOSYA_B, 26, site_va, hook_va))
		return TOSYA_INLINE_ERANGE;
	// The output buffer is required to have instruction alignment.
	if ((unsigned long)out & 3UL)
		return TOSYA_INLINE_EINSN;
	*(unsigned int *)out = encoded;
	return TOSYA_INLINE_ENTRY;
}

int tosya_inline_relocate(void *to, size_t to_size, const void *from,
			  unsigned long from_va, unsigned long to_va,
			  size_t len, size_t *out_len)
{
	struct tosya_layout lay;
	const unsigned int *src = from;
	unsigned int *dst = to;
	unsigned int words, i;
	int rc;

	if (out_len)
		*out_len = 0;
	if (!to || !from || !len || len > TOSYA_INLINE_MAX_SOURCE)
		return TOSYA_INLINE_ESIZE;
	if (((unsigned long)to | (unsigned long)from | from_va | to_va | len) &
	    3UL)
		return TOSYA_INLINE_EINSN;
	if (from_va > ~0UL - len || to_va > ~0UL - TOSYA_INLINE_MAX_COPY)
		return TOSYA_INLINE_ERANGE;
	words = (unsigned int)(len / TOSYA_INLINE_INSN);
	rc = tosya_plan(src, words, from_va, to_va, &lay);
	if (rc)
		return rc;
	if (lay.size > to_size)
		return TOSYA_INLINE_ESIZE;

	/* Validate every branch before writing anything to the destination. In
	 * particular external calls stay direct: BLR would impose a new BTI
	 * requirement on a direct-only target and clobber x16/x17. */
	for (i = 0; i < words; i++) {
		const unsigned int bits = tosya_branch_bits(src[i]);
		unsigned int encoded;
		unsigned long target;

		if (!bits)
			continue;
		target = tosya_branch_target(src[i], bits, from_va + i * 4UL);
		if (target >= from_va && target - from_va < len)
			target = to_va + lay.out[(target - from_va) / 4];
		if (tosya_branch_encode(&encoded, src[i], bits,
					to_va + lay.out[i], target))
			return TOSYA_INLINE_ERANGE;
	}

	for (i = 0; i < words; i++) {
		const unsigned int insn = src[i];
		const unsigned int bits = tosya_branch_bits(insn);
		const unsigned long va = to_va + lay.out[i];
		unsigned int *at = &dst[lay.out[i] / 4];

		if (bits) {
			unsigned long target = tosya_branch_target(
				insn, bits, from_va + i * 4UL);

			if (target >= from_va && target - from_va < len)
				target =
					to_va + lay.out[(target - from_va) / 4];
			tosya_branch_encode(at, insn, bits, va, target);
		} else if ((insn & 0x9f000000u) == TOSYA_ADRP) {
			const unsigned long page =
				tosya_adrp_value(insn, from_va + i * 4UL);

			if (tosya_adrp_encode(at, insn & 31u, page, va))
				tosya_mov_imm(at, insn & 31u, page);
		} else {
			*at = insn;
		}
	}
	if (out_len)
		*out_len = lay.size;
	return TOSYA_INLINE_OK;
}
