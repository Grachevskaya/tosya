/* SPDX-License-Identifier: GPL-2.0 */
#ifndef TOSYA_INLINE_ALLOC_H
#define TOSYA_INLINE_ALLOC_H

#include <linux/types.h>

/* Initialization-only ownership. Once published, the containing hook and its
 * module are pinned, and this page must survive until reboot as well. */
struct tosya_inline_region {
	void *addr;
	size_t size;
	bool sealed;
	bool published;
};

int tosya_inline_alloc(struct tosya_inline_region *region,
		       unsigned long target);
int tosya_inline_seal(struct tosya_inline_region *region);
void tosya_inline_free(struct tosya_inline_region *region);

#endif
