#ifndef _FAKE_VMALLOC_H
#define _FAKE_VMALLOC_H
#include <linux/types.h>
#include <stdlib.h>

static inline void *vmalloc(size_t sz)
{
	return malloc(sz);
}
static inline void *vzalloc(size_t sz)
{
	return calloc(1, sz);
}
static inline void vfree(const void *p)
{
	free((void *)p);
}
#endif
