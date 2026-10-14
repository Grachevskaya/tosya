#ifndef _FAKE_MM_H
#define _FAKE_MM_H
#include <linux/types.h>
#include <linux/slab.h>

/* One flat address space on the host: the split the kernel makes between the page allocator and
 * vmalloc is plain malloc here, and a "page" is just the address of the block. */
static inline void *kvmalloc(size_t sz, int f)
{
	(void)f;
	return malloc(sz);
}
static inline void *kvzalloc(size_t sz, int f)
{
	(void)f;
	return calloc(1, sz);
}
static inline void *kvmalloc_array(size_t n, size_t sz, int f)
{
	(void)f;
	return calloc(n, sz);
}
static inline void *kvcalloc(size_t n, size_t sz, int f)
{
	(void)f;
	return calloc(n, sz);
}
static inline void kvfree(const void *p)
{
	free((void *)p);
}
static inline unsigned long page_address(const void *p)
{
	return (unsigned long)p;
}
#endif
