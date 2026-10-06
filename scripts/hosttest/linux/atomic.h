// SPDX-License-Identifier: GPL-2.0
// A host shim: policy.c takes xchg() from the kernel's atomic headers to publish
// a snapshot, and the host test compiles that file as it is.
#pragma once

#define xchg(ptr, value) __atomic_exchange_n((ptr), (value), __ATOMIC_SEQ_CST)

/* policy.c moves the identity tag with a compare-and-swap so that a TIF_* bit set
 * by the kernel in the same word is never lost; single-threaded here, but the
 * shape has to be the kernel's: it returns the value that was there. */
static inline unsigned long
tosya_host_cmpxchg(unsigned long *p, unsigned long old, unsigned long new)
{
	if (*p == old) {
		*p = new;
		return old;
	}
	return *p;
}

#define cmpxchg(ptr, old, new)                                           \
	tosya_host_cmpxchg((unsigned long *)(ptr), (unsigned long)(old), \
			   (unsigned long)(new))
