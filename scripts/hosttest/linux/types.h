#ifndef _FAKE_TYPES_H
#define _FAKE_TYPES_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h> /* the host dev_t and friends, only for these host tests */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
/*
 * The kernel's own spellings. The system's headers use them too, and a typedef that says the same
 * thing twice is not a conflict -- which is what lets a host build pull in both.
 */
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t __s8;
typedef int16_t __s16;
typedef int32_t __s32;
typedef int64_t __s64;
typedef uint32_t uid_t;
typedef u32 kuid_t;
// the kernel's pointer annotations; nothing to say in a host build
#ifndef __rcu
#define __rcu
#endif
#define ____cacheline_aligned
#ifndef ENOMEM
#define ENOMEM 12
#endif
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef ENOSPC
#define ENOSPC 28
#endif
#endif
