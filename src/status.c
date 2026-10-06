// SPDX-License-Identifier: GPL-2.0
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uidgid.h>
#include <linux/user.h>
#include <linux/version.h>

#include "tosya.h"
#include "kaux.h"

static struct kaux_status g_status = {
	.magic = KAUX_STATUS_MAGIC,
	.version = KAUX_FAMILY_VERSION,
	// what this build assumes; the userspace half checks it against the running kernel
	.va_bits = CONFIG_ARM64_VA_BITS,
	.page_shift = PAGE_SHIFT,
};
void tosya_status_get(struct kaux_status *out)
{
	*out = g_status;
	/* The reader checks these before it believes anything else, so they are set
	 * here and not left to whoever filled the rest in. */
	out->magic = KAUX_STATUS_MAGIC;
	out->size = sizeof(*out);
	out->version = KAUX_FAMILY_VERSION;
}
void tosya_status_set_hooks(unsigned int native, unsigned int compat)
{
	g_status.native = native;
	g_status.compat = compat;
	if (native == g_status.native_expected)
		g_status.flags |= KAUX_F_NATIVE;
	if (compat == g_status.compat_expected)
		g_status.flags |= KAUX_F_COMPAT;
}
static void set_name(char *dst, size_t len, const char *src)
{
	if (src && *src) {
		strscpy(dst, src, len);
		return;
	}
	dst[0] = '\0';
}

void tosya_status_set_uid_tier(const char *name)
{
	set_name(g_status.uid_tier, sizeof(g_status.uid_tier), name);
}

void tosya_status_set_setuid_tier(const char *name)
{
	set_name(g_status.setuid_tier, sizeof(g_status.setuid_tier), name);
	if (name && *name)
		g_status.flags |= KAUX_F_SETUID;
}

void tosya_status_set_apks(unsigned int inodes, unsigned int expected,
			   unsigned int failed)
{
	g_status.apk_inodes = inodes;
	g_status.apk_offered = expected;
	g_status.apk_failed = failed;
	/*
	 * An inode that could not be put in place is worth keeping: the next apply
	 * that goes well would otherwise report no failures at all, and a hook that
	 * is missing on one file is not something a later success undoes.
	 */
	g_status.apk_failed_total += failed;
	g_status.apk_updates++;
	if (failed == 0)
		g_status.flags |= KAUX_F_APKS;
}
void tosya_status_note(int error)
{
	g_status.last_error = error;
}
void tosya_status_add_flags(unsigned int flags)
{
	g_status.flags |= flags;
}

void tosya_status_set_hooks_expected(unsigned int native, unsigned int compat)
{
	g_status.native_expected = native;
	g_status.compat_expected = compat;
}

void tosya_status_add_hooks(unsigned int native, unsigned int compat)
{
	g_status.native += native;
	g_status.compat += compat;
	tosya_status_set_hooks(g_status.native, g_status.compat);
}

void tosya_status_add_hooks_expected(unsigned int native, unsigned int compat)
{
	g_status.native_expected += native;
	g_status.compat_expected += compat;
}
