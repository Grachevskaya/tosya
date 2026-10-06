// SPDX-License-Identifier: GPL-2.0
/*
 * hooks.c - the two questions, and the order the mechanisms are tried in.
 *
 * How a uid with no processes is reported, and where an identity change is seen:
 * each has a family of mechanisms that can answer it, each mechanism registers
 * itself with the order it wants (tiers.c reads the registry), and this file is
 * what starts the walk, names the winner in the log, and takes everything back
 * at unload. The mechanisms live in the files named after them:
 *
 *   inline_hooks.c   short entry hooks for find_user / cap_task_fix_setuid
 *   table_hooks.c    the uid queries / the id setters in sys_call_table
 *   lsm.c            the LSM hook the kernel hands both creds to
 */
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
#include "tier.h"

static char *tosya_uid_tier = "";
static char *tosya_setuid_tier = "";
module_param_named(uid_tier, tosya_uid_tier, charp, 0644);
MODULE_PARM_DESC(uid_tier,
		 "force a mechanism for the uid queries: inline, tables");
module_param_named(setuid_tier, tosya_setuid_tier, charp, 0644);
MODULE_PARM_DESC(
	setuid_tier,
	"force a mechanism for the identity change: inline, lsm, setters");

int hooks_install(void)
{
	int uid, setuid;

	if (tosya_patch_init())
		return 0;

	/*
	 * The uid queries come first: they are the question every one of those
	 * syscalls asks on its USER lookup path. One find_user entry hook serves
	 * the native and compat callers.
	 */
	uid = tosya_tier_install(TOSYA_TIER_UID, tosya_uid_tier);
	tosya_status_set_uid_tier(tosya_tier_name(TOSYA_TIER_UID));
	if (uid)
		pr_err("tosya: no mechanism on this kernel can answer the uid queries\n");
	else
		pr_info("tosya: uid queries are answered by %s\n",
			tosya_tier_name(TOSYA_TIER_UID));

	/*
	 * Then the identity changes. A kernel where nothing can watch them gets a
	 * module that hides callers but never learns about new ones, and says so
	 * loudly.
	 */
	setuid = tosya_tier_install(TOSYA_TIER_SETUID, tosya_setuid_tier);
	tosya_status_set_setuid_tier(tosya_tier_name(TOSYA_TIER_SETUID));
	if (setuid) {
		pr_err("tosya: identity changes are NOT watched on this kernel\n");
		tosya_status_note(-ENODEV);
	} else {
		pr_info("tosya: id changes are watched by %s\n",
			tosya_tier_name(TOSYA_TIER_SETUID));
	}

	/* No installed family can use these tags if both attempts failed. Leave
	 * existing tasks untouched so a diagnostics-only load can be unloaded
	 * without leaving identity bits behind in thread_info.flags. */
	if (uid && setuid)
		return 0;

	tosya_tag_prime(); // give the processes that already run their tag
	return 1;
}

void hooks_remove(void)
{
	/*
	 * Published inline hooks pin the module and never reach normal unload.
	 * Otherwise revert the uid family, release APK records, then revert the
	 * setuid family (the LSM slot or syscall setters).
	 */
	tosya_tier_revert(TOSYA_TIER_UID);
	tosya_apk_remove();
	tosya_tier_revert(TOSYA_TIER_SETUID);
}
