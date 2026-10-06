// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/module.h>
#ifdef TOSYA_HOST_TEST
// the host test compiles this file against its own shims
#include <string.h>
#else
#include <linux/string.h>
#endif

#include "tosya.h"
#include "tier.h"

extern const struct tosya_tier tosya_tier_uid_inline;
extern const struct tosya_tier tosya_tier_uid_tables;
extern const struct tosya_tier tosya_tier_setuid_inline;
extern const struct tosya_tier tosya_tier_setuid_lsm;
extern const struct tosya_tier tosya_tier_setuid_setters;

#ifdef TOSYA_HOST_TEST
static const struct tosya_tier *const *g_test_tiers;
static unsigned int g_test_tiers_n;

void tosya_tier_set_table(const struct tosya_tier *const *tiers, unsigned int n)
{
	g_test_tiers = tiers;
	g_test_tiers_n = n;
}
#endif

#ifndef TOSYA_HOST_TEST
static const struct tosya_tier *const g_tiers[] = {
	&tosya_tier_uid_inline,	    &tosya_tier_uid_tables,
	&tosya_tier_setuid_inline,  &tosya_tier_setuid_lsm,
	&tosya_tier_setuid_setters,
};
#else
static const struct tosya_tier *const g_tiers[] = { NULL };
#endif

static const struct tosya_tier *tier_at(unsigned int i)
{
#ifdef TOSYA_HOST_TEST
	if (g_test_tiers)
		return g_test_tiers[i];
#endif
	return g_tiers[i];
}

static unsigned int tier_count(void)
{
#ifdef TOSYA_HOST_TEST
	if (g_test_tiers)
		return g_test_tiers_n;
#endif
	return (unsigned int)ARRAY_SIZE(g_tiers);
}

#define TOSYA_TIER_MAX 8
static const struct tosya_tier *g_installed[TOSYA_TIER_MAX];
static int g_installed_n;
static const struct tosya_tier *g_tried[16];
static int g_tried_n;

static bool already_tried(const struct tosya_tier *t)
{
	int i;

	for (i = 0; i < g_tried_n; i++)
		if (g_tried[i] == t)
			return true;
	return false;
}

int tosya_tier_install(const char *family, const char *force)
{
	const struct tosya_tier *t, *best;
	bool forced = force && *force && strcmp(force, "auto");
	unsigned int i;

	g_tried_n = 0;
	if (forced) {
		for (i = 0; i < tier_count(); i++) {
			int rc;

			t = tier_at(i);
			if (strcmp(t->family, family) != 0 ||
			    strcmp(t->key, force) != 0)
				continue;
			rc = t->install();
			if (rc) {
				pr_err("tosya: %s: %s was asked for and did not install (%d)\n",
				       family, t->name, rc);
				return rc;
			}
			if (g_installed_n < TOSYA_TIER_MAX)
				g_installed[g_installed_n++] = t;
			return 0;
		}
		pr_err("tosya: %s: no mechanism named '%s'\n", family, force);
		return -ENOENT;
	}

	for (;;) {
		best = NULL;
		for (i = 0; i < tier_count(); i++) {
			t = tier_at(i);
			if (strcmp(t->family, family) != 0 || already_tried(t))
				continue;
			if (!best || t->order < best->order)
				best = t;
		}
		if (!best)
			break;
		if (g_tried_n < (int)ARRAY_SIZE(g_tried))
			g_tried[g_tried_n++] = best;

		if (best->install() == 0) {
			if (g_installed_n < TOSYA_TIER_MAX)
				g_installed[g_installed_n++] = best;
			return 0;
		}
		pr_warn("tosya: %s: %s did not install, trying the next\n",
			family, best->name);
	}
	return -ENODEV;
}

static void forget(int i)
{
	memmove(&g_installed[i], &g_installed[i + 1],
		(size_t)(g_installed_n - i - 1) * sizeof(g_installed[0]));
	g_installed_n--;
}

void tosya_tier_revert(const char *family)
{
	int i;

	if (tosya_inline_active()) {
		pr_warn("tosya: inline tiers are permanent until reboot; keeping the registry\n");
		return;
	}

	for (i = g_installed_n - 1; i >= 0; i--) {
		if (strcmp(g_installed[i]->family, family) != 0)
			continue;
		g_installed[i]->remove();
		forget(i);
	}
}

void tosya_tier_revert_all(void)
{
	if (tosya_inline_active()) {
		pr_warn("tosya: inline tiers are permanent until reboot; keeping the registry\n");
		return;
	}
	while (g_installed_n > 0) {
		g_installed[g_installed_n - 1]->remove();
		g_installed_n--;
	}
}

const char *tosya_tier_name(const char *family)
{
	int i;

	for (i = g_installed_n - 1; i >= 0; i--)
		if (strcmp(g_installed[i]->family, family) == 0)
			return g_installed[i]->name;
	return NULL;
}
