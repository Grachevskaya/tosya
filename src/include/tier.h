/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#if defined(__KERNEL__) || defined(TOSYA_HOST_TEST)

struct tosya_tier {
	const char *family;
	const char *key; // what a module parameter names it by
	const char *name; // what the status line shows when this one wins
	int order; // lower is tried first
	int (*install)(void);
	void (*remove)(void);
};

#define TOSYA_TIER_UID "uid queries"
#define TOSYA_TIER_SETUID "setuid"

#define TOSYA_TIER(_sym, _family, _key, _name, _order, _install, _remove) \
	const struct tosya_tier _sym = {                                  \
		.family = (_family),                                      \
		.key = (_key),                                            \
		.name = (_name),                                          \
		.order = (_order),                                        \
		.install = (_install),                                    \
		.remove = (_remove),                                      \
	}

int tosya_tier_install(const char *family, const char *force);

void tosya_tier_revert(const char *family);
void tosya_tier_revert_all(void);

const char *tosya_tier_name(const char *family);

#endif
