#ifndef TOSYA_HOSTTEST_LINUX_RCUPDATE_H
#define TOSYA_HOSTTEST_LINUX_RCUPDATE_H

#include <pthread.h>

/*
 * RCU, modelled so that a race the module has is a race this test can see: a reader holds the read
 * side for as long as it is in the table, and a grace period is the write side taken and given back,
 * so anything freed with kvfree_rcu waits until no reader can still be inside what pointed at it.
 * The lock itself is the test's to define.
 */
// One lock per test binary: every one of them is a single translation unit.
static pthread_rwlock_t g_rcu_lock = PTHREAD_RWLOCK_INITIALIZER;

struct rcu_head {
	struct rcu_head *next;
	void (*func)(struct rcu_head *head);
};

#ifndef rcu_read_lock
#define rcu_read_lock() pthread_rwlock_rdlock(&g_rcu_lock)
#endif

#ifndef rcu_read_unlock
#define rcu_read_unlock() pthread_rwlock_unlock(&g_rcu_lock)
#endif

#ifndef rcu_dereference
#define rcu_dereference(p) (p)
#endif

#ifndef rcu_dereference_protected
#define rcu_dereference_protected(p, c) ((void)(c), (p))
#endif

/*
 * Publishing is a release, and the model says so: the write side is taken for the store, so a
 * reader that took the read side either sees the table before it or the one after it, never a
 * mixture, and the thread sanitizer sees the same order the barrier gives in the kernel.
 */
#ifndef rcu_assign_pointer
#define rcu_assign_pointer(p, v)                    \
	do {                                        \
		pthread_rwlock_wrlock(&g_rcu_lock); \
		(p) = (v);                          \
		pthread_rwlock_unlock(&g_rcu_lock); \
	} while (0)
#endif

#ifndef synchronize_rcu
#define synchronize_rcu()                           \
	do {                                        \
		pthread_rwlock_wrlock(&g_rcu_lock); \
		pthread_rwlock_unlock(&g_rcu_lock); \
	} while (0)
#endif

#ifndef kvfree_rcu
#define kvfree_rcu(ptr, member)    \
	do {                       \
		synchronize_rcu(); \
		kvfree(ptr);       \
	} while (0)
#endif

#endif
