#ifndef TOSYA_HOSTTEST_LINUX_RCUPDATE_H
#define TOSYA_HOSTTEST_LINUX_RCUPDATE_H

/*
 * RCU, for a host that has no kernel and one thread: a reader is never in a table for longer than
 * the call that takes it, so a grace period is the return of this call and a table handed to RCU is
 * freed at once. Every name is guarded, because a test that drives the block itself may have said
 * the same thing already.
 */
struct rcu_head {
	struct rcu_head *next;
	void (*func)(struct rcu_head *head);
};

#ifndef rcu_read_lock
#define rcu_read_lock() ((void)0)
#endif

#ifndef rcu_read_unlock
#define rcu_read_unlock() ((void)0)
#endif

#ifndef rcu_dereference
#define rcu_dereference(p) (p)
#endif

#ifndef rcu_dereference_protected
#define rcu_dereference_protected(p, c) ((void)(c), (p))
#endif

#ifndef rcu_assign_pointer
#define rcu_assign_pointer(p, v) ((p) = (v))
#endif

#ifndef kvfree_rcu
#define kvfree_rcu(ptr, member) \
	do {                    \
		kvfree(ptr);    \
	} while (0)
#endif

#ifndef synchronize_rcu
static inline void synchronize_rcu(void)
{
}
#endif

#endif
