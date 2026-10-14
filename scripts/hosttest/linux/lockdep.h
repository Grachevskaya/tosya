#ifndef _FAKE_LOCKDEP_H
#define _FAKE_LOCKDEP_H
// Host-test shim: one thread, so every lock the caller holds "is held".
#define lockdep_is_held(lock) (1)
#endif
