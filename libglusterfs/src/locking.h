/*
  Copyright (c) 2008-2012 Red Hat, Inc. <http://www.redhat.com>
  This file is part of GlusterFS.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

#ifndef _LOCKING_H
#define _LOCKING_H

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <pthread.h>


#if defined(GF_CYGWIN_HOST_OS)
#include <uv.h>

#define USE_SPIN_LOCKS

#ifdef USE_SPIN_LOCKS
/* Custom pthread-style spin locks on x86 and x64 for gcc */
struct pthread_mlock_t
{
  volatile pthread_t threadid;
  volatile unsigned int c;
  volatile unsigned int l;
};
#define MLOCK_T struct pthread_mlock_t
#define CURRENT_THREAD        pthread_self()
#define SPINS_PER_YIELD       63

static inline int spinlock_init_lock (MLOCK_T *sl) {
        sl->threadid = 0;
        sl->c = 0;
        sl->l = 0;
        return 0;
}

static inline int spinlock_acquire_lock (MLOCK_T *sl) {
  if(CURRENT_THREAD==sl->threadid)
    ++sl->c;
  else {
    int spins = 0;
    for (;;) {
      int ret;
      __asm__ __volatile__ ("lock cmpxchgl %2,(%1)" : "=a" (ret) : "r" (&sl->l), "r" (1), "a" (0));
      if(!ret) {
        sl->threadid=CURRENT_THREAD;
        sl->c=1;
        break;
      }
      if ((++spins & SPINS_PER_YIELD) == 0) {
        sched_yield();
      }
    }
  }

  return 0;
}

static inline int spinlock_release_lock (MLOCK_T *sl) {
  int ret;
  if (!--sl->c) {
    sl->threadid=0;
    __asm__ __volatile__ ("xchgl %2,(%1)" : "=r" (ret) : "r" (&sl->l), "0" (0));
  }
  return 0;
}

static inline int spinlock_try_lock (MLOCK_T *sl) {
  int ret;
  __asm__ __volatile__ ("lock cmpxchgl %2,(%1)" : "=a" (ret) : "r" (&sl->l), "r" (1), "a" (0));
  if(!ret){
    sl->threadid=CURRENT_THREAD;
    sl->c=1;
    return 0;
  }
  return 1;
}

static inline int spinlock_destroy_lock (MLOCK_T *sl) {
        return 0;
}

#define LOCK_INIT(x)    spinlock_init_lock (x)
#define LOCK(x)         spinlock_acquire_lock(x)
#define UNLOCK(x)       spinlock_release_lock(x)
#define TRY_LOCK(x)     spinlock_try_lock(x)
#define LOCK_DESTROY(x) spinlock_destroy_lock (x)

typedef MLOCK_T         gf_lock_t;
#else

static inline int
__uv_mutex_lock (uv_mutex_t *x)
{
        uv_mutex_lock (x);
        return 0;
}

static inline int
__uv_mutex_unlock (uv_mutex_t *x)
{
        uv_mutex_unlock (x);
        return 0;
}

static inline int
__uv_mutex_destroy (uv_mutex_t *x)
{
        uv_mutex_destroy (x);
        return 0;
}

#define LOCK_INIT(x)    uv_mutex_init (x)
#define LOCK(x)         __uv_mutex_lock (x)
#define TRY_LOCK(x)     uv_mutex_trylock (x)
#define UNLOCK(x)       __uv_mutex_unlock (x)
#define LOCK_DESTROY(x) __uv_mutex_destroy (x)

typedef uv_mutex_t gf_lock_t;
#endif /* USE_SPIN_LOCKS */
#elif defined(HAVE_SPINLOCK)
#define LOCK_INIT(x)    pthread_spin_init (x, 0)
#define LOCK(x)         pthread_spin_lock (x)
#define TRY_LOCK(x)     pthread_spin_trylock (x)
#define UNLOCK(x)       pthread_spin_unlock (x)
#define LOCK_DESTROY(x) pthread_spin_destroy (x)

typedef pthread_spinlock_t gf_lock_t;
#else
#define LOCK_INIT(x)    pthread_mutex_init (x, 0)
#define LOCK(x)         pthread_mutex_lock (x)
#define TRY_LOCK(x)     pthread_mutex_trylock (x)
#define UNLOCK(x)       pthread_mutex_unlock (x)
#define LOCK_DESTROY(x) pthread_mutex_destroy (x)

typedef pthread_mutex_t gf_lock_t;
#endif /* HAVE_SPINLOCK */


#endif /* _LOCKING_H */
