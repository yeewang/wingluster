/*
  Copyright (c) 2008-2012 Red Hat, Inc. <http://www.redhat.com>
  This file is part of GlusterFS.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

#ifndef _EVENT_H_
#define _EVENT_H_

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <pthread.h>

#ifdef GF_CYGWIN_HOST_OS
#include <uv.h>
#endif

struct event_pool;
struct event_ops;
struct event_slot_poll;
struct event_slot_epoll;
struct event_data {
	int idx;
	int gen;
} __attribute__ ((__packed__, __may_alias__));


#ifndef GF_CYGWIN_HOST_OS
typedef int (*event_handler_t) (int fd, int idx, void *data,
				int poll_in, int poll_out, int poll_err);
#else
typedef int (*event_init_handler_t) (uv_loop_t *loop, void *data);
typedef int (*event_handler_t) (void *data, int status,
				int poll_in, int poll_out, int poll_err);
#endif

#define EVENT_EPOLL_TABLES 1024
#define EVENT_EPOLL_SLOTS 1024
#define EVENT_MAX_THREADS  32

struct event_pool {
	struct event_ops *ops;

#ifndef GF_CYGWIN_HOST_OS
	int fd;
	int breaker[2];
#else
        uv_loop_t loop;
        uv_pipe_t breaker;
#endif

	int count;
#ifndef GF_CYGWIN_HOST_OS
	struct event_slot_poll  *reg;
	struct event_slot_epoll *ereg[EVENT_EPOLL_TABLES];
#else
        struct event_slot_poll_win32 *reg;
#endif
	int slots_used[EVENT_EPOLL_TABLES];

	int used;
	int changed;

#ifndef GF_CYGWIN_HOST_OS
        pthread_mutex_t mutex;
	pthread_cond_t cond;
#else
	uv_mutex_t mutex;
	uv_cond_t cond;
#endif

	void *evcache;
	int evcache_size;

        /* NOTE: Currently used only when event processing is done using
         * epoll. */
        int eventthreadcount; /* number of event threads to execute. */
#ifndef GF_CYGWIN_HOST_OS
        pthread_t pollers[EVENT_MAX_THREADS]; /* poller thread_id store,
                                                     * and live status */
#else
        uv_thread_t pollers[EVENT_MAX_THREADS];
#endif

        int destroy;
        int activethreadcount;
};

#ifndef GF_CYGWIN_HOST_OS
struct event_ops {
        struct event_pool * (*new) (int count, int eventthreadcount);

        int (*event_register) (struct event_pool *event_pool, int fd,
                               event_handler_t handler,
                               void *data, int poll_in, int poll_out);

        int (*event_select_on) (struct event_pool *event_pool, int fd, int idx,
                                int poll_in, int poll_out);

        int (*event_unregister) (struct event_pool *event_pool, int fd, int idx);

        int (*event_unregister_close) (struct event_pool *event_pool, int fd,
				       int idx);

        int (*event_dispatch) (struct event_pool *event_pool);

        int (*event_reconfigure_threads) (struct event_pool *event_pool,
                                          int newcount);
        int (*event_pool_destroy) (struct event_pool *event_pool);
};

struct event_pool *event_pool_new (int count, int eventthreadcount);
int event_select_on (struct event_pool *event_pool, int fd, int idx,
		     int poll_in, int poll_out);
int event_register (struct event_pool *event_pool, int fd,
		    event_handler_t handler,
		    void *data, int poll_in, int poll_out);
int event_unregister (struct event_pool *event_pool, int fd, int idx);
int event_unregister_close (struct event_pool *event_pool, int fd, int idx);
int event_dispatch (struct event_pool *event_pool);
int event_reconfigure_threads (struct event_pool *event_pool, int value);
int event_pool_destroy (struct event_pool *event_pool);
int event_dispatch_destroy (struct event_pool *event_pool);

#else
struct event_ops {
        struct event_pool * (*new) (int count, int eventthreadcount);

        int (*event_register) (struct event_pool *event_pool, uv_handle_t *fd,
                               event_handler_t init,
                               event_init_handler_t handler,
                               void *data, int poll_in, int poll_out);

        int (*event_select_on) (struct event_pool *event_pool, uv_handle_t *fd, int idx,
                                int poll_in, int poll_out);

        int (*event_unregister) (struct event_pool *event_pool, uv_handle_t *fd, int idx);

        int (*event_unregister_close) (struct event_pool *event_pool, uv_handle_t *fd,
				       int idx);

        int (*event_dispatch) (struct event_pool *event_pool);

        int (*event_reconfigure_threads) (struct event_pool *event_pool,
                                          int newcount);
        int (*event_pool_destroy) (struct event_pool *event_pool);
};

struct event_pool *event_pool_new (int count, int eventthreadcount);
int event_select_on (struct event_pool *event_pool, int idx,
		     int poll_in, int poll_out);
int event_register (struct event_pool *event_pool,
                    event_init_handler_t init,
		    event_handler_t handler,
		    void *data, int poll_in, int poll_out);
int event_unregister (struct event_pool *event_pool, int idx);
int event_unregister_close (struct event_pool *event_pool, int idx);
int event_dispatch (struct event_pool *event_pool);
int event_reconfigure_threads (struct event_pool *event_pool, int value);
int event_pool_destroy (struct event_pool *event_pool);
int event_dispatch_destroy (struct event_pool *event_pool);

#endif

#endif /* _EVENT_H_ */

