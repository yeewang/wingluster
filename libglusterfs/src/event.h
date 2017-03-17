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

#include "list.h"

#include <pthread.h>

#ifdef GF_CYGWIN_HOST_OS
#include <uv.h>
#endif

struct event_pool;
struct event_ops;
struct event_slot_poll;
struct event_slot_epoll;

#ifndef GF_CYGWIN_HOST_OS
struct event_data
{
        int idx;
        int gen;
} __attribute__ ((__packed__, __may_alias__));

typedef int (*event_handler_t) (int fd, int idx, void* data, int poll_in,
                                int poll_out, int poll_err);
#else
typedef int (*event_handler_t) (uv_loop_t* loop, void* translator, int action);
#endif

#define EVENT_EPOLL_TABLES 1024
#define EVENT_EPOLL_SLOTS 1024
#define EVENT_MAX_THREADS 32

#ifndef GF_CYGWIN_HOST_OS
struct event_pool
{
        struct event_ops* ops;

        int fd;
        int breaker[2];

        int count;
        struct event_slot_poll* reg;
        struct event_slot_epoll* ereg[EVENT_EPOLL_TABLES];
        int slots_used[EVENT_EPOLL_TABLES];

        int used;
        int changed;

        pthread_mutex_t mutex;
        pthread_cond_t cond;

        void* evcache;
        int evcache_size;

        /* NOTE: Currently used only when event processing is done using
         * epoll. */
        int eventthreadcount; /* number of event threads to execute. */
        pthread_t pollers[EVENT_MAX_THREADS]; /* poller thread_id store,
                                                     * and live status */
        int destroy;
        int activethreadcount;
};

#else

struct reg_node
{
        union
        {
                struct list_head list;
                struct
                {
                        struct reg_node* next;
                        struct reg_node* prev;
                };
        };
        uint8_t reg[];
};

struct event_node
{
        union
        {
                struct list_head list;
                struct
                {
                        struct event_node* next;
                        struct event_node* prev;
                };
        };
        uint8_t event[];
};

struct event_pool
{
        struct event_ops* ops;

        uv_loop_t loop;
        uv_async_t broker;

        struct reg_node regs;

        struct event_node events;

        int changed;

        pthread_t poller;

        pthread_mutex_t mutex;
        pthread_cond_t cond;

        /* NOTE: Currently used only when event processing is done using
         * epoll. */
        int eventthreadcount; /* number of event threads to execute. */

        int destroy;
        int activethreadcount;
};
#endif

#ifndef GF_CYGWIN_HOST_OS
struct event_ops
{
        struct event_pool* (*new) (int count, int eventthreadcount);

        int (*event_register) (struct event_pool* event_pool, int fd,
                               event_handler_t handler, void* data, int poll_in,
                               int poll_out);

        int (*event_select_on) (struct event_pool* event_pool, int fd, int idx,
                                int poll_in, int poll_out);

        int (*event_unregister) (struct event_pool* event_pool, int fd,
                                 int idx);

        int (*event_unregister_close) (struct event_pool* event_pool, int fd,
                                       int idx);

        int (*event_dispatch) (struct event_pool* event_pool);

        int (*event_reconfigure_threads) (struct event_pool* event_pool,
                                          int newcount);
        int (*event_pool_destroy) (struct event_pool* event_pool);
};

struct event_pool* event_pool_new (int count, int eventthreadcount);
int event_select_on (struct event_pool* event_pool, int fd, int idx,
                     int poll_in, int poll_out);
int event_register (struct event_pool* event_pool, int fd,
                    event_handler_t handler, void* data, int poll_in,
                    int poll_out);
int event_unregister (struct event_pool* event_pool, int fd, int idx);
int event_unregister_close (struct event_pool* event_pool, int fd, int idx);
int event_dispatch (struct event_pool* event_pool);
int event_reconfigure_threads (struct event_pool* event_pool, int value);
int event_pool_destroy (struct event_pool* event_pool);
int event_dispatch_destroy (struct event_pool* event_pool);

#else
struct event_ops
{
        struct event_pool* (*new) (int count, int eventthreadcount);

        int (*event_register) (struct event_pool* event_pool, void* trans,
                               event_handler_t init);

        int (*event_select_on) (struct event_pool* event_pool, void* trans,
                                int poll_in, int poll_out);

        int (*event_unregister) (struct event_pool* event_pool, void* trans);

        int (*event_unregister_close) (struct event_pool* event_pool,
                                       void* trans);

        int (*event_dispatch) (struct event_pool* event_pool);

        int (*event_reconfigure_threads) (struct event_pool* event_pool,
                                          int newcount);

        int (*event_pool_destroy) (struct event_pool* event_pool);
};

struct event_pool* event_pool_new (int count, int eventthreadcount);
int event_select_on (struct event_pool* event_pool, void* trans, int poll_in,
                     int poll_out);
int event_register (struct event_pool* event_pool, void* trans,
                    event_handler_t handler);
int event_unregister (struct event_pool* event_pool, void* trans);
int event_unregister_close (struct event_pool* event_pool, void* trans);
int event_dispatch (struct event_pool* event_pool);
int event_reconfigure_threads (struct event_pool* event_pool, int value);
int event_pool_destroy (struct event_pool* event_pool);
int event_dispatch_destroy (struct event_pool* event_pool);

#endif

#endif /* _EVENT_H_ */
