
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "common-utils.h"
#include "event.h"
#include "libglusterfs-messages.h"
#include "logging.h"
#include "mem-pool.h"

#include <uv.h>

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#ifndef CONTAINER_OF
#define CONTAINER_OF(ptr, type, field)                                         \
        ((type*)((char*)(ptr) - ((char*)&((type*)0)->field)))
#endif

typedef enum broker_type {
        BT_INIT = 1,
        BT_CLOSE = 2,
} broker_type_t;

struct event_node
{
        struct list_head list;
        void* trans;
        broker_type_t type;
};

struct loop_node
{
        struct list_head list;
        uv_mutex_t mutex;
	int inited;
        pthread_t tid;
        uv_loop_t loop;
        uv_async_t broker;
        void* trans;
        event_handler_t handler;
        struct list_head event_list;
};

static int event_register_poll (struct event_pool* event_pool, void* translator,
                                event_handler_t handler);

static int event_unregister_poll (struct event_pool* event_pool, void* handle);

static int event_unregister_close_poll (struct event_pool* event_pool,
                                        void* handle);

static void* event_dispatch_worker (void* data);

static void __event_async_cb (uv_async_t* handle);

static void __event_handler (struct loop_node* loop_node,
                             struct event_node* event_node);

static void __close_loop_cb (uv_handle_t* handle);

static struct loop_node*
__event_get_loop_node (struct event_pool* event_pool, void* trans)
{
        struct loop_node* loop_node = NULL;
        struct loop_node* retval = NULL;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);

        list_for_each_entry (loop_node, &event_pool->loop_list, list)
        {
                if (loop_node->trans == trans) {
                        retval = loop_node;
                        break;
                }
        }
out:
        return retval;
}

static int
__event_invoke (struct event_pool* event_pool, int type, void* trans)
{
        struct loop_node* loop_node = NULL;
        struct event_node* new_event = NULL;
        uv_async_t* handle = NULL;
        int ret = 0;

        loop_node = __event_get_loop_node (event_pool, trans);
        if (loop_node == NULL) {
		ret = -1;
                goto fail;
	}

        new_event =
          GF_CALLOC (1, sizeof (struct event_node), gf_common_mt_data_t);
        if (new_event == NULL) {
                ret = -1;
                goto fail;
        }

        INIT_LIST_HEAD (&new_event->list);
        new_event->type = type;
        new_event->trans = trans;

        uv_mutex_lock (&loop_node->mutex);
        list_add_tail (&new_event->list, &loop_node->event_list);
        uv_mutex_unlock (&loop_node->mutex);

	while (!loop_node->inited) {
		gf_msg ("poll", GF_LOG_DEBUG, 0, LG_MSG_POLL_IGNORE_MULTIPLE_THREADS,
                "Wait for loop get ready: this=%p", trans);
		sleep (1);
	}

        ret = uv_async_send (&loop_node->broker);

fail:
        if (ret == -1)
                if (new_event)
                        GF_FREE (new_event);

        return ret;
}

static struct event_pool*
event_pool_new_poll (int count, int eventthreadcount)
{
        struct event_pool* event_pool = NULL;
        int ret = -1;

        /* load libuv */
        void cyguv_init (int force);
        cyguv_init (1);

        event_pool =
          GF_CALLOC (1, sizeof (*event_pool), gf_common_mt_event_pool);

        if (!event_pool)
                return NULL;

	uv_mutex_init (&event_pool->mutex);

        INIT_LIST_HEAD (&event_pool->loop_list);

        event_pool->destroy = 0;

        if (eventthreadcount > 1) {
                gf_msg ("poll", GF_LOG_INFO, 0,
                        LG_MSG_POLL_IGNORE_MULTIPLE_THREADS,
                        "Currently poll "
                        "does not use multiple event processing threads, "
                        "thread count (%d) ignored",
                        eventthreadcount);
        }

        return event_pool;
}

static int
event_register_poll (struct event_pool* event_pool, void* trans,
                     event_handler_t handler)
{
        struct loop_node* new_loop = NULL;
        struct event_node* new_event = NULL;
        int ret = -1;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);
        GF_VALIDATE_OR_GOTO ("event", trans, out);

        gf_msg ("poll", GF_LOG_DEBUG, 0, LG_MSG_POLL_IGNORE_MULTIPLE_THREADS,
                "Registering a new trans (trans=%p) to the pool", trans);

        uv_mutex_lock (&event_pool->mutex);
        {
                if (__event_get_loop_node (event_pool, trans)) {
                        ret = __event_invoke (event_pool, BT_INIT, trans);

                } else {
                        new_loop = GF_CALLOC (1, sizeof (struct loop_node),
                                              gf_common_mt_reg);
                        if (!new_loop) {
                                ret = -1;
                                goto unlock;
                        }

                        INIT_LIST_HEAD (&new_loop->list);
			uv_mutex_init (&new_loop->mutex);
			new_loop->inited = 0;
                        new_loop->trans = trans;
                        new_loop->handler = handler;
			INIT_LIST_HEAD (&new_loop->event_list);

                        ret = pthread_create (&new_loop->tid, NULL,
                                              event_dispatch_worker, new_loop);
                        if (ret) {
                                ret = -1;
                                gf_msg ("epoll", GF_LOG_WARNING, 0,
                                        LG_MSG_START_EPOLL_THREAD_FAILED,
                                        "Failed to start dispatch thread");
                                goto unlock;
                        }

                        list_add_tail (&new_loop->list, &event_pool->loop_list);

                        ret = __event_invoke (event_pool, BT_INIT, trans);

                        event_pool->changed = 1;
                }
        }
unlock:
        uv_mutex_unlock (&event_pool->mutex);

out:
        if (ret == -1) {
                GF_FREE (new_loop);
        }

        return ret;
}

static int
event_unregister_poll (struct event_pool* event_pool, void* trans)
{
        int ret = 0;
        struct loop_node* loop_node = NULL;
        struct event_node* event_node = NULL;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);

        uv_mutex_lock (&event_pool->mutex);
        {
                list_for_each_entry (loop_node, &event_pool->loop_list, list)
                {
                        if (loop_node->trans == trans) {
				loop_node->handler = NULL;
                                event_pool->changed = 1;
                                break;
                        }
                }
        }
unlock:
        uv_mutex_unlock (&event_pool->mutex);

out:
        return ret;
}

static int
event_unregister_close_poll (struct event_pool* event_pool, void* trans)
{
        int ret = -1;

        ret = event_unregister_poll (event_pool, trans);

        return ret;
}

static int
event_select_on_poll (struct event_pool* event_pool, void* trans, int poll_in,
                      int poll_out)
{
        int ret = -1;
        struct loop_node* loop_node = NULL;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);

        uv_mutex_lock (&event_pool->mutex);
        {
                loop_node = __event_get_loop_node (event_pool, trans);
                if (loop_node == NULL) {
                        gf_msg ("poll", GF_LOG_ERROR, 0, LG_MSG_INDEX_NOT_FOUND,
                                "trans not found for trans=%p", trans);
                        errno = ENOENT;
                        goto unlock;
                }

                ret = 0;

                __event_invoke (event_pool, -1, trans);
        }
unlock:
        uv_mutex_unlock (&event_pool->mutex);

out:
        return ret;
}

static void
__event_handler (struct loop_node* loop_node, struct event_node* event_node)
{
        switch (event_node->type) {
                case BT_CLOSE:
                        uv_close (&loop_node->broker, __close_loop_cb);
                        break;

                case BT_INIT:
                        if (loop_node->handler)
                                loop_node->handler (&loop_node->loop,
                                                    loop_node->trans,
                                                    event_node->type);
                        else {
                                gf_msg ("epoll", GF_LOG_DEBUG, 0,
                                        LG_MSG_START_EPOLL_THREAD_FAILED,
                                        "The handler is NULL: %p",
                                        event_node->trans);
                        }

			/* append a next notify to the loop */
			uv_async_send (&loop_node->broker);
        }
}

static void
__event_async_cb (uv_async_t* handle)
{
        int ret = 0;
        struct loop_node* loop_node = NULL;
        struct event_node* event_node = NULL;

        loop_node = CONTAINER_OF (handle, struct loop_node, broker);

        uv_mutex_lock (&loop_node->mutex);
        {
                if (!list_empty (&loop_node->event_list)) {
                        event_node = list_first_entry (
                          &loop_node->event_list, struct event_node, list);
			list_del_init (&event_node->list);
		}
	}
	uv_mutex_unlock (&loop_node->mutex);

	if (event_node) {
                __event_handler (loop_node, event_node);
	}
}

static void*
event_dispatch_worker (void* data)
{
        struct loop_node* loop_node = NULL;
        int ret = -1;

        loop_node = data;

        GF_VALIDATE_OR_GOTO ("event", loop_node, out);

        ret = uv_loop_init (&loop_node->loop);
        if (ret != 0) {
                gf_msg ("epoll", GF_LOG_INFO, 0, LG_MSG_EXITED_EPOLL_THREAD,
                        "Exited loop with ret %d", ret);
                goto out;
        }

        ret = uv_async_init (&loop_node->loop, &loop_node->broker,
                             __event_async_cb);
        if (ret != 0) {
                gf_msg ("epoll", GF_LOG_INFO, 0, LG_MSG_EXITED_EPOLL_THREAD,
                        "Init broker failed with ret %d", ret);
                goto out;
        }

	loop_node->inited = 1;

        uv_run (&loop_node->loop, UV_RUN_DEFAULT);

out:
        return NULL;
}

static int
event_dispatch_poll (struct event_pool* event_pool)
{
        struct loop_node* loop_node = NULL;
        int ret = -1;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);

        event_pool->poller = pthread_self ();

        while (!event_pool->destroy) {
                loop_node = NULL;

                uv_mutex_lock (&event_pool->mutex);
                {
                        if (!list_empty (&event_pool->loop_list)) {
                                loop_node =
                                  list_first_entry (&event_pool->loop_list,
                                                    struct loop_node, list);
                        }
                }
                uv_mutex_unlock (&event_pool->mutex);

                if (loop_node)
                        pthread_join (loop_node->tid, NULL);

                sleep (1);
        }

out:
        return -1;
}

int
event_reconfigure_threads_poll (struct event_pool* event_pool, int value)
{
        /* No-op for poll */
        return 0;
}

static void
__close_loop_cb (uv_handle_t* handle)
{
        struct loop_node* loop_node = NULL;
	struct event_node* event_node = NULL;

        loop_node = CONTAINER_OF (handle, struct loop_node, broker);

        while (!list_empty (&loop_node->event_list)) {
                event_node = list_first_entry (
                  &loop_node->event_list, struct event_node, list);

		list_del_init (&event_node->list);
		GF_FREE (event_node);
        }

        uv_loop_close (&loop_node->loop);
        GF_FREE (loop_node);
}

/* This function is the destructor for the event_pool data structure
 * Should be called only after poller_threads_destroy() is called,
 * else will lead to crashes.
 */
static int
event_pool_destroy_poll (struct event_pool* event_pool)
{
        struct loop_node* loop_node = NULL, *n;
        struct event_node* event_node = NULL;
        int ret = 0;

        uv_mutex_lock (&event_pool->mutex);
        {
                list_for_each_entry_safe (loop_node, n, &event_pool->loop_list,
			                  list)
                {
                	list_del_init (&loop_node->list);

                        event_node = GF_CALLOC (1, sizeof (struct event_node),
                                                gf_common_mt_reg);
                        if (event_node == NULL) {
                                ret = -1;
                                break;
                        }

                        INIT_LIST_HEAD (&event_node->list);
                        event_node->trans = loop_node->trans;
                        event_node->type = BT_CLOSE;

                        uv_mutex_lock (&loop_node->mutex);
                        list_add_tail (&event_node->list,
                                       &loop_node->event_list);
                        uv_mutex_unlock (&loop_node->mutex);

			if (loop_node->inited)
	                        uv_async_send (&loop_node->broker);

                        event_pool->changed = 1;
                }
        }
        uv_mutex_unlock (&event_pool->mutex);

        GF_FREE (event_pool);

        return ret;
}

struct event_ops event_ops_poll = {
        .new = event_pool_new_poll,
        .event_register = event_register_poll,
        .event_select_on = event_select_on_poll,
        .event_unregister = event_unregister_poll,
        .event_unregister_close = event_unregister_close_poll,
        .event_dispatch = event_dispatch_poll,
        .event_reconfigure_threads = event_reconfigure_threads_poll,
        .event_pool_destroy = event_pool_destroy_poll
};
