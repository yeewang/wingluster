
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

enum broker_type
{
        INIT = 1,
        REINIT = 2,
};

struct broker_data
{
        int type;
        void* handle;
};

struct reg_data
{
        uv_loop_t* loop;
        void* translator;
        uv_handle_t* handle;
        int events;
        event_handler_t handler;
};

static int event_register_poll (struct event_pool* event_pool, void* translator,
                                void* handle, event_handler_t handler);

static int event_unregister_poll (struct event_pool* event_pool, void* handle);

static int event_unregister_close_poll (struct event_pool* event_pool,
                                        void* handle);

static void* event_dispatch_win32_worker (void* data);

static void __event_async_cb (uv_async_t* handle);

static void __event_handler (struct event_pool* event_pool,
                             struct event_node* event_node);

static void __event_handler_all (struct event_pool* event_pool);


static struct reg_data*
__event_getindex (struct event_pool* event_pool, void* handle)
{
        struct reg_node* reg_node = NULL;
        struct reg_data* retval = NULL;
        struct reg_data* item = NULL;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);

        list_for_each_entry (reg_node, &event_pool->regs.list, list)
        {
                item = (struct reg_data*)&reg_node->reg;
                if (item->handle == handle) {
                        retval = item;
                        break;
                }
        }
out:
        return retval;
}

static int
__event_invoke (struct event_pool* event_pool, int type, void* handle)
{
        struct event_node* new_event = NULL;
        struct broker_data* bd = NULL;
        int ret = -1;

	new_event = GF_CALLOC (1, sizeof (struct broker_data) +
				    sizeof (struct event_node),
			       gf_common_mt_data_t);
	if (new_event == NULL) {
		ret = -1;
		goto fail;
	}
	bd = (struct broker_data*)new_event->event;
	bd->type = type;
	bd->handle = handle;

	list_add_tail (&new_event->list, &event_pool->events.list);

	if (event_pool->poller == pthread_self()) {
		__event_handler_all (event_pool);
		ret = 0;
	}
	else {
	        ret = uv_async_send (&event_pool->broker);
	}

fail:
        return ret;
}

static struct event_pool*
event_pool_new_poll (int count, int eventthreadcount)
{
        struct event_pool* event_pool = NULL;
        pthread_t t_id;
        int ret = -1;

        /* load libuv */
        void cyguv_init (int force);
        cyguv_init (1);

        event_pool =
          GF_CALLOC (1, sizeof (*event_pool), gf_common_mt_event_pool);

        if (!event_pool)
                return NULL;

        INIT_LIST_HEAD (&event_pool->regs);

        INIT_LIST_HEAD (&event_pool->events);

        pthread_mutex_init (&event_pool->mutex, NULL);
        pthread_cond_init (&event_pool->cond, NULL);

        ret =
          pthread_create (&t_id, NULL, event_dispatch_win32_worker, event_pool);
        if (ret) {
                gf_msg ("epoll", GF_LOG_WARNING, 0,
                        LG_MSG_START_EPOLL_THREAD_FAILED,
                        "Failed to start poll thread");
                GF_FREE (event_pool);
                return NULL;
        } else {
                event_pool->poller = t_id;
        }

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
event_register_poll (struct event_pool* event_pool, void* translator,
                     void* handle, event_handler_t handler)
{
        uv_loop_t* loop = NULL;
        struct reg_node* new_reg = NULL;
        struct reg_data* reg_data = NULL;
        struct event_node* new_event = NULL;
        struct broker_data* bd = NULL;
        int need_clean = 0;
        int ret = -1;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);
        GF_VALIDATE_OR_GOTO ("event", translator, out);
        GF_VALIDATE_OR_GOTO ("event", handle, out);

        gf_msg ("poll", GF_LOG_DEBUG, 0, LG_MSG_POLL_IGNORE_MULTIPLE_THREADS,
                "Registering a new handle %p to the pool", handle);

        pthread_mutex_lock (&event_pool->mutex);
        {
                if (__event_getindex (event_pool, handle))
                        need_clean = 1;

                if (need_clean) {
                        ret = __event_invoke (event_pool, REINIT, handle);

                        gf_msg ("poll", GF_LOG_DEBUG, 0,
                                LG_MSG_POLL_IGNORE_MULTIPLE_THREADS,
                                "Register handle %p to the pool is more times!",
                                handle);
                } else {
                        loop = &event_pool->loop;

                        new_reg = GF_CALLOC (1, sizeof (event_pool->regs) +
                                                  sizeof (struct reg_data),
                                             gf_common_mt_reg);

                        if (!new_reg) {
                                ret = -1;
                                goto unlock;
                        }

                        reg_data = (struct reg_data*)new_reg->reg;
                        reg_data->loop = loop;
                        reg_data->translator = translator;
                        reg_data->handle = handle;
                        reg_data->events = UV_DISCONNECT;
                        reg_data->handler = handler;
                        list_add_tail (&new_reg->list, &event_pool->regs.list);

                        ret = __event_invoke (event_pool, INIT, handle);
                        if (ret != 0)
                                GF_FREE (new_reg);

                        event_pool->changed = 1;
                }
        }
unlock:
        pthread_mutex_unlock (&event_pool->mutex);

out:
        return ret;
}

static int
event_unregister_poll (struct event_pool* event_pool, void* handle)
{
        int ret = 0;
        struct reg_node* reg_node = NULL;
        struct reg_node* n = NULL;
        struct reg_data* reg_data = NULL;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);

        pthread_mutex_lock (&event_pool->mutex);
        {
                list_for_each_entry_safe (reg_node, n, &event_pool->regs.list,
                                          list)
                {
                        reg_data = (struct reg_data*)&reg_node->reg;
                        if (reg_data->handle == handle) {
                                list_del (&reg_node->list);
                                GF_FREE (reg_node);

                                event_pool->changed = 1;
                                break;
                        }
                }
        }
unlock:
        pthread_mutex_unlock (&event_pool->mutex);

out:
        return ret;
}

static void
__close_handle (uv_handle_t* handle)
{
        struct event_pool* event_pool = NULL;

        event_pool = CONTAINER_OF (handle->loop, struct event_pool, loop);
}

static int
event_unregister_close_poll (struct event_pool* event_pool, void* handle)
{
        int ret = -1;

        uv_close (handle, __close_handle);

        ret = event_unregister_poll (event_pool, handle);

        return ret;
}

static int
event_select_on_poll (struct event_pool* event_pool, void* handle, int poll_in,
                      int poll_out)
{
        int ret = -1;
        struct reg_data* slot = NULL;
        struct event_node* new_event = NULL;
        struct broker_data* bd = NULL;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);

        pthread_mutex_lock (&event_pool->mutex);
        {
                slot = __event_getindex (event_pool, handle);

                if (slot == NULL) {
                        gf_msg ("poll", GF_LOG_ERROR, 0, LG_MSG_INDEX_NOT_FOUND,
                                "index not found for handle=%p", handle);
                        errno = ENOENT;
                        goto unlock;
                }

                ret = 0;

                new_event = GF_CALLOC (1, sizeof (struct broker_data) +
                                            sizeof (struct event_node),
                                       gf_common_mt_data_t);

                if (new_event == NULL) {
                        errno = ENOMEM;
                        ret = -1;
                        goto unlock;
                }

                bd = (struct broker_data*)new_event->event;
                bd->type = 0;
                bd->handle = handle;

                if (poll_in + poll_out > -2) {
                        //__event_handler(event_pool, new_event);
                        uv_async_send (&event_pool->broker);
                        event_pool->changed = 1;
                }

                // GF_FREE (new_event);
        }
unlock:
        pthread_mutex_unlock (&event_pool->mutex);

out:
        return ret;
}

static struct reg_data*
__event_registered (struct event_pool* event_pool, uv_handle_t* handle)
{
        struct reg_node* reg_node = NULL;
        struct reg_data* reg_data = NULL;

        list_for_each_entry (reg_node, &event_pool->regs.list, list)
        {
                reg_data = (struct reg_data*)reg_node->reg;
                if (reg_data->handle == handle) {
                        return reg_data;
                        break;
                }
        }

        return NULL;
}

static void
__event_handler (struct event_pool* event_pool, struct event_node* event_node)
{
        struct broker_data* ed = NULL;
        struct reg_data* reg_data = NULL;
	int ret = -1;

        ed = (struct broker_data*)&event_node->event;
        reg_data = __event_registered (event_pool, ed->handle);
        if (reg_data == NULL)
                gf_msg ("epoll", GF_LOG_DEBUG, 0,
                        LG_MSG_START_EPOLL_THREAD_FAILED,
                        "Not found the handle in reg table: %p", ed->handle);

        if (reg_data->handler)
                ret = reg_data->handler (reg_data->loop, reg_data->translator,
                                         ed->type);
        else {
                gf_msg ("epoll", GF_LOG_DEBUG, 0,
                        LG_MSG_START_EPOLL_THREAD_FAILED,
                        "The handler is NULL: %p", ed->handle);
        }
}

static void
__event_handler_all (struct event_pool* event_pool)
{
        struct event_node *event_node = NULL, *n;

        list_for_each_entry_safe (event_node, n, &event_pool->events.list, list)
        {
		__event_handler (event_pool, event_node);

                list_del_init (&event_node->list);
                GF_FREE (event_node);
        }
}


static void
__event_async_cb (uv_async_t* handle)
{
        int ret = 0;
        struct event_pool* event_pool = NULL;

        event_pool = CONTAINER_OF (handle, struct event_pool, broker);

	pthread_mutex_lock (&event_pool->mutex);
	{
		__event_handler_all (event_pool);
	}
	pthread_mutex_unlock (&event_pool->mutex);
}

static void*
event_dispatch_win32_worker (void* data)
{
        struct event_pool* event_pool = NULL;
        int ret = -1;

        event_pool = data;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);

        for (;;) {
                ret = uv_loop_init (&event_pool->loop);
                if (ret != 0) {
                        gf_msg ("epoll", GF_LOG_INFO, 0,
                                LG_MSG_EXITED_EPOLL_THREAD, "Exited "
                                                            "loop with ret %d",
                                ret);
                        goto out;
                }

                ret = uv_async_init (&event_pool->loop, &event_pool->broker,
                                     __event_async_cb);
                if (ret != 0) {
                        gf_msg ("epoll", GF_LOG_INFO, 0,
                                LG_MSG_EXITED_EPOLL_THREAD,
                                "Init "
                                "broker failed with ret %d",
                                ret);
                        goto out;
                }

                if (uv_run (&event_pool->loop, UV_RUN_DEFAULT)) {
                        break;
                }

                uv_loop_close (&event_pool->loop);
        }

out:
        return NULL;
}

static int
event_dispatch_poll (struct event_pool* event_pool)
{
        int size = 0;
        int i = 0;
        int ret = -1;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);

        pthread_join (event_pool->poller, NULL);

out:
        return -1;
}

int
event_reconfigure_threads_poll (struct event_pool* event_pool, int value)
{
        /* No-op for poll */
        return 0;
}

/* This function is the destructor for the event_pool data structure
 * Should be called only after poller_threads_destroy() is called,
 * else will lead to crashes.
 */
static int
event_pool_destroy_poll (struct event_pool* event_pool)
{
        struct reg_node* slot = &event_pool->regs;
        struct reg_node* n;
        struct reg_data* item = NULL;
        int ret = 0;

        uv_close ((uv_handle_t*)&event_pool->broker, NULL);

        ret = uv_loop_close (&event_pool->loop);

        list_for_each_entry_safe (slot, n, &event_pool->regs.list, list)
        {
                list_del_init (&slot->list);
                GF_FREE (slot);
        }

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
