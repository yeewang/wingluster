
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "logging.h"
#include "event.h"
#include "mem-pool.h"
#include "common-utils.h"
#include "libglusterfs-messages.h"

#include <uv.h>

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#ifndef CONTAINER_OF
#define CONTAINER_OF(ptr, type, field)                                        \
  ((type *) ((char *) (ptr) - ((char *) &((type *) 0)->field)))
#endif

enum broker_type {
        INIT = 1,
        READ = 2,
        WRITE = 4,
};

struct broker_data {
        int type;
        void *handle;
};

struct reg_data {
        uv_loop_t *loop;
        uv_handle_t *handle;
        int events;
        void *data;
        event_init_handler_t init;
        event_handler_t handler;
};

static int
event_register_poll (struct event_pool *event_pool,
                     event_init_handler_t init,
		     event_handler_t handler,
                     void *data, int poll_in, int poll_out);

static int
event_unregister_poll (struct event_pool *event_pool,
                       void *handle);


static struct reg_data *
__event_getindex (struct event_pool *event_pool, void *handle)
{
        struct reg_node *slot = NULL;
        struct reg_data *retval = NULL;
        struct reg_data *item = NULL;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);

        list_for_each_entry(slot, &event_pool->regs.list, list) {
                item = (struct reg_data *)&slot->reg;
                if (item->handle == handle) {
                        retval = item;
                        break;
                }
        }
out:
        return retval;
}

static struct event_pool *
event_pool_new_poll (int count, int eventthreadcount)
{
        struct event_pool *event_pool = NULL;
        int                ret = -1;

        /* load libuv */
        void cyguv_init(int force);
        cyguv_init(1);

        event_pool = GF_CALLOC (1, sizeof (*event_pool),
                                gf_common_mt_event_pool);

        if (!event_pool)
                return NULL;

        INIT_LIST_HEAD(&event_pool->regs);

        INIT_LIST_HEAD(&event_pool->events);

        pthread_mutex_init (&event_pool->mutex, NULL);

        if (eventthreadcount > 1) {
                gf_msg ("poll", GF_LOG_INFO, 0,
                        LG_MSG_POLL_IGNORE_MULTIPLE_THREADS, "Currently poll "
                        "does not use multiple event processing threads, "
                        "thread count (%d) ignored", eventthreadcount);
        }

        return event_pool;
}

static int
event_register_poll (struct event_pool *event_pool,
                     event_init_handler_t init,
		     event_handler_t handler,
                     void *data, int poll_in, int poll_out)
{
        uv_loop_t *loop = NULL;
        uv_handle_t *handle = NULL;
        struct reg_node *new_reg = NULL;
        struct reg_data *item = NULL;
        struct event_node *new_event = NULL;
        struct broker_data *bd = NULL;
        int need_clean = 0;
        int ret = -1;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);
        GF_VALIDATE_OR_GOTO ("event", data, out);

        handle = data;

        gf_msg ("poll", GF_LOG_DEBUG, 0,
                LG_MSG_POLL_IGNORE_MULTIPLE_THREADS, "Registering a new "
                "handle %p to the pool", data);

        pthread_mutex_lock (&event_pool->mutex);
        {
                if (__event_getindex (event_pool, handle))
                        need_clean = 1;
        }
        pthread_mutex_unlock (&event_pool->mutex);

        if (need_clean) {
                gf_msg ("poll", GF_LOG_DEBUG, 0,
                        LG_MSG_POLL_IGNORE_MULTIPLE_THREADS, "Remove the old "
                        "handle %p to the pool", data);
                event_unregister_poll(event_pool, handle);
        }

        pthread_mutex_lock (&event_pool->mutex);
        {

                loop = &event_pool->loop;

                new_reg = GF_CALLOC (1,
                             sizeof (event_pool->regs) + sizeof(struct reg_data),
                             gf_common_mt_reg);

                if (!new_reg) {
                        ret = -1;
                        goto unlock;
                }

                item = (struct reg_data *)new_reg->reg;
                item->loop = loop;
                item->handle = handle;
                item->events = UV_DISCONNECT;
                item->init = init;
                item->handler = handler;
                item->data = data;

                switch (poll_in) {
                case 1:
                        item->events |= UV_READABLE;
                        break;
                case 0:
                        item->events &= ~UV_READABLE;
                        break;
                case -1:
                        /* do nothing */
                        break;
                default:
                        gf_msg ("poll", GF_LOG_ERROR, 0,
                                LG_MSG_INVALID_POLL_IN,
                                "invalid poll_in value %d", poll_in);
                        break;
                }

                switch (poll_out) {
                case 1:
                        item->events |= UV_WRITABLE;
                        break;
                case 0:
                        item->events &= ~UV_WRITABLE;
                        break;
                case -1:
                        /* do nothing */
                        break;
                default:
                        gf_msg ("poll", GF_LOG_ERROR, 0,
                                LG_MSG_INVALID_POLL_OUT,
                                "invalid poll_out value %d", poll_out);
                        break;
                }

                ret = 0;

                list_add_tail(&new_reg->list, &event_pool->regs.list);

                new_event = GF_CALLOC(1,
                                      sizeof (struct broker_data) + sizeof (struct event_node),
                                      gf_common_mt_data_t);

                if (new_event == NULL) {
                        GF_FREE(new_reg);
                        ret = -1;
                        goto unlock;
                }
                bd = (struct broker_data *)new_event->event;
                bd->type = INIT;
                bd->handle = handle;

                list_add_tail(&new_event->list, &event_pool->events.list);

                uv_async_send(&event_pool->broker);

                event_pool->changed = 1;
        }
unlock:
        pthread_mutex_unlock (&event_pool->mutex);

out:
        return ret;
}


static int
event_unregister_poll (struct event_pool *event_pool, void *handle)
{
        int ret = 0;
        struct reg_node *reg = NULL;
        static struct reg_data *slot = NULL;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);

        pthread_mutex_lock (&event_pool->mutex);
        {
                slot = __event_getindex (event_pool, handle);

                if (slot == NULL) {
                        gf_msg ("poll", GF_LOG_ERROR, 0, LG_MSG_INDEX_NOT_FOUND,
                                "handle not found for handle=%p",
                                handle);
                        errno = ENOENT;
                        ret = -1;
                        goto unlock;
                }

                reg = CONTAINER_OF(slot, struct reg_node, reg);

                list_del(&reg->list);
                GF_FREE(reg);

                event_pool->changed = 1;
        }
unlock:
        pthread_mutex_unlock (&event_pool->mutex);

out:
        return ret;
}

static void __close_handle(uv_handle_t* handle)
{

}

static int
event_unregister_close_poll (struct event_pool *event_pool, void *handle)
{
        int ret = -1;

	ret = event_unregister_poll (event_pool, handle);

	uv_close (handle, __close_handle);

        return ret;
}

static int
event_select_on_poll (struct event_pool *event_pool, void *handle,
                      int poll_in, int poll_out)
{
        int ret = -1;
        struct reg_data *slot = NULL;
        struct event_node *new_event = NULL;
        struct broker_data *bd = NULL;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);

        pthread_mutex_lock (&event_pool->mutex);
        {
                slot = __event_getindex (event_pool, handle);

                if (slot == NULL) {
                        gf_msg ("poll", GF_LOG_ERROR, 0, LG_MSG_INDEX_NOT_FOUND,
                                "index not found for handle=%p",
                                handle);
                        errno = ENOENT;
                        goto unlock;
                }

                ret = 0;

                new_event = GF_CALLOC(1,
                                      sizeof (struct broker_data) + sizeof (struct event_node),
                                      gf_common_mt_data_t);

                if (new_event == NULL) {
                        errno = ENOMEM;
                        ret = -1;
                        goto unlock;
                }

                list_add_tail(&new_event->list, &event_pool->events.list);

                bd = (struct broker_data *) new_event->event;

                bd->type = 0;
                bd->handle = handle;

                if (poll_in) {
                        bd->type |= READ;
                }

                if (poll_out) {
                        bd->type |= WRITE;
                }

                if (poll_in + poll_out > -2) {
                        uv_async_send (&event_pool->broker);
                        event_pool->changed = 1;
                }
        }
unlock:
        pthread_mutex_unlock (&event_pool->mutex);

out:
        return ret;
}

static void
__event_async_cb(uv_async_t* handle)
{
        int ret = 0;
        struct event_pool *event_pool = NULL;
        struct event_node *event_node = NULL, *n;
        struct broker_data *ed = NULL;
        struct reg_data *slot = NULL;
        int toread = 0, towrite = 0;

        event_pool = CONTAINER_OF(handle, struct event_pool, broker);

        list_for_each_entry_safe(event_node, n, &event_pool->events.list, list) {
                ed = (struct broker_data *)&event_node->event;
                slot = CONTAINER_OF(ed->handle, struct reg_data, handle);

                if (ed->type & INIT) {
                        if (slot->init)
                                ret = slot->init(slot->loop, slot->handle);
                        else {
                                gf_msg ("epoll", GF_LOG_DEBUG, 0,
                                        LG_MSG_START_EPOLL_THREAD_FAILED,
                                        "The init handler is NULL: %p", ed->handle);
                        }
                }
                if (ed->type & READ) {
                        toread = 1;
                }
                if (ed->type & WRITE) {
                        towrite = 1;
                }

                if (toread || towrite)
                        if (slot->handler)
                                ret = slot->handler(slot->handle, 0, toread, towrite, 0);
                        else
                                gf_msg ("epoll", GF_LOG_DEBUG, 0,
                                        LG_MSG_START_EPOLL_THREAD_FAILED,
                                        "The handler is NULL: %p", ed->handle);

                list_del_init(&event_node->list);
                GF_FREE(event_node);
        }
}


static void
event_dispatch_win32_worker (struct event_pool  *event_pool)
{
        int                 ret = -1;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);

	for (;;) {
                ret = uv_loop_init(&event_pool->loop);
                if (ret != 0) {
                        gf_msg ("epoll", GF_LOG_INFO, 0,
                                LG_MSG_EXITED_EPOLL_THREAD, "Exited "
                                "loop with ret %d", ret);
                                goto out;
                }

                ret = uv_async_init(&event_pool->loop,
                                    &event_pool->broker, __event_async_cb);
                if (ret != 0) {
                        gf_msg ("epoll", GF_LOG_INFO, 0,
                                LG_MSG_EXITED_EPOLL_THREAD, "Init "
                                "broker failed with ret %d", ret);
                                goto out;
                }

                if (uv_run(&event_pool->loop, UV_RUN_DEFAULT)) {
                    break;
                }

                uv_loop_close(&event_pool->loop);
        }

out:
        return;
}


static int
event_dispatch_poll (struct event_pool *event_pool)
{
        int              size = 0;
        int              i = 0;
        int              ret = -1;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);

        event_pool->activethreadcount++;

        event_dispatch_win32_worker(event_pool);

        event_pool->activethreadcount--;

out:
        return -1;
}

int
event_reconfigure_threads_poll (struct event_pool *event_pool, int value)
{
        /* No-op for poll */
        return 0;
}

/* This function is the destructor for the event_pool data structure
 * Should be called only after poller_threads_destroy() is called,
 * else will lead to crashes.
 */
static int
event_pool_destroy_poll (struct event_pool *event_pool)
{
        struct reg_node *slot = &event_pool->regs;
        struct reg_node *n;
        struct reg_data *item = NULL;
        int ret = 0;

        uv_close((uv_handle_t *)&event_pool->broker, NULL);

        ret = uv_loop_close(&event_pool->loop);

        list_for_each_entry_safe(slot, n, &event_pool->regs.list, list) {
                list_del_init (&slot->list);
                GF_FREE (slot);
        }

        GF_FREE (event_pool);

        return ret;
}

struct event_ops event_ops_poll = {
        .new                    = event_pool_new_poll,
        .event_register         = event_register_poll,
        .event_select_on        = event_select_on_poll,
        .event_unregister       = event_unregister_poll,
        .event_unregister_close = event_unregister_close_poll,
        .event_dispatch         = event_dispatch_poll,
        .event_reconfigure_threads = event_reconfigure_threads_poll,
        .event_pool_destroy     = event_pool_destroy_poll
};

