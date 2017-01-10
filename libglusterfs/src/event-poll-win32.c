
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


struct event_slot_poll_win32 {
        uv_handle_t *handle;
        uv_loop_t loop;
	int events;
	void *data;
	event_handler_t handler;
};

struct event_thread_data {
        struct event_pool *event_pool;
        int    event_index;
};

static int
event_register_poll (struct event_pool *event_pool, uv_handle_t *fd,
                     event_handler_t handler,
                     void *data, int poll_in, int poll_out);


static int
__flush_fd (uv_handle_t *fd, void *data,
            int poll_in, int poll_out, int poll_err)
{
        int ret = -1;

        if (!poll_in)
                return ret;

        return ret;
}


static int
__event_getindex (struct event_pool *event_pool, uv_handle_t *fd, int idx)
{
        int  ret = -1;
        int  i = 0;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);

        /* lookup in used space based on index provided */
        if (idx > -1 && idx < event_pool->used) {
                if (event_pool->reg[idx].handle == fd) {
                        ret = idx;
                        goto out;
                }
        }

        /* search in used space, if lookup fails */
        for (i = 0; i < event_pool->used; i++) {
                if (event_pool->reg[idx].handle == fd) {
                        ret = i;
                        break;
                }
        }

out:
        return ret;
}

static void __close_event_pool(uv_handle_t* handle)
{
        uv_loop_close(handle->loop);
}

static struct event_pool *
event_pool_new_poll (int count, int eventthreadcount)
{
        struct event_pool *event_pool = NULL;
        int                ret = -1;

        event_pool = GF_CALLOC (1, sizeof (*event_pool),
                                gf_common_mt_event_pool);

        if (!event_pool)
                return NULL;

        event_pool->count = count;
        event_pool->reg = GF_CALLOC (event_pool->count,
                                     sizeof (*event_pool->reg),
                                     gf_common_mt_reg);

        if (!event_pool->reg) {
                GF_FREE (event_pool);
                return NULL;
        }

        uv_mutex_init (&event_pool->mutex);

        ret = uv_loop_init(&event_pool->loop);
        if (ret != 0) {
                gf_msg ("poll", GF_LOG_ERROR, errno, LG_MSG_PIPE_CREATE_FAILED,
                        "event loop creation failed");
                GF_FREE (event_pool->reg);
                GF_FREE (event_pool);
                return NULL;
        }

        ret = uv_pipe_init(&event_pool->loop, &event_pool->breaker, 0);
        if (ret != 0) {
                gf_msg ("poll", GF_LOG_ERROR, errno, LG_MSG_PIPE_CREATE_FAILED,
                        "pipe creation failed");
                uv_close((uv_handle_t *)&event_pool->breaker, __close_event_pool);
                GF_FREE (event_pool->reg);
                GF_FREE (event_pool);
                return NULL;
        }

        ret = event_register_poll (event_pool, (uv_handle_t *)&event_pool->breaker,
                                   __flush_fd, NULL, 1, 0);
        if (ret == -1) {
                gf_msg ("poll", GF_LOG_ERROR, 0, LG_MSG_REGISTER_PIPE_FAILED,
                        "could not register pipe fd with poll event loop");
                uv_close((uv_handle_t *)&event_pool->breaker, __close_event_pool);
                GF_FREE (event_pool->reg);
                GF_FREE (event_pool);
                return NULL;
        }

        if (eventthreadcount > 1) {
                gf_msg ("poll", GF_LOG_INFO, 0,
                        LG_MSG_POLL_IGNORE_MULTIPLE_THREADS, "Currently poll "
                        "does not use multiple event processing threads, "
                        "thread count (%d) ignored", eventthreadcount);
        }

        /* load libuv */
        void cyguv_init(int force);
        cyguv_init(1);

        return event_pool;
}

static int
event_register_poll (struct event_pool *event_pool, struct sockaddr *fd,
                     event_handler_t handler,
                     void *data, int poll_in, int poll_out)
{
        struct event_thread_data *fd_data = NULL;
        int idx = -1;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);
        GF_VALIDATE_OR_GOTO ("event", fd, out);

        uv_mutex_lock (&event_pool->mutex);
        {
                if (event_pool->count == event_pool->used)
                {
                        event_pool->count += 256;

                        event_pool->reg = GF_REALLOC (event_pool->reg,
                                                      event_pool->count *
                                                      sizeof (*event_pool->reg));
                        if (!event_pool->reg)
                                goto unlock;
                }

                fd_data = GF_CALLOC(1, sizeof (struct event_thread_data), gf_common_mt_data_t);
                if (!fd_data)
                        goto unlock;

                idx = event_pool->used++;

                fd_data->event_pool = event_pool;
                fd_data->event_index = idx;
                fd->data = fd_data;

                event_pool->reg[idx].handle = fd;
                event_pool->reg[idx].events = UV_DISCONNECT;
                event_pool->reg[idx].handler = handler;
                event_pool->reg[idx].data = data;

                switch (poll_in) {
                case 1:
                        event_pool->reg[idx].events |= UV_READABLE;
                        break;
                case 0:
                        event_pool->reg[idx].events &= ~UV_READABLE;
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
                        event_pool->reg[idx].events |= UV_WRITABLE;
                        break;
                case 0:
                        event_pool->reg[idx].events &= ~UV_WRITABLE;
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

#ifdef NEVER
                uv_poll_start(event_pool->reg_win32[idx].handle,
                        event_pool->reg[idx].events,
                        uv_poll_cb);
#endif /* NEVER */

                /* send a connecting request */
                uv_async_t async;
                uv_async_send(&async);

                event_pool->changed = 1;
        }
unlock:
        uv_mutex_unlock (&event_pool->mutex);

out:
        return idx;
}


static int
event_unregister_poll (struct event_pool *event_pool, uv_handle_t *fd, int idx_hint)
{
        int idx = -1;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);

        uv_mutex_lock (&event_pool->mutex);
        {
                idx = __event_getindex (event_pool, fd, idx_hint);

                if (idx == -1) {
                        gf_msg ("poll", GF_LOG_ERROR, 0, LG_MSG_INDEX_NOT_FOUND,
                                "index not found for fd=0x%p (idx_hint=%d)",
                                fd, idx_hint);
                        errno = ENOENT;
                        goto unlock;
                }

                event_pool->reg[idx] =  event_pool->reg[--event_pool->used];
                event_pool->changed = 1;
        }
unlock:
        uv_mutex_unlock (&event_pool->mutex);

out:
        return idx;
}

static void __close_handle(uv_handle_t* handle)
{

}

static int
event_unregister_close_poll (struct event_pool *event_pool, uv_handle_t *fd,
			     int idx_hint)
{
	int ret = -1;

	ret = event_unregister_poll (event_pool, fd, idx_hint);

	uv_close (fd, __close_handle);

        return ret;
}

static int
event_select_on_poll (struct event_pool *event_pool, uv_handle_t *fd, int idx_hint,
                      int poll_in, int poll_out)
{
        int idx = -1;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);

        uv_mutex_lock (&event_pool->mutex);
        {
                idx = __event_getindex (event_pool, fd, idx_hint);

                if (idx == -1) {
                        gf_msg ("poll", GF_LOG_ERROR, 0, LG_MSG_INDEX_NOT_FOUND,
                                "index not found for fd=0x%p(idx_hint=%d)",
                                fd, idx_hint);
                        errno = ENOENT;
                        goto unlock;
                }

                switch (poll_in) {
                case 1:
                        event_pool->reg[idx].events |= POLLIN;
                        break;
                case 0:
                        event_pool->reg[idx].events &= ~POLLIN;
                        break;
                case -1:
                        /* do nothing */
                        break;
                default:
                        /* TODO: log error */
                        break;
                }

                switch (poll_out) {
                case 1:
                        event_pool->reg[idx].events |= POLLOUT;
                        break;
                case 0:
                        event_pool->reg[idx].events &= ~POLLOUT;
                        break;
                case -1:
                        /* do nothing */
                        break;
                default:
                        /* TODO: log error */
                        break;
                }

                if (poll_in + poll_out > -2)
                        event_pool->changed = 1;
        }
unlock:
        uv_mutex_unlock (&event_pool->mutex);

out:
        return idx;
}

static int
event_dispatch_poll_handler (uv_handle_t *handle, int status, int events)
{
        event_handler_t  handler = NULL;
        struct event_thread_data *etd = NULL;
        void            *data = NULL;
        int              idx = -1;
        int              ret = 0;
        struct event_pool *event_pool = NULL;

        etd = handle->data;
        event_pool = etd->event_pool;
        handler = NULL;
        data    = NULL;

        uv_mutex_lock (&event_pool->mutex);
        {
                idx = __event_getindex (event_pool, handle, etd->event_index);

                if (idx == -1) {
                        gf_msg ("poll", GF_LOG_ERROR, 0,
                                LG_MSG_INDEX_NOT_FOUND, "index not found for "
                                "fd=0x%p (idx_hint=%d)", handle, etd->event_index);
                        goto unlock;
                }

                handler = event_pool->reg[idx].handler;
                data = event_pool->reg[idx].data;
        }
unlock:
        uv_mutex_unlock (&event_pool->mutex);

        if (handler)
                if (status < 0)
                        ret = handler (handle, data,
                               0,
                               0,
                               UV_DISCONNECT);
                else
                        ret = handler (handle, data,
                                       events & UV_READABLE,
                                       events & UV_WRITABLE,
                                       events & UV_DISCONNECT);

        return ret;
}


static int
event_dispatch_poll_resize (struct event_pool *event_pool,
                            struct event_slot_poll_win32 *ufds, int size)
{
        int              i = 0;

        uv_mutex_lock (&event_pool->mutex);
        {
                if (event_pool->changed == 0) {
                        goto unlock;
                }

                if (event_pool->used > event_pool->evcache_size) {
                        GF_FREE (event_pool->evcache);

                        event_pool->evcache = ufds = NULL;

                        event_pool->evcache_size = event_pool->used;

                        ufds = GF_CALLOC (sizeof (struct event_slot_poll_win32),
                                          event_pool->evcache_size,
                                          gf_common_mt_pollfd);
                        if (!ufds)
                                goto unlock;
                        event_pool->evcache = ufds;
                }

                for (i = 0; i < event_pool->used; i++) {
                        ufds[i].handle = event_pool->reg[i].handle;
                        ufds[i].events = event_pool->reg[i].events;
                }

                size = i;
        }
unlock:
        uv_mutex_unlock (&event_pool->mutex);

        return size;
}

/* This handler is in the related pipe/open/socket() files. */
void event_dispatch_win32_handler(uv_poll_t* handle, int status, int events)
{
        event_dispatch_poll_handler ((uv_handle_t*)handle, status, events);
}

static void
event_dispatch_win32_worker (void *data)
{
        int                 ret = -1;
        struct event_thread_data *ev_data = data;
	struct event_pool  *event_pool;
        int                 myindex = -1;
        int                 timetodie = 0;

        GF_VALIDATE_OR_GOTO ("event", ev_data, out);

        event_pool = ev_data->event_pool;
        myindex = ev_data->event_index;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);

        gf_msg ("epoll", GF_LOG_INFO, 0, LG_MSG_STARTED_EPOLL_THREAD, "Started"
                " thread with index %d", myindex);

        uv_mutex_lock (&event_pool->mutex);
        {
                event_pool->activethreadcount++;
        }
        uv_mutex_unlock (&event_pool->mutex);

	for (;;) {
                if (event_pool->eventthreadcount < myindex) {
                        /* ...time to die, thread count was decreased below
                         * this threads index */
                        /* Start with extra safety at this point, reducing
                         * lock conention in normal case when threads are not
                         * reconfigured always */
                        uv_mutex_lock (&event_pool->mutex);
                        {
                                if (event_pool->eventthreadcount <
                                    myindex) {
                                        /* if found true in critical section,
                                         * die */
                                        uv_loop_close(&event_pool->reg[myindex - 1].loop);
                                        event_pool->activethreadcount--;
                                        timetodie = 1;
                                        uv_cond_broadcast (&event_pool->cond);
                                }
                        }
                        uv_mutex_unlock (&event_pool->mutex);
                        if (timetodie) {
                                gf_msg ("epoll", GF_LOG_INFO, 0,
                                        LG_MSG_EXITED_EPOLL_THREAD, "Exited "
                                        "thread with index %d", myindex);
                                goto out;
                        }
                }

                ret = uv_loop_init(&event_pool->reg[myindex].loop);
                if (ret != 0) {
                        gf_msg ("epoll", GF_LOG_INFO, 0,
                                LG_MSG_EXITED_EPOLL_THREAD, "Exited "
                                "thread with index %d", myindex);
                                goto out;
                }

                //uv_poll_start(event_pool->reg[myindex].handle,
                //        UV_READABLE | UV_WRITABLE | UV_DISCONNECT, event_dispatch_win32_handler);


                if () {
                        /* connect as a client */
                        uv_tcp_init();

                        uv_connect_t* req;
                        ret = uv_tcp_connect(req, priv->sock, SA (&this->peerinfo.sockaddr),
                                       uv_connect_cb);
                        if (ret != 0 && errno == UV_ENOENT && ign_enoent) {
                                gf_log (this->name, GF_LOG_WARNING,
                                       "Ignore failed connection attempt on %s, (%s) ",
                                        this->peerinfo.identifier, strerror (errno));
                                goto handler;
                        }

                        if (ret == -1 && ((errno != UV_EINPROGRESS) && (errno != UV_ENOENT))) {
                                /* For unix path based sockets, the socket path is
                                 * cryptic (md5sum of path) and may not be useful for
                                 * the user in debugging so log it in DEBUG
                                 */
                                gf_log (this->name, ((sa_family == AF_UNIX) ?
                                        GF_LOG_DEBUG : GF_LOG_ERROR),
                                        "connection attempt on %s failed, (%s)",
                                        this->peerinfo.identifier, strerror (errno));
                                goto handler;
                        }
                        else {
                                ret = 0;
                        }

                        if (priv->use_ssl && !priv->own_thread) {
                                cname = ssl_setup_connection(this,0);
                                if (!cname) {
                                        errno = ENOTCONN;
                                        ret = -1;
                                        gf_log(this->name,GF_LOG_ERROR,
                                               "client setup failed");
                                        goto handler;
                                }
                                if (priv->connected) {
                                        this->ssl_name = cname;
                                }
                                else {
                                        GF_FREE(cname);
                                }
                        }
                }
                else {
                        /* connect as a server */
                        priv->sock = socket (sa_family, SOCK_STREAM, 0);

                        if (priv->sock == -1) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "socket creation failed (%s)",
                                        strerror (errno));
                                goto unlock;
                        }


                        ret = __socket_server_bind (this);

                        if ((ret == -EADDRINUSE) || (ret == -1)) {
                                /* logged inside __socket_server_bind() */
                                close (priv->sock);
                                priv->sock = -1;
                                goto unlock;
                        }

                        if (priv->backlog)
                                ret = listen (priv->sock, priv->backlog);
                        else
                                ret = listen (priv->sock, 10);

                        if (ret == -1) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "could not set socket %d to listen mode (%s)",
                                        priv->sock, strerror (errno));
                                close (priv->sock);
                                priv->sock = -1;
                                goto unlock;
                        }
                }

                if (uv_run(&event_pool->reg[myindex].loop, UV_RUN_DEFAULT)) {
                    break;
                }

                uv_loop_close(&event_pool->reg[myindex].loop);
        }
out:
        if (ev_data)
                GF_FREE (ev_data);
}


static int
event_dispatch_poll (struct event_pool *event_pool)
{
        struct pollfd   *ufds = NULL;
        int              size = 0;
        int              i = 0;
        int              ret = -1;
        int              pollercount = 0;
        struct event_thread_data *ev_data = NULL;
        uv_thread_t      t_id;

        GF_VALIDATE_OR_GOTO ("event", event_pool, out);

        uv_mutex_lock (&event_pool->mutex);
        {
                event_pool->activethreadcount = 1;

                pollercount = event_pool->eventthreadcount;

                /* Set to MAX if greater */
                if (pollercount > EVENT_MAX_THREADS)
                        pollercount = EVENT_MAX_THREADS;

                /* Default pollers to 1 in case this is incorrectly set */
                if (pollercount <= 0)
                        pollercount = 1;

                event_pool->activethreadcount++;

                for (i = 0; i < pollercount; i++) {
                        ev_data = GF_CALLOC (1, sizeof (*ev_data),
                                     gf_common_mt_event_pool);
                        if (!ev_data) {
                                if (i == 0) {
                                        /* Need to suceed creating 0'th
                                         * thread, to joinable and wait */
                                        break;
                                } else {
                                        /* Inability to create other threads
                                         * are a lesser evil, and ignored */
                                        continue;
                                }
                        }

                        ev_data->event_pool = event_pool;
                        ev_data->event_index = i + 1;

                        ret = uv_thread_create (&t_id,
                                              event_dispatch_win32_worker,
                                              ev_data);
                        if (!ret) {
                                event_pool->pollers[i] = t_id;
                        } else {
                                gf_msg ("win32-poll", GF_LOG_WARNING, 0,
                                        LG_MSG_START_EPOLL_THREAD_FAILED,
                                        "Failed to start thread for index %d",
                                        i);
                                if (i == 0) {
                                        GF_FREE (ev_data);
                                        break;
                                } else {
                                        GF_FREE (ev_data);
                                        continue;
                                }
                        }
                }
        }

        uv_mutex_unlock (&event_pool->mutex);

        /* Just wait for the first thread, that is created in a joinable state
         * and will never die, ensuring this function never returns */
        if (event_pool->pollers[0] != 0)
		uv_thread_join (&event_pool->pollers[0]);

        uv_mutex_lock (&event_pool->mutex);
        {
                event_pool->activethreadcount--;
        }
        uv_mutex_unlock (&event_pool->mutex);
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
        int ret = 0;

        /*
        uv_close(&event_pool->breaker, NULL);
        */

        ret = uv_loop_close(&event_pool->loop);

        GF_FREE (event_pool->reg);
        GF_FREE (event_pool);

        return ret;
}

struct event_ops event_ops_poll = {
        .new                    = event_pool_new_poll,
        .event_new_on_poll      = event_new_on_poll,
        .event_register         = event_register_poll,
        .event_select_on        = event_select_on_poll,
        .event_unregister       = event_unregister_poll,
        .event_unregister_close = event_unregister_close_poll,
        .event_dispatch         = event_dispatch_poll,
        .event_reconfigure_threads = event_reconfigure_threads_poll,
        .event_pool_destroy     = event_pool_destroy_poll
};

