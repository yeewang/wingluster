/*
  Copyright (c) 2008-2012 Red Hat, Inc. <http://www.redhat.com>
  This file is part of GlusterFS.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "byte-order.h"
#include "common-utils.h"
#include "compat-errno.h"
#include "dict.h"
#include "logging.h"
#include "rpc-transport.h"
#include "name.h"
#include "socket-mem-types.h"
#include "socket.h"
#include "syscall.h"
#include "timer.h"
#include "xlator.h"

/* ugly #includes below */
#include "glusterfs3-xdr.h"
#include "protocol-common.h"
#include "rpcsvc.h"
#include "xdr-nfs3.h"

/* for TCP_USER_TIMEOUT */
#if !defined(TCP_USER_TIMEOUT) && defined(GF_LINUX_HOST_OS)
#include <linux/tcp.h>
#else
#include <netinet/tcp.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <rpc/xdr.h>
#include <sys/ioctl.h>

#define USE_IOBUF (1)

#define GF_LOG_ERRNO(errno) ((errno == ENOTCONN) ? GF_LOG_DEBUG : GF_LOG_ERROR)
#define SA(ptr) ((struct sockaddr*)ptr)

#define SSL_ENABLED_OPT "transport.socket.ssl-enabled"
#define SSL_OWN_CERT_OPT "transport.socket.ssl-own-cert"
#define SSL_PRIVATE_KEY_OPT "transport.socket.ssl-private-key"
#define SSL_CA_LIST_OPT "transport.socket.ssl-ca-list"
#define SSL_CERT_DEPTH_OPT "transport.socket.ssl-cert-depth"
#define SSL_CIPHER_LIST_OPT "transport.socket.ssl-cipher-list"
#define SSL_DH_PARAM_OPT "transport.socket.ssl-dh-param"
#define SSL_EC_CURVE_OPT "transport.socket.ssl-ec-curve"
#define SSL_CRL_PATH_OPT "transport.socket.ssl-crl-path"
#define OWN_THREAD_OPT "transport.socket.own-thread"

/* TBD: do automake substitutions etc. (ick) to set these. */
#if !defined(DEFAULT_ETC_SSL)
#ifdef GF_LINUX_HOST_OS
#define DEFAULT_ETC_SSL "/etc/ssl"
#endif
#ifdef GF_BSD_HOST_OS
#define DEFAULT_ETC_SSL "/etc/openssl"
#endif
#ifdef GF_DARWIN_HOST_OS
#define DEFAULT_ETC_SSL "/usr/local/etc/openssl"
#endif
#if !defined(DEFAULT_ETC_SSL)
#define DEFAULT_ETC_SSL "/etc/ssl"
#endif
#endif

#if !defined(DEFAULT_CERT_PATH)
#define DEFAULT_CERT_PATH DEFAULT_ETC_SSL "/glusterfs.pem"
#endif
#if !defined(DEFAULT_KEY_PATH)
#define DEFAULT_KEY_PATH DEFAULT_ETC_SSL "/glusterfs.key"
#endif
#if !defined(DEFAULT_CA_PATH)
#define DEFAULT_CA_PATH DEFAULT_ETC_SSL "/glusterfs.ca"
#endif
#if !defined(DEFAULT_VERIFY_DEPTH)
#define DEFAULT_VERIFY_DEPTH 1
#endif
#define DEFAULT_CIPHER_LIST "EECDH:EDH:HIGH:!3DES:!RC4:!DES:!MD5:!aNULL:!eNULL"
#define DEFAULT_DH_PARAM DEFAULT_ETC_SSL "/dhparam.pem"
#define DEFAULT_EC_CURVE "prime256v1"

#define POLL_MASK_INPUT (POLLIN | POLLPRI)
#define POLL_MASK_OUTPUT (POLLOUT)
#define POLL_MASK_ERROR (POLLERR | POLLHUP | POLLNVAL)

typedef int SSL_unary_func (SSL*);
typedef int SSL_trinary_func (SSL*, void*, int);

#define __socket_proto_reset_pending(priv)                                     \
        do {                                                                   \
                struct gf_sock_incoming_frag* frag;                            \
                frag = &priv->incoming.frag;                                   \
                                                                               \
                memset (&frag->vector, 0, sizeof (frag->vector));              \
                frag->pending_vector = &frag->vector;                          \
                frag->pending_vector->iov_base = frag->fragcurrent;            \
                priv->incoming.pending_vector = frag->pending_vector;          \
        } while (0)

#define __socket_proto_update_pending(priv)                                    \
        do {                                                                   \
                uint32_t remaining;                                            \
                struct gf_sock_incoming_frag* frag;                            \
                frag = &priv->incoming.frag;                                   \
                if (frag->pending_vector->iov_len == 0) {                      \
                        remaining = (RPC_FRAGSIZE (priv->incoming.fraghdr) -   \
                                     frag->bytes_read);                        \
                                                                               \
                        frag->pending_vector->iov_len =                        \
                          (remaining > frag->remaining_size)                   \
                            ? frag->remaining_size                             \
                            : remaining;                                       \
                                                                               \
                        frag->remaining_size -= frag->pending_vector->iov_len; \
                }                                                              \
        } while (0)

#define __socket_proto_update_priv_after_read(priv, ret, bytes_read)           \
        {                                                                      \
                struct gf_sock_incoming_frag* frag;                            \
                frag = &priv->incoming.frag;                                   \
                                                                               \
                frag->fragcurrent += bytes_read;                               \
                frag->bytes_read += bytes_read;                                \
                                                                               \
                if ((ret > 0) || (frag->remaining_size != 0)) {                \
                        if (frag->remaining_size != 0 && ret == 0) {           \
                                __socket_proto_reset_pending (priv);           \
                        }                                                      \
                                                                               \
                        gf_log (this->name, GF_LOG_TRACE,                      \
                                "partial read on non-blocking socket");        \
                                                                               \
                        break;                                                 \
                }                                                              \
        }

#define __socket_proto_init_pending(priv, size)                                \
        do {                                                                   \
                uint32_t remaining = 0;                                        \
                struct gf_sock_incoming_frag* frag;                            \
                frag = &priv->incoming.frag;                                   \
                                                                               \
                remaining =                                                    \
                  (RPC_FRAGSIZE (priv->incoming.fraghdr) - frag->bytes_read);  \
                                                                               \
                __socket_proto_reset_pending (priv);                           \
                                                                               \
                frag->pending_vector->iov_len =                                \
                  (remaining > size) ? size : remaining;                       \
                                                                               \
                frag->remaining_size = (size - frag->pending_vector->iov_len); \
                                                                               \
        } while (0)

/* This will be used in a switch case and breaks from the switch case if all
 * the pending data is not read.
 */
#define __socket_proto_read(priv, ret)                                         \
        {                                                                      \
                size_t bytes_read = 0;                                         \
                struct gf_sock_incoming* in;                                   \
                in = &priv->incoming;                                          \
                                                                               \
                __socket_proto_update_pending (priv);                          \
                                                                               \
                ret = __socket_readv (this, in->pending_vector, 1,             \
                                      &in->pending_vector, &in->pending_count, \
                                      &bytes_read);                            \
                if (ret == -1)                                                 \
                        break;                                                 \
                __socket_proto_update_priv_after_read (priv, ret, bytes_read); \
        }

struct socket_connect_error_state_
{
        xlator_t* this;
        rpc_transport_t* trans;
        gf_boolean_t refd;
};
typedef struct socket_connect_error_state_ socket_connect_error_state_t;

static int socket_init (rpc_transport_t* this);
static ssize_t __socket_readv_internal (socket_private_t* priv,
                                        struct iovec* opvector, int opcount);
static void socket_write_cb (uv_write_t* req, int status);

static void socket_timer_cb (uv_timer_t* handle);

static void socket_read_start (rpc_transport_t* this);

static int __socket_handle_init (uv_loop_t* loop, rpc_transport_t* this);

static inline size_t bufq_get_size (struct bufq* readq);

static inline size_t writeq_get_size (struct ioq* writeq);

static int socket_do_next (rpc_transport_t* this);

static void free_bufq (struct bufq* bufq);

static int socket_register_handler (uv_loop_t* loop, void* translator,
                                    int action);

static int __socket_disconnect (rpc_transport_t* this);

static int __socket_connect (uv_loop_t* loop, rpc_transport_t* this, int port);

static int __socket_listen (rpc_transport_t* this);

static void socket_close (rpc_transport_t* this);

static int32_t __socket_submit_request (rpc_transport_t* this,
                                        struct ioq* entry);

static int32_t __socket_submit_reply (rpc_transport_t* this, struct ioq* entry);

static void
__socket_do_action (uv_loop_t* loop, rpc_transport_t* this,
                    struct action_req* action)
{
        GF_ASSERT (this == action->args[0]);

        switch (action->type) {
                case AR_SOCKET_DISCONNECT:
                        __socket_disconnect ((rpc_transport_t*)action->args[0]);
                        break;

                case AR_SOCKET_CONNECT:
                        __socket_connect (loop, this, (int)action->args[1]);
                        break;

                case AR_SOCKET_LISTEN:
                        __socket_listen ((rpc_transport_t*)action->args[0]);
                        break;

                case AR_SOCKET_SUBMIT_REQUEST:
                        __socket_submit_request (
                          (rpc_transport_t*)action->args[0],
                          (struct ioq*)action->args[1]);
                        break;

                case AR_SOCKET_SUBMIT_REPLY:
                        __socket_submit_reply (
                          (rpc_transport_t*)action->args[0],
                          (struct ioq*)action->args[1]);
                        break;
        }
}

static int
emit_socket_disconnect (rpc_transport_t* this)
{
        socket_private_t* priv = this->private;
        struct action_req* action_req = NULL;
        int ret = -1;

        action_req =
          GF_CALLOC (1, sizeof (struct action_req), gf_sock_mt_action_q);
        if (action_req == NULL) {
                gf_log (this->name, GF_LOG_ERROR,
                        "failure on allocating action_req.");
                goto out;
        }

        INIT_LIST_HEAD (&action_req->list);
        action_req->type = AR_SOCKET_DISCONNECT;
        action_req->args[0] = this;
        action_req->num_of_args = 1;

        uv_mutex_lock (&priv->comm_lock);
        {
                list_add_tail (&action_req->list, &priv->action_q);
        }
        uv_mutex_unlock (&priv->comm_lock);

        ret = 0;

out:
        return ret;
}

static int
emit_socket_connect (rpc_transport_t* this, int port)
{
        socket_private_t* priv = this->private;
        struct action_req* action_req = NULL;
        int ret = -1;

        action_req =
          GF_CALLOC (1, sizeof (struct action_req), gf_sock_mt_action_q);
        if (action_req == NULL) {
                gf_log (this->name, GF_LOG_ERROR,
                        "failure on allocating action_req.");
                goto out;
        }

        INIT_LIST_HEAD (&action_req->list);
        action_req->type = AR_SOCKET_CONNECT;
        action_req->args[0] = this;
        action_req->args[1] = port;
        action_req->num_of_args = 2;

        uv_mutex_lock (&priv->comm_lock);
        {
                list_add_tail (&action_req->list, &priv->action_q);
        }
        uv_mutex_unlock (&priv->comm_lock);

        ret = 0;

out:
        return ret;
}

static int
emit_socket_listen (rpc_transport_t* this)
{
        socket_private_t* priv = this->private;
        struct action_req* action_req = NULL;
        int ret = -1;

        action_req =
          GF_CALLOC (1, sizeof (struct action_req), gf_sock_mt_action_q);
        if (action_req == NULL) {
                gf_log (this->name, GF_LOG_ERROR,
                        "failure on allocating action_req.");
                goto out;
        }

        INIT_LIST_HEAD (&action_req->list);
        action_req->type = AR_SOCKET_LISTEN;
        action_req->args[0] = this;
        action_req->num_of_args = 1;

        uv_mutex_lock (&priv->comm_lock);
        {
                list_add_tail (&action_req->list, &priv->action_q);
        }
        uv_mutex_unlock (&priv->comm_lock);

        ret = 0;

out:
        return ret;
}

static void
ssl_dump_error_stack (const char* caller)
{
        unsigned long errnum = 0;
        char errbuf[120] = {
                0,
        };

        /* OpenSSL docs explicitly give 120 as the error-string length. */

        while ((errnum = ERR_get_error ())) {
                ERR_error_string (errnum, errbuf);
                gf_log (caller, GF_LOG_ERROR, "  %s", errbuf);
        }
}

static int
ssl_do (rpc_transport_t* this, void* buf, size_t len, SSL_trinary_func* func)
{
        int r = (-1);
        struct pollfd pfd = {
                -1,
        };
        socket_private_t* priv = NULL;

        GF_VALIDATE_OR_GOTO (this->name, this->private, out);
        priv = this->private;

        for (;;) {
                if (buf) {
                        if (priv->connected == -1) {
                                /*
                                 * Fields in the SSL structure (especially
                                 * the BIO pointers) are not valid at this
                                 * point, so we'll segfault if we pass them
                                 * to SSL_read/SSL_write.
                                 */
                                gf_log (this->name, GF_LOG_INFO,
                                        "lost connection in %s", __func__);
                                break;
                        }
                        r = func (priv->ssl_ssl, buf, len);
                } else {
                        /*
                         * We actually need these functions to get to
                         * priv->connected == 1.
                         */
                        r = ((SSL_unary_func*)func) (priv->ssl_ssl);
                }
                switch (SSL_get_error (priv->ssl_ssl, r)) {
                        case SSL_ERROR_NONE:
                                return r;
                        case SSL_ERROR_WANT_READ:
                                /* If we are attempting to connect/accept then
                                 * we
                                 * should wait here on the poll, for the SSL
                                 * (re)negotiation to complete, else we would
                                 * error out
                                 * on the accept/connect.
                                 * If we are here when attempting to read/write
                                 * then we return r (or -1) as the socket is
                                 * always
                                 * primed for the read event, and it would
                                 * eventually
                                 * call one of the SSL routines */
                                /* NOTE: Only way to determine this is a
                                 * accept/connect
                                 * is to examine buf or func, which is not very
                                 * clean */
                                if ((func == (SSL_trinary_func*)SSL_read) ||
                                    (func == (SSL_trinary_func*)SSL_write)) {
                                        return r;
                                }

                                // pfd.fd = priv->handle->h.sock;
                                pfd.events = POLLIN;
                                if (poll (&pfd, 1, -1) < 0) {
                                        gf_log (this->name, GF_LOG_ERROR,
                                                "poll error %d", errno);
                                }
                                break;
                        case SSL_ERROR_WANT_WRITE:
                                // pfd.fd = priv->handle->h.sock;
                                pfd.events = POLLOUT;
                                if (poll (&pfd, 1, -1) < 0) {
                                        gf_log (this->name, GF_LOG_ERROR,
                                                "poll error %d", errno);
                                }
                                break;
                        case SSL_ERROR_SYSCALL:
                                /* This is what we get when remote disconnects.
                                 */
                                gf_log (
                                  this->name, GF_LOG_DEBUG,
                                  "syscall error (probably remote disconnect)");
                                errno = ENODATA;
                                goto out;
                        default:
                                errno = EIO;
                                goto out; /* "break" would just loop again */
                }
        }
out:
        return -1;
}

#define ssl_connect_one(t) ssl_do ((t), NULL, 0, (SSL_trinary_func*)SSL_connect)
#define ssl_accept_one(t) ssl_do ((t), NULL, 0, (SSL_trinary_func*)SSL_accept)
#define ssl_read_one(t, b, l)                                                  \
        ssl_do ((t), (b), (l), (SSL_trinary_func*)SSL_read)
#define ssl_write_one(t, b, l)                                                 \
        ssl_do ((t), (b), (l), (SSL_trinary_func*)SSL_write)

static char*
ssl_setup_connection (rpc_transport_t* this, int server)
{
        X509* peer = NULL;
        char peer_CN[256] = "";
        int ret = -1;
        socket_private_t* priv = NULL;

        GF_VALIDATE_OR_GOTO (this->name, this->private, done);
        priv = this->private;

        priv->ssl_ssl = SSL_new (priv->ssl_ctx);
        if (!priv->ssl_ssl) {
                gf_log (this->name, GF_LOG_ERROR, "SSL_new failed");
                ssl_dump_error_stack (this->name);
                goto done;
        }
        // priv->ssl_sbio = BIO_new_socket(priv->handle->h.sock,BIO_NOCLOSE);
        if (!priv->ssl_sbio) {
                gf_log (this->name, GF_LOG_ERROR, "BIO_new_socket failed");
                ssl_dump_error_stack (this->name);
                goto free_ssl;
        }
        SSL_set_bio (priv->ssl_ssl, priv->ssl_sbio, priv->ssl_sbio);

        if (server) {
                ret = ssl_accept_one (this);
        } else {
                ret = ssl_connect_one (this);
        }

        /* Make sure _the call_ succeeded. */
        if (ret < 0) {
                goto ssl_error;
        }

        /* Make sure _SSL verification_ succeeded, yielding an identity. */
        if (SSL_get_verify_result (priv->ssl_ssl) != X509_V_OK) {
                goto ssl_error;
        }
        peer = SSL_get_peer_certificate (priv->ssl_ssl);
        if (!peer) {
                goto ssl_error;
        }

        /* Finally, everything seems OK. */
        X509_NAME_get_text_by_NID (X509_get_subject_name (peer), NID_commonName,
                                   peer_CN, sizeof (peer_CN) - 1);
        peer_CN[sizeof (peer_CN) - 1] = '\0';
        gf_log (this->name, GF_LOG_INFO, "peer CN = %s", peer_CN);
        gf_log (this->name, GF_LOG_INFO,
                "SSL verification succeeded (client: %s)",
                this->xl_private ? this->xl_private->client_uid : "");
        return gf_strdup (peer_CN);

/* Error paths. */
ssl_error:
        gf_log (this->name, GF_LOG_ERROR, "SSL connect error (client: %s)",
                this->xl_private ? this->xl_private->client_uid : "");
        ssl_dump_error_stack (this->name);
free_ssl:
        SSL_free (priv->ssl_ssl);
        priv->ssl_ssl = NULL;
done:
        return NULL;
}

static void
ssl_teardown_connection (socket_private_t* priv)
{
        if (priv->ssl_ssl) {
                SSL_shutdown (priv->ssl_ssl);
                SSL_clear (priv->ssl_ssl);
                SSL_free (priv->ssl_ssl);
                priv->ssl_ssl = NULL;
        }
        priv->use_ssl = _gf_false;
}

static ssize_t
__socket_ssl_readv (rpc_transport_t* this, struct iovec* opvector, int opcount)
{
        socket_private_t* priv = NULL;
        int ret = -1;

        priv = this->private;

        if (priv->use_ssl) {
                ret =
                  ssl_read_one (this, opvector->iov_base, opvector->iov_len);
        } else {
                ret =
                  __socket_readv_internal (priv, opvector, IOV_MIN (opcount));
        }

        return ret;
}

static ssize_t
__socket_ssl_read (rpc_transport_t* this, void* buf, size_t count)
{
        struct iovec iov = {
                0,
        };
        int ret = -1;

        iov.iov_base = buf;
        iov.iov_len = count;

        ret = __socket_ssl_readv (this, &iov, 1);

        return ret;
}

static int
__socket_cached_read (rpc_transport_t* this, struct iovec* opvector,
                      int opcount)
{
        socket_private_t* priv = NULL;
        struct gf_sock_incoming* in = NULL;
        int req_len = -1;
        int ret = -1;

        priv = this->private;
        in = &priv->incoming;
        req_len = iov_length (opvector, opcount);

        if (in->record_state == SP_STATE_READING_FRAGHDR) {
                in->ra_read = 0;
                in->ra_served = 0;
                in->ra_max = 0;
                in->ra_buf = NULL;
                goto uncached;
        }

        if (!in->ra_max) {
                /* first call after passing SP_STATE_READING_FRAGHDR */
                in->ra_max = min (RPC_FRAGSIZE (in->fraghdr), GF_SOCKET_RA_MAX);
                /* Note that the in->iobuf is the primary iobuf into which
                   headers are read into, and in->frag.fragcurrent points to
                   some position in the buffer. By using this itself as our
                   read-ahead cache, we can avoid memory copies in iov_load
                */
                in->ra_buf = in->frag.fragcurrent;
        }

        /* fill read-ahead */
        if (in->ra_read < in->ra_max) {
                ret = __socket_ssl_read (this, &in->ra_buf[in->ra_read],
                                         (in->ra_max - in->ra_read));
                if (ret > 0)
                        in->ra_read += ret;

                /* we proceed to test if there is still cached data to
                   be served even if readahead could not progress */
        }

        /* serve cached */
        if (in->ra_served < in->ra_read) {
                ret = iov_load (opvector, opcount, &in->ra_buf[in->ra_served],
                                min (req_len, (in->ra_read - in->ra_served)));

                in->ra_served += ret;

                /* Do not read uncached and cached in the same call */
                goto out;
        }

uncached:
        ret = __socket_ssl_readv (this, opvector, opcount);
out:

#ifdef NEVER
        gf_log (this->name, GF_LOG_DEBUG,
                "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv:%d,ret=%d",
                req_len, ret);
#endif /* NEVER */
        return ret;
}

static gf_boolean_t
__does_socket_rwv_error_need_logging (socket_private_t* priv, int write)
{
        int read = !write;

        if (priv->connected == -1) /* Didn't even connect, of course it fails */
                return _gf_false;

        if (read && (priv->read_fail_log == _gf_false))
                return _gf_false;

        return _gf_true;
}

static ssize_t
__socket_readv_internal (socket_private_t* priv, struct iovec* opvector,
                         int opcount)
{
        struct bufq *entry = NULL, *n;
        ssize_t toread = 0, read = 0, totol = 0;
#if 0
        ssize_t origin = bufq_get_size (&priv->read_q);
#endif /* NEVER */
        int i = 0;
        int ret = -1;

        uv_mutex_lock (&priv->comm_lock);

        while (!list_empty (&priv->read_q)) {
                entry = list_first_entry (&priv->read_q, struct bufq, list);
                if (entry->vector.iov_len - entry->read >
                    opvector[i].iov_len - read) {
                        toread = opvector[i].iov_len - read;
                        memcpy (opvector[i].iov_base + read,
                                entry->vector.iov_base + entry->read, toread);
                        entry->read += toread;
                        read = 0;
                        totol += toread;
                        i++;

                        if (i == opcount) {
                                break;
                        }
                } else {
                        toread = entry->vector.iov_len - entry->read;
                        memcpy (opvector[i].iov_base + read,
                                entry->vector.iov_base + entry->read, toread);
                        free_bufq (entry);
                        read += toread;
                        totol += toread;
                }
        }

#if 0
        rpc_transport_t* this = priv->translator;

        gf_log (this->name, GF_LOG_ERROR,
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee:"
                "tid=%p,read=%d,origin=%d,remain=%d,%s",
                pthread_self (), totol, origin, bufq_get_size (&priv->read_q),
                origin - bufq_get_size (&priv->read_q) == totol ? "OKKKKK"
                                                                : "BADDDD");

        if (origin - bufq_get_size (&priv->read_q) != totol)
                __asm__("int $3");
#endif /* NEVER */

        uv_mutex_unlock (&priv->comm_lock);

        return totol;
}

/*
 * return value:
 *   0 = success (completed)
 *  -1 = error
 * > 0 = incomplete
 */

static int
__socket_rwv (rpc_transport_t* this, struct iovec* vector, int count,
              struct iovec** pending_vector, int* pending_count, size_t* bytes,
              int write)
{
        socket_private_t* priv = NULL;
        int ret = -1;
        struct iovec* opvector = NULL;
        int opcount = 0;
        int moved = 0;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;

        opvector = vector;
        opcount = count;

        if (bytes != NULL) {
                *bytes = 0;
        }

        while (opcount > 0) {
                if (opvector->iov_len == 0) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "would have passed zero length to read/write");
                        ++opvector;
                        --opcount;
                        continue;
                }
                if (priv->use_ssl && !priv->ssl_ssl) {
                        /*
                         * We could end up here with priv->ssl_ssl still NULL
                         * if (a) the connection failed and (b) some fool
                         * called other socket functions anyway.  Demoting to
                         * non-SSL might be insecure, so just fail it outright.
                         */
                        ret = -1;
                } else if (write) {
                        if (priv->use_ssl) {
                                ret = ssl_write_one (this, opvector->iov_base,
                                                     opvector->iov_len);
                        } else {
                                /*
                                ret = __socket_write (priv, opvector,
                                                      IOV_MIN (opcount));
                                                      */
                        }

                        if (ret == 0 || (ret == -1 && errno == EAGAIN)) {
                                /* done for now */
                                break;
                        }
                        this->total_bytes_write += ret;
                } else {
                        ret = __socket_cached_read (this, opvector, opcount);

                        if (ret == 0) {
                                gf_log (this->name, GF_LOG_DEBUG,
                                        "EOF on socket");
                                errno = ENODATA;
                                ret = -1;
                        }
                        if (ret == -1) {
                                /* done for now */
                                break;
                        }
                }

                if (ret == 0) {
                        /* Mostly due to 'umount' in client */

                        gf_log (this->name, GF_LOG_DEBUG, "EOF from peer %s",
                                this->peerinfo.identifier);
                        opcount = -1;
                        errno = ENODATA;
                        break;
                }
                if (ret == -1) {
                        if (errno == EINTR)
                                continue;

                        if (__does_socket_rwv_error_need_logging (priv,
                                                                  write)) {
                                GF_LOG_OCCASIONALLY (
                                  priv->log_ctr, this->name, GF_LOG_WARNING,
                                  "%s on %s failed (%s)",
                                  write ? "writev" : "readv",
                                  this->peerinfo.identifier, strerror (errno));
                        }

                        if (priv->use_ssl && priv->ssl_ssl) {
                                ssl_dump_error_stack (this->name);
                        }
                        opcount = -1;
                        break;
                }

                if (bytes != NULL) {
                        *bytes += ret;
                }

                this->total_bytes_read += ret;

                moved = 0;

                while (moved < ret) {
                        if (!opcount) {
                                gf_log (this->name, GF_LOG_DEBUG,
                                        "ran out of iov, moved %d/%d", moved,
                                        ret);
                                goto ran_out;
                        }
                        if (!opvector[0].iov_len) {
                                opvector++;
                                opcount--;
                                continue;
                        }
                        if ((ret - moved) >= opvector[0].iov_len) {
                                moved += opvector[0].iov_len;
                                opvector++;
                                opcount--;
                        } else {
                                opvector[0].iov_len -= (ret - moved);
                                opvector[0].iov_base += (ret - moved);
                                moved += (ret - moved);
                        }
                }
        }

ran_out:

        if (pending_vector)
                *pending_vector = opvector;

        if (pending_count)
                *pending_count = opcount;

out:
        return opcount;
}

static int
__socket_readv (rpc_transport_t* this, struct iovec* vector, int count,
                struct iovec** pending_vector, int* pending_count,
                size_t* bytes)
{
        int ret = -1;

        ret = __socket_rwv (this, vector, count, pending_vector, pending_count,
                            bytes, 0);

        return ret;
}

static int
__socket_server_bind (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        int ret = -1;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;

        ret = uv_tcp_bind (&priv->handle,
                           (struct sockaddr*)&this->myinfo.sockaddr, 0);
        if (ret != 0) {
                gf_log (this->name, GF_LOG_ERROR, "binding to %s failed: %s",
                        this->myinfo.identifier, strerror (errno));
                if (ret == UV_EADDRINUSE) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "Port is already in use");

                        ret = UV_EADDRINUSE;
                }
        }

out:
        return ret;
}

static void
__socket_reset (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;

        /* TODO: use mem-pool on incoming data */

        if (priv->incoming.iobref) {
                iobref_unref (priv->incoming.iobref);
                priv->incoming.iobref = NULL;
        }

        if (priv->incoming.iobuf) {
                iobuf_unref (priv->incoming.iobuf);
                priv->incoming.iobuf = NULL;
        }

        GF_FREE (priv->incoming.request_info);

        memset (&priv->incoming, 0, sizeof (priv->incoming));

        //event_unregister_close (this->ctx->event_pool, this);

        priv->connected = -1;

out:
        return;
}

static void
socket_set_lastfrag (uint32_t* fragsize)
{
        (*fragsize) |= 0x80000000U;
}

static void
socket_set_frag_header_size (uint32_t size, char* haddr)
{
        size = htonl (size);
        memcpy (haddr, &size, sizeof (size));
}

static void
socket_set_last_frag_header_size (uint32_t size, char* haddr)
{
        socket_set_lastfrag (&size);
        socket_set_frag_header_size (size, haddr);
}

static struct ioq*
__socket_ioq_new (rpc_transport_t* this, rpc_transport_msg_t* msg)
{
        struct ioq* entry = NULL;
        int count = 0;
        uint32_t size = 0;
        struct iobuf* iobuf = NULL;

        GF_VALIDATE_OR_GOTO ("socket", this, out);

/* TODO: use mem-pool */
#ifndef USE_IOBUF
        entry = GF_CALLOC (1, sizeof (*entry), gf_common_mt_ioq);
        if (!entry)
                return NULL;
#else
        iobuf = iobuf_get2 (this->ctx->iobuf_pool, sizeof (*entry));
        if (!iobuf)
                return NULL;
        entry = iobuf_ptr (iobuf);
#endif /* USE_IOBUF */

        count = msg->rpchdrcount + msg->proghdrcount + msg->progpayloadcount;

        GF_ASSERT (count <= (MAX_IOVEC - 1));

        size = iov_length (msg->rpchdr, msg->rpchdrcount) +
               iov_length (msg->proghdr, msg->proghdrcount) +
               iov_length (msg->progpayload, msg->progpayloadcount);

        if (size > RPC_MAX_FRAGMENT_SIZE) {
                gf_log (this->name, GF_LOG_ERROR,
                        "msg size (%u) bigger than the maximum allowed size on "
                        "sockets (%u)",
                        size, RPC_MAX_FRAGMENT_SIZE);
#ifndef USE_IOBUF
                GF_FREE (entry);
#else
                iobuf_unref (entry);
#endif /* USE_IOBUF */
                return NULL;
        }

        socket_set_last_frag_header_size (size, (char*)&entry->fraghdr);

        entry->vector[0].iov_base = (char*)&entry->fraghdr;
        entry->vector[0].iov_len = sizeof (entry->fraghdr);
        entry->count = 1;

        if (msg->rpchdr != NULL) {
                memcpy (&entry->vector[1], msg->rpchdr,
                        sizeof (struct iovec) * msg->rpchdrcount);
                entry->count += msg->rpchdrcount;
        }

        if (msg->proghdr != NULL) {
                memcpy (&entry->vector[entry->count], msg->proghdr,
                        sizeof (struct iovec) * msg->proghdrcount);
                entry->count += msg->proghdrcount;
        }

        if (msg->progpayload != NULL) {
                memcpy (&entry->vector[entry->count], msg->progpayload,
                        sizeof (struct iovec) * msg->progpayloadcount);
                entry->count += msg->progpayloadcount;
        }

        entry->pending_vector = entry->vector;
        entry->pending_count = entry->count;

        if (msg->iobref != NULL)
                entry->iobref = iobref_ref (msg->iobref);
#ifdef USE_IOBUF
        else
                entry->iobref = iobref_new ();
#endif /* USE_IOBUF */
        iobref_add (entry->iobref, iobuf);
        iobuf_unref (iobuf);

        INIT_LIST_HEAD (&entry->list);

out:
        return entry;
}

static void
__socket_ioq_entry_free (struct ioq* entry)
{
        GF_VALIDATE_OR_GOTO ("socket", entry, out);

        list_del_init (&entry->list);
        if (entry->iobref)
                iobref_unref (entry->iobref);

#ifndef USE_IOBUF
        GF_FREE (entry);
#endif /* USE_IOBUF */

out:
        return;
}

static void
__socket_ioq_flush (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        struct ioq* entry = NULL;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;

        while (!list_empty (&priv->ioq)) {
                entry = priv->ioq_next;
                __socket_ioq_entry_free (entry);
        }

out:
        return;
}

static int
__socket_ioq_churn_entry (rpc_transport_t* this, struct ioq* entry)
{
        int ret = 0;
        socket_private_t* priv = NULL;
        uv_buf_t bufs[MAX_IOVEC];
        int count = 0;
        int i = 0;

        priv = this->private;

#if 0
	for (int i = 0; i < entry->pending_count; i++) {
		if (i == 2 && entry->pending_vector[i].iov_len != 131072)
		gf_log (this->name, GF_LOG_INFO, "WRITE: tid=%p, %p, c=%d,i=%d, len=%d",
			pthread_self (),  entry->pending_vector[i].iov_base, entry->pending_count, i,
			entry->pending_vector[i].iov_len);
	}
#endif /* DEBUG */

        for (; i < entry->pending_count; i++) {
                if (entry->pending_vector[i].iov_len > 0) {
                        bufs[count].base = entry->pending_vector[i].iov_base;
                        bufs[count].len = entry->pending_vector[i].iov_len;
                }
                count++;
        }

        ret = uv_try_write (&priv->handle, bufs, count);
        if (ret > 0) {
                __socket_ioq_entry_free (entry);
                this->total_bytes_write += ret;
        } else {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        LG_MSG_POLL_IGNORE_MULTIPLE_THREADS,
                        "write error: this=%p, rdstate=%d, %d(%s)", this,
                        priv->rdstate, ret, uv_strerror (ret));
        }

        return ret;
}

static int
__socket_ioq_append_entry (rpc_transport_t* this, struct ioq* entry)
{
        int ret = 0;
        socket_private_t* priv = NULL;
        int i = 0;

        priv = this->private;

#if 0
	for (int i = 0; i < entry->pending_count; i++) {
		gf_log (this->name, GF_LOG_ERROR, "yyyy"
						  "tid=%p, %p, c=%d,i=%d, len=%d",
			pthread_self (),  entry->pending_vector[i].iov_base, entry->pending_count, i,
			entry->pending_vector[i].iov_len);
	}
#endif /* NEVER */

        INIT_LIST_HEAD (&entry->list);

#if 0
	for (int i = 0; i < write_q->count; i++) {
		gf_log (this->name, GF_LOG_ERROR, "wwwww"
						  "tid=%p, %p, c=%d,i=%d, len=%d",
			pthread_self (), write_q->bufs[i].base, write_q->count, i,
			write_q->bufs[i].len);
	}
#endif /* NEVER */

        uv_mutex_lock (&priv->comm_lock);
        list_add_tail (entry, &priv->write_q);
        uv_mutex_unlock (&priv->comm_lock);

        return ret;
}

static int
socket_event_poll_err (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        int ret = -1;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;

        //-- pthread_mutex_lock (&priv->lock);
        {
                __socket_ioq_flush (this);
                __socket_reset (this);
        }
        //-- pthread_mutex_unlock (&priv->lock);

        // rpc_transport_notify (this, RPC_TRANSPORT_DISCONNECT, this);
out:
        return ret;
}

static int
__socket_read_simple_msg (rpc_transport_t* this)
{
        int ret = 0;
        uint32_t remaining_size = 0;
        size_t bytes_read = 0;
        socket_private_t* priv = NULL;
        struct gf_sock_incoming* in = NULL;
        struct gf_sock_incoming_frag* frag = NULL;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;

        in = &priv->incoming;
        frag = &in->frag;

        switch (frag->simple_state) {

                case SP_STATE_SIMPLE_MSG_INIT:
                        remaining_size =
                          RPC_FRAGSIZE (in->fraghdr) - frag->bytes_read;

                        __socket_proto_init_pending (priv, remaining_size);

                        frag->simple_state = SP_STATE_READING_SIMPLE_MSG;

                /* fall through */

                case SP_STATE_READING_SIMPLE_MSG:
                        ret = 0;

                        remaining_size =
                          RPC_FRAGSIZE (in->fraghdr) - frag->bytes_read;

                        if (remaining_size > 0) {
                                ret = __socket_readv (this, in->pending_vector,
                                                      1, &in->pending_vector,
                                                      &in->pending_count,
                                                      &bytes_read);
                        }

                        if (ret == -1) {
                                gf_log (
                                  this->name, GF_LOG_WARNING,
                                  "reading from socket failed. Error (%s), "
                                  "peer (%s)",
                                  strerror (errno), this->peerinfo.identifier);
                                break;
                        }

                        frag->bytes_read += bytes_read;
                        frag->fragcurrent += bytes_read;

                        if (ret > 0) {
                                gf_log (this->name, GF_LOG_TRACE,
                                        "partial read on non-blocking socket.");
                                break;
                        }

                        if (ret == 0) {
                                frag->simple_state = SP_STATE_SIMPLE_MSG_INIT;
                        }
        }

out:
        return ret;
}

static int
__socket_read_simple_request (rpc_transport_t* this)
{
        return __socket_read_simple_msg (this);
}

#define rpc_cred_addr(buf) (buf + RPC_MSGTYPE_SIZE + RPC_CALL_BODY_SIZE - 4)

#define rpc_verf_addr(fragcurrent) (fragcurrent - 4)

#define rpc_msgtype_addr(buf) (buf + 4)

#define rpc_prognum_addr(buf) (buf + RPC_MSGTYPE_SIZE + 4)
#define rpc_progver_addr(buf) (buf + RPC_MSGTYPE_SIZE + 8)
#define rpc_procnum_addr(buf) (buf + RPC_MSGTYPE_SIZE + 12)

static int
__socket_read_vectored_request (rpc_transport_t* this,
                                rpcsvc_vector_sizer vector_sizer)
{
        socket_private_t* priv = NULL;
        int ret = 0;
        uint32_t credlen = 0, verflen = 0;
        char* addr = NULL;
        struct iobuf* iobuf = NULL;
        uint32_t remaining_size = 0;
        ssize_t readsize = 0;
        size_t size = 0;
        struct gf_sock_incoming* in = NULL;
        struct gf_sock_incoming_frag* frag = NULL;
        sp_rpcfrag_request_state_t* request = NULL;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;

        /* used to reduce the indirection */
        in = &priv->incoming;
        frag = &in->frag;
        request = &frag->call_body.request;

        switch (request->vector_state) {
                case SP_STATE_VECTORED_REQUEST_INIT:
                        request->vector_sizer_state = 0;

                        addr = rpc_cred_addr (iobuf_ptr (in->iobuf));

                        /* also read verf flavour and verflen */
                        credlen = ntoh32 (*((uint32_t*)addr)) +
                                  RPC_AUTH_FLAVOUR_N_LENGTH_SIZE;

                        __socket_proto_init_pending (priv, credlen);

                        request->vector_state = SP_STATE_READING_CREDBYTES;

                /* fall through */

                case SP_STATE_READING_CREDBYTES:
                        __socket_proto_read (priv, ret);

                        request->vector_state = SP_STATE_READ_CREDBYTES;

                /* fall through */

                case SP_STATE_READ_CREDBYTES:
                        addr = rpc_verf_addr (frag->fragcurrent);
                        verflen = ntoh32 (*((uint32_t*)addr));

                        if (verflen == 0) {
                                request->vector_state = SP_STATE_READ_VERFBYTES;
                                goto sp_state_read_verfbytes;
                        }
                        __socket_proto_init_pending (priv, verflen);

                        request->vector_state = SP_STATE_READING_VERFBYTES;

                /* fall through */

                case SP_STATE_READING_VERFBYTES:
                        __socket_proto_read (priv, ret);

                        request->vector_state = SP_STATE_READ_VERFBYTES;

                /* fall through */

                case SP_STATE_READ_VERFBYTES:
                sp_state_read_verfbytes:
                        /* set the base_addr 'persistently' across multiple
                           calls
                           into the state machine */
                        in->proghdr_base_addr = frag->fragcurrent;

                        request->vector_sizer_state = vector_sizer (
                          request->vector_sizer_state, &readsize,
                          in->proghdr_base_addr, frag->fragcurrent);
                        __socket_proto_init_pending (priv, readsize);

                        request->vector_state = SP_STATE_READING_PROGHDR;

                /* fall through */

                case SP_STATE_READING_PROGHDR:
                        __socket_proto_read (priv, ret);

                        request->vector_state = SP_STATE_READ_PROGHDR;

                /* fall through */

                case SP_STATE_READ_PROGHDR:
                sp_state_read_proghdr:
                        request->vector_sizer_state = vector_sizer (
                          request->vector_sizer_state, &readsize,
                          in->proghdr_base_addr, frag->fragcurrent);
                        if (readsize == 0) {
                                request->vector_state =
                                  SP_STATE_READ_PROGHDR_XDATA;
                                goto sp_state_read_proghdr_xdata;
                        }

                        __socket_proto_init_pending (priv, readsize);

                        request->vector_state = SP_STATE_READING_PROGHDR_XDATA;

                /* fall through */

                case SP_STATE_READING_PROGHDR_XDATA:
                        __socket_proto_read (priv, ret);

                        request->vector_state = SP_STATE_READ_PROGHDR;
                        /* check if the vector_sizer() has more to say */
                        goto sp_state_read_proghdr;

                case SP_STATE_READ_PROGHDR_XDATA:
                sp_state_read_proghdr_xdata:
                        if (in->payload_vector.iov_base == NULL) {

                                size =
                                  RPC_FRAGSIZE (in->fraghdr) - frag->bytes_read;
                                iobuf =
                                  iobuf_get2 (this->ctx->iobuf_pool, size);
                                if (!iobuf) {
                                        ret = -1;
                                        break;
                                }

                                if (in->iobref == NULL) {
                                        in->iobref = iobref_new ();
                                        if (in->iobref == NULL) {
                                                ret = -1;
                                                iobuf_unref (iobuf);
                                                break;
                                        }
                                }

                                iobref_add (in->iobref, iobuf);
                                iobuf_unref (iobuf);

                                in->payload_vector.iov_base = iobuf_ptr (iobuf);

                                frag->fragcurrent = iobuf_ptr (iobuf);
                        }

                        request->vector_state = SP_STATE_READING_PROG;

                /* fall through */

                case SP_STATE_READING_PROG:
                        /* now read the remaining rpc msg into buffer pointed by
                         * fragcurrent
                         */

                        ret = __socket_read_simple_msg (this);

                        remaining_size =
                          RPC_FRAGSIZE (in->fraghdr) - frag->bytes_read;

                        if ((ret == -1) ||
                            ((ret == 0) && (remaining_size == 0) &&
                             RPC_LASTFRAG (in->fraghdr))) {
                                request->vector_state =
                                  SP_STATE_VECTORED_REQUEST_INIT;
                                in->payload_vector.iov_len =
                                  ((unsigned long)frag->fragcurrent -
                                   (unsigned long)in->payload_vector.iov_base);
                        }
                        break;
        }

out:
        return ret;
}

static int
__socket_read_request (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        uint32_t prognum = 0, procnum = 0, progver = 0;
        uint32_t remaining_size = 0;
        int ret = -1;
        char* buf = NULL;
        rpcsvc_vector_sizer vector_sizer = NULL;
        struct gf_sock_incoming* in = NULL;
        struct gf_sock_incoming_frag* frag = NULL;
        sp_rpcfrag_request_state_t* request = NULL;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;

        /* used to reduce the indirection */
        in = &priv->incoming;
        frag = &in->frag;
        request = &frag->call_body.request;

        switch (request->header_state) {

                case SP_STATE_REQUEST_HEADER_INIT:

                        __socket_proto_init_pending (priv, RPC_CALL_BODY_SIZE);

                        request->header_state = SP_STATE_READING_RPCHDR1;

                /* fall through */

                case SP_STATE_READING_RPCHDR1:
                        __socket_proto_read (priv, ret);

                        request->header_state = SP_STATE_READ_RPCHDR1;

                /* fall through */

                case SP_STATE_READ_RPCHDR1:
                        buf = rpc_prognum_addr (iobuf_ptr (in->iobuf));
                        prognum = ntoh32 (*((uint32_t*)buf));

                        buf = rpc_progver_addr (iobuf_ptr (in->iobuf));
                        progver = ntoh32 (*((uint32_t*)buf));

                        buf = rpc_procnum_addr (iobuf_ptr (in->iobuf));
                        procnum = ntoh32 (*((uint32_t*)buf));

                        if (priv->is_server) {
                                /* this check is needed as rpcsvc and rpc-clnt
                                 * actor structures are not same */
                                vector_sizer = rpcsvc_get_program_vector_sizer (
                                  (rpcsvc_t*)this->mydata, prognum, progver,
                                  procnum);
                        }

                        if (vector_sizer) {
                                ret = __socket_read_vectored_request (
                                  this, vector_sizer);
                        } else {
                                ret = __socket_read_simple_request (this);
                        }

                        remaining_size =
                          RPC_FRAGSIZE (in->fraghdr) - frag->bytes_read;

                        if ((ret == -1) ||
                            ((ret == 0) && (remaining_size == 0) &&
                             (RPC_LASTFRAG (in->fraghdr)))) {
                                request->header_state =
                                  SP_STATE_REQUEST_HEADER_INIT;
                        }

                        break;
        }

out:
        return ret;
}

static int
__socket_read_accepted_successful_reply (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        int ret = 0;
        struct iobuf* iobuf = NULL;
        gfs3_read_rsp read_rsp = {
                0,
        };
        ssize_t size = 0;
        ssize_t default_read_size = 0;
        XDR xdr;
        struct gf_sock_incoming* in = NULL;
        struct gf_sock_incoming_frag* frag = NULL;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;

        /* used to reduce the indirection */
        in = &priv->incoming;
        frag = &in->frag;

        switch (frag->call_body.reply.accepted_success_state) {

                case SP_STATE_ACCEPTED_SUCCESS_REPLY_INIT:
                        default_read_size =
                          xdr_sizeof ((xdrproc_t)xdr_gfs3_read_rsp, &read_rsp);

                        /* We need to store the current base address because we
                         * will
                         * need it after a partial read. */
                        in->proghdr_base_addr = frag->fragcurrent;

                        __socket_proto_init_pending (priv, default_read_size);

                        frag->call_body.reply.accepted_success_state =
                          SP_STATE_READING_PROC_HEADER;

                /* fall through */

                case SP_STATE_READING_PROC_HEADER:
                        __socket_proto_read (priv, ret);

                        /* there can be 'xdata' in read response, figure it out
                         */
                        default_read_size =
                          frag->fragcurrent - in->proghdr_base_addr;
                        xdrmem_create (&xdr, in->proghdr_base_addr,
                                       default_read_size, XDR_DECODE);

                        /* This will fail if there is xdata sent from server, if
                           not,
                           well and good, we don't need to worry about  */
                        xdr_gfs3_read_rsp (&xdr, &read_rsp);

                        free (read_rsp.xdata.xdata_val);

                        /* need to round off to proper roof (%4), as XDR packing
                           pads
                           the end of opaque object with '0' */
                        size = roof (read_rsp.xdata.xdata_len, 4);

                        if (!size) {
                                frag->call_body.reply.accepted_success_state =
                                  SP_STATE_READ_PROC_OPAQUE;
                                goto read_proc_opaque;
                        }

                        __socket_proto_init_pending (priv, size);

                        frag->call_body.reply.accepted_success_state =
                          SP_STATE_READING_PROC_OPAQUE;

                case SP_STATE_READING_PROC_OPAQUE:
                        __socket_proto_read (priv, ret);

                        frag->call_body.reply.accepted_success_state =
                          SP_STATE_READ_PROC_OPAQUE;

                case SP_STATE_READ_PROC_OPAQUE:
                read_proc_opaque:
                        if (in->payload_vector.iov_base == NULL) {

                                size = (RPC_FRAGSIZE (in->fraghdr) -
                                        frag->bytes_read);

                                iobuf =
                                  iobuf_get2 (this->ctx->iobuf_pool, size);
                                if (iobuf == NULL) {
                                        ret = -1;
                                        goto out;
                                }

                                if (in->iobref == NULL) {
                                        in->iobref = iobref_new ();
                                        if (in->iobref == NULL) {
                                                ret = -1;
                                                iobuf_unref (iobuf);
                                                goto out;
                                        }
                                }

                                iobref_add (in->iobref, iobuf);
                                iobuf_unref (iobuf);

                                in->payload_vector.iov_base = iobuf_ptr (iobuf);

                                in->payload_vector.iov_len = size;
                        }

                        frag->fragcurrent = in->payload_vector.iov_base;

                        frag->call_body.reply.accepted_success_state =
                          SP_STATE_READ_PROC_HEADER;

                /* fall through */

                case SP_STATE_READ_PROC_HEADER:
                        /* now read the entire remaining msg into new iobuf */
                        ret = __socket_read_simple_msg (this);
                        if ((ret == -1) ||
                            ((ret == 0) && RPC_LASTFRAG (in->fraghdr))) {
                                frag->call_body.reply.accepted_success_state =
                                  SP_STATE_ACCEPTED_SUCCESS_REPLY_INIT;
                        }

                        break;
        }

out:
        return ret;
}

#define rpc_reply_verflen_addr(fragcurrent) ((char*)fragcurrent - 4)
#define rpc_reply_accept_status_addr(fragcurrent) ((char*)fragcurrent - 4)

static int
__socket_read_accepted_reply (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        int ret = -1;
        char* buf = NULL;
        uint32_t verflen = 0, len = 0;
        uint32_t remaining_size = 0;
        struct gf_sock_incoming* in = NULL;
        struct gf_sock_incoming_frag* frag = NULL;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;
        /* used to reduce the indirection */
        in = &priv->incoming;
        frag = &in->frag;

        switch (frag->call_body.reply.accepted_state) {

                case SP_STATE_ACCEPTED_REPLY_INIT:
                        __socket_proto_init_pending (
                          priv, RPC_AUTH_FLAVOUR_N_LENGTH_SIZE);

                        frag->call_body.reply.accepted_state =
                          SP_STATE_READING_REPLY_VERFLEN;

                /* fall through */

                case SP_STATE_READING_REPLY_VERFLEN:
                        __socket_proto_read (priv, ret);

                        frag->call_body.reply.accepted_state =
                          SP_STATE_READ_REPLY_VERFLEN;

                /* fall through */

                case SP_STATE_READ_REPLY_VERFLEN:
                        buf = rpc_reply_verflen_addr (frag->fragcurrent);

                        verflen = ntoh32 (*((uint32_t*)buf));

                        /* also read accept status along with verf data */
                        len = verflen + RPC_ACCEPT_STATUS_LEN;

                        __socket_proto_init_pending (priv, len);

                        frag->call_body.reply.accepted_state =
                          SP_STATE_READING_REPLY_VERFBYTES;

                /* fall through */

                case SP_STATE_READING_REPLY_VERFBYTES:
                        __socket_proto_read (priv, ret);

                        frag->call_body.reply.accepted_state =
                          SP_STATE_READ_REPLY_VERFBYTES;

                        buf = rpc_reply_accept_status_addr (frag->fragcurrent);

                        frag->call_body.reply.accept_status =
                          ntoh32 (*(uint32_t*)buf);

                /* fall through */

                case SP_STATE_READ_REPLY_VERFBYTES:

                        if (frag->call_body.reply.accept_status == SUCCESS) {
                                ret = __socket_read_accepted_successful_reply (
                                  this);
                        } else {
                                /* read entire remaining msg into buffer pointed
                                 * to by
                                 * fragcurrent
                                 */
                                ret = __socket_read_simple_msg (this);
                        }

                        remaining_size =
                          RPC_FRAGSIZE (in->fraghdr) - frag->bytes_read;

                        if ((ret == -1) ||
                            ((ret == 0) && (remaining_size == 0) &&
                             (RPC_LASTFRAG (in->fraghdr)))) {
                                frag->call_body.reply.accepted_state =
                                  SP_STATE_ACCEPTED_REPLY_INIT;
                        }

                        break;
        }

out:
        return ret;
}

static int
__socket_read_denied_reply (rpc_transport_t* this)
{
        return __socket_read_simple_msg (this);
}

#define rpc_reply_status_addr(fragcurrent) ((char*)fragcurrent - 4)

static int
__socket_read_vectored_reply (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        int ret = 0;
        char* buf = NULL;
        uint32_t remaining_size = 0;
        struct gf_sock_incoming* in = NULL;
        struct gf_sock_incoming_frag* frag = NULL;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;
        in = &priv->incoming;
        frag = &in->frag;

        switch (frag->call_body.reply.status_state) {

                case SP_STATE_ACCEPTED_REPLY_INIT:
                        __socket_proto_init_pending (priv,
                                                     RPC_REPLY_STATUS_SIZE);

                        frag->call_body.reply.status_state =
                          SP_STATE_READING_REPLY_STATUS;

                /* fall through */

                case SP_STATE_READING_REPLY_STATUS:
                        __socket_proto_read (priv, ret);

                        buf = rpc_reply_status_addr (frag->fragcurrent);

                        frag->call_body.reply.accept_status =
                          ntoh32 (*((uint32_t*)buf));

                        frag->call_body.reply.status_state =
                          SP_STATE_READ_REPLY_STATUS;

                /* fall through */

                case SP_STATE_READ_REPLY_STATUS:
                        if (frag->call_body.reply.accept_status ==
                            MSG_ACCEPTED) {
                                ret = __socket_read_accepted_reply (this);
                        } else {
                                ret = __socket_read_denied_reply (this);
                        }

                        remaining_size =
                          RPC_FRAGSIZE (in->fraghdr) - frag->bytes_read;

                        if ((ret == -1) ||
                            ((ret == 0) && (remaining_size == 0) &&
                             (RPC_LASTFRAG (in->fraghdr)))) {
                                frag->call_body.reply.status_state =
                                  SP_STATE_ACCEPTED_REPLY_INIT;
                                in->payload_vector.iov_len =
                                  (unsigned long)frag->fragcurrent -
                                  (unsigned long)in->payload_vector.iov_base;
                        }
                        break;
        }

out:
        return ret;
}

static int
__socket_read_simple_reply (rpc_transport_t* this)
{
        return __socket_read_simple_msg (this);
}

#define rpc_xid_addr(buf) (buf)

static int
__socket_read_reply (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        char* buf = NULL;
        int32_t ret = -1;
        rpc_request_info_t* request_info = NULL;
        struct iobuf* iobuf = NULL;
        char map_xid = 0;
        struct gf_sock_incoming* in = NULL;
        struct gf_sock_incoming_frag* frag = NULL;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;
        in = &priv->incoming;
        frag = &in->frag;

        buf = rpc_xid_addr (iobuf_ptr (in->iobuf));

        if (in->request_info == NULL) {
#if 1
                in->request_info = GF_CALLOC (1, sizeof (*request_info),
                                              gf_common_mt_rpc_trans_reqinfo_t);
#else
                iobuf =
                  iobuf_get2 (this->ctx->iobuf_pool, sizeof (*request_info));
                in->request_info = iobuf_ptr (iobuf);
                in->request_info->iobuf = iobuf;
#endif /* USE_IOBUF */
                if (in->request_info == NULL) {
                        goto out;
                }

                map_xid = 1;
        }

        request_info = in->request_info;

        if (map_xid) {
                request_info->xid = ntoh32 (*((uint32_t*)buf));

                /* release priv->lock, so as to avoid deadlock b/w conn->lock
                 * and priv->lock, since we are doing an upcall here.
                 */
                frag->state = SP_STATE_NOTIFYING_XID;

                ret = rpc_transport_notify (this, RPC_TRANSPORT_MAP_XID_REQUEST,
                                            in->request_info);

                /* Transition back to externally visible state. */
                frag->state = SP_STATE_READ_MSGTYPE;

                if (ret == -1) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "notify for event MAP_XID failed for %s",
                                this->peerinfo.identifier);
                        goto out;
                }
        }

        if ((request_info->prognum == GLUSTER_FOP_PROGRAM) &&
            (request_info->procnum == GF_FOP_READ)) {
                if (map_xid && request_info->rsp.rsp_payload_count != 0) {
                        in->iobref = iobref_ref (request_info->rsp.rsp_iobref);
                        in->payload_vector = *request_info->rsp.rsp_payload;
                }

                ret = __socket_read_vectored_reply (this);
        } else {
                ret = __socket_read_simple_reply (this);
        }
out:
        return ret;
}

/* returns the number of bytes yet to be read in a fragment */
static int
__socket_read_frag (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        int32_t ret = 0;
        char* buf = NULL;
        uint32_t remaining_size = 0;
        struct gf_sock_incoming* in = NULL;
        struct gf_sock_incoming_frag* frag = NULL;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;
        /* used to reduce the indirection */
        in = &priv->incoming;
        frag = &in->frag;

        switch (frag->state) {
                case SP_STATE_NADA:
                        __socket_proto_init_pending (priv, RPC_MSGTYPE_SIZE);

                        frag->state = SP_STATE_READING_MSGTYPE;

                /* fall through */

                case SP_STATE_READING_MSGTYPE:
                        __socket_proto_read (priv, ret);

                        frag->state = SP_STATE_READ_MSGTYPE;
                /* fall through */

                case SP_STATE_READ_MSGTYPE:
                        buf = rpc_msgtype_addr (iobuf_ptr (in->iobuf));
                        in->msg_type = ntoh32 (*((uint32_t*)buf));

                        if (in->msg_type == CALL) {
                                ret = __socket_read_request (this);
                        } else if (in->msg_type == REPLY) {
                                ret = __socket_read_reply (this);
                        } else if (in->msg_type == GF_UNIVERSAL_ANSWER) {
                                gf_log (
                                  "rpc", GF_LOG_ERROR,
                                  "older version of protocol/process trying to "
                                  "connect from %s. use newer version on that "
                                  "node",
                                  this->peerinfo.identifier);
                        } else {
                                gf_log ("rpc", GF_LOG_ERROR,
                                        "wrong MSG-TYPE (%d) received from %s",
                                        in->msg_type,
                                        this->peerinfo.identifier);
                                ret = -1;
                        }

                        remaining_size =
                          RPC_FRAGSIZE (in->fraghdr) - frag->bytes_read;

                        if ((ret == -1) ||
                            ((ret == 0) && (remaining_size == 0) &&
                             (RPC_LASTFRAG (in->fraghdr)))) {
                                frag->state = SP_STATE_NADA;
                        }

                        break;

                case SP_STATE_NOTIFYING_XID:
                        /* Another epoll thread is notifying higher layers
                         *of reply's xid. */
                        errno = EAGAIN;
                        return -1;
                        break;
        }

out:
        return ret;
}

static void
__socket_reset_priv (socket_private_t* priv)
{
        struct gf_sock_incoming* in = NULL;

        /* used to reduce the indirection */
        in = &priv->incoming;

        if (in->iobref) {
                iobref_unref (in->iobref);
                in->iobref = NULL;
        }

        if (in->iobuf) {
                iobuf_unref (in->iobuf);
                in->iobuf = NULL;
        }

        if (in->request_info != NULL) {
#if 1
                GF_FREE (in->request_info);
#else
                iobuf_unref (in->request_info->iobuf);
#endif /* USE_IOBUF */
                in->request_info = NULL;
        }

        memset (&in->payload_vector, 0, sizeof (in->payload_vector));
}

static int
__socket_proto_state_machine (rpc_transport_t* this,
                              rpc_transport_pollin_t** pollin)
{
        int ret = -1;
        socket_private_t* priv = NULL;
        struct iobuf* iobuf = NULL;
        struct iobref* iobref = NULL;
        struct iovec vector[2];
        struct gf_sock_incoming* in = NULL;
        struct gf_sock_incoming_frag* frag = NULL;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;
        /* used to reduce the indirection */
        in = &priv->incoming;
        frag = &in->frag;

        while (in->record_state != SP_STATE_COMPLETE) {
                switch (in->record_state) {

                        case SP_STATE_NADA:
                                in->total_bytes_read = 0;
                                in->payload_vector.iov_len = 0;

                                in->pending_vector = in->vector;
                                in->pending_vector->iov_base = &in->fraghdr;

                                in->pending_vector->iov_len =
                                  sizeof (in->fraghdr);

                                in->record_state = SP_STATE_READING_FRAGHDR;

                        /* fall through */

                        case SP_STATE_READING_FRAGHDR:
                                ret = __socket_readv (this, in->pending_vector,
                                                      1, &in->pending_vector,
                                                      &in->pending_count, NULL);
                                if (ret == -1)
                                        goto out;

                                if (ret > 0) {
                                        gf_log (this->name, GF_LOG_TRACE,
                                                "partial "
                                                "fragment header read");
                                        goto out;
                                }

                                if (ret == 0) {
                                        in->record_state =
                                          SP_STATE_READ_FRAGHDR;
                                }
                        /* fall through */

                        case SP_STATE_READ_FRAGHDR:

                                in->fraghdr = ntoh32 (in->fraghdr);
                                in->total_bytes_read +=
                                  RPC_FRAGSIZE (in->fraghdr);

                                if (in->total_bytes_read >= GF_UNIT_GB) {
                                        ret = -ENOMEM;
                                        goto out;
                                }

                                iobuf = iobuf_get2 (this->ctx->iobuf_pool,
                                                    (in->total_bytes_read +
                                                     sizeof (in->fraghdr)));
                                if (!iobuf) {
                                        ret = -ENOMEM;
                                        goto out;
                                }

                                if (in->iobuf == NULL) {
                                        /* first fragment */
                                        frag->fragcurrent = iobuf_ptr (iobuf);
                                } else {
                                        /* second or further fragment */
                                        memcpy (iobuf_ptr (iobuf),
                                                iobuf_ptr (in->iobuf),
                                                in->total_bytes_read -
                                                  RPC_FRAGSIZE (in->fraghdr));
                                        iobuf_unref (in->iobuf);
                                        frag->fragcurrent =
                                          (char*)iobuf_ptr (iobuf) +
                                          in->total_bytes_read -
                                          RPC_FRAGSIZE (in->fraghdr);
                                        frag->pending_vector->iov_base =
                                          frag->fragcurrent;
                                        in->pending_vector =
                                          frag->pending_vector;
                                }

                                in->iobuf = iobuf;
                                in->iobuf_size = 0;
                                in->record_state = SP_STATE_READING_FRAG;
                        /* fall through */

                        case SP_STATE_READING_FRAG:
                                ret = __socket_read_frag (this);

                                if ((ret == -1) ||
                                    (frag->bytes_read !=
                                     RPC_FRAGSIZE (in->fraghdr))) {
                                        goto out;
                                }

                                frag->bytes_read = 0;

                                if (!RPC_LASTFRAG (in->fraghdr)) {
                                        in->pending_vector = in->vector;
                                        in->pending_vector->iov_base =
                                          &in->fraghdr;
                                        in->pending_vector->iov_len =
                                          sizeof (in->fraghdr);
                                        in->record_state =
                                          SP_STATE_READING_FRAGHDR;
                                        break;
                                }

                                /* we've read the entire rpc record, notify the
                                 * upper layers.
                                 */
                                if (pollin != NULL) {
                                        int count = 0;
                                        in->iobuf_size =
                                          (in->total_bytes_read -
                                           in->payload_vector.iov_len);

                                        memset (vector, 0, sizeof (vector));

                                        if (in->iobref == NULL) {
                                                in->iobref = iobref_new ();
                                                if (in->iobref == NULL) {
                                                        ret = -1;
                                                        goto out;
                                                }
                                        }

                                        vector[count].iov_base =
                                          iobuf_ptr (in->iobuf);
                                        vector[count].iov_len = in->iobuf_size;

                                        iobref = in->iobref;

                                        count++;

                                        if (in->payload_vector.iov_base !=
                                            NULL) {
                                                vector[count] =
                                                  in->payload_vector;
                                                count++;
                                        }

                                        *pollin = rpc_transport_pollin_alloc (
                                          this, vector, count, in->iobuf,
                                          iobref, in->request_info);
                                        iobuf_unref (in->iobuf);
                                        in->iobuf = NULL;

                                        if (*pollin == NULL) {
                                                gf_log (this->name,
                                                        GF_LOG_WARNING,
                                                        "transport pollin "
                                                        "allocation failed");
                                                ret = -1;
                                                goto out;
                                        }
                                        if (in->msg_type == REPLY)
                                                (*pollin)->is_reply = 1;

                                        in->request_info = NULL;
                                }
                                in->record_state = SP_STATE_COMPLETE;
                                break;

                        case SP_STATE_COMPLETE:
                                /* control should not reach here */
                                gf_log (
                                  this->name, GF_LOG_WARNING,
                                  "control reached to "
                                  "SP_STATE_COMPLETE, which should not have "
                                  "happened");
                                break;
                }
        }

        if (in->record_state == SP_STATE_COMPLETE) {
                in->record_state = SP_STATE_NADA;
                __socket_reset_priv (priv);
        }

out:

        return ret;
}

static int
socket_proto_state_machine (rpc_transport_t* this,
                            rpc_transport_pollin_t** pollin)
{
        socket_private_t* priv = NULL;
        int ret = 0;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;

        //-- pthread_mutex_lock (&priv->lock);
        {
                ret = __socket_proto_state_machine (this, pollin);
        }
        //-- pthread_mutex_unlock (&priv->lock);

out:
        return ret;
}

static int
socket_event_poll_in (rpc_transport_t* this)
{
        int ret = -1;
        rpc_transport_pollin_t* pollin = NULL;
        socket_private_t* priv = this->private;

        ret = socket_proto_state_machine (this, &pollin);
        if (pollin) {
                priv->ot_state = OT_CALLBACK;
                ret = rpc_transport_notify (this, RPC_TRANSPORT_MSG_RECEIVED,
                                            pollin);

                if (priv->ot_state == OT_CALLBACK) {
                        priv->ot_state = OT_RUNNING;
                }
                rpc_transport_pollin_destroy (pollin);
        }

        return ret;
}

static int
socket_connect_finish (rpc_transport_t* this, int status)
{
        int ret = -1;
        socket_private_t* priv = NULL;
        rpc_transport_event_t event = 0;
        char notify_rpc = 0;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;

        //-- pthread_mutex_lock (&priv->lock);
        {
                if (priv->connected != 0) {
                        ret = 0;
                        goto unlock;
                }

                if (status != 0) {
                        ret = -1;

                        if (!priv->connect_finish_log) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "sock %p connection to %s failed (%s)",
                                        &priv->handle,
                                        this->peerinfo.identifier,
                                        uv_strerror (status));
                                priv->connect_finish_log = 1;
                        }
                        __socket_disconnect (this);
                        goto unlock;
                } else {
                        notify_rpc = 1;

                        this->myinfo.sockaddr_len =
                          sizeof (this->myinfo.sockaddr);

                        ret = uv_tcp_getsockname (&priv->handle,
                                                  SA (&this->myinfo.sockaddr),
                                                  &this->myinfo.sockaddr_len);
                        if (ret != 0) {
                                gf_log (this->name, GF_LOG_WARNING,
                                        "getsockname on sock(%p) failed (%s)",
                                        &priv->handle, uv_strerror (ret));
                                __socket_disconnect (this);
                                event = GF_EVENT_POLLERR;
                                ret = -1;
                                goto unlock;
                        }

                        priv->connected = 1;
                        priv->connect_finish_log = 0;
                        event = RPC_TRANSPORT_CONNECT;
                }
        }
unlock:
        //-- pthread_mutex_unlock (&priv->lock);

        gf_log (this->name, GF_LOG_DEBUG,
                "connected to %s, (tid=%p, this=%p, priv->connected=%d)",
                this->peerinfo.identifier, pthread_self (), this,
                priv->connected);

        if (notify_rpc) {
                rpc_transport_notify (this, event, this);
        }
out:
        return ret;
}

static int
socket_server_event_handler (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        int ret = 0;
        uv_tcp_t* sock = 0;
        uv_tcp_t* new_sock = 0;
        rpc_transport_t* new_trans = NULL;
        struct sockaddr_storage new_sockaddr = {
                0,
        };
        socklen_t addrlen = sizeof (new_sockaddr);
        socket_private_t* new_priv = NULL;
        glusterfs_ctx_t* ctx = NULL;
        char* cname = NULL;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);
        GF_VALIDATE_OR_GOTO ("socket", this->xl, out);

        THIS = this->xl;
        priv = this->private;
        ctx = this->ctx;
        sock = &priv->handle;

        //-- pthread_mutex_lock (&priv->lock);
        {
                new_trans =
                  GF_CALLOC (1, sizeof (*new_trans), gf_common_mt_rpc_trans_t);
                if (!new_trans) {
                        goto unlock;
                }

                ret = pthread_mutex_init (&new_trans->lock, NULL);
                if (ret == -1) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "pthread_mutex_init() failed: %s",
                                strerror (errno));
                        GF_FREE (new_trans);
                        goto unlock;
                }
                INIT_LIST_HEAD (&new_trans->list);

                new_trans->name = gf_strdup (this->name);

                memcpy (&new_trans->peerinfo.sockaddr, &new_sockaddr, addrlen);
                new_trans->peerinfo.sockaddr_len = addrlen;

                new_trans->myinfo.sockaddr_len =
                  sizeof (new_trans->myinfo.sockaddr);

                ret =
                  uv_tcp_getsockname (sock, SA (&new_trans->myinfo.sockaddr),
                                      &new_trans->myinfo.sockaddr_len);
                if (ret != 0) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "getsockname on %p failed (%s)", sock,
                                uv_strerror (errno));
                        GF_FREE (new_trans->name);
                        GF_FREE (new_trans);
                        goto unlock;
                }

                get_transport_identifiers (new_trans);
                ret = socket_init (new_trans);
                if (ret != 0) {
                        GF_FREE (new_trans->name);
                        GF_FREE (new_trans);
                        goto unlock;
                }
                new_trans->ops = this->ops;
                new_trans->init = this->init;
                new_trans->fini = this->fini;
                new_trans->ctx = ctx;
                new_trans->xl = this->xl;
                new_trans->mydata = this->mydata;
                new_trans->notify = this->notify;
                new_trans->listener = this;
                new_priv = new_trans->private;

                if (new_sockaddr.ss_family == AF_UNIX) {
                        new_priv->use_ssl = _gf_false;
                } else {
                        switch (priv->srvr_ssl) {
                                case MGMT_SSL_ALWAYS:
                                        /* Glusterd with secure_mgmt. */
                                        new_priv->use_ssl = _gf_true;
                                        break;
                                case MGMT_SSL_COPY_IO:
                                        /* Glusterfsd. */
                                        new_priv->use_ssl = priv->ssl_enabled;
                                        break;
                                default:
                                        new_priv->use_ssl = _gf_false;
                        }
                }

                new_sock = &new_priv->handle;
                new_priv->own_thread = priv->own_thread;

                ret = uv_accept ((uv_stream_t*)sock, (uv_stream_t*)new_sock);
                if (ret != 0) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "accept on %p failed (%s)", sock,
                                uv_strerror (ret));
                        goto unlock;
                }

                if (priv->nodelay) {
                        ret = uv_tcp_nodelay (new_sock, 1);
                        if (ret != 0) {
                                gf_log (this->name, GF_LOG_WARNING,
                                        "setsockopt() failed for "
                                        "NODELAY (%s)",
                                        uv_strerror (ret));
                        }
                }

                if (priv->keepalive) {
                        ret =
                          uv_tcp_keepalive (new_sock, 1, priv->keepaliveintvl +
                                                           priv->keepaliveidle);
                        if (ret != 0)
                                gf_log (this->name, GF_LOG_WARNING,
                                        "Failed to set keep-alive: %s",
                                        uv_strerror (ret));
                }

                new_priv->ssl_ctx = priv->ssl_ctx;
                if (new_priv->use_ssl && !new_priv->own_thread) {
                        cname = ssl_setup_connection (new_trans, 1);
                        if (!cname) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "server setup failed");
                                GF_FREE (new_trans->name);
                                GF_FREE (new_trans);
                                goto unlock;
                        }
                        this->ssl_name = cname;
                }

                //-- pthread_mutex_lock (&new_priv->lock);
                {
                        /*
                         * In the own_thread case, this is used to
                         * indicate that we're initializing a server
                         * connection.
                         */
                        new_priv->connected = 1;
                        new_priv->is_server = _gf_true;
                        rpc_transport_ref (new_trans);
                }
                pthread_mutex_unlock (&new_priv->lock);

                ret = event_register (ctx->event_pool, this,
                                      socket_register_handler);
                if (ret != 0) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "failed to register the socket "
                                "with event");

                        if (ret > 0)
                                ret = 0;
                }

                if (ret == -1) {
                        rpc_transport_unref (new_trans);
                        goto unlock;
                }

                if (!priv->own_thread) {
                        rpc_transport_notify (this, RPC_TRANSPORT_ACCEPT,
                                              new_trans);
                }
        }
unlock:
//-- pthread_mutex_unlock (&priv->lock);

out:
        if (cname && (cname != this->ssl_name)) {
                GF_FREE (cname);
        }
        return ret;
}

void*
socket_connect_error_cbk (void* opaque)
{
        socket_connect_error_state_t* arg;

        GF_ASSERT (opaque);

        arg = opaque;
        THIS = arg->this;

        rpc_transport_notify (arg->trans, RPC_TRANSPORT_DISCONNECT, arg->trans);

        if (arg->refd)
                rpc_transport_unref (arg->trans);

        GF_FREE (opaque);
        return NULL;
}

static void
socket_fix_ssl_opts (rpc_transport_t* this, socket_private_t* priv,
                     uint16_t port)
{
        if (port == GF_DEFAULT_SOCKET_LISTEN_PORT) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "%s SSL for portmapper connection",
                        priv->mgmt_ssl ? "enabling" : "disabling");
                priv->use_ssl = priv->mgmt_ssl;
        } else if (priv->ssl_enabled && !priv->use_ssl) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "re-enabling SSL for I/O connection");
                priv->use_ssl = _gf_true;
        }
}

static inline size_t
iovec_get_size (struct iovec* vec, uint32_t count)
{
        int i;
        size_t size = 0;
        for (i = 0; i < count; i++)
                size += vec[i].iov_len;
        return size;
}

static inline size_t
bufq_get_size (struct bufq* read_q)
{
        struct bufq* entry = NULL;
        size_t size = 0;
        int i = 0;

        list_for_each_entry (entry, &read_q->list, list)
        {
                size += (entry->vector.iov_len - entry->read);
        }

        return size;
}

static inline size_t
writeq_get_size (struct ioq* write_q)
{
        struct ioq* entry = NULL;
        size_t size = 0;
        int i = 0;

        list_for_each_entry (entry, &write_q->list, list)
        {
                for (i = 0; i < entry->pending_count; i++)
                        size += entry->vector[i].iov_len;
        }

        return size;
}

static void
on_buf_alloc (uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
        rpc_transport_t* this = NULL;
        socket_private_t* priv = NULL;
        struct iobuf* iobuf = NULL;
        struct bufq* bufq = NULL;
        int frame_size = 256 * 1024;
        int bufq_size = 0;
        int ret = -1;

        priv = CONTAINER_OF (handle, socket_private_t, handle);
        this = priv->translator;

        if (suggested_size < frame_size)
                suggested_size = frame_size;

        iobuf = iobuf_get2 (this->ctx->iobuf_pool, suggested_size);
        GF_ASSERT (iobuf);

        bufq_size = iobuf_pagesize (iobuf) - sizeof (*bufq);

        bufq = iobuf_ptr (iobuf) + bufq_size;
        bufq->iobuf = iobuf;

        buf->base = iobuf_ptr (iobuf);
        buf->len = bufq_size;

out:
        return;
}

static void
free_bufq (struct bufq* buf_ioq)
{
        list_del_init (&buf_ioq->list);
        iobuf_unref (buf_ioq->iobuf);
}

static int
socket_write_start (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        struct ioq* write_q = NULL;
        struct iobuf* iobuf = NULL;
        struct req_buf* req_buf = NULL;
        uv_buf_t bufs[MAX_IOVEC];
        int i = 0, count = 0;
        int len = 0;
        int ret = -1;

        priv = this->private;

        uv_mutex_lock (&priv->comm_lock);
        list_for_each_entry (write_q, &priv->write_q, list)
        {
                list_del_init (&write_q->list);
                break;
        }
        uv_mutex_unlock (&priv->comm_lock);

        if (write_q == NULL) {
                ret = -1;
                goto out;
        }

#ifdef NEVER
        req_buf = GF_CALLOC (1, sizeof (struct req_buf), gf_sock_mt_req);
        if (req_buf == NULL) {
                ret = -1;
                gf_log (this->name, GF_LOG_ERROR,
                        "failure on allocating req_buf.");
                goto out;
        }
#else
        iobuf = iobuf_get2 (this->ctx->iobuf_pool, sizeof (struct req_buf));
        req_buf = iobuf_ptr (iobuf);
        req_buf->iobuf = iobuf;
        req_buf->priv = priv;
        req_buf->data = write_q;
#endif /* NEVER */

#if 0
	for (int i = 0; i < write_q->count; i++) {
		gf_log (this->name, GF_LOG_ERROR, "WRITE: "
						  "tid=%p, %p, c=%d,i=%d, len=%d",
			pthread_self (), write_q->bufs[i].base, write_q->count, i,
			write_q->bufs[i].len);
	}
#endif /* NEVER */

        priv->wrstate = C_BUSY;
        priv->wrcount++;

        count = 0;
        for (; i < write_q->pending_count; i++) {
                if (write_q->pending_vector[i].iov_len > 0) {
                        bufs[count].base = write_q->pending_vector[i].iov_base;
                        bufs[count].len = write_q->pending_vector[i].iov_len;

                        len += write_q->pending_vector[i].iov_len;
                }
                count++;
        }

        ret = uv_write (&req_buf->write_req, &priv->handle, bufs, count,
                        &socket_write_cb);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR,
                        "failure on writing socket: priv=%p, %s.", priv,
                        uv_strerror (ret));
                goto out;
        }

        uv_mutex_lock (&priv->comm_lock);
        this->total_bytes_write += len;
        uv_mutex_unlock (&priv->comm_lock);

        uv_timer_again (&priv->timer);

out:
        return ret;
}

static int
socket_write_directly (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        struct ioq *write_q = NULL, *n;
        size_t size = 0, written = 0;
        uv_buf_t bufs[MAX_IOVEC];
        int i = 0, count = 0;

        priv = this->private;

        uv_mutex_lock (&priv->comm_lock);

        list_for_each_entry_safe (write_q, n, &priv->write_q, list)
        {
#if 0
	for (int i = 0; i < write_q->count; i++) {
			gf_log (this->name, GF_LOG_ERROR, "WWWWWWWW"
							  "tid=%p, %p, len=%d",
				pthread_self (), write_q->bufs[i].base,
				write_q->bufs[i].len);
	}
#endif /* NEVER */

                count = 0;
                for (; i < write_q->pending_count; i++) {
                        if (write_q->pending_vector[i].iov_len > 0) {
                                bufs[count].base =
                                  write_q->pending_vector[i].iov_base;
                                bufs[count].len =
                                  write_q->pending_vector[i].iov_len;
                        }
                        count++;
                }

                size = uv_try_write (&priv->handle, bufs, count);
                if (size <= 0) {
                        gf_msg (this->name, GF_LOG_ERROR, 0,
                                LG_MSG_POLL_IGNORE_MULTIPLE_THREADS,
                                "write error: this=%p, rdstate=%d, (%s)", this,
                                priv->rdstate, uv_strerror (size));
                        break;
                }

#ifdef DEBUG
                written = 0;
                for (int i = 0; i < count; i++)
                        written += bufs[i].len;

                GF_ASSERT (written == size);
#endif /* DEBUG */

                __socket_ioq_entry_free (write_q);
                this->total_bytes_write += size;
        }

        uv_mutex_unlock (&priv->comm_lock);

        return size;
}

static int
socket_write_simultaneous (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        int max = 3;
        int empty = 0;

        priv = this->private;

        while (max--) {
                uv_mutex_lock (&priv->comm_lock);
                empty = list_empty (&priv->write_q);
                uv_mutex_unlock (&priv->comm_lock);
                if (!empty) {
                        socket_write_start (this);
                }
        }
        return 0;
}

static struct action_req*
socket_get_action (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        struct action_req* action_req = NULL;

        priv = this->private;

        uv_mutex_lock (&priv->comm_lock);
        {
                if (!list_empty (&priv->action_q)) {
                        action_req = list_first_entry (&priv->action_q,
                                                       struct action_req, list);
                        list_del_init (action_req);
                }
        }
        uv_mutex_unlock (&priv->comm_lock);

        return action_req;
}

static int socket_do_kill (rpc_transport_t* this);

static int
socket_do_connect (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        gf_boolean_t write = _gf_false;

        priv = this->private;

        if (priv->connected == 1) {
                return S_HANDSHAKE;
        }
        else
                return S_REQ_CONNECT;
}

static int
socket_do_handshake (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        gf_boolean_t write = _gf_false;

        priv = this->private;

        if (priv->connected == -1)
                return socket_do_kill (this);

        /*
                write_stop -> write_busy -> write_done -> read_stop ->
                read_busy -> read_done ->
        */

        if (priv->wrstate == C_DONE) {
                priv->wrstate = C_STOP;
        }

        if (priv->rdstate == C_DONE) {
                priv->rdstate = C_STOP;
        }

        if (priv->rdstate == C_BUSY) {
                priv->rdstate = C_STOP;
                uv_read_stop (&priv->handle);
        }

        if (priv->wrstate == C_STOP && priv->rdstate == C_STOP) {
                uv_mutex_lock (&priv->comm_lock);
                write = !list_empty (&priv->write_q);
                uv_mutex_unlock (&priv->comm_lock);

                if (write) {
                        socket_write_simultaneous (this);
                } else
                        socket_read_start (this);
        } else if (priv->wrstate == C_DONE && priv->rdstate == C_STOP) {
                socket_read_start (this);
        }

        return S_HANDSHAKE;
}

static int
socket_do_kill (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        struct ioq *write_q = NULL, *n;

        priv = this->private;

        uv_mutex_lock (&priv->comm_lock);

        list_for_each_entry_safe (write_q, n, &priv->write_q, list)
        {
                //-- pthread_mutex_lock (&priv->lock);
                {
                        __socket_ioq_entry_free (write_q);
                }
                //-- pthread_mutex_unlock (&priv->lock);
        }

        uv_mutex_unlock (&priv->comm_lock);

        socket_close (this);

        return s_almost_dead_0;
}

static int
socket_do_almost_dead (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;

        priv = this->private;

        GF_ASSERT (priv->state >= s_almost_dead_0);
        return priv->state + 1; /* Another finalizer completed. */
}

static int
socket_do_revive (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;

        priv = this->private;

        return S_REQ_CONNECT;
}

static int
socket_do_next (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        sess_state_t new_state;
        int ret = -1;

        priv = this->private;

        if (priv->connected == 1) {
                if (priv->state > S_KILL)
                        priv->state = S_REQ_CONNECT;
        }

#if 0
       gf_log (this->name, GF_LOG_ERROR,
                "ZZZZZZZZZZZZ:tid=%p,state=%d,rdstate=%d,wrstate=%d, wrc=%d, rdc=%d",
                pthread_self (), priv->state, priv->rdstate, priv->wrstate,
                priv->wrcount, priv->rdcount);
#endif /* NEVER */

        switch (priv->state) {
                case S_REQ_CONNECT:
                        new_state = socket_do_connect (this);
                        break;
                case S_HANDSHAKE:
                        new_state = socket_do_handshake (this);
                        break;
                case S_KILL:
                        new_state = socket_do_kill (this);
                        break;
                case s_almost_dead_0:
                case s_almost_dead_1:
                case s_almost_dead_2:
                case s_almost_dead_3:
                case s_almost_dead_4:
                        new_state = socket_do_almost_dead (this);
                        break;
                case S_DEAD:
                        new_state = socket_do_revive (this);
                        break;
                default:
                        GF_ASSERT (0 && "No this state");
                        new_state = S_DEAD;
                        break;
        }

        priv->state = new_state;

        return ret;
}

static void
socket_error_cb (rpc_transport_t* this, int status)
{
        socket_private_t* priv = NULL;

        priv = this->private;

        /* Logging has happened already in earlier cases */
        gf_log ("transport", GF_LOG_DEBUG,
                "disconnecting now:status=%d, fd=%p, %s", status, &priv->handle,
                uv_strerror (status));
        socket_event_poll_err (this);

        /* rpc_transport will never quit.
        rpc_transport_unref (this);
        */
}

static void
socket_close_cb (uv_handle_t* handle);


static void
socket_read_cb (uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
        rpc_transport_t* this = NULL;
        socket_private_t* priv = NULL;
        struct bufq* bufq = NULL;
        struct list_head* node = NULL;
        int before = 0, after = 0;
        int handle_incoming = 0;
        int ret = -1;

        priv = CONTAINER_OF (stream, socket_private_t, handle);
        this = priv->translator;

        THIS = this->xl;

        priv->rdcount = 0;

#if 0
        gf_msg (this->name, GF_LOG_ERROR, 0,
                LG_MSG_POLL_IGNORE_MULTIPLE_THREADS,
                "READ: tid=%p, rdstate=%d, nread=%ld", pthread_self(),
                priv->rdstate, nread);
#endif /* NEVER */

        bufq = (struct bufq*)(buf->base + buf->len);

        if (nread <= 0) {
                if (buf->base != NULL)
                        iobuf_unref (bufq->iobuf);

                if (nread == 0 || nread == UV_EOF || nread == UV_EAGAIN) {
                        handle_incoming = 1;
                } else {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "End of read from peer %s(%s)",
                                this->peerinfo.identifier, uv_strerror (nread));

                        socket_error_cb (this, nread);

                        if (nread == UV_ECONNRESET) {
                                priv->handle.data = priv;
                                rpc_transport_notify (this, RPC_TRANSPORT_DISCONNECT, this);
                                //uv_close (&priv->handle, socket_close_cb);
                                //uv_timer_again (&priv->timer);
                        }
                }
        } else if (nread <= buf->len) {
                uv_mutex_lock (&priv->comm_lock);
                {
#if 0
                        size_t dd = bufq_get_size (&priv->read_q);
#endif /* NEVER */

                        INIT_LIST_HEAD (&bufq->list);
                        bufq->vector.iov_base = buf->base;
                        bufq->vector.iov_len = nread;
                        bufq->read = 0;

                        list_add_tail (&bufq->list, &priv->read_q);

#if 0
                        gf_msg (this->name, GF_LOG_ERROR, 0,
                                LG_MSG_POLL_IGNORE_MULTIPLE_THREADS,
                                "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm:nread=%d. "
                                "orign=%d.readf=%d, tid=%p, addr=%p",
                                nread, dd, bufq_get_size (&priv->read_q),
                                pthread_self (), bufq);

                        if (dd + nread != bufq_get_size (&priv->read_q)) {
                                __asm__("int $3");
                        }
#endif /* NEVER */
                }
                uv_mutex_unlock (&priv->comm_lock);

                handle_incoming = (nread < buf->len);
        }

        if (handle_incoming) {
                priv->rdstate = C_DONE;
                uv_read_stop (&priv->handle);

                before = bufq_get_size (&priv->read_q);
                while (before > 0) {
                        socket_event_poll_in (this);
                        after = bufq_get_size (&priv->read_q);
                        if (after < before)
                                before = after;
                        else
                                break;
                }

                socket_do_next (this);
        }
}

static void
socket_write_cb (uv_write_t* req, int status)
{
        rpc_transport_t* this = NULL;
        socket_private_t* priv = NULL;
        struct req_buf* req_buf = NULL;
        struct req_buf* next_req_buf = NULL;
        struct ioq* write_q = NULL;
        struct ioq* ioq = NULL;
        ssize_t len = 0;
        int write_empty = 0;

        if (status == UV_ECANCELED) {
                socket_do_next (this);
                return; /* Handle has been closed. */
        }

        req_buf = CONTAINER_OF (req, struct req_buf, req);
        priv = req_buf->priv;
        write_q = req_buf->data;
#ifdef NEVER
        GF_FREE (req_buf);
#else
        iobuf_unref (req_buf->iobuf);
#endif /* NEVER */

        ioq = write_q;
        this = priv->translator;

        priv->result = status;
        priv->wrcount = 0;

        if (status == 0) {
                len = ioq->pending_count;
                if (ioq) {
                        //-- pthread_mutex_lock (&priv->lock);
                        {
                                __socket_ioq_entry_free (ioq);
                        }
                        //-- pthread_mutex_unlock (&priv->lock);
                }

                uv_mutex_lock (&priv->comm_lock);
                write_empty = list_empty (&priv->write_q);
                uv_mutex_unlock (&priv->comm_lock);

                if (write_empty) {
                        priv->wrstate = C_DONE;
                        priv->fcstate &= ~FC_WRITE;
                        socket_do_next (this);
                } else {
                        socket_write_start (this);
                }

                rpc_transport_notify (this, RPC_TRANSPORT_MSG_SENT,
                      NULL);
        } else {
                gf_log (this->name, GF_LOG_ERROR,
                        "failure on writing socket:%s.", uv_strerror (status));

                /* restore the write data to queue */
                uv_mutex_lock (&priv->comm_lock);
                list_add (&ioq->list, &priv->write_q);
                uv_mutex_unlock (&priv->comm_lock);

                if (status == UV_EAGAIN) {
                        socket_write_start (this);
                } else {
                        if (__does_socket_rwv_error_need_logging (priv, 1)) {
                                GF_LOG_OCCASIONALLY (
                                  priv->log_ctr, this->name, GF_LOG_WARNING,
                                  "%s on %s failed (%s)", "writev",
                                  this->peerinfo.identifier,
                                  uv_strerror (status));
                        }

                        if (priv->use_ssl && priv->ssl_ssl) {
                                ssl_dump_error_stack (this->name);
                        }

                        socket_error_cb (this, status);

                        socket_do_next (this);
                }
        }
}

static void
socket_connect_cb (uv_connect_t* req, int status)
{
        rpc_transport_t* this;
        socket_private_t* priv;
        struct req_buf* req_buf = NULL;
        int ret = -1;

        req_buf = CONTAINER_OF (req, struct req_buf, req);
        priv = req_buf->priv;
        this = priv->translator;

        THIS = this->xl;

        GF_FREE (req_buf);

        if (status == 0) {
                if (priv->connected != 1)
                        socket_connect_finish (this, 0);

                priv->wrstate = C_STOP;
                priv->rdstate = C_STOP;
                priv->fcstate = FC_READ | FC_WRITE;
        } else if (status == UV_ECANCELED) {
                /* Handle has been closed. */
        } else if (status != 0) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "socket (%s) connect callback with error: %s",
                        this->peerinfo.identifier, uv_strerror (status));

                socket_error_cb (this, status);
        }

        socket_do_next (this);
}

static void
socket_timer_cb (uv_timer_t* handle)
{
        socket_private_t* priv = NULL;

        priv = CONTAINER_OF (handle, socket_private_t, timer);

        socket_do_next (priv->translator);
}

static void
socket_action_cb (uv_async_t* handle)
{
        rpc_transport_t* this = NULL;
        socket_private_t* priv = NULL;
        struct action_req* action_req = NULL;

        priv = CONTAINER_OF (handle, socket_private_t, action);
        this = priv->translator;

        socket_do_next (this);
}

static int socket_connect (rpc_transport_t* this, int port);

static void
socket_close_cb (uv_handle_t* handle)
{
        socket_private_t* priv = NULL;

        priv = handle->data;
        priv->handle_inited = 0;

        priv->state = S_DEAD;

        socket_do_next (priv->translator);
}

static void
socket_close (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;

        priv = this->private;
        priv->handle.data = priv;

        if (uv_is_closing (&priv->handle))
                return;

        uv_close (&priv->handle, socket_close_cb);
        uv_timer_again (&priv->timer);
}

static int
__socket_handle_init (uv_loop_t* loop, rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        struct req_buf* req = NULL;
        char* cname = NULL;
        gf_boolean_t init_sock = 0;
        gf_boolean_t init_req = 0;
        union gf_sock_union sock_union;
        struct sockaddr_in* addr = NULL;
        socklen_t sockaddr_len = 0;
        sa_family_t sa_family = {
                0,
        };
        char* local_addr = NULL;
        gf_boolean_t ign_enoent = _gf_false;
        int send_buff_size = 256 * 1024, recv_buff_size = 256 * 1024;
        int ret = -1;

        priv = this->private;

        ret = uv_tcp_init (loop, &priv->handle);
        if (ret != 0) {
                gf_log (this->name, GF_LOG_ERROR,
                        "init socket creation failed (%s)", uv_strerror (ret));
                goto fail;
        }
        priv->handle_inited = 1;

        // fill socket info
        {
                ret = socket_client_get_remote_sockaddr (
                  this, &sock_union.sa, &sockaddr_len, &sa_family);
                if (ret == -1) {
                        /* logged inside client_get_remote_sockaddr */
                        goto fail;
                }

                if (sa_family == AF_UNIX) {
                        priv->ssl_enabled = _gf_false;
                        priv->mgmt_ssl = _gf_false;
                } else {
                        if (priv->port > 0) {
                                sock_union.sin.sin_port = htons (priv->port);
                        }
                        socket_fix_ssl_opts (this, priv,
                                             ntohs (sock_union.sin.sin_port));
                }

                memcpy (&this->peerinfo.sockaddr, &sock_union.storage,
                        sockaddr_len);
                this->peerinfo.sockaddr_len = sockaddr_len;

                ret = socket_client_get_remote_sockaddr (
                  this, &sock_union.sa, &sockaddr_len, &sa_family);
                if (ret == -1) {
                        /* logged inside client_get_remote_sockaddr */
                        goto fail;
                }

                if (sa_family == AF_UNIX) {
                        priv->ssl_enabled = _gf_false;
                        priv->mgmt_ssl = _gf_false;
                } else {
                        if (priv->port > 0) {
                                sock_union.sin.sin_port = htons (priv->port);
                        }
                        socket_fix_ssl_opts (this, priv,
                                             ntohs (sock_union.sin.sin_port));
                }

                memcpy (&this->peerinfo.sockaddr, &sock_union.storage,
                        sockaddr_len);
                this->peerinfo.sockaddr_len = sockaddr_len;

                SA (&this->myinfo.sockaddr)->sa_family =
                  SA (&this->peerinfo.sockaddr)->sa_family;

                /* If a source addr is explicitly specified, use it */
                ret = dict_get_str (
                  this->options, "transport.socket.source-addr", &local_addr);
                if (!ret && SA (&this->myinfo.sockaddr)->sa_family == AF_INET) {
                        addr = (struct sockaddr_in*)(&this->myinfo.sockaddr);
                        ret = inet_pton (AF_INET, local_addr,
                                         &(addr->sin_addr.s_addr));
                }

                /* If client wants ENOENT to be ignored */
                ign_enoent = dict_get_str_boolean (
                  this->options, "transport.socket.ignore-enoent", _gf_false);

                uv_tcp_nodelay (&priv->handle, 0);

                uv_tcp_simultaneous_accepts (&priv->handle, 1);

#ifdef NEVER
                uv_send_buffer_size ((uv_handle_t*)&priv->handle,
                                     &send_buff_size);
                uv_recv_buffer_size ((uv_handle_t*)&priv->handle,
                                     &recv_buff_size);
                uv_tcp_nodelay (&priv->handle, 1);

                send_buff_size = 0;
                recv_buff_size = 0;
                uv_send_buffer_size ((uv_handle_t*)&priv->handle,
                                     &send_buff_size);
                uv_recv_buffer_size ((uv_handle_t*)&priv->handle,
                                     &recv_buff_size);
#endif /* NEVER */
                gf_log (this->name, GF_LOG_DEBUG,
                        "set send and recv buffer size:%d,%d", send_buff_size,
                        recv_buff_size);

#ifdef ENABLE_BIND
                ret = uv_tcp_bind (&sock->h.sock,
                                   (struct sockaddr*)&this->myinfo.sockaddr, 0);
                if (ret != 0) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "client bind failed: %s", uv_strerror (ret));
                        goto fail;
                }
#endif /* ENABLE_BIND */
        }

        get_transport_identifiers (this);

        req = GF_CALLOC (1, sizeof (struct req_buf), gf_sock_mt_req);
        if (!req)
                goto fail;

        req->priv = priv;
        req->data = NULL;
        ret = uv_tcp_connect (&req->connect_req, &priv->handle,
                              SA (&this->peerinfo.sockaddr), socket_connect_cb);
        if (ret != 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "Ignore failed connection attempt on %s, (%s) ",
                        this->peerinfo.identifier, strerror (errno));
                goto fail;
        }
        init_req = 1;

        if (priv->use_ssl && !priv->own_thread) {
                cname = ssl_setup_connection (this, 0);
                if (!cname) {
                        errno = ENOTCONN;
                        ret = -1;
                        gf_log (this->name, GF_LOG_ERROR,
                                "client setup failed");
                        goto fail;
                }
                if (priv->connected) {
                        this->ssl_name = cname;
                } else {
                        GF_FREE (cname);
                }
        }

fail:
        priv->result = ret;
        uv_timer_again (&priv->timer);

        return ret;
}

static int
__socket_init (uv_loop_t* loop, rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        struct req_buf* req = NULL;
        char* cname = NULL;
        union gf_sock_union sock_union;
        struct sockaddr_in* addr = NULL;
        socklen_t sockaddr_len = 0;
        sa_family_t sa_family = {
                0,
        };
        char* local_addr = NULL;
        gf_boolean_t ign_enoent = _gf_false;
        int ret = -1;

        priv = this->private;

        if (!priv->timer_inited) {
                ret = uv_timer_init (loop, &priv->timer);
                if (ret != 0) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "init socket timer handle failed (%s)",
                                uv_strerror (ret));
                        goto end;
                }
                priv->timer_inited = _gf_true;

                uv_timer_start (&priv->timer, socket_timer_cb, 3 * 1000, 3 * 1000);
        }

        if (!priv->action_handle_inited) {
                ret = uv_async_init (loop, &priv->action, socket_action_cb);
                if (ret != 0) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "init socket action handle failed (%s)",
                                uv_strerror (ret));
                        goto end;
                }
                priv->action_handle_inited = _gf_true;
        }

        ret = __socket_handle_init (loop, this);
        if (ret != 0)
                goto end;

end:
        return ret;
}

static int
socket_register_handler (uv_loop_t* loop, void* translator, int action)
{
        rpc_transport_t* this = NULL;
        socket_private_t* priv = NULL;
        struct action_req* action_req = NULL;
        int ret = -1;

        this = translator;
        priv = this->private;
        priv->loop = loop;

        THIS = this->xl;

        priv->th_id = pthread_self ();

        action_req = socket_get_action (this);
        if (action_req) {
#if 0
	gf_log (this->name, GF_LOG_ERROR,
		"Register:tid=%p,state=%d,rdstate=%d,wrstate=%d,req=%d",
		pthread_self (), priv->state, priv->rdstate, priv->wrstate, action_req->type);
#endif /* NEVER */

                __socket_do_action (loop, this, action_req);
                GF_FREE (action_req);
                ret = 0;
        }

        return ret;
}

static void
__socket_listen_cb (uv_stream_t* server, int status)
{
        rpc_transport_t* this;
        socket_private_t* priv;
        int ret = -1;

        priv = CONTAINER_OF (server, socket_private_t, handle);
        this = priv->translator;

        if (status != 0)
                return;

        // init myinfo peerinfo

        socket_server_event_handler (this);

        socket_do_next (this);
}

static int
__socket_listen_handler (uv_loop_t* loop, void* translator, int action)
{
        rpc_transport_t* this;
        socket_private_t* priv;
        uv_tcp_t* sock;
        int ret = -1;

        this = translator;
        priv = this->private;
        sock = &priv->handle;

        ret = uv_tcp_init (loop, sock);
        if (ret != 0) {
                gf_log (this->name, GF_LOG_ERROR,
                        "init socket creation failed (%s)", uv_strerror (ret));
                return ret;
        }

        ret = __socket_server_bind (this);

        if ((ret == UV_EADDRINUSE) || (ret != 0)) {
                /* logged inside __socket_server_bind() */
                return ret;
        }

        if (priv->backlog)
                ret =
                  uv_listen (&priv->handle, priv->backlog, __socket_listen_cb);
        else
                ret = uv_listen (&priv->handle, 10, __socket_listen_cb);

        if (ret != 0) {
                gf_log (this->name, GF_LOG_ERROR,
                        "could not set socket %p to listen mode (%s)", sock,
                        uv_strerror (ret));
        }

        uv_timer_again (&priv->timer);

        return ret;
}

static void
socket_read_start (rpc_transport_t* this)
{
        int ret = -1;
        socket_private_t* priv = NULL;

        priv = this->private;

        GF_ASSERT (priv->rdstate == C_STOP);

        //-- pthread_mutex_lock (&priv->lock);
        {
                priv->rdstate = C_BUSY;
                priv->rdcount++;

                ret = uv_read_start ((uv_stream_t*)&priv->handle, on_buf_alloc,
                                     socket_read_cb);
                if (ret != 0) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "failure on read:%p (%s)", &priv->handle,
                                uv_strerror (ret));

                        socket_error_cb (this, ret);
                }

                uv_timer_again (&priv->timer);
        }
end:
        //-- pthread_mutex_unlock (&priv->lock);

        return;
}

static int
__socket_disconnect (rpc_transport_t* this)
{
        int ret = -1;
        socket_private_t* priv = NULL;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;

        if (priv->use_ssl) {
                ssl_teardown_connection (priv);
        }

        gf_msg (
          this->name, GF_LOG_DEBUG, 0, LG_MSG_POLL_IGNORE_MULTIPLE_THREADS,
          "disconnecting %p, state=%u gen=%u priv=%p, sock=%p, tid=%p", this,
          priv->ot_state, priv->ot_gen, priv, &priv->handle, pthread_self ());

        priv->connected = -1;

        ret = socket_do_next (this);
out:
        return ret;
}

static int
__socket_connect (uv_loop_t* loop, rpc_transport_t* this, int port)
{
        int ret = -1;
        int th_ret = -1;
        socket_private_t* priv = NULL;
        glusterfs_ctx_t* ctx = NULL;
        gf_boolean_t refd = _gf_false;
        socket_connect_error_state_t* arg = NULL;
        pthread_t th_id = {
                0,
        };
        char* cname = NULL;
        int sock_opt = 0;
        socklen_t sock_opt_size = 0;
        gf_boolean_t reg = _gf_false;

        GF_VALIDATE_OR_GOTO ("socket", this, err);
        GF_VALIDATE_OR_GOTO ("socket", this->private, err);

        priv = this->private;
        ctx = this->ctx;

        if (!priv) {
                gf_log_callingfn (
                  this->name, GF_LOG_WARNING,
                  "connect() called on uninitialized transport");
                goto err;
        }

        //-- pthread_mutex_lock (&priv->lock);
        {
                if (priv->handle_inited) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "connect (this=%p, port=%d, new_port=%d) "
                                "called on transport already connected",
                                this, priv->port, port);
                        errno = EINPROGRESS;
                        ret = 0;
                        goto unlock;
                }

                gf_msg (this->name, GF_LOG_DEBUG, 0,
                        LG_MSG_POLL_IGNORE_MULTIPLE_THREADS,
                        "connecting %p, sock=%p, port=%d", this, &priv->handle,
                        port);

                /*
                 * In the own_thread case, this is used to indicate that we're
                 * initializing a client connection.
                 */
                priv->port = port;
                priv->connected = 0;
                priv->is_server = _gf_false;
                rpc_transport_ref (this);
                refd = _gf_true;
                reg = _gf_true;

                ret = __socket_init (loop, this);
        }
unlock:
//-- pthread_mutex_unlock (&priv->lock);

err:
        /* if sock != -1, then cleanup is done from the event handler */
        if (ret == -1) {
                /* Cleaup requires to send notification to upper layer which
                   intern holds the big_lock. There can be dead-lock situation
                   if big_lock is already held by the current thread.
                   So transfer the ownership to seperate thread for cleanup.
                */
                arg =
                  GF_CALLOC (1, sizeof (*arg), gf_sock_connect_error_state_t);
                arg->this = THIS;
                arg->trans = this;
                arg->refd = refd;
                th_ret = gf_thread_create_detached (
                  &th_id, socket_connect_error_cbk, arg);
                if (th_ret) {
                        /* Error will be logged by gf_thread_create_attached */
                        gf_log (this->name, GF_LOG_ERROR, "Thread creation "
                                                          "failed");
                        GF_FREE (arg);
                        GF_ASSERT (0);
                }
        }

        return ret;
}

static int
__socket_listen (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        int ret = -1;
        struct sockaddr_storage sockaddr;
        socklen_t sockaddr_len = 0;
        peer_info_t* myinfo = NULL;
        glusterfs_ctx_t* ctx = NULL;
        sa_family_t sa_family = {
                0,
        };

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;
        myinfo = &this->myinfo;
        ctx = this->ctx;

        ret = socket_server_get_local_sockaddr (this, SA (&sockaddr),
                                                &sockaddr_len, &sa_family);
        if (ret == -1) {
                return ret;
        }

        //-- pthread_mutex_lock (&priv->lock);
        {
                memcpy (&myinfo->sockaddr, &sockaddr, sockaddr_len);
                myinfo->sockaddr_len = sockaddr_len;

                rpc_transport_ref (this);
        }
unlock:
//-- pthread_mutex_unlock (&priv->lock);

// TODO:
// __socket_listen_handler (loop, this,);

out:
        return ret;
}

static int32_t
__socket_submit_request (rpc_transport_t* this, struct ioq* entry)
{
        socket_private_t* priv = NULL;
        int can_write = 0;
        int need_append = 1;
        int ret = -1;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;

        //-- pthread_mutex_lock (&priv->lock);
        {
                if (pthread_self () == priv->th_id) {
                        uv_mutex_lock (&priv->comm_lock);

                        if (list_empty (&priv->write_q)) {
                                ret = __socket_ioq_churn_entry (this, entry);
                                if (ret > 0)
                                        need_append = 0;
                        }

                        uv_mutex_unlock (&priv->comm_lock);
                }

                if (need_append) {
                        ret = __socket_ioq_append_entry (this, entry);
                        uv_mutex_lock (&priv->comm_lock);
                        priv->fcstate |= FC_WRITE;
                        uv_mutex_unlock (&priv->comm_lock);

                        uv_async_send (&priv->action);
                }
        }
//-- pthread_mutex_unlock (&priv->lock);

out:
        return ret;
}

static int32_t
__socket_submit_reply (rpc_transport_t* this, struct ioq* entry)
{
        socket_private_t* priv = NULL;
        int can_write = 0;
        int need_append = 1;
        int ret = 0;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        priv = this->private;

        //-- pthread_mutex_lock (&priv->lock);
        {
                if (pthread_self () == priv->th_id) {
                        uv_mutex_lock (&priv->comm_lock);

                        if (list_empty (&priv->write_q)) {
                                ret = __socket_ioq_churn_entry (this, entry);
                                if (ret > 0)
                                        need_append = 0;
                        }

                        uv_mutex_unlock (&priv->comm_lock);
                }

                if (need_append) {
                        ret = __socket_ioq_append_entry (this, entry);
                        uv_mutex_lock (&priv->comm_lock);
                        priv->fcstate |= FC_WRITE;
                        uv_mutex_unlock (&priv->comm_lock);

                        uv_async_send (&priv->action);
                }
        }
unlock:
//-- pthread_mutex_unlock (&priv->lock);

out:
        return ret;
}

static int
socket_disconnect (rpc_transport_t* this)
{
        glusterfs_ctx_t* ctx = NULL;
        int ret = -1;

        ret = emit_socket_disconnect (this);

        ctx = this->ctx;
        ret = event_register (ctx->event_pool, this, socket_register_handler);
        if (ret != 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "could not register rpc %p to loop.", this);
        }

        return ret;
}

static int
socket_connect (rpc_transport_t* this, int port)
{
        glusterfs_ctx_t* ctx = NULL;
        int ret = -1;

        ret = emit_socket_connect (this, port);

        ctx = this->ctx;
        ret = event_register (ctx->event_pool, this, socket_register_handler);
        if (ret != 0) {
                gf_log (this->name, GF_LOG_WARNING,
                        "could not register rpc %p to loop.", this);
        }

        return ret;
}

static int
socket_listen (rpc_transport_t* this)
{
        int ret = -1;

        ret = emit_socket_listen (this);

        return ret;
}

static int32_t
socket_submit_request (rpc_transport_t* this, rpc_transport_req_t* req)
{
        int ret = -1;
        struct ioq* entry = NULL;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        entry = __socket_ioq_new (this, &req->msg);
        if (entry)
                ret = __socket_submit_request (this, entry);

out:
        return ret;
}

static int32_t
socket_submit_reply (rpc_transport_t* this, rpc_transport_reply_t* reply)
{
        int ret = -1;
        struct ioq* entry = NULL;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        entry = __socket_ioq_new (this, &reply->msg);
        if (entry)
                ret = __socket_submit_reply (this, entry);

out:
        return ret;
}

static int32_t
socket_getpeername (rpc_transport_t* this, char* hostname, int hostlen)
{
        int32_t ret = -1;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", hostname, out);

        if (hostlen < (strlen (this->peerinfo.identifier) + 1)) {
                goto out;
        }

        strcpy (hostname, this->peerinfo.identifier);
        ret = 0;
out:
        return ret;
}

static int32_t
socket_getpeeraddr (rpc_transport_t* this, char* peeraddr, int addrlen,
                    struct sockaddr_storage* sa, socklen_t salen)
{
        int32_t ret = -1;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", sa, out);

        *sa = this->peerinfo.sockaddr;

        if (peeraddr != NULL) {
                ret = socket_getpeername (this, peeraddr, addrlen);
        }
        ret = 0;

out:
        return ret;
}

static int32_t
socket_getmyname (rpc_transport_t* this, char* hostname, int hostlen)
{
        int32_t ret = -1;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", hostname, out);

        if (hostlen < (strlen (this->myinfo.identifier) + 1)) {
                goto out;
        }

        strcpy (hostname, this->myinfo.identifier);
        ret = 0;
out:
        return ret;
}

static int32_t
socket_getmyaddr (rpc_transport_t* this, char* myaddr, int addrlen,
                  struct sockaddr_storage* sa, socklen_t salen)
{
        int32_t ret = 0;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", sa, out);

        *sa = this->myinfo.sockaddr;

        if (myaddr != NULL) {
                ret = socket_getmyname (this, myaddr, addrlen);
        }

out:
        return ret;
}

static int
socket_throttle (rpc_transport_t* this, gf_boolean_t onoff)
{
        socket_private_t* priv = NULL;

        priv = this->private;

        /* The way we implement throttling is by taking off
           POLLIN event from the polled flags. This way we
           never get called with the POLLIN event and therefore
           will never read() any more data until throttling
           is turned off.
        */
        //-- pthread_mutex_lock (&priv->lock);
        {

                /* Throttling is useless on a disconnected transport. In fact,
                 * it's dangerous since priv->idx and priv->handle->h.sock are
                 * set
                 * to -1
                 * on a disconnected transport, which breaks epoll's event to
                 * registered fd mapping. */

                uv_mutex_lock (&priv->comm_lock);

                if (priv->connected == 1) {
                        if (!onoff)
                                priv->fcstate |= FC_READ;
                        else
                                priv->fcstate &= ~FC_READ;
                }

                uv_mutex_unlock (&priv->comm_lock);
        }
        //-- pthread_mutex_unlock (&priv->lock);
        return 0;
}

struct rpc_transport_ops tops = {
        .listen = socket_listen,
        .connect = socket_connect,
        .disconnect = socket_disconnect,
        .submit_request = socket_submit_request,
        .submit_reply = socket_submit_reply,
        .get_peername = socket_getpeername,
        .get_peeraddr = socket_getpeeraddr,
        .get_myname = socket_getmyname,
        .get_myaddr = socket_getmyaddr,
        .throttle = socket_throttle,
};

int
reconfigure (rpc_transport_t* this, dict_t* options)
{
        socket_private_t* priv = NULL;
        gf_boolean_t tmp_bool = _gf_false;
        char* optstr = NULL;
        int ret = 0;
        uint64_t windowsize = 0;
        uint32_t timeout = 0;

        GF_VALIDATE_OR_GOTO ("socket", this, out);
        GF_VALIDATE_OR_GOTO ("socket", this->private, out);

        if (!this || !this->private) {
                ret = -1;
                goto out;
        }

        priv = this->private;

        if (dict_get_str (this->options, "transport.socket.keepalive",
                          &optstr) == 0) {
                if (gf_string2boolean (optstr, &tmp_bool) == -1) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "'transport.socket.keepalive' takes only "
                                "boolean options, not taking any action");
                        priv->keepalive = 1;
                        ret = -1;
                        goto out;
                }
                gf_log (this->name, GF_LOG_DEBUG,
                        "Reconfigured transport.socket.keepalive");

                priv->keepalive = tmp_bool;
        } else
                priv->keepalive = 1;

        if (dict_get_uint32 (this->options, "transport.tcp-user-timeout",
                             &timeout) == 0) {
                priv->timeout = timeout;
                gf_log (this->name, GF_LOG_DEBUG,
                        "Reconfigued "
                        "transport.tcp-user-timeout=%d",
                        timeout);
        }

        optstr = NULL;
        if (dict_get_str (this->options, "tcp-window-size", &optstr) == 0) {
                if (gf_string2uint64 (optstr, &windowsize) != 0) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "invalid number format: %s", optstr);
                        goto out;
                }
        }

        priv->windowsize = (int)windowsize;

        if (dict_get (this->options, "non-blocking-io")) {
                optstr =
                  data_to_str (dict_get (this->options, "non-blocking-io"));

                if (gf_string2boolean (optstr, &tmp_bool) == -1) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "'non-blocking-io' takes only boolean options,"
                                " not taking any action");
                        tmp_bool = 1;
                }

                if (!tmp_bool) {
                        priv->bio = 1;
                        gf_log (this->name, GF_LOG_WARNING,
                                "disabling non-blocking IO");
                }
        }

        ret = 0;
out:
        return ret;
}

/*
 * Unlike the stuff in init, this only needs to be called once GLOBALLY no
 * matter how many translators/sockets we end up with.  Conveniently,
 * __attribute__(constructor) provides exactly those semantics in a pretty
 * portable fashion.
 */

static pthread_mutex_t* lock_array = NULL;
static gf_boolean_t constructor_ok = _gf_false;

static void
locking_func (int mode, int type, const char* file, int line)
{
        if (mode & CRYPTO_UNLOCK) {
                pthread_mutex_unlock (&lock_array[type]);
        } else {
                //-- pthread_mutex_lock (&lock_array[type]);
        }
}

#if HAVE_CRYPTO_THREADID
static void
threadid_func (CRYPTO_THREADID* id)
{
        /*
         * We're not supposed to know whether a pthread_t is a number or a
         * pointer, but we definitely need an unsigned long.  Even though it
         * happens to be an unsigned long already on Linux, do the cast just in
         * case that's not so on another platform.  Note that this can still
         * break if any platforms are left where a pointer is larger than an
         * unsigned long.  In that case there's not much we can do; hopefully
         * anyone porting to such a platform will be aware enough to notice the
         * compile warnings about truncating the pointer value.
         */
        CRYPTO_THREADID_set_numeric (id, (unsigned long)pthread_self ());
}
#else /* older openssl */
static unsigned long
legacy_threadid_func (void)
{
        /* See comments above, it applies here too. */
        return (unsigned long)pthread_self ();
}
#endif

static void __attribute__ ((constructor)) init_openssl_mt (void)
{
        int num_locks = CRYPTO_num_locks ();
        int i;

        lock_array = GF_CALLOC (num_locks, sizeof (pthread_mutex_t),
                                gf_sock_mt_lock_array);
        if (lock_array) {
                for (i = 0; i < num_locks; ++i) {
                        pthread_mutex_init (&lock_array[i], NULL);
                }
                CRYPTO_set_locking_callback (locking_func);
#if HAVE_CRYPTO_THREADID
                CRYPTO_THREADID_set_callback (threadid_func);
#else /* older openssl */
                CRYPTO_set_id_callback (legacy_threadid_func);
#endif
                constructor_ok = _gf_true;
        }

        SSL_library_init ();
        SSL_load_error_strings ();
}

static int
socket_init (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        gf_boolean_t tmp_bool = 0;
        uint64_t windowsize = GF_DEFAULT_SOCKET_WINDOW_SIZE;
        char* optstr = NULL;
        uint32_t keepalive = 0;
        uint32_t timeout = 0;
        uint32_t backlog = 0;
        int session_id = 0;
        int32_t cert_depth = DEFAULT_VERIFY_DEPTH;
        char* cipher_list = DEFAULT_CIPHER_LIST;
        char* dh_param = DEFAULT_DH_PARAM;
        char* ec_curve = DEFAULT_EC_CURVE;
        char* crl_path = NULL;
        pthread_mutexattr_t attr;

        if (this->private) {
                gf_log_callingfn (this->name, GF_LOG_ERROR,
                                  "double init attempted");
                return -1;
        }

        priv = GF_CALLOC (1, sizeof (*priv), gf_common_mt_socket_private_t);
        if (!priv) {
                return -1;
        }
        memset (priv, 0, sizeof (*priv));

        if (xlator_mem_acct_init (THIS, gf_sock_mt_end + 1) != 0) {
                gf_log_callingfn (this->name, GF_LOG_ERROR,
                                  "Memory accounting init failed");
                return -1;
        }

        uv_mutex_init (&priv->comm_lock);
        uv_cond_init (&priv->comm_cond);

        pthread_mutexattr_init (&attr);
        pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init (&priv->lock, &attr);
        priv->translator = this;
        priv->handle_inited = _gf_false;
        priv->timer_inited = _gf_false;
        priv->action_handle_inited = _gf_false;
        priv->state = S_REQ_CONNECT;
        priv->wrstate = C_STOP;
        priv->rdstate = C_STOP;
        priv->fcstate = FC_READ | FC_WRITE;
        priv->rdcount = 0;
        priv->wrcount = 0;
        priv->connected = -1;
        priv->nodelay = 1;
        priv->bio = 0;
        priv->port = 0;
        priv->windowsize = GF_DEFAULT_SOCKET_WINDOW_SIZE;
        INIT_LIST_HEAD (&priv->read_q);
        INIT_LIST_HEAD (&priv->write_q);
        INIT_LIST_HEAD (&priv->event_q);
        INIT_LIST_HEAD (&priv->action_q);
        INIT_LIST_HEAD (&priv->ioq);

        /* All the below section needs 'this->options' to be present */
        if (!this->options)
                goto out;

        if (dict_get (this->options, "non-blocking-io")) {
                optstr =
                  data_to_str (dict_get (this->options, "non-blocking-io"));

                if (gf_string2boolean (optstr, &tmp_bool) == -1) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "'non-blocking-io' takes only boolean options,"
                                " not taking any action");
                        tmp_bool = 1;
                }

                if (!tmp_bool) {
                        priv->bio = 1;
                        gf_log (this->name, GF_LOG_WARNING,
                                "disabling non-blocking IO");
                }
        }

        optstr = NULL;

        // By default, we enable NODELAY
        if (dict_get (this->options, "transport.socket.nodelay")) {
                optstr = data_to_str (
                  dict_get (this->options, "transport.socket.nodelay"));

                if (gf_string2boolean (optstr, &tmp_bool) == -1) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "'transport.socket.nodelay' takes only "
                                "boolean options, not taking any action");
                        tmp_bool = 1;
                }
                if (!tmp_bool) {
                        priv->nodelay = 0;
                        gf_log (this->name, GF_LOG_DEBUG, "disabling nodelay");
                }
        }

        optstr = NULL;
        if (dict_get_str (this->options, "tcp-window-size", &optstr) == 0) {
                if (gf_string2uint64 (optstr, &windowsize) != 0) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "invalid number format: %s", optstr);
                        return -1;
                }
        }

        priv->windowsize = (int)windowsize;

        optstr = NULL;
        /* Enable Keep-alive by default. */
        priv->keepalive = 1;
        priv->keepaliveintvl = 2;
        priv->keepaliveidle = 20;
        if (dict_get_str (this->options, "transport.socket.keepalive",
                          &optstr) == 0) {
                if (gf_string2boolean (optstr, &tmp_bool) == -1) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "'transport.socket.keepalive' takes only "
                                "boolean options, not taking any action");
                        tmp_bool = 1;
                }

                if (!tmp_bool)
                        priv->keepalive = 0;
        }

        if (dict_get_uint32 (this->options,
                             "transport.socket.keepalive-interval",
                             &keepalive) == 0) {
                priv->keepaliveintvl = keepalive;
        }

        if (dict_get_uint32 (this->options, "transport.socket.keepalive-time",
                             &keepalive) == 0) {
                priv->keepaliveidle = keepalive;
        }

        if (dict_get_uint32 (this->options, "transport.tcp-user-timeout",
                             &timeout) == 0) {
                priv->timeout = timeout;
        }
        gf_log (this->name, GF_LOG_DEBUG, "Configued "
                                          "transport.tcp-user-timeout=%d",
                priv->timeout);

        if (dict_get_uint32 (this->options, "transport.socket.listen-backlog",
                             &backlog) == 0) {
                priv->backlog = backlog;
        }

        optstr = NULL;

        /* Check if socket read failures are to be logged */
        priv->read_fail_log = 1;
        if (dict_get (this->options, "transport.socket.read-fail-log")) {
                optstr = data_to_str (
                  dict_get (this->options, "transport.socket.read-fail-log"));
                if (gf_string2boolean (optstr, &tmp_bool) == -1) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "'transport.socket.read-fail-log' takes only "
                                "boolean options; logging socket read fails");
                } else if (tmp_bool == _gf_false) {
                        priv->read_fail_log = 0;
                }
        }

        priv->windowsize = (int)windowsize;

        priv->ssl_enabled = _gf_false;
        if (dict_get_str (this->options, SSL_ENABLED_OPT, &optstr) == 0) {
                if (gf_string2boolean (optstr, &priv->ssl_enabled) != 0) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "invalid value given for ssl-enabled boolean");
                }
        }
        priv->mgmt_ssl = this->ctx->secure_mgmt;
        priv->srvr_ssl = this->ctx->secure_srvr;

        priv->ssl_own_cert = DEFAULT_CERT_PATH;
        if (dict_get_str (this->options, SSL_OWN_CERT_OPT, &optstr) == 0) {
                if (!priv->ssl_enabled) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "%s specified without %s (ignored)",
                                SSL_OWN_CERT_OPT, SSL_ENABLED_OPT);
                }
                priv->ssl_own_cert = optstr;
        }
        priv->ssl_own_cert = gf_strdup (priv->ssl_own_cert);

        priv->ssl_private_key = DEFAULT_KEY_PATH;
        if (dict_get_str (this->options, SSL_PRIVATE_KEY_OPT, &optstr) == 0) {
                if (!priv->ssl_enabled) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "%s specified without %s (ignored)",
                                SSL_PRIVATE_KEY_OPT, SSL_ENABLED_OPT);
                }
                priv->ssl_private_key = optstr;
        }
        priv->ssl_private_key = gf_strdup (priv->ssl_private_key);

        priv->ssl_ca_list = DEFAULT_CA_PATH;
        if (dict_get_str (this->options, SSL_CA_LIST_OPT, &optstr) == 0) {
                if (!priv->ssl_enabled) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "%s specified without %s (ignored)",
                                SSL_CA_LIST_OPT, SSL_ENABLED_OPT);
                }
                priv->ssl_ca_list = optstr;
        }
        priv->ssl_ca_list = gf_strdup (priv->ssl_ca_list);

        if (dict_get_str (this->options, SSL_CRL_PATH_OPT, &optstr) == 0) {
                if (!priv->ssl_enabled) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "%s specified without %s (ignored)",
                                SSL_CRL_PATH_OPT, SSL_ENABLED_OPT);
                }
                if (strcasecmp (optstr, "NULL") == 0)
                        crl_path = NULL;
                else
                        crl_path = optstr;
        }

        gf_log (this->name, priv->ssl_enabled ? GF_LOG_INFO : GF_LOG_DEBUG,
                "SSL support on the I/O path is %s",
                priv->ssl_enabled ? "ENABLED" : "NOT enabled");
        gf_log (this->name, priv->mgmt_ssl ? GF_LOG_INFO : GF_LOG_DEBUG,
                "SSL support for glusterd is %s",
                priv->mgmt_ssl ? "ENABLED" : "NOT enabled");
        /*
         * This might get overridden temporarily in socket_connect (q.v.)
         * if we're using the glusterd portmapper.
         */
        priv->use_ssl = priv->ssl_enabled;

        priv->own_thread = priv->use_ssl;
        if (dict_get_str (this->options, OWN_THREAD_OPT, &optstr) == 0) {
                gf_log (this->name, GF_LOG_INFO, "OWN_THREAD_OPT found");
                if (gf_string2boolean (optstr, &priv->own_thread) != 0) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "invalid value given for own-thread boolean");
                }
        }
        gf_log (this->name, priv->own_thread ? GF_LOG_INFO : GF_LOG_DEBUG,
                "using %s polling thread",
                priv->own_thread ? "private" : "system");

        if (!dict_get_int32 (this->options, SSL_CERT_DEPTH_OPT, &cert_depth)) {
                gf_log (this->name, GF_LOG_INFO, "using certificate depth %d",
                        cert_depth);
        }
        if (!dict_get_str (this->options, SSL_CIPHER_LIST_OPT, &cipher_list)) {
                gf_log (this->name, GF_LOG_INFO, "using cipher list %s",
                        cipher_list);
        }
        if (!dict_get_str (this->options, SSL_DH_PARAM_OPT, &dh_param)) {
                gf_log (this->name, GF_LOG_INFO, "using DH parameters %s",
                        dh_param);
        }
        if (!dict_get_str (this->options, SSL_EC_CURVE_OPT, &ec_curve)) {
                gf_log (this->name, GF_LOG_INFO, "using EC curve %s", ec_curve);
        }

        if (priv->ssl_enabled || priv->mgmt_ssl) {
                BIO* bio = NULL;

                /*
                 * The right time to check this is after all of our relevant
                 * fields have been set, but before we start issuing OpenSSL
                 * calls for the current translator.  In other words, now.
                 */
                if (!constructor_ok) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "can't initialize TLS socket (%s)",
                                "static constructor failed");
                        goto err;
                }

#if HAVE_TLSV1_2_METHOD
                priv->ssl_meth = (SSL_METHOD*)TLSv1_2_method ();
#else
/*
 * Nobody should use an OpenSSL so old it does not support TLS 1.2.
 * If that is really required, build with -DUSE_INSECURE_OPENSSL
 */
#ifndef USE_INSECURE_OPENSSL
#error Old and insecure OpenSSL, use -DUSE_INSECURE_OPENSSL to use it anyway
#endif
                /* SSLv23_method uses highest available protocol */
                priv->ssl_meth = (SSL_METHOD*)SSLv23_method ();
#endif
                priv->ssl_ctx = SSL_CTX_new (priv->ssl_meth);

                SSL_CTX_set_options (priv->ssl_ctx, SSL_OP_NO_SSLv2);
                SSL_CTX_set_options (priv->ssl_ctx, SSL_OP_NO_SSLv3);
#ifdef SSL_OP_NO_TICKET
                SSL_CTX_set_options (priv->ssl_ctx, SSL_OP_NO_TICKET);
#endif
#ifdef SSL_OP_NO_COMPRESSION
                SSL_CTX_set_options (priv->ssl_ctx, SSL_OP_NO_COMPRESSION);
#endif

                if ((bio = BIO_new_file (dh_param, "r")) == NULL) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "failed to open %s, "
                                "DH ciphers are disabled",
                                dh_param);
                }

                if (bio != NULL) {
#ifdef HAVE_OPENSSL_DH_H
                        DH* dh;
                        unsigned long err;

                        dh = PEM_read_bio_DHparams (bio, NULL, NULL, NULL);
                        BIO_free (bio);
                        if (dh != NULL) {
                                SSL_CTX_set_options (priv->ssl_ctx,
                                                     SSL_OP_SINGLE_DH_USE);
                                SSL_CTX_set_tmp_dh (priv->ssl_ctx, dh);
                                DH_free (dh);
                        } else {
                                err = ERR_get_error ();
                                gf_log (this->name, GF_LOG_ERROR,
                                        "failed to read DH param from %s: %s "
                                        "DH ciphers are disabled.",
                                        dh_param, ERR_error_string (err, NULL));
                        }
#else  /* HAVE_OPENSSL_DH_H */
                        BIO_free (bio);
                        gf_log (this->name, GF_LOG_ERROR,
                                "OpenSSL has no DH support");
#endif /* HAVE_OPENSSL_DH_H */
                }

                if (ec_curve != NULL) {
#ifdef HAVE_OPENSSL_ECDH_H
                        EC_KEY* ecdh = NULL;
                        int nid;
                        unsigned long err;

                        nid = OBJ_sn2nid (ec_curve);
                        if (nid != 0)
                                ecdh = EC_KEY_new_by_curve_name (nid);

                        if (ecdh != NULL) {
                                SSL_CTX_set_options (priv->ssl_ctx,
                                                     SSL_OP_SINGLE_ECDH_USE);
                                SSL_CTX_set_tmp_ecdh (priv->ssl_ctx, ecdh);
                                EC_KEY_free (ecdh);
                        } else {
                                err = ERR_get_error ();
                                gf_log (this->name, GF_LOG_ERROR,
                                        "failed to load EC curve %s: %s. "
                                        "ECDH ciphers are disabled.",
                                        ec_curve, ERR_error_string (err, NULL));
                        }
#else  /* HAVE_OPENSSL_ECDH_H */
                        gf_log (this->name, GF_LOG_ERROR,
                                "OpenSSL has no ECDH support");
#endif /* HAVE_OPENSSL_ECDH_H */
                }

                /* This must be done after DH and ECDH setups */
                if (SSL_CTX_set_cipher_list (priv->ssl_ctx, cipher_list) == 0) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "failed to find any valid ciphers");
                        goto err;
                }

                SSL_CTX_set_options (priv->ssl_ctx,
                                     SSL_OP_CIPHER_SERVER_PREFERENCE);

                if (!SSL_CTX_use_certificate_chain_file (priv->ssl_ctx,
                                                         priv->ssl_own_cert)) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "could not load our cert");
                        goto err;
                }

                if (!SSL_CTX_use_PrivateKey_file (
                      priv->ssl_ctx, priv->ssl_private_key, SSL_FILETYPE_PEM)) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "could not load private key");
                        goto err;
                }

                if (!SSL_CTX_load_verify_locations (
                      priv->ssl_ctx, priv->ssl_ca_list, crl_path)) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "could not load CA list");
                        goto err;
                }

#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
                SSL_CTX_set_verify_depth (ctx, cert_depth);
#endif

                if (crl_path) {
#ifdef X509_V_FLAG_CRL_CHECK_ALL
                        X509_STORE* x509store;

                        x509store = SSL_CTX_get_cert_store (priv->ssl_ctx);
                        X509_STORE_set_flags (x509store,
                                              X509_V_FLAG_CRL_CHECK |
                                                X509_V_FLAG_CRL_CHECK_ALL);
#else
                        gf_log (this->name, GF_LOG_ERROR,
                                "OpenSSL version does not support CRL");
#endif
                }

                priv->ssl_session_id = ++session_id;
                SSL_CTX_set_session_id_context (priv->ssl_ctx,
                                                (void*)&priv->ssl_session_id,
                                                sizeof (priv->ssl_session_id));

                SSL_CTX_set_verify (priv->ssl_ctx, SSL_VERIFY_PEER, 0);

                /*
                 * Since glusterfs shares the same settings for client-side
                 * and server-side of SSL, we need to ignore any certificate
                 * usage specification (SSL client vs SSL server), otherwise
                 * SSL connexions will fail with 'unsupported cerritifcate"
                 */
                SSL_CTX_set_purpose (priv->ssl_ctx, X509_PURPOSE_ANY);
        }

        priv->ot_state = OT_IDLE;

out:
        this->private = priv;

        return 0;

err:
        if (priv->ssl_own_cert) {
                GF_FREE (priv->ssl_own_cert);
        }
        if (priv->ssl_private_key) {
                GF_FREE (priv->ssl_private_key);
        }
        if (priv->ssl_ca_list) {
                GF_FREE (priv->ssl_ca_list);
        }
        GF_FREE (priv);
        return -1;
}

void
fini (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;

        if (!this)
                return;

        priv = this->private;
        if (priv) {
                pthread_mutex_lock (&priv->lock);
                {
                        __socket_ioq_flush (this);
                        __socket_reset (this);

                        uv_cond_destroy (&priv->comm_cond);
                        uv_mutex_destroy (&priv->comm_lock);
                }
                pthread_mutex_unlock (&priv->lock);

                gf_log (this->name, GF_LOG_TRACE, "transport %p destroyed",
                        this);

                pthread_mutex_destroy (&priv->lock);
                if (priv->ssl_private_key) {
                        GF_FREE (priv->ssl_private_key);
                }
                if (priv->ssl_own_cert) {
                        GF_FREE (priv->ssl_own_cert);
                }
                if (priv->ssl_ca_list) {
                        GF_FREE (priv->ssl_ca_list);
                }
                GF_FREE (priv);
        }

        this->private = NULL;
}

int32_t
init (rpc_transport_t* this)
{
        int ret = -1;

        ret = socket_init (this);

        if (ret == -1) {
                gf_log (this->name, GF_LOG_DEBUG, "socket_init() failed");
        }

        return ret;
}

struct volume_options options[] =
  { {.key = { "remote-port", "transport.remote-port",
              "transport.socket.remote-port" },
     .type = GF_OPTION_TYPE_INT },
    {.key = { "transport.socket.listen-port", "listen-port" },
     .type = GF_OPTION_TYPE_INT },
    {.key = { "transport.socket.bind-address", "bind-address" },
     .type = GF_OPTION_TYPE_INTERNET_ADDRESS },
    {.key = { "transport.socket.connect-path", "connect-path" },
     .type = GF_OPTION_TYPE_ANY },
    {.key = { "transport.socket.bind-path", "bind-path" },
     .type = GF_OPTION_TYPE_ANY },
    {.key = { "transport.socket.listen-path", "listen-path" },
     .type = GF_OPTION_TYPE_ANY },
    {.key = { "transport.address-family", "address-family" },
     .value = { "inet", "inet6", "unix", "inet-sdp" },
     .type = GF_OPTION_TYPE_STR },

    {.key = { "non-blocking-io" },
     .type = GF_OPTION_TYPE_BOOL,
     .default_value = "on" },
    {.key = { "tcp-window-size" },
     .type = GF_OPTION_TYPE_SIZET,
     .min = GF_MIN_SOCKET_WINDOW_SIZE,
     .max = GF_MAX_SOCKET_WINDOW_SIZE },
    {
      .key = { "transport.tcp-user-timeout" },
      .type = GF_OPTION_TYPE_INT,
      .default_value = "42",
    },
    {.key = { "transport.socket.nodelay" },
     .type = GF_OPTION_TYPE_BOOL,
     .default_value = "on" },
    {.key = { "transport.socket.lowlat" },
     .type = GF_OPTION_TYPE_BOOL,
     .default_value = "on" },
    {.key = { "transport.socket.keepalive" },
     .type = GF_OPTION_TYPE_BOOL,
     .default_value = "on" },
    {.key = { "transport.socket.keepalive-interval" },
     .type = GF_OPTION_TYPE_INT,
     .default_value = "20" },
    {.key = { "transport.socket.keepalive-time" },
     .type = GF_OPTION_TYPE_INT,
     .default_value = "20" },
    {.key = { "transport.socket.listen-backlog" }, .type = GF_OPTION_TYPE_INT },
    {.key = { "transport.socket.read-fail-log" }, .type = GF_OPTION_TYPE_BOOL },
    {.key = { SSL_ENABLED_OPT }, .type = GF_OPTION_TYPE_BOOL },
    {.key = { SSL_OWN_CERT_OPT }, .type = GF_OPTION_TYPE_STR },
    {.key = { SSL_PRIVATE_KEY_OPT }, .type = GF_OPTION_TYPE_STR },
    {.key = { SSL_CA_LIST_OPT }, .type = GF_OPTION_TYPE_STR },
    {.key = { SSL_CERT_DEPTH_OPT }, .type = GF_OPTION_TYPE_STR },
    {.key = { SSL_CIPHER_LIST_OPT }, .type = GF_OPTION_TYPE_STR },
    {.key = { SSL_DH_PARAM_OPT }, .type = GF_OPTION_TYPE_STR },
    {.key = { SSL_EC_CURVE_OPT }, .type = GF_OPTION_TYPE_STR },
    {.key = { SSL_CRL_PATH_OPT }, .type = GF_OPTION_TYPE_STR },
    {.key = { OWN_THREAD_OPT }, .type = GF_OPTION_TYPE_BOOL },
    {.key = { "ssl-own-cert" },
     .type = GF_OPTION_TYPE_STR,
     .description = "SSL certificate. Ignored if SSL is not enabled." },
    {.key = { "ssl-private-key" },
     .type = GF_OPTION_TYPE_STR,
     .description = "SSL private key. Ignored if SSL is not enabled." },
    {.key = { "ssl-ca-list" },
     .type = GF_OPTION_TYPE_STR,
     .description = "SSL CA list. Ignored if SSL is not enabled." },
    {.key = { "ssl-cert-depth" },
     .type = GF_OPTION_TYPE_INT,
     .description = "Maximum certificate-chain depth.  If zero, the "
                    "peer's certificate itself must be in the local "
                    "certificate list.  Otherwise, there may be up to N "
                    "signing certificates between the peer's and the "
                    "local list.  Ignored if SSL is not enabled." },
    {.key = { "ssl-cipher-list" },
     .type = GF_OPTION_TYPE_STR,
     .description = "Allowed SSL ciphers. Ignored if SSL is not enabled." },
    {.key = { "ssl-dh-param" },
     .type = GF_OPTION_TYPE_STR,
     .description = "DH parameters file. Ignored if SSL is not enabled." },
    {.key = { "ssl-ec-curve" },
     .type = GF_OPTION_TYPE_STR,
     .description = "ECDH curve name. Ignored if SSL is not enabled." },
    {.key = { "ssl-crl-path" },
     .type = GF_OPTION_TYPE_STR,
     .description = "Path to directory containing CRL. "
                    "Ignored if SSL is not enabled." },
    {.key = { NULL } } };
