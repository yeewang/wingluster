/*
  Copyright (c) 2008-2012 Red Hat, Inc. <http://www.redhat.com>
  This file is part of GlusterFS.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

#ifndef _SOCKET_H
#define _SOCKET_H

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#ifdef HAVE_OPENSSL_DH_H
#include <openssl/dh.h>
#endif
#ifdef HAVE_OPENSSL_ECDH_H
#include <openssl/ecdh.h>
#include <openssl/objects.h>
#endif

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <uv.h>

#include "dict.h"
#include "event.h"
#include "globals.h"
#include "logging.h"
#include "mem-pool.h"
#include "rpc-transport.h"

#ifndef MAX_IOVEC
#define MAX_IOVEC 16
#endif /* MAX_IOVEC */

#define GF_DEFAULT_SOCKET_LISTEN_PORT GF_DEFAULT_BASE_PORT

#define RPC_MAX_FRAGMENT_SIZE 0x7fffffff

/* The default window size will be 0, indicating not to set
 * it to any size. Default size of Linux is found to be
 * performance friendly.
 * Linux allows us to over-ride the max values for the system.
 * Should we over-ride them? Because if we set a value larger than the default
 * setsockopt will fail. Having larger values might be beneficial for
 * IB links.
 */
#ifdef GF_CYGWIN_HOST_OS
#define GF_DEFAULT_SOCKET_WINDOW_SIZE (0 * GF_UNIT_KB)
#else
#define GF_DEFAULT_SOCKET_WINDOW_SIZE (0)
#endif

#define GF_MAX_SOCKET_WINDOW_SIZE (1 * GF_UNIT_MB)
#define GF_MIN_SOCKET_WINDOW_SIZE (0)
#define GF_USE_DEFAULT_KEEPALIVE (-1)

typedef enum {
        SP_STATE_NADA = 0,
        SP_STATE_COMPLETE,
        SP_STATE_READING_FRAGHDR,
        SP_STATE_READ_FRAGHDR,
        SP_STATE_READING_FRAG,
} sp_rpcrecord_state_t;

typedef enum {
        SP_STATE_RPCFRAG_INIT,
        SP_STATE_READING_MSGTYPE,
        SP_STATE_READ_MSGTYPE,
        SP_STATE_NOTIFYING_XID
} sp_rpcfrag_state_t;

typedef enum {
        SP_STATE_SIMPLE_MSG_INIT,
        SP_STATE_READING_SIMPLE_MSG,
} sp_rpcfrag_simple_msg_state_t;

typedef enum {
        SP_STATE_VECTORED_REQUEST_INIT,
        SP_STATE_READING_CREDBYTES,
        SP_STATE_READ_CREDBYTES, /* read credential data. */
        SP_STATE_READING_VERFBYTES,
        SP_STATE_READ_VERFBYTES, /* read verifier data */
        SP_STATE_READING_PROGHDR,
        SP_STATE_READ_PROGHDR,
        SP_STATE_READING_PROGHDR_XDATA,
        SP_STATE_READ_PROGHDR_XDATA, /* It's a bad "name" in the generic
                                        RPC state machine, but greatly
                                        aids code review (and xdata is
                                        the only "consumer" of this state)
                                     */
        SP_STATE_READING_PROG,
} sp_rpcfrag_vectored_request_state_t;

typedef enum {
        SP_STATE_REQUEST_HEADER_INIT,
        SP_STATE_READING_RPCHDR1,
        SP_STATE_READ_RPCHDR1, /* read msg from beginning till and
                                * including credlen
                                */
} sp_rpcfrag_request_header_state_t;

typedef enum {
	AR_SOCKET_DISCONNECT,
	AR_SOCKET_CONNECT,
	AR_SOCKET_LISTEN,
	AR_SOCKET_SUBMIT_REQUEST,
	AR_SOCKET_SUBMIT_REPLY,
        AR_SOCKET_SHUTDOWN,
        AR_SOCKET_CLOSE,
} action_req_t;

#ifdef NEVER
typedef struct  {
	int   inited;
	void *priv;

	union {
		uv_handle_t handle;
		uv_stream_t stream;
		uv_tcp_t sock;
		uv_udp_t udp;
	} h;
} socket_handle_t;
#endif /* NEVER */

struct ioq
{
        union
        {
                struct list_head list;
                struct
                {
                        struct ioq* next;
                        struct ioq* prev;
                };
        };

        uint32_t fraghdr;
        struct iovec vector[MAX_IOVEC];
        int count;
        struct iovec* pending_vector;
        int pending_count;
        struct iobref* iobref;
};

struct bufq
{
        struct list_head list;
	struct iobuf* iobuf;
        struct iovec vector;
        size_t read;
};

struct write_q
{
	struct list_head list;
        struct ioq* ioq;
        uv_buf_t bufs[MAX_IOVEC];
        int count;
};

struct req_buf
{
        void* priv;
        void* data;
        union
        {
		uv_req_t req;
                uv_getnameinfo_t nameinfo_req;
                uv_getaddrinfo_t addrinfo_req;
                uv_connect_t connect_req;
                uv_shutdown_t shutdown_req;
                uv_write_t write_req;
		uv_work_t work_req;
        };
};

struct action_req
{
        struct list_head list;
        action_req_t type;
	int num_of_args;
	void *args[10];
};

struct event_q
{
	struct list_head list;
        int event;
	void *data;
};

typedef struct
{
        sp_rpcfrag_request_header_state_t header_state;
        sp_rpcfrag_vectored_request_state_t vector_state;
        int vector_sizer_state;
} sp_rpcfrag_request_state_t;

typedef enum {
        SP_STATE_VECTORED_REPLY_STATUS_INIT,
        SP_STATE_READING_REPLY_STATUS,
        SP_STATE_READ_REPLY_STATUS,
} sp_rpcfrag_vectored_reply_status_state_t;

typedef enum {
        SP_STATE_ACCEPTED_SUCCESS_REPLY_INIT,
        SP_STATE_READING_PROC_HEADER,
        SP_STATE_READING_PROC_OPAQUE,
        SP_STATE_READ_PROC_OPAQUE,
        SP_STATE_READ_PROC_HEADER,
} sp_rpcfrag_vectored_reply_accepted_success_state_t;

typedef enum {
        SP_STATE_ACCEPTED_REPLY_INIT,
        SP_STATE_READING_REPLY_VERFLEN,
        SP_STATE_READ_REPLY_VERFLEN,
        SP_STATE_READING_REPLY_VERFBYTES,
        SP_STATE_READ_REPLY_VERFBYTES,
} sp_rpcfrag_vectored_reply_accepted_state_t;

typedef struct
{
        uint32_t accept_status;
        sp_rpcfrag_vectored_reply_status_state_t status_state;
        sp_rpcfrag_vectored_reply_accepted_state_t accepted_state;
        sp_rpcfrag_vectored_reply_accepted_success_state_t
          accepted_success_state;
} sp_rpcfrag_vectored_reply_state_t;

struct gf_sock_incoming_frag
{
        char* fragcurrent;
        uint32_t bytes_read;
        uint32_t remaining_size;
        struct iovec vector;
        struct iovec* pending_vector;
        union
        {
                sp_rpcfrag_request_state_t request;
                sp_rpcfrag_vectored_reply_state_t reply;
        } call_body;

        sp_rpcfrag_simple_msg_state_t simple_state;
        sp_rpcfrag_state_t state;
};

#define GF_SOCKET_RA_MAX 1024

struct gf_sock_incoming
{
        sp_rpcrecord_state_t record_state;
        struct gf_sock_incoming_frag frag;
        char* proghdr_base_addr;
        struct iobuf* iobuf;
        size_t iobuf_size;
        struct iovec vector[2];
        int count;
        struct iovec payload_vector;
        struct iobref* iobref;
        rpc_request_info_t* request_info;
        struct iovec* pending_vector;
        int pending_count;
        uint32_t fraghdr;
        char complete_record;
        msg_type_t msg_type;
        size_t total_bytes_read;

        size_t ra_read;
        size_t ra_max;
        size_t ra_served;
        char* ra_buf;
};

/* This macro looks complicated but it's not: it calculates the address
 * of the embedding struct through the address of the embedded struct.
 * In other words, if struct A embeds struct B, then we can obtain
 * the address of A by taking the address of B and subtracting the
 * field offset of B in A.
 */
#define CONTAINER_OF(ptr, type, field)                                         \
        ((type*)((char*)(ptr) - ((char*)&((type*)0)->field)))

typedef enum {
        OT_IDLE,       /* Uninitialized or termination complete. */
        OT_SPAWNING,   /* Past pthread_create but not in thread yet. */
        OT_RUNNING,    /* Poller thread running normally. */
        OT_CALLBACK,   /* Poller thread in the middle of a callback. */
        OT_PLEASE_DIE, /* Poller termination requested. */
} ot_state_t;

/* Session states. */
typedef enum sess_state {
	S_REQ_CONNECT,	    /* Wait for uv_tcp_connect() to complete. */
	S_HANDSHAKE,        /* Wait for client handshake. */
	S_KILL,             /* Tear down session. */
	s_almost_dead_0,    /* Waiting for finalizers to complete. */
	s_almost_dead_1,    /* Waiting for finalizers to complete. */
	s_almost_dead_2,    /* Waiting for finalizers to complete. */
	s_almost_dead_3,    /* Waiting for finalizers to complete. */
	s_almost_dead_4,    /* Waiting for finalizers to complete. */
	S_DEAD              /* Dead. Safe to free now. */
} sess_state_t;

typedef enum {
        C_BUSY, /* Busy; waiting for incoming data or for a write to complete.
                   */
        C_DONE, /* Done; read incoming data or write finished. */
        C_DEAD
} conn_state_t;

typedef struct
{int kkk, jjj;
	pthread_t th_id;
        void* translator;

        uv_tcp_t handle;
        uv_timer_t timer;
	uv_async_t action;

	gf_boolean_t handle_inited;
	gf_boolean_t timer_inited;
	gf_boolean_t action_handle_inited;

	sess_state_t state;
        conn_state_t rdstate;
        conn_state_t wrstate;
        ssize_t result;

        struct list_head read_q;
	struct list_head write_q;
        struct list_head event_q;
	struct list_head action_q;
	struct iobref* read_iobref;

	uv_mutex_t comm_lock;
        uv_cond_t comm_cond;

	uv_prepare_t prepare;

        /* -1 = not connected. 0 = in progress. 1 = connected */
        char connected;
        char bio;
        char connect_finish_log;
        char submit_log;
        union
        {
                struct list_head ioq;
                struct
                {
                        struct ioq* ioq_next;
                        struct ioq* ioq_prev;
                };
        };
        struct gf_sock_incoming incoming;
        int outgoing;
        pthread_mutex_t lock;
        int port;
        int windowsize;
        char lowlat;
        char nodelay;
        int keepalive;
        int keepaliveidle;
        int keepaliveintvl;
        int timeout;
        uint32_t backlog;
        gf_boolean_t read_fail_log;
        gf_boolean_t ssl_enabled; /* outbound I/O */
        gf_boolean_t mgmt_ssl;    /* outbound mgmt */
        mgmt_ssl_t srvr_ssl;
        gf_boolean_t use_ssl;
        SSL_METHOD* ssl_meth;
        SSL_CTX* ssl_ctx;
        int ssl_session_id;
        BIO* ssl_sbio;
        SSL* ssl_ssl;
        char* ssl_own_cert;
        char* ssl_private_key;
        char* ssl_ca_list;
        pthread_t thread;

        gf_boolean_t own_thread;
        ot_state_t ot_state;
        uint32_t ot_gen;
        gf_boolean_t is_server;
        int log_ctr;
} socket_private_t;

#endif
