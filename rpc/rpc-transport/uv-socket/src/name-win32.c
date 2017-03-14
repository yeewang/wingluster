/*
  Copyright (c) 2008-2012 Red Hat, Inc. <http://www.redhat.com>
  This file is part of GlusterFS.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

#include <errno.h>
#include <string.h>
#include <sys/types.h>

#ifndef AF_INET_SDP
#define AF_INET_SDP 27
#endif

#include "common-utils.h"
#include "rpc-transport.h"
#include "socket.h"

#ifndef AI_ADDRCONFIG
#define AI_ADDRCONFIG 0
#endif /* AI_ADDRCONFIG */

struct dnscache6
{
        struct addrinfo* first;
        struct addrinfo* next;
};

static int32_t
gf_resolve_ip6 (uv_loop_t* loop, const char* hostname, uint16_t port,
                int family, void** dnscache, struct addrinfo** addr_info)
{
        int32_t ret = 0;
        struct addrinfo hints;
        struct dnscache6* cache = NULL;
        uv_getnameinfo_t name_req;
        uv_getaddrinfo_t addrinfo_req;

        if (!hostname) {
                gf_msg_callingfn ("resolver", GF_LOG_WARNING, 0,
                                  LG_MSG_HOSTNAME_NULL, "hostname is NULL");
                return -1;
        }

        if (!*dnscache) {
                *dnscache = GF_CALLOC (1, sizeof (struct dnscache6),
                                       gf_common_mt_dnscache6);
                if (!*dnscache)
                        return -1;
        }

        cache = *dnscache;
        if (cache->first && !cache->next) {
                uv_freeaddrinfo (cache->first);
                cache->first = cache->next = NULL;
                gf_msg_trace ("resolver", 0, "flushing DNS cache");
        }

        if (!cache->first) {
                char* port_str = NULL;
                gf_msg_trace ("resolver", 0, "DNS cache not present, freshly "
                                             "probing hostname: %s",
                              hostname);

                memset (&hints, 0, sizeof (hints));
                hints.ai_family = family;
                hints.ai_socktype = SOCK_STREAM;
#ifndef __NetBSD__
                hints.ai_flags = AI_ADDRCONFIG;
#endif

                ret = gf_asprintf (&port_str, "%d", port);
                if (-1 == ret) {
                        return -1;
                }
                if ((ret = uv_getaddrinfo (loop, &addrinfo_req, NULL, hostname,
                                           port_str, &hints)) != 0) {
                        gf_msg ("resolver", GF_LOG_ERROR, 0,
                                LG_MSG_GETADDRINFO_FAILED, "getaddrinfo failed"
                                                           " (%s)",
                                gai_strerror (ret));

                        GF_FREE (*dnscache);
                        *dnscache = NULL;
                        GF_FREE (port_str);
                        return -1;
                }
                cache->first = (struct addrinfo_cyguv*)addrinfo_req.addrinfo;
                GF_FREE (port_str);

                cache->next = cache->first;
        }

        if (cache->next) {
                ret = uv_getnameinfo (loop, &name_req, NULL,
                                      (struct sockaddr*)cache->next->ai_addr,
                                      NI_NUMERICHOST);
                if (ret != 0) {
                        gf_msg ("resolver", GF_LOG_ERROR, 0,
                                LG_MSG_GETNAMEINFO_FAILED, "getnameinfo failed"
                                                           " (%s)",
                                gai_strerror (ret));
                        goto err;
                }

                gf_msg_debug ("resolver", 0, "returning ip-%s (port-%s) for "
                                             "hostname: %s and port: %d",
                              name_req.host, name_req.service, hostname, port);

                *addr_info = cache->next;
        }

        if (cache->next)
                cache->next = cache->next->ai_next;
        if (cache->next) {
                ret = uv_getnameinfo (loop, &name_req, NULL,
                                      (struct sockaddr*)cache->next->ai_addr,
                                      NI_NUMERICHOST);
                if (ret != 0) {
                        gf_msg ("resolver", GF_LOG_ERROR, 0,
                                LG_MSG_GETNAMEINFO_FAILED, "getnameinfo failed"
                                                           " (%s)",
                                gai_strerror (ret));
                        goto err;
                }

                gf_msg_debug ("resolver", 0, "next DNS query will return: "
                                             "ip-%s port-%s",
                              name_req.host, name_req.service);
        }

        return 0;

err:
        uv_freeaddrinfo (cache->first);
        cache->first = cache->next = NULL;
        GF_FREE (cache);
        *dnscache = NULL;
        return -1;
}

int32_t
client_fill_address_family (rpc_transport_t* this, sa_family_t* sa_family)
{
        data_t* address_family_data = NULL;
        int32_t ret = -1;

        if (sa_family == NULL) {
                gf_log_callingfn ("", GF_LOG_WARNING,
                                  "sa_family argument is NULL");
                goto out;
        }

        address_family_data =
          dict_get (this->options, "transport.address-family");
        if (!address_family_data) {
                data_t *remote_host_data = NULL, *connect_path_data = NULL;
                remote_host_data = dict_get (this->options, "remote-host");
                connect_path_data =
                  dict_get (this->options, "transport.socket.connect-path");

                if (!(remote_host_data || connect_path_data) ||
                    (remote_host_data && connect_path_data)) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "transport.address-family not specified. "
                                "Could not guess default value from "
                                "(remote-host:%s or "
                                "transport.unix.connect-path:%s) options",
                                data_to_str (remote_host_data),
                                data_to_str (connect_path_data));
                        *sa_family = AF_UNSPEC;
                        goto out;
                }

                if (remote_host_data) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "address-family not specified, guessing it "
                                "to be inet from (remote-host: %s)",
                                data_to_str (remote_host_data));
                        *sa_family = AF_INET;
                } else {
                        gf_log (
                          this->name, GF_LOG_DEBUG,
                          "address-family not specified, guessing it "
                          "to be unix from (transport.unix.connect-path: %s)",
                          data_to_str (connect_path_data));
                        *sa_family = AF_UNIX;
                }

        } else {
                char* address_family = data_to_str (address_family_data);
                if (!strcasecmp (address_family, "unix")) {
                        *sa_family = AF_UNIX;
                } else if (!strcasecmp (address_family, "inet")) {
                        *sa_family = AF_INET;
                } else if (!strcasecmp (address_family, "inet6")) {
                        *sa_family = AF_INET6;
                } else if (!strcasecmp (address_family, "inet-sdp")) {
                        *sa_family = AF_INET_SDP;
                } else {
                        gf_log (this->name, GF_LOG_ERROR,
                                "unknown address-family (%s) specified",
                                address_family);
                        *sa_family = AF_UNSPEC;
                        goto out;
                }
        }

        ret = 0;

out:
        return ret;
}

static int32_t
af_inet_client_get_remote_sockaddr (rpc_transport_t* this,
                                    struct sockaddr* sockaddr,
                                    socklen_t* sockaddr_len)
{
        socket_private_t* priv = NULL;
        dict_t* options = this->options;
        data_t* remote_host_data = NULL;
        data_t* remote_port_data = NULL;
        char* remote_host = NULL;
        uint16_t remote_port = 0;
        struct addrinfo_cyguv* addr_info = NULL;
        int32_t ret = 0;

        priv = this->private;

        remote_host_data = dict_get (options, "remote-host");
        if (remote_host_data == NULL) {
                gf_log (this->name, GF_LOG_ERROR,
                        "option remote-host missing in volume %s", this->name);
                ret = -1;
                goto err;
        }

        remote_host = data_to_str (remote_host_data);
        if (remote_host == NULL) {
                gf_log (this->name, GF_LOG_ERROR,
                        "option remote-host has data NULL in volume %s",
                        this->name);
                ret = -1;
                goto err;
        }

        remote_port_data = dict_get (options, "remote-port");
        if (remote_port_data == NULL) {
                gf_log (
                  this->name, GF_LOG_TRACE,
                  "option remote-port missing in volume %s. Defaulting to %d",
                  this->name, GF_DEFAULT_SOCKET_LISTEN_PORT);

                remote_port = GF_DEFAULT_SOCKET_LISTEN_PORT;
        } else {
                remote_port = data_to_uint16 (remote_port_data);
        }

        if (remote_port == (uint16_t)-1) {
                gf_log (this->name, GF_LOG_ERROR,
                        "option remote-port has invalid port in volume %s",
                        this->name);
                ret = -1;
                goto err;
        }

        /* TODO: gf_resolve is a blocking call. kick in some
           non blocking dns techniques */
        ret = gf_resolve_ip6 (priv->handle.sock.loop, remote_host, remote_port,
                              sockaddr->sa_family, &this->dnscache, &addr_info);
        if (ret == -1) {
                gf_log (this->name, GF_LOG_ERROR,
                        "DNS resolution failed on host %s", remote_host);
                goto err;
        }

        memcpy (sockaddr, addr_info->ai_addr, addr_info->ai_addrlen);
        *sockaddr_len = addr_info->ai_addrlen;

err:
        return ret;
}

static int32_t
af_unix_client_get_remote_sockaddr (rpc_transport_t* this,
                                    struct sockaddr* sockaddr,
                                    socklen_t* sockaddr_len)
{
        struct sockaddr_un* sockaddr_un = NULL;
        char* connect_path = NULL;
        data_t* connect_path_data = NULL;
        int32_t ret = 0;

        connect_path_data =
          dict_get (this->options, "transport.socket.connect-path");
        if (!connect_path_data) {
                gf_log (this->name, GF_LOG_ERROR,
                        "option transport.unix.connect-path not specified for "
                        "address-family unix");
                ret = -1;
                goto err;
        }

        connect_path = data_to_str (connect_path_data);
        if (!connect_path) {
                gf_log (this->name, GF_LOG_ERROR,
                        "transport.unix.connect-path is null-string");
                ret = -1;
                goto err;
        }

        if ((strlen (connect_path) + 1) > UNIX_PATH_MAX) {
                gf_log (this->name, GF_LOG_ERROR,
                        "connect-path value length %" GF_PRI_SIZET
                        " > %d octets",
                        strlen (connect_path), UNIX_PATH_MAX);
                ret = -1;
                goto err;
        }

        gf_log (this->name, GF_LOG_TRACE, "using connect-path %s",
                connect_path);
        sockaddr_un = (struct sockaddr_un*)sockaddr;
        strcpy (sockaddr_un->sun_path, connect_path);
        *sockaddr_len = sizeof (struct sockaddr_un);

err:
        return ret;
}

static int32_t
af_unix_server_get_local_sockaddr (rpc_transport_t* this, struct sockaddr* addr,
                                   socklen_t* addr_len)
{
        data_t* listen_path_data = NULL;
        char* listen_path = NULL;
        int32_t ret = 0;
        struct sockaddr_un* sunaddr = (struct sockaddr_un*)addr;

        listen_path_data =
          dict_get (this->options, "transport.socket.listen-path");
        if (!listen_path_data) {
                gf_log (this->name, GF_LOG_ERROR,
                        "missing option transport.socket.listen-path");
                ret = -1;
                goto err;
        }

        listen_path = data_to_str (listen_path_data);

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

        if ((strlen (listen_path) + 1) > UNIX_PATH_MAX) {
                gf_log (this->name, GF_LOG_ERROR,
                        "option transport.unix.listen-path has value length "
                        "%" GF_PRI_SIZET " > %d",
                        strlen (listen_path), UNIX_PATH_MAX);
                ret = -1;
                goto err;
        }

        sunaddr->sun_family = AF_UNIX;
        strcpy (sunaddr->sun_path, listen_path);
        *addr_len = sizeof (struct sockaddr_un);

err:
        return ret;
}

static int32_t
af_inet_server_get_local_sockaddr (rpc_transport_t* this, struct sockaddr* addr,
                                   socklen_t* addr_len)
{
        socket_private_t* priv = NULL;
        struct addrinfo_cyguv hints, *res = 0, *rp = NULL;
        data_t *listen_port_data = NULL, *listen_host_data = NULL;
        uint16_t listen_port = -1;
        char service[NI_MAXSERV], *listen_host = NULL;
        dict_t* options = NULL;
        uv_getaddrinfo_t addrinfo_req;
        int32_t ret = 0;

        priv = this->private;
        options = this->options;

        listen_port_data = dict_get (options, "transport.socket.listen-port");
        listen_host_data = dict_get (options, "transport.socket.bind-address");

        if (listen_port_data) {
                listen_port = data_to_uint16 (listen_port_data);
        }

        if (listen_port == (uint16_t)-1)
                listen_port = GF_DEFAULT_SOCKET_LISTEN_PORT;

        if (listen_host_data) {
                listen_host = data_to_str (listen_host_data);
        } else {
                if (addr->sa_family == AF_INET6) {
                        struct sockaddr_in6_cyguv* in =
                          (struct sockaddr_in6_cyguv*)addr;
                        memcpy (&in->sin6_addr, &in6addr_any,
                                sizeof (in->sin6_addr));
                        in->sin6_port = htons (listen_port);
                        *addr_len = sizeof (struct sockaddr_in6);
                        goto out;
                } else if (addr->sa_family == AF_INET) {
                        struct sockaddr_in_cyguv* in =
                          (struct sockaddr_in_cyguv*)addr;
                        in->sin_addr.s_addr_cyguv = htonl (INADDR_ANY);
                        in->sin_port = htons (listen_port);
                        *addr_len = sizeof (struct sockaddr_in);
                        goto out;
                }
        }

        memset (service, 0, sizeof (service));
        sprintf (service, "%d", listen_port);

        memset (&hints, 0, sizeof (hints));
        hints.ai_family = addr->sa_family;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;

        ret = uv_getaddrinfo (priv->handle.sock.loop, &addrinfo_req, NULL,
                              listen_host, service, &hints);
        if (ret != 0) {
                gf_log (this->name, GF_LOG_ERROR,
                        "getaddrinfo failed for host %s, service %s (%s)",
                        listen_host, service, gai_strerror (ret));
                ret = -1;
                goto out;
        }

        res = (struct addrinfo_cyguv*)addrinfo_req.addrinfo;

        /* IPV6 server can handle both ipv4 and ipv6 clients */
        for (rp = res; rp != NULL; rp = rp->ai_next) {
                if (rp->ai_addr == NULL)
                        continue;
                if (rp->ai_family == AF_INET6) {
                        memcpy (addr, rp->ai_addr, rp->ai_addrlen);
                        *addr_len = rp->ai_addrlen;
                }
        }

        if (!(*addr_len)) {
                memcpy (addr, res->ai_addr, res->ai_addrlen);
                *addr_len = res->ai_addrlen;
        }

        uv_freeaddrinfo ((struct addrinfo*)res);

out:
        return ret;
}

int32_t
socket_client_get_remote_sockaddr (rpc_transport_t* this,
                                   struct sockaddr* sockaddr,
                                   socklen_t* sockaddr_len,
                                   sa_family_t* sa_family)
{
        int32_t ret = 0;

        GF_VALIDATE_OR_GOTO ("socket", sockaddr, err);
        GF_VALIDATE_OR_GOTO ("socket", sockaddr_len, err);
        GF_VALIDATE_OR_GOTO ("socket", sa_family, err);

        ret = client_fill_address_family (this, &sockaddr->sa_family);
        if (ret) {
                ret = -1;
                goto err;
        }

        *sa_family = sockaddr->sa_family;

        switch (sockaddr->sa_family) {
                case AF_INET_SDP:
                        sockaddr->sa_family = AF_INET;

                case AF_INET:
                case AF_INET6:
                case AF_UNSPEC:
                        ret = af_inet_client_get_remote_sockaddr (
                          this, sockaddr, sockaddr_len);
                        break;

                case AF_UNIX:
                        ret = af_unix_client_get_remote_sockaddr (
                          this, sockaddr, sockaddr_len);
                        break;

                default:
                        gf_log (this->name, GF_LOG_ERROR,
                                "unknown address-family %d",
                                sockaddr->sa_family);
                        ret = -1;
        }

        if (*sa_family == AF_UNSPEC) {
                *sa_family = sockaddr->sa_family;
        }

err:
        return ret;
}

int32_t
server_fill_address_family (rpc_transport_t* this, sa_family_t* sa_family)
{
        data_t* address_family_data = NULL;
        int32_t ret = -1;

        GF_VALIDATE_OR_GOTO ("socket", sa_family, out);

        address_family_data =
          dict_get (this->options, "transport.address-family");
        if (address_family_data) {
                char* address_family = NULL;
                address_family = data_to_str (address_family_data);

                if (!strcasecmp (address_family, "inet")) {
                        *sa_family = AF_INET;
                } else if (!strcasecmp (address_family, "inet6")) {
                        *sa_family = AF_INET6;
                } else if (!strcasecmp (address_family, "inet-sdp")) {
                        *sa_family = AF_INET_SDP;
                } else if (!strcasecmp (address_family, "unix")) {
                        *sa_family = AF_UNIX;
                } else {
                        gf_log (this->name, GF_LOG_ERROR,
                                "unknown address family (%s) specified",
                                address_family);
                        *sa_family = AF_UNSPEC;
                        goto out;
                }
        } else {
                gf_log (
                  this->name, GF_LOG_DEBUG,
                  "option address-family not specified, defaulting to inet");
                *sa_family = AF_INET;
        }

        ret = 0;
out:
        return ret;
}

int32_t
socket_server_get_local_sockaddr (rpc_transport_t* this, struct sockaddr* addr,
                                  socklen_t* addr_len, sa_family_t* sa_family)
{
        int32_t ret = -1;

        GF_VALIDATE_OR_GOTO ("socket", sa_family, err);
        GF_VALIDATE_OR_GOTO ("socket", addr, err);
        GF_VALIDATE_OR_GOTO ("socket", addr_len, err);

        ret = server_fill_address_family (this, &addr->sa_family);
        if (ret == -1) {
                goto err;
        }

        *sa_family = addr->sa_family;

        switch (addr->sa_family) {
                case AF_INET_SDP:
                        addr->sa_family = AF_INET;

                case AF_INET:
                case AF_INET6:
                case AF_UNSPEC:
                        ret = af_inet_server_get_local_sockaddr (this, addr,
                                                                 addr_len);
                        break;

                case AF_UNIX:
                        ret = af_unix_server_get_local_sockaddr (this, addr,
                                                                 addr_len);
                        break;
        }

        if (*sa_family == AF_UNSPEC) {
                *sa_family = addr->sa_family;
        }

err:
        return ret;
}

int32_t
get_transport_identifiers (rpc_transport_t* this)
{
        socket_private_t* priv = NULL;
        int32_t ret = 0;
        char is_inet_sdp = 0;
        uv_getnameinfo_t name_req;

        priv = this->private;

        switch (((struct sockaddr*)&this->myinfo.sockaddr)->sa_family) {
                case AF_INET_SDP:
                        is_inet_sdp = 1;
                        ((struct sockaddr*)&this->peerinfo.sockaddr)
                          ->sa_family =
                          ((struct sockaddr*)&this->myinfo.sockaddr)
                            ->sa_family = AF_INET;

                case AF_INET:
                case AF_INET6: {
                        ret = uv_getnameinfo (
                          priv->handle.sock.loop, &name_req, NULL,
                          (struct sockaddr*)&this->peerinfo.sockaddr, 0);
                        if (ret != 0) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "getnameinfo failed (%s)",
                                        uv_strerror (ret));
                                goto err;
                        } else {
                                sprintf (this->peerinfo.identifier, "%s:%s",
                                         name_req.host, name_req.service);
                        }

                        ret = uv_getnameinfo (
                          priv->handle.sock.loop, &name_req, NULL,
                          (struct sockaddr*)&this->myinfo.sockaddr, 0);
                        if (ret != 0) {
                                gf_log (this->name, GF_LOG_ERROR,
                                        "getnameinfo failed (%s)",
                                        uv_strerror (ret));
                                goto err;
                        } else {
                                sprintf (this->myinfo.identifier, "%s:%s",
                                         name_req.host, name_req.service);
                        }

                        if (is_inet_sdp) {
                                ((struct sockaddr*)&this->peerinfo.sockaddr)
                                  ->sa_family =
                                  ((struct sockaddr*)&this->myinfo.sockaddr)
                                    ->sa_family = AF_INET_SDP;
                        }
                } break;

                case AF_UNIX: {
                        struct sockaddr_un* sunaddr = NULL;

                        sunaddr = (struct sockaddr_un*)&this->myinfo.sockaddr;
                        strcpy (this->myinfo.identifier, sunaddr->sun_path);

                        sunaddr = (struct sockaddr_un*)&this->peerinfo.sockaddr;
                        strcpy (this->peerinfo.identifier, sunaddr->sun_path);
                } break;

                default:
                        gf_log (this->name, GF_LOG_ERROR,
                                "unknown address family (%d)",
                                ((struct sockaddr*)&this->myinfo.sockaddr)
                                  ->sa_family);
                        ret = -1;
                        break;
        }

err:
        return ret;
}
