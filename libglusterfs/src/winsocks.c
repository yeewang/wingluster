

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cygwin.h>
#include <unistd.h>
#include "common-utils.h"

#ifndef _WIN32
//#include "windows-socks.h"
#endif

#define WSOCKS_API_CALL(api) (pfn_##api)

static void* winsocks_init();
static void* winsocks_init_fail();

static pthread_mutex_t winsocks_mutex = PTHREAD_MUTEX_INITIALIZER;
static void* winsocks_handle = 0;

void __attribute__((constructor)) winsocks_init_internal(int force)
{
    pthread_mutex_lock(&winsocks_mutex);
    if (force || 0 == winsocks_handle)
        winsocks_handle = winsocks_init();
    pthread_mutex_unlock(&winsocks_mutex);
}

#define WSOCKS_GET_API(h, n)                       \
    if (0 == (*(void**)&(pfn_##n) = dlsym(h, #n))) \
        return winsocks_init_fail(#n);

#define WSOCKS_API_NAME(api) (*pfn_##api)

int WSOCKS_API_NAME(wsock_init)();
int WSOCKS_API_NAME(wsock_cleanup)();
int WSOCKS_API_NAME(wsock_accept)(int s,
    struct sockaddr* addr,
    int* addrlen);
int WSOCKS_API_NAME(wsock_bind)(int s,
    struct sockaddr* name,
    int namelen);
int WSOCKS_API_NAME(wsock_closesocket)(int s);
int WSOCKS_API_NAME(wsock_connect)(int s,
    struct sockaddr* name,
    int namelen);
int WSOCKS_API_NAME(wsock_ioctlsocket)(int s,
    long cmd,
    u_long* argp);
int WSOCKS_API_NAME(wsock_listen)(int s, int backlog);
ssize_t WSOCKS_API_NAME(wsock_recv)(int s, char* buf, int len);
int WSOCKS_API_NAME(wsock_recvfrom)(int s, char* buf, int len, int flags,
    struct sockaddr* from, int* fromlen);
ssize_t WSOCKS_API_NAME(wsock_recvv)(int fd, const struct iovec* iov, int iovcnt);
int WSOCKS_API_NAME(wsock_select)(int nfds,
    fd_set* readfds,
    fd_set* writefds,
    fd_set* exceptfds,
    struct timeval* timeout);
ssize_t WSOCKS_API_NAME(wsock_send)(int s, char* buf, int len);
ssize_t WSOCKS_API_NAME(wsock_sendv)(int fd, const struct iovec* iov, int iovcnt);
int WSOCKS_API_NAME(wsock_sendto)(int s, char* buf, int len, int flags,
    struct sockaddr* to, int tolen);
int WSOCKS_API_NAME(wsock_setsockopt)(int s,
    int level,
    int optname,
    char* optval,
    int optlen);
int WSOCKS_API_NAME(wsock_getsockopt)(int s,
    int level,
    int optname,
    char* optval,
    int* optlen);
int WSOCKS_API_NAME(wsock_shutdown)(int s, int how);
int WSOCKS_API_NAME(wsock_socket)(int af, int type, int protocol);
int WSOCKS_API_NAME(wsock_poll)(struct pollfd* fds, int nfds, int timeout);
int WSOCKS_API_NAME(wsock_tcp_nodelay)(int socket, int enable);
int WSOCKS_API_NAME(wsock_tcp_keepalive)(int socket, int enable, unsigned int delay);
int WSOCKS_API_NAME(wsock_getpeername)(int s, struct sockaddr* name, int* namelen);
int WSOCKS_API_NAME(wsock_getsockname)(int s, struct sockaddr* name, int* namelen);
int WSOCKS_API_NAME(wsock_getnameinfo)(const struct sockaddr *addr, socklen_t addrlen,
	char *host, socklen_t hostlen,
	char *serv, socklen_t servlen, int flags);

static void* winsocks_init()
{
    void* h;

    h = dlopen("wsocks.dll", RTLD_NOW);
    if (0 == h) {
        h = dlopen("/bin/wsocks.dll", RTLD_NOW);
        if (0 == h)
            return winsocks_init_fail();
    }

    WSOCKS_GET_API(h, wsock_accept);
    WSOCKS_GET_API(h, wsock_bind);
    WSOCKS_GET_API(h, wsock_closesocket);
    WSOCKS_GET_API(h, wsock_connect);
    WSOCKS_GET_API(h, wsock_ioctlsocket);
    WSOCKS_GET_API(h, wsock_listen);
    WSOCKS_GET_API(h, wsock_recv);
    WSOCKS_GET_API(h, wsock_recvfrom);
    WSOCKS_GET_API(h, wsock_recvv);
    WSOCKS_GET_API(h, wsock_select);
    WSOCKS_GET_API(h, wsock_send);
    WSOCKS_GET_API(h, wsock_sendv);
    WSOCKS_GET_API(h, wsock_sendto);
    WSOCKS_GET_API(h, wsock_setsockopt);
    WSOCKS_GET_API(h, wsock_getsockopt);
    WSOCKS_GET_API(h, wsock_shutdown);
    WSOCKS_GET_API(h, wsock_socket);
    WSOCKS_GET_API(h, wsock_poll);
    WSOCKS_GET_API(h, wsock_tcp_nodelay);
    WSOCKS_GET_API(h, wsock_tcp_keepalive);
    WSOCKS_GET_API(h, wsock_getpeername);
    WSOCKS_GET_API(h, wsock_getsockname);
    WSOCKS_GET_API(h, wsock_getnameinfo);

    return h;
}

static void* winsocks_init_fail(const char* msg)
{
    GF_ASSERT(0);
    return 0;
}

int wsock_accept(int s, struct sockaddr* addr, int* addrlen)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_accept)(s, addr, addrlen);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

int wsock_bind(int s, struct sockaddr* name, int namelen)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_bind)(s, name, namelen);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

int wsock_closesocket(int s)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_closesocket)(s);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

int wsock_connect(int s, struct sockaddr* name, int namelen)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_connect)(s, name, namelen);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

int wsock_ioctlsocket(int s, long cmd, u_long* argp)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_ioctlsocket)(s, cmd, argp);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

int wsock_listen(int s, int backlog)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_listen)(s, backlog);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

ssize_t wsock_recv(int s, char* buf, int len)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_recv)(s, buf, len);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

int wsock_recvfrom(int s, char* buf, int len, int flags,
    struct sockaddr* from, int* fromlen)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_recvfrom)(s, buf, len, flags, from, fromlen);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;

}

#if 0
struct iovec {
    void* iov_base; /* Starting address */
    size_t iov_len; /* Number of bytes to transfer */
};
#endif
ssize_t wsock_recvv(int fd, const struct iovec* iov, int iovcnt)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_recvv)(fd, iov, iovcnt);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;

}

int wsock_select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds,
    struct timeval* timeout)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_select)(nfds, readfds, writefds, exceptfds, timeout);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

ssize_t wsock_send(int s, char* buf, int len)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_send)(s, buf, len);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

ssize_t wsock_sendv(int fd, const struct iovec* iov, int iovcnt)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_sendv)(fd, iov, iovcnt);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

int wsock_sendto(int s, char* buf, int len, int flags, struct sockaddr* to,
    int tolen)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_sendto)(s, buf, len, flags, to, tolen);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

int wsock_setsockopt(int s, int level, int optname, char* optval,
    int optlen)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_setsockopt)(s, level, optname, optval, optlen);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

int wsock_getsockopt(int s, int level, int optname, char* optval,
    int* optlen)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_getsockopt)(s, level, optname, optval, optlen);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

int wsock_shutdown(int s, int how)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_shutdown)(s, how);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

int wsock_socket(int af, int type, int protocol)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_socket)(af, type, protocol);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

int wsock_poll(struct pollfd* fds, int nfds, int timeout)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_poll)(fds, nfds, timeout);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

int wsock_tcp_nodelay(int socket, int enable)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_tcp_nodelay)(socket, enable);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

int wsock_tcp_keepalive(int socket, int enable, unsigned int delay)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_tcp_keepalive)(socket, enable, delay);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

int wsock_getpeername(int s, struct sockaddr* name, int* namelen)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_getpeername)(s, name, namelen);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

int wsock_getsockname(int s, struct sockaddr* name, int* namelen)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_getsockname)(s, name, namelen);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

int wsock_getnameinfo(const struct sockaddr *addr, socklen_t addrlen,
	char *host, socklen_t hostlen,
	char *serv, socklen_t servlen, int flags)
{
    int ret;
    ret = WSOCKS_API_CALL(wsock_getnameinfo)(addr, addrlen, host, hostlen,
        serv, servlen, flags);
    if (ret < 0) {
        errno = -ret;
        ret = -1;
    }
    return ret;
}

