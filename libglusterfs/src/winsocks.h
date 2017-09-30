#ifndef _WINDOWS_SOCKS_H_
#define _WINDOWS_SOCKS_H_

#include <poll.h>

int wsock_init();
int wsock_cleanup();
int wsock_accept(int s,
    struct sockaddr* addr,
    int* addrlen);
int wsock_bind(int s,
    struct sockaddr* name,
    int namelen);
int wsock_closesocket(int s);
int wsock_connect(int s,
    struct sockaddr* name,
    int namelen);
int wsock_ioctlsocket(int s,
    long cmd,
    u_long* argp);
int wsock_listen(int s, int backlog);
ssize_t wsock_recv(int s, char* buf, int len);
int wsock_recvfrom(int s, char* buf, int len, int flags,
    struct sockaddr* from, int* fromlen);
ssize_t wsock_recvv(int fd, const struct iovec* iov, int iovcnt);
int wsock_select(int nfds,
    fd_set* readfds,
    fd_set* writefds,
    fd_set* exceptfds,
    struct timeval* timeout);
ssize_t wsock_send(int s, char* buf, int len);
ssize_t wsock_sendv(int fd, const struct iovec* iov, int iovcnt);
int wsock_sendto(int s, char* buf, int len, int flags,
    struct sockaddr* to, int tolen);
int wsock_setsockopt(int s,
    int level,
    int optname,
    char* optval,
    int optlen);
int wsock_getsockopt(int s,
    int level,
    int optname,
    char* optval,
    int* optlen);
int wsock_shutdown(int s, int how);
int wsock_socket(int af, int type, int protocol);
int wsock_poll(struct pollfd* fds, int nfds, int timeout);
int wsock_tcp_nodelay(int socket, int enable);
int wsock_tcp_keepalive(int socket, int enable, unsigned int delay);
int wsock_getpeername(int s, struct sockaddr* name, int* namelen);
int wsock_getsockname(int s, struct sockaddr* name, int* namelen);
int wsock_getnameinfo(const struct sockaddr *addr, socklen_t addrlen,
	char *host, socklen_t hostlen,
	char *serv, socklen_t servlen, int flags);

#endif /* _WINDOWS_SOCKS_H_ */