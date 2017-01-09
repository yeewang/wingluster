lib_LTLIBRARIES = libgfrpc.la

libgfrpc_la_SOURCES = auth-unix.c rpcsvc-auth.c rpcsvc.c auth-null.c \
	rpc-transport.c xdr-rpc.c xdr-rpcclnt.c rpc-clnt.c auth-glusterfs.c \
	rpc-drc.c $(CONTRIBDIR)/sunrpc/xdr_sizeof.c  rpc-clnt-ping.c

libgfrpc_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la $(top_srcdir)/rpc/xdr/src/libgfxdr.la
libgfrpc_la_LDFLAGS = -version-info $(LIBGFRPC_LT_VERSION) $(GF_LDFLAGS)  -no-undefined

noinst_HEADERS = rpcsvc.h rpc-transport.h xdr-common.h xdr-rpc.h xdr-rpcclnt.h \
	rpc-clnt.h rpcsvc-common.h protocol-common.h rpc-drc.h rpc-clnt-ping.h \
	rpc-lib-messages.h

AM_CPPFLAGS = $(GF_CPPFLAGS) -I$(top_srcdir)/libglusterfs/src \
	-I$(top_srcdir)/rpc/xdr/src \
	-DRPC_TRANSPORTDIR=\"$(libdir)/glusterfs/$(PACKAGE_VERSION)/rpc-transport\" \
	-I$(top_srcdir)/contrib/rbtree \
	-I/usr/include/tirpc

AM_CFLAGS = -Wall $(GF_CFLAGS) -I/usr/include/tirpc -I$(top_builddir)/../libuv-v1.9.1/include

CLEANFILES = *~
