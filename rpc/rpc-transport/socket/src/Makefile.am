noinst_HEADERS = socket.h name.h socket-mem-types.h

rpctransport_LTLIBRARIES = socket.la
rpctransportdir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/rpc-transport

socket_la_LDFLAGS = $(GF_LDFLAGS) -module -avoid-version

socket_la_SOURCES = socket.c name.c
socket_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la \
                   $(top_builddir)/rpc/xdr/src/libgfxdr.la \
				   $(top_builddir)/rpc/rpc-lib/src/libgfrpc.la \
                   -lssl

if GF_CYGWIN_HOST_OS
#socket_la_SOURCES += winsocks.c
endif

AM_CPPFLAGS = $(GF_CPPFLAGS) \
	-I$(top_srcdir)/libglusterfs/src \
	-I$(top_srcdir)/rpc/rpc-lib/src/ \
	-I$(top_srcdir)/rpc/xdr/src/ \
	-I$(top_builddir)/rpc/xdr/src/
	-I/usr/include/tirpc \
	-I$(top_builddir)/../cyguv/libuv/include

AM_CFLAGS = -Wall $(GF_CFLAGS)

CLEANFILES = *~
