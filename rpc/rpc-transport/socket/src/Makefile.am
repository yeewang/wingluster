noinst_HEADERS = socket.h name.h socket-mem-types.h

rpctransport_LTLIBRARIES = socket.la
rpctransportdir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/rpc-transport

socket_la_LDFLAGS = -module -avoid-version -no-undefined

socket_la_SOURCES =

if GF_CYGWIN_HOST_OS
socket_la_SOURCES += name-win32.c socket-win32.c
else
socket_la_SOURCES += name.c socket.c
endif

socket_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la -lssl $(top_builddir)/rpc/rpc-lib/src/libgfrpc.la

AM_CPPFLAGS = $(GF_CPPFLAGS) \
	-I$(top_srcdir)/libglusterfs/src -I$(top_srcdir)/rpc/rpc-lib/src/ \
	-I$(top_srcdir)/rpc/xdr/src/ \
	-I/usr/include/tirpc \
	-I$(top_builddir)/../cyguv/libuv/include

AM_CFLAGS = -Wall $(GF_CFLAGS) -I/usr/include/tirpc

CLEANFILES = *~
