
winfsp_dir = $(top_builddir)/../winfsp

noinst_HEADERS_windows = \
	$(CONTRIBDIR)/winfsp/fuse.h \
	$(CONTRIBDIR)/winfsp/fuse_common.h \
	$(CONTRIBDIR)/winfsp/fuse_opt.h \
	$(CONTRIBDIR)/winfsp/winfsp_fuse.h
noinst_HEADERS_common = $(CONTRIBDIR)/fuse-include/fuse-mount.h\
	$(CONTRIBDIR)/fuse-include/fuse-misc.h fuse-mem-types.h \
	fuse-bridge.h

noinst_HEADERS = $(noinst_HEADERS_common) $(noinst_HEADERS_windows)

xlator_LTLIBRARIES = fuse.la
xlatordir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/mount

fuse_la_SOURCES = fuse-helpers.c fuse-resolve.c fuse-bridge.c \
	fuse-cache.c \
	winfsp-bridge.c \
	$(CONTRIBDIR)/winfsp/mount-winfsp.c \
	$(CONTRIBDIR)/winfsp/mount-winfsp-common.c \
	$(CONTRIBDIR)/winfsp/misc.c

fuse_la_LDFLAGS = -module -avoid-version  -no-undefined
fuse_la_LIBADD = $(GF_LDADD) $(top_builddir)/libglusterfs/src/libglusterfs.la

AM_CPPFLAGS = $(GF_CPPFLAGS) $(GF_FUSE_CFLAGS) -DCYGFUSE \
    -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -lglib-2.0 \
	-I$(top_srcdir)/libglusterfs/src -I$(CONTRIBDIR)/fuse-include \
	-I$(CONTRIBDIR)/winfsp \
	-D_FILE_OFFSET_BITS=64 -L$(winfsp_dir)/opt/cygfuse -lfuse-2.8 \
	-I$(top_builddir)/../cyguv/libuv/include

AM_CFLAGS = -Wall $(GF_CFLAGS) $(GF_FUSE_CFLAGS) -DCYGFUSE \
	-I$(CONTRIBDIR)/fuse-include \
    -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -lglib-2.0 \
	-D_FILE_OFFSET_BITS=64 -L$(winfsp_dir)/opt/cygfuse -lfuse-2.8

CLEANFILES =
