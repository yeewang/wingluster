
dokan_dir = $(top_builddir)/../dokany

noinst_HEADERS_windows = $(CONTRIBDIR)/fuse-include/fuse_kernel.h\
	$(CONTRIBDIR)/fuse-include/mount_util.h\
	$(CONTRIBDIR)/dokan/mount-gluster-compat.h
noinst_HEADERS_common = $(CONTRIBDIR)/fuse-include/fuse-mount.h\
	$(CONTRIBDIR)/fuse-include/fuse-misc.h fuse-mem-types.h \
	fuse-bridge.h

noinst_HEADERS = $(noinst_HEADERS_common) $(noinst_HEADERS_windows)

xlator_LTLIBRARIES = dokan.la
xlatordir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/mount

dokan_la_SOURCES = fuse-helpers.c fuse-resolve.c fuse-bridge.c \
	$(CONTRIBDIR)/fuse-lib/misc.c \
	$(CONTRIBDIR)/dokan/mount_dokan.c $(CONTRIBDIR)/dokan/mount_dokan-common.c

dokan_la_LDFLAGS = -module -avoid-version  -no-undefined
dokan_la_LIBADD = $(GF_LDADD) $(top_builddir)/libglusterfs/src/libglusterfs.la

AM_CPPFLAGS = $(GF_CPPFLAGS) $(GF_FUSE_CFLAGS) \
	-I$(top_srcdir)/libglusterfs/src -I$(CONTRIBDIR)/fuse-include \
	-I$(CONTRIBDIR)/fuse-lib \
	-I$(dokan_dir)/dokan_fuse/include -D_FILE_OFFSET_BITS=64 -L$(dokan_dir)/dokan_fuse -ldokanfuse1

AM_CFLAGS = -Wall $(GF_CFLAGS) $(GF_FUSE_CFLAGS) \
	-I$(dokan_dir)/dokan_fuse/include -D_FILE_OFFSET_BITS=64 -L$(dokan_dir)/dokan_fuse -ldokanfuse1

CLEANFILES =
