xlator_LTLIBRARIES = afr.la pump.la
xlatordir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/cluster

afr_common_source = afr-dir-read.c afr-dir-write.c afr-inode-read.c \
	afr-inode-write.c afr-open.c afr-transaction.c afr-lk-common.c \
	afr-read-txn.c \
	$(top_builddir)/xlators/lib/src/libxlator.c

AFR_SELFHEAL_SOURCES = afr-self-heal-common.c afr-self-heal-data.c \
	afr-self-heal-entry.c afr-self-heal-metadata.c afr-self-heald.c \
	afr-self-heal-name.c

afr_la_LDFLAGS = -module -avoid-version -no-undefined
afr_la_SOURCES = $(afr_common_source) $(AFR_SELFHEAL_SOURCES) afr.c
afr_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la

pump_la_LDFLAGS = -module -avoid-version -no-undefined
pump_la_SOURCES =  $(afr_common_source) $(AFR_SELFHEAL_SOURCES) pump.c
pump_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la

noinst_HEADERS = afr.h afr-transaction.h afr-inode-write.h afr-inode-read.h \
	afr-dir-read.h afr-dir-write.h afr-self-heal.h afr-mem-types.h \
	afr-common.c afr-self-heald.h pump.h \
	$(top_builddir)/xlators/lib/src/libxlator.h afr-messages.h

AM_CPPFLAGS = $(GF_CPPFLAGS) \
	-I$(top_srcdir)/libglusterfs/src -I$(top_srcdir)/xlators/lib/src \
	-I$(top_srcdir)/rpc/rpc-lib/src

AM_CFLAGS = -Wall $(GF_CFLAGS)

CLEANFILES =

uninstall-local:
if GF_CYGWIN_HOST_OS
	rm -f $(DESTDIR)$(xlatordir)/replicate.dll
else
	rm -f $(DESTDIR)$(xlatordir)/replicate.so
endif

install-data-hook:
if GF_CYGWIN_HOST_OS
	cp .libs/afr.dll $(DESTDIR)$(xlatordir)/replicate.dll
else
	ln -sf afr.so $(DESTDIR)$(xlatordir)/replicate.so
endif
