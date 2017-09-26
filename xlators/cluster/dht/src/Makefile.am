xlator_LTLIBRARIES = dht.la nufa.la switch.la
if BUILD_GFDB
   xlator_LTLIBRARIES += tier.la
endif

AM_CFLAGS = -Wall $(GF_CFLAGS)

xlatordir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/cluster

dht_common_source = dht-layout.c dht-helper.c dht-linkfile.c dht-rebalance.c \
	dht-selfheal.c dht-rename.c dht-hashfn.c dht-diskusage.c \
	dht-common.c dht-inode-write.c dht-inode-read.c dht-shared.c \
	dht-lock.c $(top_builddir)/xlators/lib/src/libxlator.c

dht_la_SOURCES = $(dht_common_source) dht.c

nufa_la_SOURCES = $(dht_common_source) nufa.c
switch_la_SOURCES = $(dht_common_source) switch.c
tier_la_SOURCES = $(dht_common_source) tier.c tier-common.c

if GF_CYGWIN_HOST_OS
dht_la_LDFLAGS = -module -avoid-version -no-undefined
else
dht_la_LDFLAGS = -module -avoid-version -export-symbols \
	$(top_srcdir)/xlators/cluster/dht/src/dht.sym
endif
dht_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la

if GF_CYGWIN_HOST_OS
nufa_la_LDFLAGS = -module -avoid-version -no-undefined
else
nufa_la_LDFLAGS = -module -avoid-version -export-symbols \
	$(top_srcdir)/xlators/cluster/dht/src/nufa.sym
endif
nufa_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la

if GF_CYGWIN_HOST_OS
switch_la_LDFLAGS = -module -avoid-version -no-undefined
else
switch_la_LDFLAGS = -module -avoid-version -export-symbols \
	$(top_srcdir)/xlators/cluster/dht/src/switch.sym
endif
switch_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la

if GF_CYGWIN_HOST_OS
tier_la_LDFLAGS = -module -avoid-version -no-undefined
else
tier_la_LDFLAGS = -module -avoid-version -export-symbols \
	$(top_srcdir)/xlators/cluster/dht/src/tier.sym
endif
tier_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la

noinst_HEADERS = dht-common.h dht-mem-types.h dht-messages.h \
	dht-lock.h tier-common.h tier.h \
	$(top_builddir)/xlators/lib/src/libxlator.h

AM_CPPFLAGS = $(GF_CPPFLAGS) -I$(top_srcdir)/libglusterfs/src \
	-I$(top_srcdir)/libglusterfs/src/gfdb \
	-I$(top_srcdir)/rpc/xdr/src -I$(top_builddir)/rpc/xdr/src \
	-I$(top_srcdir)/rpc/rpc-lib/src \
	-I$(top_srcdir)/xlators/lib/src \
	-DDATADIR=\"$(localstatedir)\" \
	-DLIBDIR=\"$(libdir)\" \
	-DLIBGFDB_VERSION=\"$(LIBGFDB_VERSION)\"

CLEANFILES =

EXTRA_DIST = dht.sym nufa.sym switch.sym tier.sym

if GF_CYGWIN_HOST_OS
uninstall-local:
	rm -f $(DESTDIR)$(xlatordir)/distribute.dll

install-data-hook:
	cp .libs/dht.dll $(DESTDIR)$(xlatordir)/distribute.dll
else
uninstall-local:
	rm -f $(DESTDIR)$(xlatordir)/distribute.so

install-data-hook:
	ln -sf dht.so $(DESTDIR)$(xlatordir)/distribute.so
endif

if UNITTEST
CLEANFILES += *.gcda *.gcno *_xunit.xml
noinst_PROGRAMS =
TESTS =
endif
