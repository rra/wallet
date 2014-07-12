# Automake makefile for wallet.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2006, 2007, 2008, 2010, 2013, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

# These variables exist only for the use of the Debian packaging and similar
# situations and aren't normally set.  We want to honor them if they're set
# in the environment, as well as via make arguments.
#
# WALLET_PERL_FLAGS are additional flags to pass to Build.PL when building
# the Makefile.
WALLET_PERL_FLAGS ?=

# These two lists of files are needed for Perl builds and for the test suite
# and are not generated or touched by configure.  They're listed here to be
# added to EXTRA_DIST and so that they can be copied over properly for
# builddir != srcdir builds.
PERL_FILES = perl/Build.PL perl/MANIFEST perl/MANIFEST.SKIP		   \
	perl/lib/Wallet/ACL.pm perl/lib/Wallet/ACL/Base.pm		   \
	perl/lib/Wallet/ACL/Krb5.pm perl/lib/Wallet/ACL/Krb5/Regex.pm	   \
	perl/lib/Wallet/ACL/LDAP/Attribute.pm perl/lib/Wallet/ACL/NetDB.pm \
	perl/lib/Wallet/ACL/NetDB/Root.pm perl/lib/Wallet/Admin.pm	   \
	perl/lib/Wallet/Config.pm perl/lib/Wallet/Database.pm		   \
	perl/lib/Wallet/Kadmin.pm perl/lib/Wallet/Kadmin/Heimdal.pm	   \
	perl/lib/Wallet/Kadmin/MIT.pm perl/lib/Wallet/Object/Base.pm	   \
	perl/lib/Wallet/Object/Duo.pm perl/lib/Wallet/Object/File.pm	   \
	perl/lib/Wallet/Object/Keytab.pm				   \
	perl/lib/Wallet/Object/WAKeyring.pm				   \
	perl/lib/Wallet/Policy/Stanford.pm perl/lib/Wallet/Report.pm	   \
	perl/lib/Wallet/Schema.pm perl/lib/Wallet/Server.pm		   \
	perl/lib/Wallet/Schema/Result/Acl.pm				   \
	perl/lib/Wallet/Schema/Result/AclEntry.pm			   \
	perl/lib/Wallet/Schema/Result/AclHistory.pm			   \
	perl/lib/Wallet/Schema/Result/AclScheme.pm			   \
	perl/lib/Wallet/Schema/Result/Duo.pm				   \
	perl/lib/Wallet/Schema/Result/Enctype.pm			   \
	perl/lib/Wallet/Schema/Result/Flag.pm				   \
	perl/lib/Wallet/Schema/Result/KeytabEnctype.pm			   \
	perl/lib/Wallet/Schema/Result/KeytabSync.pm			   \
	perl/lib/Wallet/Schema/Result/Object.pm				   \
	perl/lib/Wallet/Schema/Result/ObjectHistory.pm			   \
	perl/lib/Wallet/Schema/Result/SyncTarget.pm			   \
	perl/lib/Wallet/Schema/Result/Type.pm				   \
	perl/sql/Wallet-Schema-0.07-0.08-MySQL.sql			   \
	perl/sql/Wallet-Schema-0.07-0.08-SQLite.sql			   \
	perl/sql/Wallet-Schema-0.07-MySQL.sql				   \
	perl/sql/Wallet-Schema-0.07-SQLite.sql				   \
	perl/sql/Wallet-Schema-0.08-0.09-MySQL.sql			   \
	perl/sql/Wallet-Schema-0.08-0.09-PostgreSQL.sql			   \
	perl/sql/Wallet-Schema-0.08-0.09-SQLite.sql			   \
	perl/sql/Wallet-Schema-0.08-MySQL.sql				   \
	perl/sql/Wallet-Schema-0.08-PostgreSQL.sql			   \
	perl/sql/Wallet-Schema-0.08-SQLite.sql				   \
	perl/sql/Wallet-Schema-0.09-MySQL.sql				   \
	perl/sql/Wallet-Schema-0.09-PostgreSQL.sql			   \
	perl/sql/Wallet-Schema-0.09-SQLite.sql perl/t/data/README	   \
	perl/t/data/duo/integration.json perl/t/data/duo/keys.json	   \
	perl/t/data/keytab-fake perl/t/data/keytab.conf			   \
	perl/t/data/netdb.conf perl/t/data/netdb-fake			   \
	perl/t/docs/pod-spelling.t perl/t/docs/pod.t perl/t/general/acl.t  \
	perl/t/general/admin.t perl/t/general/config.t			   \
	perl/t/general/init.t perl/t/general/report.t			   \
	perl/t/general/server.t perl/t/lib/Util.pm perl/t/object/base.t	   \
	perl/t/object/duo.t perl/t/object/file.t perl/t/object/keytab.t	   \
	perl/t/object/wa-keyring.t perl/t/policy/stanford.t		   \
	perl/t/util/kadmin.t perl/t/verifier/basic.t			   \
	perl/t/verifier/ldap-attr.t perl/t/verifier/netdb.t

# Directories that have to be created in builddir != srcdir builds before
# copying PERL_FILES over.
PERL_DIRECTORIES = perl perl/lib perl/lib/Wallet perl/lib/Wallet/ACL	\
	perl/lib/Wallet/ACL/Krb5 perl/lib/Wallet/ACL/LDAP		\
	perl/lib/Wallet/ACL/NetDB perl/lib/Wallet/Kadmin		\
	perl/lib/Wallet/Object perl/lib/Wallet/Policy			\
	perl/lib/Wallet/Schema perl/lib/Wallet/Schema/Result perl/sql	\
	perl/t perl/t/data perl/t/docs perl/t/general perl/t/lib	\
	perl/t/object perl/t/policy perl/t/util perl/t/verifier

ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = .gitignore LICENSE autogen client/wallet.pod		   \
	client/wallet-rekey.pod config/allow-extract config/keytab	   \
	config/keytab.acl config/wallet config/wallet-report.acl	   \
	docs/design contrib/README contrib/convert-srvtab-db		   \
	contrib/used-principals contrib/wallet-contacts			   \
	contrib/wallet-summary contrib/wallet-summary.8			   \
	contrib/wallet-unknown-hosts contrib/wallet-unknown-hosts.8	   \
	docs/design-acl docs/design-api docs/netdb-role-api docs/notes	   \
	docs/objects-and-schemes docs/setup docs/stanford-naming	   \
	examples/stanford.conf perl/create-ddl tests/HOWTO tests/TESTS	   \
	tests/config/README tests/data/allow-extract tests/data/basic.conf \
	tests/data/cmd-fake tests/data/cmd-wrapper tests/data/fake-data	   \
	tests/data/fake-kadmin tests/data/fake-keytab			   \
	tests/data/fake-keytab-2 tests/data/fake-keytab-foreign		   \
	tests/data/fake-keytab-merge tests/data/fake-keytab-old		   \
	tests/data/fake-keytab-partial					   \
	tests/data/fake-keytab-partial-result tests/data/fake-keytab-rekey \
	tests/data/fake-keytab-unknown tests/data/fake-srvtab		   \
	tests/data/full.conf tests/data/perl.conf tests/data/wallet.conf   \
	tests/docs/pod-spelling-t tests/docs/pod-t tests/server/admin-t	   \
	tests/server/backend-t tests/server/keytab-t tests/server/report-t \
	tests/tap/kerberos.sh tests/tap/libtap.sh			   \
	tests/tap/perl/Test/RRA.pm tests/tap/perl/Test/RRA/Automake.pm	   \
	tests/tap/perl/Test/RRA/Config.pm tests/tap/remctl.sh		   \
	tests/util/xmalloc-t $(PERL_FILES)

# Supporting convenience libraries used by other targets.
noinst_LIBRARIES = portable/libportable.a util/libutil.a
portable_libportable_a_SOURCES = portable/dummy.c portable/krb5-extra.c	\
	portable/krb5.h portable/macros.h portable/stdbool.h		\
	portable/system.h portable/uio.h
portable_libportable_a_CPPFLAGS = $(KRB5_CPPFLAGS)
portable_libportable_a_LIBADD = $(LIBOBJS)
util_libutil_a_SOURCES = util/macros.h util/messages-krb5.c		    \
	util/messages-krb5.h util/messages.c util/messages.h util/xmalloc.c \
	util/xmalloc.h
util_libutil_a_CPPFLAGS = $(KRB5_CPPFLAGS)

# The private library used by both wallet and wallet-rekey.
noinst_LIBRARIES += client/libwallet.a
client_libwallet_a_SOURCES = client/file.c client/internal.h client/keytab.c \
	client/krb5.c client/options.c client/remctl.c client/srvtab.c
client_libwallet_a_CPPFLAGS = $(REMCTL_CPPFLAGS) $(KRB5_CPPFLAGS)

# The client and server programs.
bin_PROGRAMS = client/wallet client/wallet-rekey
dist_sbin_SCRIPTS = server/keytab-backend server/wallet-admin \
	server/wallet-backend server/wallet-report
client_wallet_CPPFLAGS = $(REMCTL_CPPFLAGS) $(KRB5_CPPFLAGS)
client_wallet_LDFLAGS = $(REMCTL_LDFLAGS) $(KRB5_LDFLAGS)
client_wallet_LDADD = client/libwallet.a util/libutil.a \
	portable/libportable.a $(REMCTL_LIBS) $(KRB5_LIBS)
client_wallet_rekey_CPPFLAGS = $(REMCTL_CPPFLAGS) $(KRB5_CPPFLAGS)
client_wallet_rekey_LDFLAGS = $(REMCTL_LDFLAGS) $(KRB5_LDFLAGS)
client_wallet_rekey_LDADD = client/libwallet.a util/libutil.a \
	portable/libportable.a $(REMCTL_LIBS) $(KRB5_LIBS)

# The manual pages.
dist_man_MANS = client/wallet.1 client/wallet-rekey.1 server/keytab-backend.8 \
	server/wallet-admin.8 server/wallet-backend.8 server/wallet-report.8

# Install the SQL files that are used by the server code to do upgrades.
dist_pkgdata_DATA = perl/sql/Wallet-Schema-0.07-0.08-MySQL.sql	\
	perl/sql/Wallet-Schema-0.07-0.08-SQLite.sql		\
	perl/sql/Wallet-Schema-0.07-MySQL.sql			\
	perl/sql/Wallet-Schema-0.07-SQLite.sql			\
	perl/sql/Wallet-Schema-0.08-0.09-MySQL.sql		\
	perl/sql/Wallet-Schema-0.08-0.09-PostgreSQL.sql		\
	perl/sql/Wallet-Schema-0.08-0.09-SQLite.sql		\
	perl/sql/Wallet-Schema-0.08-MySQL.sql			\
	perl/sql/Wallet-Schema-0.08-PostgreSQL.sql		\
	perl/sql/Wallet-Schema-0.08-SQLite.sql			\
	perl/sql/Wallet-Schema-0.09-MySQL.sql			\
	perl/sql/Wallet-Schema-0.09-PostgreSQL.sql		\
	perl/sql/Wallet-Schema-0.09-SQLite.sql

# A set of flags for warnings.	Add -O because gcc won't find some warnings
# without optimization turned on.  Desirable warnings that can't be turned
# on due to other problems:
#
#     -Wconversion	http://bugs.debian.org/488884 (htons warnings)
#
# Last checked against gcc 4.8.2 (2014-04-12).	-D_FORTIFY_SOURCE=2 enables
# warn_unused_result attribute markings on glibc functions on Linux, which
# catches a few more issues.
WARNINGS = -g -O -fstrict-overflow -fstrict-aliasing -D_FORTIFY_SOURCE=2    \
	-Wall -Wextra -Wendif-labels -Wformat=2 -Winit-self -Wswitch-enum   \
	-Wstrict-overflow=5 -Wfloat-equal -Wdeclaration-after-statement	    \
	-Wshadow -Wpointer-arith -Wbad-function-cast -Wcast-align	    \
	-Wwrite-strings -Wjump-misses-init -Wlogical-op -Wstrict-prototypes \
	-Wold-style-definition -Wmissing-prototypes -Wnormalized=nfc	    \
	-Wpacked -Wredundant-decls -Wnested-externs -Winline -Wvla -Werror

warnings:
	$(MAKE) V=0 CFLAGS='$(WARNINGS)' KRB5_CPPFLAGS='$(KRB5_CPPFLAGS_GCC)'
	$(MAKE) V=0 CFLAGS='$(WARNINGS)' \
	    KRB5_CPPFLAGS='$(KRB5_CPPFLAGS_GCC)' $(check_PROGRAMS)

# Remove some additional files.
CLEANFILES = perl/t/lib/Test/RRA.pm perl/t/lib/Test/RRA/Automake.pm \
	perl/t/lib/Test/RRA/Config.pm
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 build-aux/compile		     \
	build-aux/depcomp build-aux/install-sh build-aux/missing	     \
	client/wallet.1 config.h.in config.h.in~ configure		     \
	contrib/wallet-report.8 server/keytab-backend.8			     \
	server/wallet-admin.8 server/wallet-backend.8 server/wallet-report.8

# Take appropriate actions in the Perl directory as well.  We don't want to
# always build the Perl directory in all-local, since otherwise Automake does
# this for every target, which overrides some hacks we have to do for Debian
# packaging.
all-local: perl/blib/lib/Wallet/Config.pm

perl/blib/lib/Wallet/Config.pm: $(srcdir)/perl/lib/Wallet/Config.pm
	set -e; if [ x"$(builddir)" != x"$(srcdir)" ] ; then		\
	    for d in $(PERL_DIRECTORIES) ; do				\
		[ -d "$(builddir)/$$d" ] || mkdir "$(builddir)/$$d" ;	\
	    done ;							\
	    for f in $(PERL_FILES) ; do					\
		cp "$(srcdir)/$$f" "$(builddir)/$$f" ;			\
	    done ;							\
	fi
	cp -R $(srcdir)/tests/tap/perl/* perl/t/lib/
	cd perl && perl Build.PL $(WALLET_PERL_FLAGS)
	cd perl && ./Build

install-data-local:
	if [ x"$(DESTDIR)" != x ] ; then			\
	    cd perl && $(MAKE) install DESTDIR=$(DESTDIR)/ ;	\
	else							\
	    cd perl && $(MAKE) install ;			\
	fi

# ExtUtils::MakeMaker really likes moving the Makefile aside.
clean-local:
	set -e; if [ -f "perl/Build" ] ; then		\
	    cd perl && ./Build realclean ;		\
	fi

# Remove the files that we copy over if and only if builddir != srcdir.
distclean-local:
	set -e; if [ x"$(builddir)" != x"$(srcdir)" ] ; then	\
	    for f in $(PERL_FILES) ; do				\
		rm -f "$(builddir)/$$f" ;			\
	    done ;						\
	fi

# The bits below are for the test suite, not for the main package.
check_PROGRAMS = tests/runtests tests/portable/asprintf-t	\
	tests/portable/mkstemp-t tests/portable/setenv-t	\
	tests/portable/snprintf-t tests/portable/strlcat-t	\
	tests/portable/strlcpy-t tests/util/messages-krb5-t	\
	tests/util/messages-t tests/util/xmalloc
tests_runtests_CPPFLAGS = -DSOURCE='"$(abs_top_srcdir)/tests"' \
	-DBUILD='"$(abs_top_builddir)/tests"'
check_LIBRARIES = tests/tap/libtap.a
tests_tap_libtap_a_CPPFLAGS = -I$(abs_top_srcdir)/tests $(KRB5_CPPFLAGS)
tests_tap_libtap_a_SOURCES = tests/tap/basic.c tests/tap/basic.h	\
	tests/tap/kerberos.c tests/tap/kerberos.h tests/tap/macros.h	\
	tests/tap/messages.c tests/tap/messages.h tests/tap/process.c	\
	tests/tap/process.h tests/tap/string.c tests/tap/string.h

# All of the test programs.
tests_portable_asprintf_t_SOURCES = tests/portable/asprintf-t.c \
	tests/portable/asprintf.c
tests_portable_asprintf_t_LDADD = tests/tap/libtap.a portable/libportable.a
tests_portable_mkstemp_t_SOURCES = tests/portable/mkstemp-t.c \
	tests/portable/mkstemp.c
tests_portable_mkstemp_t_LDADD = tests/tap/libtap.a portable/libportable.a
tests_portable_setenv_t_SOURCES = tests/portable/setenv-t.c \
	tests/portable/setenv.c
tests_portable_setenv_t_LDADD = tests/tap/libtap.a portable/libportable.a
tests_portable_snprintf_t_SOURCES = tests/portable/snprintf-t.c \
	tests/portable/snprintf.c
tests_portable_snprintf_t_LDADD = tests/tap/libtap.a portable/libportable.a
tests_portable_strlcat_t_SOURCES = tests/portable/strlcat-t.c \
	tests/portable/strlcat.c
tests_portable_strlcat_t_LDADD = tests/tap/libtap.a portable/libportable.a
tests_portable_strlcpy_t_SOURCES = tests/portable/strlcpy-t.c \
	tests/portable/strlcpy.c
tests_portable_strlcpy_t_LDADD = tests/tap/libtap.a portable/libportable.a
tests_util_messages_krb5_t_CPPFLAGS = $(KRB5_CPPFLAGS)
tests_util_messages_krb5_t_LDFLAGS = $(KRB5_LDFLAGS)
tests_util_messages_krb5_t_LDADD = tests/tap/libtap.a util/libutil.a \
	portable/libportable.a $(KRB5_LIBS)
tests_util_messages_t_LDADD = tests/tap/libtap.a util/libutil.a \
	portable/libportable.a
tests_util_xmalloc_LDADD = util/libutil.a portable/libportable.a

check-local: $(check_PROGRAMS)
	cd tests && ./runtests -l $(abs_top_srcdir)/tests/TESTS
	@echo ''
	cd perl && ./Build test

# Alas, we have to disable this check because there's no way to do an
# uninstall from Perl.
distuninstallcheck:
	@:
