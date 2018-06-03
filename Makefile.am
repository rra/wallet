# Automake makefile for wallet.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2016, 2018 Russ Allbery <eagle@eyrie.org>
# Copyright 2006-2008, 2010, 2013-2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# SPDX-License-Identifier: MIT

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
PERL_FILES = perl/Build.PL perl/MANIFEST perl/MANIFEST.SKIP perl/create-ddl \
	perl/lib/Wallet/ACL.pm perl/lib/Wallet/ACL/Base.pm		    \
	perl/lib/Wallet/ACL/External.pm perl/lib/Wallet/ACL/Krb5.pm	    \
	perl/lib/Wallet/ACL/Krb5/Regex.pm				    \
	perl/lib/Wallet/ACL/LDAP/Attribute.pm				    \
	perl/lib/Wallet/ACL/LDAP/Attribute/Root.pm			    \
	perl/lib/Wallet/ACL/NetDB.pm perl/lib/Wallet/ACL/Nested.pm	    \
	perl/lib/Wallet/ACL/NetDB/Root.pm perl/lib/Wallet/Admin.pm	    \
	perl/lib/Wallet/Config.pm perl/lib/Wallet/Database.pm		    \
	perl/lib/Wallet/Kadmin.pm perl/lib/Wallet/Kadmin/AD.pm		    \
	perl/lib/Wallet/Kadmin/Heimdal.pm perl/lib/Wallet/Kadmin/MIT.pm	    \
	perl/lib/Wallet/Object/Base.pm perl/lib/Wallet/Object/Duo.pm	    \
	perl/lib/Wallet/Object/File.pm perl/lib/Wallet/Object/Keytab.pm	    \
	perl/lib/Wallet/Object/Password.pm				    \
	perl/lib/Wallet/Object/WAKeyring.pm				    \
	perl/lib/Wallet/Policy/Stanford.pm perl/lib/Wallet/Report.pm	    \
	perl/lib/Wallet/Schema.pm perl/lib/Wallet/Server.pm		    \
	perl/lib/Wallet/Schema/Result/Acl.pm				    \
	perl/lib/Wallet/Schema/Result/AclEntry.pm			    \
	perl/lib/Wallet/Schema/Result/AclHistory.pm			    \
	perl/lib/Wallet/Schema/Result/AclScheme.pm			    \
	perl/lib/Wallet/Schema/Result/Duo.pm				    \
	perl/lib/Wallet/Schema/Result/Enctype.pm			    \
	perl/lib/Wallet/Schema/Result/Flag.pm				    \
	perl/lib/Wallet/Schema/Result/KeytabEnctype.pm			    \
	perl/lib/Wallet/Schema/Result/KeytabSync.pm			    \
	perl/lib/Wallet/Schema/Result/Object.pm				    \
	perl/lib/Wallet/Schema/Result/ObjectHistory.pm			    \
	perl/lib/Wallet/Schema/Result/SyncTarget.pm			    \
	perl/lib/Wallet/Schema/Result/Type.pm				    \
	perl/sql/Wallet-Schema-0.07-0.08-MySQL.sql			    \
	perl/sql/Wallet-Schema-0.07-0.08-SQLite.sql			    \
	perl/sql/Wallet-Schema-0.07-MySQL.sql				    \
	perl/sql/Wallet-Schema-0.07-SQLite.sql				    \
	perl/sql/Wallet-Schema-0.08-0.09-MySQL.sql			    \
	perl/sql/Wallet-Schema-0.08-0.09-PostgreSQL.sql			    \
	perl/sql/Wallet-Schema-0.08-0.09-SQLite.sql			    \
	perl/sql/Wallet-Schema-0.08-MySQL.sql				    \
	perl/sql/Wallet-Schema-0.08-PostgreSQL.sql			    \
	perl/sql/Wallet-Schema-0.08-SQLite.sql				    \
	perl/sql/Wallet-Schema-0.09-MySQL.sql				    \
	perl/sql/Wallet-Schema-0.09-PostgreSQL.sql			    \
	perl/sql/Wallet-Schema-0.09-SQLite.sql				    \
	perl/sql/Wallet-Schema-0.09-0.10-MySQL.sql			    \
	perl/sql/Wallet-Schema-0.09-0.10-PostgreSQL.sql			    \
	perl/sql/Wallet-Schema-0.09-0.10-SQLite.sql			    \
	perl/sql/Wallet-Schema-0.10-MySQL.sql				    \
	perl/sql/Wallet-Schema-0.10-PostgreSQL.sql			    \
	perl/sql/Wallet-Schema-0.10-SQLite.sql				    \
	perl/sql/wallet-1.3-update-duo.sql perl/t/data/README		    \
	perl/t/data/acl-command perl/t/data/duo/integration.json	    \
	perl/t/data/duo/integration-ldap.json				    \
	perl/t/data/duo/integration-radius.json				    \
	perl/t/data/duo/integration-rdp.json perl/t/data/duo/keys.json	    \
	perl/t/data/keytab-fake perl/t/data/keytab.conf			    \
	perl/t/data/netdb-fake perl/t/data/netdb.conf perl/t/data/perl.conf \
	perl/t/docs/pod-spelling.t perl/t/docs/pod.t perl/t/general/acl.t   \
	perl/t/general/admin.t perl/t/general/config.t			    \
	perl/t/general/init.t perl/t/general/report.t			    \
	perl/t/general/server.t perl/t/lib/Util.pm perl/t/object/base.t	    \
	perl/t/object/duo.t perl/t/object/duo-ldap.t			    \
	perl/t/object/duo-pam.t perl/t/object/duo-radius.t		    \
	perl/t/object/duo-rdp.t perl/t/object/file.t perl/t/object/keytab.t \
	perl/t/object/password.t perl/t/object/wa-keyring.t		    \
	perl/t/policy/stanford.t perl/t/style/minimum-version.t		    \
	perl/t/style/strict.t perl/t/util/kadmin.t perl/t/verifier/basic.t  \
	perl/t/verifier/external.t perl/t/verifier/ldap-attr.t		    \
	perl/t/verifier/nested.t perl/t/verifier/netdb.t

# Directories that have to be created in builddir != srcdir builds before
# copying PERL_FILES over.
PERL_DIRECTORIES = perl perl/lib perl/lib/Wallet perl/lib/Wallet/ACL	    \
	perl/lib/Wallet/ACL/Krb5 perl/lib/Wallet/ACL/LDAP		    \
	perl/lib/Wallet/ACL/LDAP/Attribute perl/lib/Wallet/ACL/NetDB	    \
	perl/lib/Wallet/Kadmin perl/lib/Wallet/Object			    \
	perl/lib/Wallet/Policy perl/lib/Wallet/Schema			    \
	perl/lib/Wallet/Schema/Result perl/sql perl/t perl/t/data	    \
	perl/t/data/duo perl/t/docs perl/t/general perl/t/lib perl/t/object \
	perl/t/policy perl/t/style perl/t/util perl/t/verifier

ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = .gitignore .travis.yml LICENSE README.md bootstrap		    \
	client/wallet.pod client/wallet-rekey.pod config/allow-extract	    \
	config/keytab config/keytab.acl config/wallet			    \
	config/wallet-report.acl docs/design contrib/README		    \
	contrib/ad-keytab contrib/commerzbank/wallet-history		    \
	contrib/convert-srvtab-db contrib/used-principals		    \
	contrib/wallet-contacts contrib/wallet-rekey-periodic		    \
	contrib/wallet-rekey-periodic.8 contrib/wallet-summary		    \
	contrib/wallet-summary.8 contrib/wallet-unknown-hosts		    \
	contrib/wallet-unknown-hosts.8 docs/design-acl docs/design-api	    \
	docs/metadata docs/netdb-role-api docs/notes			    \
	docs/objects-and-schemes docs/setup docs/stanford-naming	    \
	examples/stanford.conf server/keytab-backend.in			    \
	server/wallet-admin.in server/wallet-backend.in			    \
	server/wallet-report.in tests/README tests/TESTS		    \
	tests/config/README tests/data/allow-extract tests/data/basic.conf  \
	tests/data/cmd-fake tests/data/cmd-wrapper tests/data/cppcheck.supp \
	tests/data/fake-data tests/data/fake-kadmin tests/data/fake-keytab  \
	tests/data/fake-keytab-2 tests/data/fake-keytab-foreign		    \
	tests/data/fake-keytab-merge tests/data/fake-keytab-old		    \
	tests/data/fake-keytab-partial					    \
	tests/data/fake-keytab-partial-result tests/data/fake-keytab-rekey  \
	tests/data/fake-keytab-unknown tests/data/fake-srvtab		    \
	tests/data/full.conf tests/data/perl.conf tests/data/wallet.conf    \
	tests/docs/pod-spelling-t tests/docs/pod-t			    \
	tests/docs/spdx-license-t tests/perl/minimum-version-t		    \
	tests/perl/module-version-t tests/perl/strict-t			    \
	tests/server/admin-t tests/server/backend-t tests/server/keytab-t   \
	tests/server/report-t tests/style/obsolete-strings-t		    \
	tests/tap/kerberos.sh tests/tap/libtap.sh			    \
	tests/tap/perl/Test/RRA.pm tests/tap/perl/Test/RRA/Automake.pm	    \
	tests/tap/perl/Test/RRA/Config.pm				    \
	tests/tap/perl/Test/RRA/ModuleVersion.pm tests/tap/remctl.sh	    \
	tests/util/xmalloc-t $(PERL_FILES)

# Supporting convenience libraries used by other targets.
noinst_LIBRARIES = portable/libportable.a util/libutil.a
portable_libportable_a_SOURCES = portable/dummy.c portable/krb5.h	\
	portable/macros.h portable/stdbool.h portable/system.h		\
	portable/uio.h
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
sbin_SCRIPTS = server/keytab-backend server/wallet-admin \
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

# Separate target for a human to request building everything with as many
# compiler warnings enabled as possible.
warnings:
	$(MAKE) V=0 CFLAGS='$(WARNINGS_CFLAGS) $(AM_CFLAGS)' \
	    KRB5_CPPFLAGS='$(KRB5_CPPFLAGS_GCC)'
	$(MAKE) V=0 CFLAGS='$(WARNINGS_CFLAGS) $(AM_CFLAGS)' \
	    KRB5_CPPFLAGS='$(KRB5_CPPFLAGS_GCC)' $(check_PROGRAMS)

# Remove some additional files.
CLEANFILES = perl/t/lib/Test/RRA.pm perl/t/lib/Test/RRA/Automake.pm	\
	perl/t/lib/Test/RRA/Config.pm server/keytab-backend		\
	server/wallet-admin server/wallet-backend server/wallet-report
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 build-aux/compile		     \
	build-aux/depcomp build-aux/install-sh build-aux/missing	     \
	client/wallet.1 config.h.in config.h.in~ configure		     \
	contrib/wallet-report.8 server/keytab-backend.8			     \
	server/wallet-admin.8 server/wallet-backend.8 server/wallet-report.8

# For each of the Perl scripts, we need to fill in the path to the Perl
# binary that was located during configuration.
server/keytab-backend: $(srcdir)/server/keytab-backend.in Makefile
	sed 's|\@PERL\@|$(PERL)|' <$(srcdir)/server/keytab-backend.in >$@
	chmod a+x $@
server/wallet-admin: $(srcdir)/server/wallet-admin.in Makefile
	sed 's|\@PERL\@|$(PERL)|' <$(srcdir)/server/wallet-admin.in >$@
	chmod a+x $@
server/wallet-backend: $(srcdir)/server/wallet-backend.in Makefile
	sed 's|\@PERL\@|$(PERL)|' <$(srcdir)/server/wallet-backend.in >$@
	chmod a+x $@
server/wallet-report: $(srcdir)/server/wallet-report.in Makefile
	sed 's|\@PERL\@|$(PERL)|' <$(srcdir)/server/wallet-report.in >$@
	chmod a+x $@

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
	$(MKDIR_P) perl/t/lib/Test/RRA
	$(INSTALL_DATA) $(srcdir)/tests/tap/perl/Test/RRA.pm perl/t/lib/Test/
	$(INSTALL_DATA) $(srcdir)/tests/tap/perl/Test/RRA/Config.pm \
	    perl/t/lib/Test/RRA/
	cd perl && $(PERL) Build.PL $(WALLET_PERL_FLAGS)
	cd perl && ./Build

# This is a really ugly hack to only honor prefix when running make install
# under Automake's distcheck.
#
# Automake insists on not using DESTDIR for distcheck and instead relying on
# prefix, but we don't want Perl module installation to follow prefix since
# that may result in a module install directory that isn't in Perl's search
# path.  So, if and only if we're running under distcheck, we pass the
# prefix in as --install_base.
install-data-local:
	set -e; flags= ;						\
	case "$(prefix)" in						\
	    */_inst) flags="--install_base $(prefix)" ;;		\
	esac ;								\
	cd perl && ./Build install $$flags --destdir '$(DESTDIR)'

clean-local:
	set -e; if [ -f "perl/Build" ] ; then		\
	    cd perl && ./Build realclean ;		\
	fi

# Remove the Autoconf cache.  Remove the files that we copy over if and only
# if builddir != srcdir.
distclean-local:
	rm -rf autom4te.cache
	set -e; if [ x"$(builddir)" != x"$(srcdir)" ] ; then	\
	    for f in $(PERL_FILES) ; do				\
		rm -f "$(builddir)/$$f" ;			\
	    done ;						\
	fi

# The bits below are for the test suite, not for the main package.
check_PROGRAMS = tests/runtests tests/portable/asprintf-t	\
	tests/portable/mkstemp-t tests/portable/setenv-t	\
	tests/portable/snprintf-t tests/util/messages-krb5-t	\
	tests/util/messages-t tests/util/xmalloc
tests_runtests_CPPFLAGS = -DC_TAP_SOURCE='"$(abs_top_srcdir)/tests"' \
	-DC_TAP_BUILD='"$(abs_top_builddir)/tests"'
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

# Used by maintainers to check the source code with cppcheck.
check-cppcheck:
	cd $(abs_top_srcdir) && cppcheck -q --error-exitcode=2	\
	    --suppressions-list=tests/data/cppcheck.supp	\
	    --enable=warning,performance,portability,style .

# Alas, we have to disable this check because there's no way to do an
# uninstall from Perl.
distuninstallcheck:
	@:
