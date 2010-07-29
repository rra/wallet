# Automake makefile for wallet.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2006, 2007, 2008, 2010
#     Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

# These two lists of files are needed for Perl builds and for the test suite
# and are not generated or touched by configure.  They're listed here to be
# added to EXTRA_DIST and so that they can be copied over properly for
# builddir != srcdir builds.
PERL_FILES = perl/Wallet/ACL.pm perl/Wallet/ACL/Base.pm			    \
	perl/Wallet/ACL/Krb5.pm perl/Wallet/ACL/NetDB.pm		    \
	perl/Wallet/ACL/NetDB/Root.pm perl/Wallet/Admin.pm		    \
	perl/Wallet/Config.pm perl/Wallet/Database.pm perl/Wallet/Kadmin.pm \
	perl/Wallet/Kadmin/Heimdal.pm perl/Wallet/Kadmin/MIT.pm		    \
	perl/Wallet/Object/Base.pm perl/Wallet/Object/File.pm		    \
	perl/Wallet/Object/Keytab.pm perl/Wallet/Report.pm		    \
	perl/Wallet/Schema.pm perl/Wallet/Server.pm perl/t/acl.t	    \
	perl/t/admin.t perl/t/config.t perl/t/data/README		    \
	perl/t/data/keytab-fake perl/t/data/keytab.conf			    \
	perl/t/data/netdb.conf perl/t/data/netdb-fake perl/t/file.t	    \
	perl/t/init.t perl/t/kadmin.t perl/t/keytab.t perl/t/lib/Util.pm    \
	perl/t/object.t perl/t/pod-spelling.t perl/t/pod.t perl/t/report.t  \
	perl/t/schema.t perl/t/server.t perl/t/verifier-netdb.t		    \
	perl/t/verifier.t

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = .gitignore LICENSE autogen client/wallet.pod		   \
	config/allow-extract config/keytab config/keytab.acl config/wallet \
	docs/design contrib/README contrib/convert-srvtab-db		   \
	contrib/used-principals contrib/wallet-contacts			   \
	contrib/wallet-summary contrib/wallet-summary.8 docs/design-acl	   \
	docs/design-api docs/netdb-role-api docs/notes docs/setup	   \
	docs/stanford-naming examples/stanford.conf tests/TESTS		   \
	tests/data/README tests/data/allow-extract tests/data/basic.conf   \
	tests/data/cmd-fake tests/data/cmd-wrapper tests/data/fake-data	   \
	tests/data/fake-kadmin tests/data/fake-keytab			   \
	tests/data/fake-keytab-2 tests/data/fake-keytab-merge		   \
	tests/data/fake-keytab-old tests/data/fake-srvtab		   \
	tests/data/full.conf tests/data/wallet.conf			   \
	tests/docs/pod-spelling-t tests/docs/pod-t tests/server/admin-t	   \
	tests/server/backend-t tests/server/keytab-t tests/server/report-t \
	tests/tap/kerberos.sh tests/tap/libtap.sh tests/tap/remctl.sh	   \
	tests/util/xmalloc-t $(PERL_FILES)

noinst_LIBRARIES = portable/libportable.a util/libutil.a
portable_libportable_a_SOURCES = portable/dummy.c portable/krb5-extra.c	\
	portable/krb5.h portable/macros.h portable/stdbool.h		\
	portable/system.h portable/uio.h
portable_libportable_a_CPPFLAGS = $(KRB5_CPPFLAGS)
portable_libportable_a_LIBADD = $(LIBOBJS)
util_libutil_a_SOURCES = util/concat.c util/concat.h util/macros.h	\
	util/messages-krb5.c util/messages-krb5.h util/messages.c	\
	util/messages.h util/xmalloc.c util/xmalloc.h
util_libutil_a_CPPFLAGS = $(KRB5_CPPFLAGS)

noinst_LIBRARIES += client/libwallet.a
client_libwallet_a_SOURCES = client/file.c client/internal.h client/keytab.c \
	client/krb5.c client/options.c client/remctl.c client/srvtab.c
client_libwallet_a_CPPFLAGS = $(REMCTL_CPPFLAGS) $(KRB5_CPPFLAGS)

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

dist_man_MANS = client/wallet.1 client/wallet-rekey.1 server/keytab-backend.8 \
	server/wallet-admin.8 server/wallet-backend.8 server/wallet-report.8

# A set of flags for warnings.  Add -O because gcc won't find some warnings
# without optimization turned on, and add -DDEBUG=1 so we'll also compile all
# debugging code and test it.
WARNINGS = -g -O -DDEBUG=1 -Wall -W -Wendif-labels -Wpointer-arith \
	-Wbad-function-cast -Wwrite-strings -Wstrict-prototypes \
	-Wmissing-prototypes -Wnested-externs -Werror

warnings:
	$(MAKE) V=0 CFLAGS='$(WARNINGS)'
	$(MAKE) V=0 CFLAGS='$(WARNINGS)' $(check_PROGRAMS)

# Remove some additional files.
DISTCLEANFILES = perl/Makefile tests/data/.placeholder
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

perl/blib/lib/Wallet/Config.pm:
	set -e; if [ x"$(builddir)" != x"$(srcdir)" ] ; then \
	    mkdir perl/Wallet perl/Wallet/ACL perl/Wallet/ACL/NetDB \
		perl/Wallet/Kadmin perl/Wallet/Object perl/t perl/t/data \
		perl/t/lib 2>/dev/null || true ; \
	    for f in $(PERL_FILES) ; do \
		cp "$(srcdir)/$$f" "$(builddir)/$$f" ; \
	    done \
	fi
	cd perl && perl Makefile.PL
	cd perl && $(MAKE)

install-data-local:
	if [ x"$(DESTDIR)" != x ] ; then \
	    cd perl && $(MAKE) install DESTDIR=$(DESTDIR)/ ; \
	else \
	    cd perl && $(MAKE) install ; \
	fi

# ExtUtils::MakeMaker really likes moving the Makefile aside.
clean-local:
	[ ! -f perl/Makefile ] || ( set -e; cd perl && $(MAKE) clean )
	cd perl && ( [ ! -f Makefile.old ] || mv Makefile.old Makefile )

# Remove the files that we copy over if and only if builddir != srcdir.
distclean-local:
	set -e; if [ x"$(builddir)" != x"$(srcdir)" ] ; then \
	    rm -f $(PERL_FILES) ; \
	fi

# The bits below are for the test suite, not for the main package.
check_PROGRAMS = tests/runtests tests/portable/asprintf-t		    \
	tests/portable/mkstemp-t tests/portable/setenv-t		    \
	tests/portable/snprintf-t tests/portable/strlcat-t		    \
	tests/portable/strlcpy-t tests/util/concat-t			    \
	tests/util/messages-krb5-t tests/util/messages-t tests/util/xmalloc
tests_runtests_CPPFLAGS = -DSOURCE='"$(abs_top_srcdir)/tests"' \
	-DBUILD='"$(abs_top_builddir)/tests"'
check_LIBRARIES = tests/tap/libtap.a
tests_tap_libtap_a_CPPFLAGS = -I$(abs_top_srcdir)/tests $(KRB5_CPPFLAGS)
tests_tap_libtap_a_SOURCES = tests/tap/basic.c tests/tap/basic.h	\
	tests/tap/kerberos.c tests/tap/kerberos.h tests/tap/messages.c	\
	tests/tap/messages.h tests/tap/process.c tests/tap/process.h

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
tests_util_concat_t_LDADD = tests/tap/libtap.a util/libutil.a \
	portable/libportable.a
tests_util_messages_krb5_t_CPPFLAGS = $(KRB5_CPPFLAGS)
tests_util_messages_krb5_t_LDFLAGS = $(KRB5_LDFLAGS)
tests_util_messages_krb5_t_LDADD = tests/tap/libtap.a util/libutil.a \
	portable/libportable.a $(KRB5_LIBS)
tests_util_messages_t_LDADD = tests/tap/libtap.a util/libutil.a \
	portable/libportable.a
tests_util_xmalloc_LDADD = util/libutil.a portable/libportable.a

check-local: $(check_PROGRAMS)
	cd tests && ./runtests $(abs_top_srcdir)/tests/TESTS
	@echo ''
	cd perl && $(MAKE) test

# Alas, we have to disable this check because there's no way to do an
# uninstall from Perl.
distuninstallcheck:
	@:
