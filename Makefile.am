# Makefile.am -- Automake makefile for wallet.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2006, 2007, 2008 Board of Trustees, Leland Stanford Jr. University
# See LICENSE for licensing terms.

# These two lists of files are needed for Perl builds and for the test suite
# and are not generated or touched by configure.  They're listed here to be
# added to EXTRA_DIST and so that they can be copied over properly for
# builddir != srcdir builds.
PERL_FILES = perl/Wallet/ACL.pm perl/Wallet/ACL/Base.pm \
	perl/Wallet/ACL/Krb5.pm perl/Wallet/ACL/NetDB.pm \
	perl/Wallet/ACL/NetDB/Root.pm perl/Wallet/Admin.pm \
	perl/Wallet/Config.pm perl/Wallet/Database.pm \
	perl/Wallet/Object/Base.pm perl/Wallet/Object/File.pm \
	perl/Wallet/Object/Keytab.pm perl/Wallet/Schema.pm \
	perl/Wallet/Server.pm perl/t/acl.t perl/t/admin.t perl/t/config.t \
	perl/t/data/README perl/t/data/keytab-fake perl/t/data/keytab.conf \
	perl/t/data/netdb.conf perl/t/data/netdb-fake perl/t/init.t \
	perl/t/keytab.t perl/t/lib/Util.pm perl/t/object.t perl/t/pod.t \
	perl/t/schema.t perl/t/server.t perl/t/verifier-netdb.t \
	perl/t/verifier.t
TEST_FILES = tests/TESTS tests/data/README tests/data/allow-extract \
	tests/data/basic.conf tests/data/cmd-fake tests/data/fake-data \
	tests/data/fake-kadmin tests/data/fake-keytab \
	tests/data/fake-keytab-2 tests/data/fake-keytab-merge \
	tests/data/fake-keytab-old tests/data/fake-srvtab \
	tests/data/wallet.conf tests/libtest.sh

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = LICENSE autogen client/wallet.pod config/allow-extract \
	config/keytab config/keytab.acl config/wallet docs/design \
	contrib/README contrib/wallet-report contrib/wallet-report.8 \
	docs/design-acl docs/design-api docs/netdb-role-api docs/notes \
	docs/setup examples/stanford.conf kasetkey/README \
	kasetkey/kasetkey.pod $(PERL_FILES) $(TEST_FILES)

noinst_LIBRARIES = portable/libportable.a util/libutil.a
portable_libportable_a_SOURCES = portable/dummy.c portable/macros.h \
	portable/stdbool.h portable/system.h
portable_libportable_a_LIBADD = $(LIBOBJS)
util_libutil_a_SOURCES = util/concat.c util/messages.c util/messages-krb5.c \
	util/util.h util/xmalloc.c
util_libutil_a_CPPFLAGS = $(KRB5_CPPFLAGS)

bin_PROGRAMS = client/wallet
dist_sbin_SCRIPTS = server/keytab-backend server/wallet-admin \
	server/wallet-backend
client_wallet_SOURCES = client/file.c client/internal.h client/keytab.c \
	client/krb5.c client/remctl.c client/srvtab.c client/wallet.c
client_wallet_CPPFLAGS = $(REMCTL_CPPFLAGS) $(KRB5_CPPFLAGS)
client_wallet_LDFLAGS = $(REMCTL_LDFLAGS) $(KRB5_LDFLAGS)
client_wallet_LDADD = util/libutil.a portable/libportable.a $(REMCTL_LIBS) \
	$(KRB5_LIBS)

dist_man_MANS = client/wallet.1 server/keytab-backend.8 \
	server/wallet-admin.8 server/wallet-backend.8

if AFS
sbin_PROGRAMS = kasetkey/kasetkey
kasetkey_kasetkey_CPPFLAGS = $(AFS_CPPFLAGS) $(KRB4_CPPFLAGS)
kasetkey_kasetkey_LDFLAGS = $(AFS_LDFLAGS) $(KRB4_LDFLAGS)
kasetkey_kasetkey_LDADD = util/libutil.a portable/libportable.a $(AFS_LIBS) \
	$(KRB4_LIBS)
dist_man_MANS += kasetkey/kasetkey.8
endif

$(srcdir)/client/wallet.1: $(srcdir)/client/wallet.pod
	pod2man --release=$(VERSION) --center="Administrative Commands" \
	    --section=1 $(srcdir)/client/wallet.pod > $@

$(srcdir)/contrib/wallet-report.8: $(srcdir)/contrib/wallet-report
	pod2man --release=$(VERSION) --center="Administrative Commands" \
	    --section=8 $(srcdir)/contrib/wallet-report > $@

$(srcdir)/kasetkey/kasetkey.8: $(srcdir)/kasetkey/kasetkey.pod
	pod2man --release=$(VERSION) --center="Administrative Commands" \
	    --section=8 $(srcdir)/kasetkey/kasetkey.pod > $@

$(srcdir)/server/keytab-backend.8: $(srcdir)/server/keytab-backend
	pod2man --release=$(VERSION) --center="Administrative Commands" \
	    --section=8 $(srcdir)/server/keytab-backend > $@

$(srcdir)/server/wallet-admin.8: $(srcdir)/server/wallet-admin
	pod2man --release=$(VERSION) --center="Administrative Commands" \
	    --section=8 $(srcdir)/server/wallet-admin > $@

$(srcdir)/server/wallet-backend.8: $(srcdir)/server/wallet-backend
	pod2man --release=$(VERSION) --center="Administrative Commands" \
	    --section=8 $(srcdir)/server/wallet-backend > $@

# A set of flags for warnings.  Add -O because gcc won't find some warnings
# without optimization turned on, and add -DDEBUG=1 so we'll also compile all
# debugging code and test it.
WARNINGS = -g -O -DDEBUG=1 -Wall -W -Wendif-labels -Wpointer-arith \
	-Wbad-function-cast -Wwrite-strings -Wstrict-prototypes \
	-Wmissing-prototypes -Wnested-externs -Werror

warnings:
	$(MAKE) CFLAGS='$(WARNINGS)'
	$(MAKE) CFLAGS='$(WARNINGS)' $(check_PROGRAMS)

# Remove some additional files.
DISTCLEANFILES = perl/Makefile
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 config.h.in config.h.in~ \
	configure client/wallet.1 kasetkey/kasetkey.8 \
	server/keytab-backend.8	server/wallet-backend.8 tools/compile \
	tools/depcomp tools/install-sh tools/missing

# Take appropriate actions in the Perl directory as well.  We don't want to
# always build the Perl directory in all-local, since otherwise Automake does
# this for every target, which overrides some hacks we have to do for Debian
# packaging.
all-local: perl/blib/lib/Wallet/Config.pm

perl/blib/lib/Wallet/Config.pm:
	set -e; if [ x"$(builddir)" != x"$(srcdir)" ] ; then \
	    mkdir perl/Wallet perl/Wallet/ACL perl/Wallet/ACL/NetDB \
		perl/Wallet/Object perl/t perl/t/data perl/t/lib \
		2>/dev/null || true ; \
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
	    rm -f $(PERL_FILES) $(TEST_FILES) ; \
	fi

# The bits below are for the test suite, not for the main package.
check_PROGRAMS = tests/runtests tests/portable/asprintf-t \
	tests/portable/snprintf-t tests/portable/strlcat-t \
	tests/portable/strlcpy-t tests/util/concat-t tests/util/messages-t \
	tests/util/xmalloc
check_LIBRARIES = tests/libtest.a
tests_libtest_a_SOURCES = tests/libtest.c tests/libtest.h

# All of the test programs.
tests_portable_asprintf_t_SOURCES = tests/portable/asprintf-t.c \
        tests/portable/asprintf.c
tests_portable_asprintf_t_LDADD = tests/libtest.a util/libutil.a \
	portable/libportable.a
tests_portable_snprintf_t_SOURCES = tests/portable/snprintf-t.c \
        tests/portable/snprintf.c
tests_portable_snprintf_t_LDADD = tests/libtest.a util/libutil.a \
	portable/libportable.a
tests_portable_strlcat_t_SOURCES = tests/portable/strlcat-t.c \
        tests/portable/strlcat.c
tests_portable_strlcat_t_LDADD = tests/libtest.a util/libutil.a \
	portable/libportable.a
tests_portable_strlcpy_t_SOURCES = tests/portable/strlcpy-t.c \
        tests/portable/strlcpy.c
tests_portable_strlcpy_t_LDADD = tests/libtest.a util/libutil.a \
	portable/libportable.a
tests_util_concat_t_LDADD = tests/libtest.a util/libutil.a \
	portable/libportable.a
tests_util_messages_t_LDADD = tests/libtest.a util/libutil.a \
	portable/libportable.a
tests_util_xmalloc_LDADD = util/libutil.a portable/libportable.a

check-local: $(check_PROGRAMS)
	set -e; if [ x"$(builddir)" != x"$(srcdir)" ] ; then \
	    mkdir tests/data/acls 2>/dev/null || true ; \
	    for f in $(TEST_FILES) ; do \
		cp "$(srcdir)/$$f" "$(builddir)/$$f" ; \
	    done \
	fi
	cd tests && ./runtests TESTS
	@echo ''
	@echo ''
	cd perl && $(MAKE) test

# Alas, we have to disable this check because there's no way to do an
# uninstall from Perl.
distuninstallcheck:
	@:
