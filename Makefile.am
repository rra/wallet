# Makefile.am -- Automake makefile for wallet.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2006, 2007 Board of Trustees, Leland Stanford Jr. University
# See LICENSE for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = LICENSE autogen client/wallet.pod config/allow-extract \
	config/keytab config/keytab.acl config/wallet docs/design \
	docs/design-acl docs/design-api docs/netdb-role-api docs/notes \
	docs/setup kasetkey/README kasetkey/kasetkey.pod perl/Wallet/ACL.pm \
	perl/Wallet/ACL/Base.pm perl/Wallet/ACL/Krb5.pm \
	perl/Wallet/Config.pm perl/Wallet/Object/Base.pm \
	perl/Wallet/Object/Keytab.pm perl/Wallet/Schema.pm \
	perl/Wallet/Server.pm perl/t/acl.t perl/t/data/README \
	perl/t/data/keytab-fake perl/t/data/keytab.conf perl/t/init.t \
	perl/t/keytab.t perl/t/object.t perl/t/pod.t perl/t/schema.t \
	perl/t/server.t perl/t/verifier.t tests/TESTS tests/data/README \
	tests/data/allow-extract tests/data/cmd-fake tests/data/fake-data \
	tests/data/fake-kadmin tests/data/fake-keytab tests/data/fake-srvtab \
	tests/data/wallet.conf

noinst_LIBRARIES = portable/libportable.a util/libutil.a
portable_libportable_a_SOURCES = portable/dummy.c
portable_libportable_a_LIBADD = $(LIBOBJS)
util_libutil_a_SOURCES = util/concat.c util/messages.c util/util.h \
	util/xmalloc.c

bin_PROGRAMS = client/wallet
sbin_PROGRAMS = kasetkey/kasetkey
sbin_SCRIPTS = server/keytab-backend server/wallet-backend
client_wallet_SOURCES = client/file.c client/internal.h client/keytab.c \
	client/remctl.c client/srvtab.c client/wallet.c system.h
client_wallet_CPPFLAGS = @REMCTL_CPPFLAGS@
client_wallet_LDFLAGS = @REMCTL_LDFLAGS@
client_wallet_LDADD = util/libutil.a portable/libportable.a -lremctl -lkrb5
kasetkey_kasetkey_CPPFLAGS = @AFS_CPPFLAGS@
kasetkey_kasetkey_LDFLAGS = @AFS_LDFLAGS@
kasetkey_kasetkey_LDADD = util/libutil.a portable/libportable.a @AFS_LIBS@ \
	-lkrb4

dist_man_MANS = client/wallet.1 kasetkey/kasetkey.8 server/keytab-backend.8 \
	server/wallet-backend.8

$(srcdir)/client/wallet.1: $(srcdir)/client/wallet.pod
	pod2man --release=$(VERSION) --center="Administrative Commands" \
	    --section=1 $(srcdir)/client/wallet.pod > $@

$(srcdir)/kasetkey/kasetkey.8: $(srcdir)/kasetkey/kasetkey.pod
	pod2man --release=$(VERSION) --center="Administrative Commands" \
	    --section=8 $(srcdir)/kasetkey/kasetkey.pod > $@

$(srcdir)/server/keytab-backend.8: $(srcdir)/server/keytab-backend
	pod2man --release=$(VERSION) --center="Administrative Commands" \
	    --section=8 $(srcdir)/server/keytab-backend > $@

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

# Take appropriate actions in the Perl directory as well.
all-local:
	cd perl && perl Makefile.PL
	cd perl && $(MAKE)

install-data-local:
	cd perl && $(MAKE) install

# ExtUtils::MakeMaker really likes moving the Makefile aside.
clean-local:
	[ ! -f perl/Makefile ] || ( set -e; cd perl && $(MAKE) clean )
	cd perl && ( [ ! -f Makefile.old ] || mv Makefile.old Makefile )

# The bits below are for the test suite, not for the main package.
check_PROGRAMS = tests/runtests tests/portable/asprintf-t \
	tests/portable/snprintf-t tests/util/concat-t tests/util/messages-t \
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
tests_util_concat_t_LDADD = tests/libtest.a util/libutil.a \
	portable/libportable.a
tests_util_messages_t_LDADD = tests/libtest.a util/libutil.a \
	portable/libportable.a
tests_util_xmalloc_LDADD = util/libutil.a portable/libportable.a

check-local: $(check_PROGRAMS)
	cd tests && ./runtests TESTS
	@echo ''
	@echo ''
	cd perl && $(MAKE) test
