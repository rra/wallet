# Makefile.am -- Automake makefile for wallet.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2006, 2007 Board of Trustees, Leland Stanford Jr. University
# See README for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
EXTRA_DIST = TODO client/wallet.pod docs/design docs/design-acl \
	docs/design-api docs/netdb-role-api docs/notes docs/setup \
	kasetkey/kasetkey.pod perl/Wallet/ACL.pm perl/Wallet/ACL/Base.pm \
	perl/Wallet/ACL/Krb5.pm perl/Wallet/Config.pm \
	perl/Wallet/Object/Base.pm perl/Wallet/Object/Keytab.pm \
	perl/Wallet/Schema.pm perl/Wallet/Server.pm perl/t/acl.t \
	perl/t/init.t perl/t/keytab.t perl/t/object.t perl/t/pod.t \
	perl/t/schema.t perl/t/server.t perl/t/verifier.t tests/TESTS \
	tests/client/basic-t.in tests/data/README tests/data/cmd-fake \
	tests/data/fake-keytab tests/data/wallet.conf

bin_PROGRAMS = client/wallet
sbin_PROGRAMS = kasetkey/kasetkey
sbin_SCRIPTS = server/keytab-backend server/wallet-backend
client_wallet_SOURCES = client/internal.h client/srvtab.c client/wallet.c \
	system.h
client_wallet_CPPFLAGS = @REMCTL_CPPFLAGS@
client_wallet_LDFLAGS = @REMCTL_LDFLAGS@
client_wallet_LDADD = -lremctl -lkrb5
kasetkey_kasetkey_CPPFLAGS = @AFS_CPPFLAGS@
kasetkey_kasetkey_LDFLAGS = @AFS_LDFLAGS@
kasetkey_kasetkey_LDADD = @AFS_LIBS@ -lkrb4

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
	server/keytab-backend.8	server/wallet-backend.8

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
check_PROGRAMS = tests/runtests

check-local: $(check_PROGRAMS)
	cd tests && ./runtests TESTS
	@echo ''
	@echo ''
	cd perl && $(MAKE) test
