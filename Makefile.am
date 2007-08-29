# Makefile.am -- Automake makefile for wallet.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2006, 2007 Board of Trustees, Leland Stanford Jr. University
# See README for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
EXTRA_DIST = TODO docs/design docs/design-acl docs/design-api \
	docs/netdb-role-api docs/notes docs/setup kasetkey/kasetkey.pod \
	perl/Wallet/ACL.pm perl/Wallet/ACL/Base.pm perl/Wallet/ACL/Krb5.pm \
	perl/Wallet/Config.pm perl/Wallet/Object/Base.pm \
	perl/Wallet/Object/Keytab.pm perl/Wallet/Schema.pm \
	perl/Wallet/Server.pm perl/t/acl.t perl/t/pod.t \
	tests/TESTS tests/client/basic-t.in tests/data/README \
	tests/data/cmd-fake tests/data/fake-keytab tests/data/wallet.conf

bin_PROGRAMS = client/wallet
sbin_PROGRAMS = kasetkey/kasetkey
client_wallet_SOURCES = client/wallet.c system.h
client_wallet_CPPFLAGS = @REMCTL_CPPFLAGS@
client_wallet_LDFLAGS = @REMCTL_LDFLAGS@
client_wallet_LDADD = -lremctl
kasetkey_kasetkey_CPPFLAGS = @AFS_CPPFLAGS@
kasetkey_kasetkey_LDFLAGS = @AFS_LDFLAGS@
kasetkey_kasetkey_LDADD = @AFS_LIBS@ -lkrb4

dist_man_MANS = kasetkey/kasetkey.8

$(srcdir)/kasetkey/kasetkey.8: $(srcdir)/kasetkey/kasetkey.pod
	pod2man --release=$(VERSION) --center="Administrative Commands" \
	    --section=8 $(srcdir)/kasetkey/kasetkey.pod > $@

# A set of flags for warnings.  Add -O because gcc won't find some warnings
# without optimization turned on, and add -DDEBUG=1 so we'll also compile all
# debugging code and test it.
WARNINGS = -g -O -DDEBUG=1 -Wall -W -Wendif-labels -Wpointer-arith \
	-Wbad-function-cast -Wwrite-strings -Wstrict-prototypes \
	-Wmissing-prototypes -Wnested-externs -Werror

warnings:
	$(MAKE) CFLAGS='$(WARNINGS)'
	$(MAKE) CFLAGS='$(WARNINGS)' $(check_PROGRAMS)

# Take appropriate actions in the Perl directory as well.
all-local:
	cd perl && perl Makefile.PL
	cd perl && $(MAKE)

install-data-local:
	cd perl && $(MAKE) install

clean-local:
	cd perl && $(MAKE) clean

distclean-local:
	cd perl && $(MAKE) distclean

# The bits below are for the test suite, not for the main package.
check_PROGRAMS = tests/runtests

check-local: $(check_PROGRAMS)
	cd tests && ./runtests TESTS
	cd perl && $(MAKE) test
