# Makefile.am -- Automake makefile for wallet.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2006, 2007 Board of Trustees, Leland Stanford Jr. University
# See README for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
EXTRA_DIST = docs/design-acl docs/design-api docs/design-schema \
	docs/netdb-role-api docs/notes kasetkey/kasetkey.pod \
	tests/TESTS tests/client/basic-t.in tests/data/README \
	tests/data/cmd-fake tests/data/fake-keytab tests/data/wallet.conf

bin_PROGRAMS = client/wallet kasetkey/kasetkey
client_wallet_CPPFLAGS = @REMCTL_CPPFLAGS@
client_wallet_LDFLAGS = @REMCTL_LDFLAGS@
client_wallet_LDADD = -lremctl
kasetkey_kasetkey_CPPFLAGS = @AFS_CPPFLAGS@
kasetkey_kasetkey_LDFLAGS = @AFS_LDFLAGS@
kasetkey_kasetkey_LDADD = -lafsauthent -lafsrpc -lpthread -lkrb4

dist_man_MANS = kasetkey/kasetkey.8

$(srcdir)/kasetkey/kasetkey.8: $(srcdir)/kasetkey/kasetkey.pod
	pod2man --release=$(VERSION) --center="Administrative Commands" \
	    --section=8 $(srcdir)/kasetkey/kasetkey.pod > $@

warnings:
	$(MAKE) CFLAGS='$(WARNINGS)'
	$(MAKE) CFLAGS='$(WARNINGS)' $(check_PROGRAMS)

# The bits below are for the test suite, not for the main package.
check_PROGRAMS = tests/runtests

check-local: $(check_PROGRAMS)
	cd tests && ./runtests TESTS
