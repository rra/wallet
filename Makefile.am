# Makefile.am -- Top-level Automake makefile for wallet.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2006 Board of Trustees, Leland Stanford Jr. University
# See README for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
EXTRA_DIST = doc/design-acl doc/design-api doc/design-schema doc/notes \
	tests/TESTS tests/client/basic-t.in tests/data/README \
	tests/data/cmd-fake tests/data/fake-keytab tests/data/wallet.conf

bin_PROGRAMS = client/wallet kasetkey/kasetkey
client_wallet_CPPFLAGS = @REMCTL_CPPFLAGS@
client_wallet_LDFLAGS = @REMCTL_LDFLAGS@
client_wallet_LDADD = -lremctl
kasetkey_kasetkey_CPPFLAGS = @AFS_CPPFLAGS@
kasetkey_kasetkey_LDFLAGS = @AFS_LDFLAGS@
kasetkey_kasetkey_LDADD = -lkauth.krb -lprot -lubik -lauth -lrxkad -ldes \
	-lrx -llwp -lcom_err -lafsutil -lsys

warnings:
	$(MAKE) CFLAGS='$(WARNINGS)'
	$(MAKE) CFLAGS='$(WARNINGS)' $(check_PROGRAMS)

# The bits below are for the test suite, not for the main package.
check_PROGRAMS = tests/runtests

check-local: $(check_PROGRAMS)
	cd tests && ./runtests TESTS
