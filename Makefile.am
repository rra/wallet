# Makefile.am -- Top-level Automake makefile for wallet.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2006 Board of Trustees, Leland Stanford Jr. University
# See README for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
EXTRA_DIST = doc/design-acl doc/design-api doc/design-schema doc/notes

bin_PROGRAMS = kasetkey/kasetkey
kasetkey_kasetkey_CPPFLAGS = @AFS_CPPFLAGS@
kasetkey_kasetkey_LDFLAGS = @AFS_LDFLAGS@
kasetkey_kasetkey_LDADD = -lkauth.krb -lprot -lubik -lauth -lrxkad -ldes \
	-lrx -llwp -lcom_err -lafsutil -lsys
