#!/usr/bin/perl
#
# t/pod.t -- Test POD formatting for the wallet Perl modules.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

eval 'use Test::Pod 1.00';
if ($@) {
    print "1..1\n";
    print "ok 1 # skip - Test::Pod 1.00 required for testing POD\n";
    exit;
}
all_pod_files_ok ();
