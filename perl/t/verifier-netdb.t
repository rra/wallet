#!/usr/bin/perl -w
# $Id$
#
# t/verifier-netdb.t -- Tests for the NetDB wallet ACL verifiers.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2008 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.
#
# This test can only be run by someone local to Stanford with appropriate
# access to the NetDB role server and will be skipped in all other
# environments.

use Test::More tests => 4;

use Wallet::ACL::NetDB;

use lib 't/lib';
use Util;

my $netdb = 'netdb-node-roles-rc.stanford.edu';
my $host  = 'windlord.stanford.edu';
my $user  = 'rra@stanford.edu';

# Determine the local principal.
my $klist = `klist 2>&1` || '';
SKIP: {
    skip "tests useful only with Stanford Kerberos tickets", 4
        unless ($klist =~ /^Default principal: \S+\@stanford\.edu$/m);

    # Set up our configuration.
    $Wallet::Config::NETDB_REALM = 'stanford.edu';
    $Wallet::Config::NETDB_REMCTL_CACHE = $ENV{KRB5CCNAME};
    $Wallet::Config::NETDB_REMCTL_HOST  = $netdb;

    # Finally, we can test.
    $verifier = eval { Wallet::ACL::NetDB->new };
    ok (defined $verifier, ' and now creation succeeds');
    ok ($verifier->isa ('Wallet::ACL::NetDB'), ' and returns the right class');
    is ($verifier->check ($user, $host), 1, "Checking $host succeeds");
    is ($verifier->check ('test-user@stanford.edu', $host), 0,
        ' but fails with another user');
}
