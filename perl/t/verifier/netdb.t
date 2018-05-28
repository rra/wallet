#!/usr/bin/perl
#
# Tests for the NetDB wallet ACL verifiers.
#
# This test can only be run by someone local to Stanford with appropriate
# access to the NetDB role server and will be skipped in all other
# environments.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2018 Russ Allbery <eagle@eyrie.org>
# Copyright 2008, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use Test::More tests => 5;

use Wallet::ACL::NetDB;

use lib 't/lib';
use Test::RRA qw(skip_unless_author);
use Util;

# This test requires a specific environment setup, so only run it for package
# maintainers.
skip_unless_author('LDAP verifier tests');

my $netdb = 'netdb-node-roles-rc.stanford.edu';
my $host  = 'windlord.stanford.edu';
my $user  = 'jonrober@stanford.edu';

# Determine the local principal.
my $klist = `klist 2>&1` || '';
SKIP: {
    skip "tests useful only with Stanford Kerberos tickets", 5
        unless ($klist =~ /^(Default p|\s+P)rincipal: \S+\@stanford\.edu$/m);

    # Set up our configuration.
    $Wallet::Config::NETDB_REALM = 'stanford.edu';
    $Wallet::Config::NETDB_REMCTL_CACHE = $ENV{KRB5CCNAME};
    $Wallet::Config::NETDB_REMCTL_HOST  = $netdb;

    # Finally, we can test.
    my $verifier = eval { Wallet::ACL::NetDB->new };
    ok (defined $verifier, ' and now creation succeeds');
    is ($@, q{}, ' with no errors');
    ok ($verifier->isa ('Wallet::ACL::NetDB'), ' and returns the right class');
    is ($verifier->check ($user, $host), 1, "Checking $host succeeds");
    is ($verifier->check ('test-user@stanford.edu', $host), 0,
        ' but fails with another user');
}
