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
# SPDX-License-Identifier: MIT

use strict;
use warnings;

use Test::More;

use Wallet::ACL::NetDB;

use lib 't/lib';
use Test::RRA qw(skip_unless_author);
use Util;

# This test requires a specific environment setup, so only run it for package
# maintainers.
skip_unless_author('NetDB verifier tests');

# Check if we have the ticket cache required to run this test.
my $klist = `klist 2>&1` || '';
if ($klist !~ /^(Default p|\s+P)rincipal: \S+\@stanford\.edu$/m) {
    plan skip_all => 'Requires Stanford Kerberos tickets';
}

# Set up the test plan.
plan tests => 5;

# Parameters for the test.
my $netdb = 'netdb-node-roles-rc.stanford.edu';
my $host  = 'windlord.stanford.edu';
my $user  = 'jonrober@stanford.edu';

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
