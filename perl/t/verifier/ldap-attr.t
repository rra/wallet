#!/usr/bin/perl
#
# Tests for the LDAP attribute ACL verifier.
#
# This test can only be run by someone local to Stanford with appropriate
# access to the LDAP server and will be skipped in all other environments.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2012, 2013, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use Test::More;

use lib 't/lib';
use Util;

# Skip all spelling tests unless the maintainer environment variable is set.
plan skip_all => 'LDAP verifier tests only run for maintainer'
    unless $ENV{RRA_MAINTAINER_TESTS};

# Declare a plan.
plan tests => 22;

require_ok ('Wallet::ACL::LDAP::Attribute');
require_ok ('Wallet::ACL::LDAP::Attribute::Root');

my $host     = 'ldap.stanford.edu';
my $base     = 'cn=people,dc=stanford,dc=edu';
my $filter   = 'uid';
my $user     = 'jonrober@stanford.edu';
my $rootuser = 'jonrober/root@stanford.edu';
my $attr     = 'suPrivilegeGroup';
my $value    = 'stanford:stanford';

# Remove the realm from principal names.
package Wallet::Config;
sub ldap_map_principal {
    my ($principal) = @_;
    $principal =~ s/\@.*//;
    return $principal;
}
package main;

# Determine the local principal.
my $klist = `klist 2>&1` || '';
SKIP: {
    skip "tests useful only with Stanford Kerberos tickets", 9
        unless ($klist =~ /[Pp]rincipal: \S+\@stanford\.edu$/m);

    # Set up our configuration.
    $Wallet::Config::LDAP_HOST        = $host;
    $Wallet::Config::LDAP_CACHE       = $ENV{KRB5CCNAME};
    $Wallet::Config::LDAP_BASE        = $base;
    $Wallet::Config::LDAP_FILTER_ATTR = $filter;

    # Finally, we can test.
    my $verifier = eval { Wallet::ACL::LDAP::Attribute->new };
    isa_ok ($verifier, 'Wallet::ACL::LDAP::Attribute');
    is ($verifier->check ($user, "$attr=$value"), 1,
        "Checking $attr=$value succeeds");
    is ($verifier->error, undef, '...with no error');
    is ($verifier->check ($user, "$attr=BOGUS"), 0,
        "Checking $attr=BOGUS fails");
    is ($verifier->error, undef, '...with no error');
    is ($verifier->check ($user, "BOGUS=$value"), undef,
        "Checking BOGUS=$value fails with error");
    is ($verifier->error,
        'cannot check LDAP attribute BOGUS for jonrober: Undefined attribute type',
        '...with correct error');
    is ($verifier->check ('user-does-not-exist', "$attr=$value"), 0,
        "Checking for nonexistent user fails");
    is ($verifier->error, undef, '...with no error');

    # Then also test the root version.
    $verifier = eval { Wallet::ACL::LDAP::Attribute::Root->new };
    isa_ok ($verifier, 'Wallet::ACL::LDAP::Attribute::Root');
    is ($verifier->check ($user, "$attr=$value"), 0,
        "Checking as a non /root user fails");
    is ($verifier->error, undef, '...with no error');
    is ($verifier->check ($rootuser, "$attr=$value"), 1,
        "Checking $attr=$value succeeds");
    is ($verifier->error, undef, '...with no error');
    is ($verifier->check ($rootuser, "$attr=BOGUS"), 0,
        "Checking $attr=BOGUS fails");
    is ($verifier->error, undef, '...with no error');
    is ($verifier->check ($rootuser, "BOGUS=$value"), undef,
        "Checking BOGUS=$value fails with error");
    is ($verifier->error,
        'cannot check LDAP attribute BOGUS for jonrober: Undefined attribute type',
        '...with correct error');
    is ($verifier->check ('user-does-not-exist', "$attr=$value"), 0,
        "Checking for nonexistent user fails");
    is ($verifier->error, undef, '...with no error');
}
