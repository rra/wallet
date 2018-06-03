#!/usr/bin/perl
#
# Tests for the wallet ACL nested verifier.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2015
#     The Board of Trustees of the Leland Stanford Junior University
#
# SPDX-License-Identifier: MIT

use strict;
use warnings;

use Test::More tests => 22;

use Wallet::ACL::Base;
use Wallet::ACL::Nested;
use Wallet::Admin;
use Wallet::Config;

use lib 't/lib';
use Util;

# Some global defaults to use.
my $admin = 'admin@EXAMPLE.COM';
my $user1 = 'alice@EXAMPLE.COM';
my $user2 = 'bob@EXAMPLE.COM';
my $user3 = 'jack@EXAMPLE.COM';
my $host = 'localhost';
my @trace = ($admin, $host, time);

# Use Wallet::Admin to set up the database.
db_setup;
my $setup = eval { Wallet::Admin->new };
is ($@, '', 'Database connection succeeded');
is ($setup->reinitialize ($setup), 1, 'Database initialization succeeded');
my $schema = $setup->schema;

# Create a few ACLs for later testing.
my $acl = eval { Wallet::ACL->create ('test', $schema, @trace) };
ok (defined ($acl), 'ACL creation');
my $acl_nesting = eval { Wallet::ACL->create ('nesting', $schema, @trace) };
ok (defined ($acl), ' and another');
my $acl_deep = eval { Wallet::ACL->create ('deepnesting', $schema, @trace) };
ok (defined ($acl), ' and another');

# Create an verifier to make sure that works
my $verifier = Wallet::ACL::Nested->new ('test', $schema);
ok (defined $verifier, 'Wallet::ACL::Nested creation');
ok ($verifier->isa ('Wallet::ACL::Nested'), ' and class verification');
is ($verifier->syntax_check ('notcreated'), 0,
    ' and it rejects a nested name that is not already an ACL');
is ($verifier->syntax_check ('test'), 1,
    ' and accepts one that already exists');

# Add a few entries to one ACL and then see if they validate.
ok ($acl->add ('krb5', $user1, @trace), 'Added test scheme');
ok ($acl->add ('krb5', $user2, @trace), ' and another');
ok ($acl_nesting->add ('nested', 'test', @trace), ' and then nested it');
ok ($acl_nesting->add ('krb5', $user3, @trace),
    ' and added a non-nesting user');
is ($acl_nesting->check ($user1), 1, ' so check of nested succeeds');
is ($acl_nesting->check ($user3), 1, ' so check of non-nested succeeds');
is (scalar ($acl_nesting->list), 2,
    ' and the acl has the right number of items');

# Add a recursive nesting to make sure it doesn't send us into loop.
ok ($acl_deep->add ('nested', 'test', @trace),
    'Adding deep nesting for one nest succeeds');
ok ($acl_deep->add ('nested', 'nesting', @trace), ' and another');
ok ($acl_deep->add ('krb5', $user3, @trace),
    ' and added a non-nesting user');
is ($acl_deep->check ($user1), 1, ' so check of nested succeeds');
is ($acl_deep->check ($user3), 1, ' so check of non-nested succeeds');

# Test getting an error in adding an invalid group to an ACL object itself.
isnt ($acl->add ('nested', 'doesnotexist', @trace), 1,
      'Adding bad nested acl fails');

# Clean up.
$setup->destroy;
END {
    unlink 'wallet-db';
}
