#!/usr/bin/perl
#
# Tests for the external wallet ACL verifier.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2016 Russ Allbery <eagle@eyrie.org>
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use Test::More tests => 9;

use Wallet::ACL::External;
use Wallet::Config;

# Configure the external ACL verifier.
$Wallet::Config::EXTERNAL_COMMAND = 't/data/acl-command';

# Check a few verifications.
my $verifier = Wallet::ACL::External->new;
ok (defined $verifier, 'Wallet::ACL::External creation');
ok ($verifier->isa ('Wallet::ACL::External'), ' and class verification');
is ($verifier->check ('eagle@eyrie.org', 'test success', 'file', 'test'),
    1, 'Success');
is ($verifier->check ('eagle@eyrie.org', 'test failure', 'file', 'test'),
    0, 'Failure');
is ($verifier->error, undef, 'No error set');
is ($verifier->check ('eagle@eyrie.org', 'test error', 'file', 'test'),
    undef, 'Error');
is ($verifier->error, 'some error', ' and right error');
is ($verifier->check (undef, 'eagle@eyrie.org', 'file', 'test'), undef,
    'Undefined principal');
is ($verifier->error, 'no principal specified', ' and right error');
