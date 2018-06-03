#!/usr/bin/perl
#
# Tests for database initialization.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2007-2008, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# SPDX-License-Identifier: MIT

use strict;
use warnings;

use Test::More tests => 18;

use Wallet::ACL;
use Wallet::Admin;

use lib 't/lib';
use Util;

# Use Wallet::Admin to set up the database.
db_setup;
my $admin = eval { Wallet::Admin->new };
is ($@, '', 'Wallet::Admin creation did not die');
ok ($admin->isa ('Wallet::Admin'), ' and returned the right class');
is ($admin->initialize ('admin@EXAMPLE.COM'), 1,
    ' and initialization succeeds');

# Check whether the database entries that should be created were.
my $acl = eval { Wallet::ACL->new ('ADMIN', $admin->schema) };
is ($@, '', 'Retrieving ADMIN ACL successful');
ok ($acl->isa ('Wallet::ACL'), ' and is the right class');
my @entries = $acl->list;
is (scalar (@entries), 1, ' and has only one entry');
isnt ($entries[0], undef, ' which is a valid entry');
is ($entries[0][0], 'krb5', ' of krb5 scheme');
is ($entries[0][1], 'admin@EXAMPLE.COM', ' with the right user');

# Test reinitialization.
is ($admin->reinitialize ('admin@EXAMPLE.ORG'), 1,
    'Reinitialization succeeded');

# Now repeat the database content checks.
$acl = eval { Wallet::ACL->new ('ADMIN', $admin->schema) };
is ($@, '', 'Retrieving ADMIN ACL successful');
ok ($acl->isa ('Wallet::ACL'), ' and is the right class');
@entries = $acl->list;
is (scalar (@entries), 1, ' and has only one entry');
isnt ($entries[0], undef, ' which is a valid entry');
is ($entries[0][0], 'krb5', ' of krb5 scheme');
is ($entries[0][1], 'admin@EXAMPLE.ORG', ' with the right user');

# Test cleanup.
is ($admin->destroy, 1, 'Destroying the database works');
$acl = eval { Wallet::ACL->new ('ADMIN', $admin->schema) };
like ($@, qr/^cannot search for ACL ADMIN: /,
      ' and now the database is gone');
END {
    unlink 'wallet-db';
}
