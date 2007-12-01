#!/usr/bin/perl -w
# $Id$
#
# t/init.t -- Tests for database initialization.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

use Test::More tests => 16;

use Wallet::ACL;
use Wallet::Config;
use Wallet::Server;

use lib 't/lib';
use Util;

# Use Wallet::Server to set up the database.
db_setup;
my $server = eval { Wallet::Server->initialize ('admin@EXAMPLE.COM') };
is ($@, '', 'Database initialization did not die');
ok ($server->isa ('Wallet::Server'), ' and returned the right class');

# Check whether the database entries that should be created were.
my $acl = eval { Wallet::ACL->new ('ADMIN', $server->dbh) };
is ($@, '', 'Retrieving ADMIN ACL successful');
ok ($acl->isa ('Wallet::ACL'), ' and is the right class');
my @entries = $acl->list;
is (scalar (@entries), 1, ' and has only one entry');
isnt ($entries[0], undef, ' which is a valid entry');
is ($entries[0][0], 'krb5', ' of krb5 scheme');
is ($entries[0][1], 'admin@EXAMPLE.COM', ' with the right user');

# Test reinitialization.
$server = eval { Wallet::Server->reinitialize ('admin@EXAMPLE.COM') };
is ($@, '', 'Reinitialization did not die');
ok ($server->isa ('Wallet::Server'), ' and returned the right class');

# Now repeat the database content checks.
$acl = eval { Wallet::ACL->new ('ADMIN', $server->dbh) };
is ($@, '', 'Retrieving ADMIN ACL successful');
ok ($acl->isa ('Wallet::ACL'), ' and is the right class');
@entries = $acl->list;
is (scalar (@entries), 1, ' and has only one entry');
isnt ($entries[0], undef, ' which is a valid entry');
is ($entries[0][0], 'krb5', ' of krb5 scheme');
is ($entries[0][1], 'admin@EXAMPLE.COM', ' with the right user');

# Clean up.
my $schema = Wallet::Schema->new;
$schema->drop ($server->dbh);
unlink 'wallet-db';
