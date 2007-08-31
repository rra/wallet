#!/usr/bin/perl -w
# $Id$
#
# t/init.t -- Tests for database initialization.

use Test::More tests => 8;

use Wallet::ACL;
use Wallet::Config;
use Wallet::Server;

# Use a local SQLite database for testing.
$Wallet::Config::DB_DRIVER = 'SQLite';
$Wallet::Config::DB_INFO = 'wallet-db';
unlink 'wallet-db';

# Use Wallet::Server to set up the database.
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

# Clean up.
unlink 'wallet-db';
