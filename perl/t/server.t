#!/usr/bin/perl -w
# $Id$
#
# t/server.t -- Tests for the wallet server API.

use Test::More tests => 44;

use DBD::SQLite;
use Wallet::Config;
use Wallet::Server;

# Use a local SQLite database for testing.
$Wallet::Config::DB_DRIVER = 'SQLite';
$Wallet::Config::DB_INFO = 'wallet-db';
unlink 'wallet-db';

# Allow creation of base objects for testing purposes.
$Wallet::Server::MAPPING{base} = 'Wallet::Object::Base';

# Some global defaults to use.
my $admin = 'admin@EXAMPLE.COM';
my $user1 = 'alice@EXAMPLE.COM';
my $user2 = 'bob@EXAMPLE.COM';
my $host = 'localhost';
my @trace = ($admin, $host);

# Use Wallet::Server to set up the database.
my $server = eval { Wallet::Server->initialize ($admin) };
is ($@, '', 'Database initialization did not die');
ok ($server->isa ('Wallet::Server'), ' and returned the right class');

# Now test the new method as well.
$server = eval { Wallet::Server->new (@trace) };
is ($@, '', 'Reopening with new did not die');
ok ($server->isa ('Wallet::Server'), ' and returned the right class');
my $dbh = $server->dbh;
ok (defined ($dbh), ' and returns a defined database handle');

# We're currently running as the administrator, so everything should succeed.
# Set up a bunch of data for us to test with, starting with some ACLs.  Test
# the error handling while we're at it.
is ($server->acl_create (3), undef, 'Cannot create ACL with a numeric name');
is ($server->error, 'ACL name may not be all numbers',
    ' and returns the right error');
is ($server->acl_create ('user1'), 1, 'Can create regular ACL');
is ($server->acl_create ('user1'), undef, ' but not twice');
like ($server->error, qr/^cannot create ACL user1: /,
      ' and returns a good error');
is ($server->acl_create ('ADMIN'), undef, ' and cannot create ADMIN');
like ($server->error, qr/^cannot create ACL ADMIN: /,
      ' and returns a good error');
is ($server->acl_create ('user2'), 1, 'Create another ACL');
is ($server->acl_create ('both'), 1, ' and one for both users');
is ($server->acl_create ('test'), 1, ' and an empty one');
is ($server->acl_create ('test2'), 1, ' and another test one');
is ($server->acl_rename ('empty', 'test'), undef,
    'Cannot rename nonexistent ACL');
is ($server->error, 'ACL empty not found', ' and returns the right error');
is ($server->acl_rename ('test', 'test2'), undef,
    ' and cannot rename to an existing name');
like ($server->error, qr/^cannot rename ACL 5 to test2: /,
      ' and returns the right error');
is ($server->acl_rename ('test', 'empty'), 1, 'Renaming does work');
is ($server->acl_rename ('test', 'empty'), undef, ' but not twice');
is ($server->error, 'ACL test not found', ' and returns the right error');
is ($server->acl_destroy ('test'), undef, 'Destroying the old name fails');
is ($server->error, 'ACL test not found', ' and returns the right error');
is ($server->acl_destroy ('test2'), 1, ' but destroying another one works');
is ($server->acl_destroy ('test2'), undef, ' but not twice');
is ($server->error, 'ACL test2 not found', ' and returns the right error');
is ($server->acl_add ('user1', 'krb4', $user1), undef,
    'Adding with a bad scheme fails');
is ($server->error, 'unknown ACL scheme krb4', ' with the right error');
is ($server->acl_add ('user1', 'krb5', $user1), 1,
    ' but works with the right scheme');
is ($server->acl_add ('user2', 'krb5', $user2), 1, 'Add another entry');
is ($server->acl_add ('both', 'krb5', $user1), 1, ' and another');
is ($server->acl_add ('both', 'krb5', $user2), 1,
    ' and another to the same ACL');
is ($server->acl_add ('empty', 'krb5', $user1), 1, ' and another to empty');
is ($server->acl_add ('test', 'krb5', $user1), undef,
    ' but adding to an unknown ACL fails');
is ($server->error, 'ACL test not found', ' and returns the right error');
is ($server->acl_remove ('test', 'krb5', $user1), undef,
    'Removing from a nonexistent ACL fails');
is ($server->error, 'ACL test not found', ' and returns the right error');
is ($server->acl_remove ('empty', 'krb5', $user2), undef,
    ' and removing an entry not there fails');
is ($server->error,
    "cannot remove krb5:$user2 from 5: entry not found in ACL",
    ' and returns the right error');
is ($server->acl_remove ('empty', 'krb5', $user1), 1,
    ' but removing a good one works');
is ($server->acl_remove ('empty', 'krb5', $user1), undef,
    ' but does not work twice');
is ($server->error,
    "cannot remove krb5:$user1 from 5: entry not found in ACL",
    ' and returns the right error');

# Clean up.
unlink 'wallet-db';
