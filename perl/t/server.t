#!/usr/bin/perl -w
# $Id$
#
# t/server.t -- Tests for the wallet server API.

use Test::More tests => 85;

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

# Now, create a few objects to use for testing and test the object API while
# we're at it.
is ($server->create ('base', 'service/admin'), 1,
    'Creating an object works');
is ($server->create ('base', 'service/admin'), undef, ' but not twice');
like ($server->error, qr{^cannot create object base:service/admin: },
      ' and returns the right error');
is ($server->create ('srvtab', 'service.admin'), undef,
    'Creating an unknown object fails');
is ($server->error, 'unknown object type srvtab', ' with the right error');
is ($server->create ('', 'service.admin'), undef,
    ' and likewise with an empty type');
is ($server->error, 'unknown object type ', ' with the right error');
is ($server->create ('base', 'service/user1'), 1,
    ' but we can create a base object');
is ($server->create ('base', 'service/user2'), 1, ' and another');
is ($server->create ('base', 'service/both'), 1, ' and another');
is ($server->create ('base', 'service/test'), 1, ' and another');
is ($server->create ('base', ''), undef, ' but not with an empty name');
is ($server->error, 'invalid object name', ' with the right error');
is ($server->destroy ('base', 'service/none'), undef,
    'Destroying an unknown object fails');
is ($server->error, 'cannot find base:service/none', ' with the right error');
is ($server->destroy ('srvtab', 'service/test'), undef,
    ' and destroying an unknown type fails');
is ($server->error, 'unknown object type srvtab', ' with a different error');
is ($server->destroy ('base', 'service/test'), 1,
    ' but destroying a good object works');
is ($server->destroy ('base', 'service/test'), undef, ' but not twice');
is ($server->error, 'cannot find base:service/test', ' with the right error');

# Because we're admin, we should be able to show one of these objects, but we
# still shouldn't be able to get or store since there are no ACLs.
is ($server->show ('base', 'service/test'), undef,
    'Cannot show nonexistent object');
is ($server->error, 'cannot find base:service/test', ' with the right error');
my $show = $server->show ('base', 'service/admin');
$show =~ s/(Created on:) \d+$/$1 0/;
my $expected = <<"EOO";
           Type: base
           Name: service/admin
     Created by: $admin
   Created from: $host
     Created on: 0
EOO
is ($show, $expected, ' but showing an existing object works');
is ($server->get ('base', 'service/admin'), undef, 'Getting an object fails');
is ($server->error, "$admin not authorized to get base:service/admin",
    ' with the right error');
is ($server->store ('base', 'service/admin', 'stuff'), undef,
    ' and storing the object also fails');
is ($server->error, "$admin not authorized to store base:service/admin",
    ' with the right error');

# Grant only the get ACL, which should give us partial permissions.
is ($server->acl ('base', 'service/test', 'get', 'ADMIN'), undef,
    'Setting ACL on unknown object fails');
is ($server->error, 'cannot find base:service/test', ' with the right error');
is ($server->acl ('base', 'service/admin', 'foo', 'ADMIN'), undef,
    ' as does setting an unknown ACL');
is ($server->error, 'invalid ACL type foo', ' with the right error');
is ($server->acl ('base', 'service/admin', 'get', 'test2'), undef,
    ' as does setting it to an unknown ACL');
is ($server->error, 'ACL test2 not found', ' with the right error');
is ($server->acl ('base', 'service/admin', 'get', 'ADMIN'), 1,
    ' but setting the right ACL works');
my $result = eval { $server->get ('base', 'service/admin') };
is ($result, undef, 'Get still fails');
is ($@, "Do not instantiate Wallet::Object::Base directly\n",
    ' but the method is called');
is ($server->store ('base', 'service/admin', 'stuff'), undef,
    ' and storing the object still fails');
is ($server->error, "$admin not authorized to store base:service/admin",
    ' with the right error');
is ($server->acl ('base', 'service/admin', 'get', ''), 1,
    'Clearing the ACL works');
is ($server->get ('base', 'service/admin'), undef, ' and now get fails');
is ($server->error, "$admin not authorized to get base:service/admin",
    ' with the right error');

# Clean up.
unlink 'wallet-db';
