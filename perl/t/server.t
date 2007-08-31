#!/usr/bin/perl -w
# $Id$
#
# t/server.t -- Tests for the wallet server API.

use Test::More tests => 201;

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

# Test manipulating expires.
my $now = time;
is ($server->expires ('base', 'service/test'), undef,
    'Retrieving expires on an unknown object fails');
is ($server->error, 'cannot find base:service/test', ' with the right error');
is ($server->expires ('base', 'service/test', $now), undef,
    ' and setting it also fails');
is ($server->error, 'cannot find base:service/test', ' with the right error');
is ($server->expires ('base', 'service/admin'), undef,
    'Retrieving expires for the right object returns undef');
is ($server->error, undef, ' but there is no error');
is ($server->expires ('base', 'service/admin', $now), 1,
    ' and we can set it');
is ($server->expires ('base', 'service/admin'), $now,
    ' and get the value back');
is ($server->expires ('base', 'service/admin', ''), 1, ' and clear it');
is ($server->expires ('base', 'service/admin'), undef, ' and now it is gone');
is ($server->error, undef, ' and still no error');

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
is ($server->acl ('base', 'service/admin', 'store', 'ADMIN'), 1,
    'Setting the store ACL works');
is ($server->store ('base', 'service/admin', 'stuff'), undef,
    ' and now store fails');
is ($server->error,
    "cannot store base:service/admin: object type is immutable",
    ' with a different error message');
is ($server->get ('base', 'service/admin'), undef, ' and get still fails');
is ($server->error, "$admin not authorized to get base:service/admin",
    ' with the right error');
is ($server->acl ('base', 'service/admin', 'store', ''), 1,
    'Clearing the ACL works');
is ($server->store ('base', 'service/admin', 'stuff'), undef,
    ' and storing the object now fails');
is ($server->error, "$admin not authorized to store base:service/admin",
    ' with the right error');

# Test manipulating the owner.
is ($server->owner ('base', 'service/test'), undef,
    'Owner of nonexistent object fails');
is ($server->error, 'cannot find base:service/test', ' with the right error');
is ($server->owner ('base', 'service/test', 'ADMIN'), undef,
    ' as does setting it');
is ($server->error, 'cannot find base:service/test', ' with the right error');
is ($server->owner ('base', 'service/admin'), undef,
    'Owner of existing object is also undef');
is ($server->error, undef, ' but there is no error');
is ($server->owner ('base', 'service/admin', 'test2'), undef,
    'Setting it to an unknown ACL fails');
is ($server->error, 'ACL test2 not found', ' with the right error');
is ($server->owner ('base', 'service/admin', 'ADMIN'), 1,
    'Setting it to ADMIN works');
$result = eval { $server->get ('base', 'service/admin') };
is ($result, undef, ' and get still fails');
is ($@, "Do not instantiate Wallet::Object::Base directly\n",
    ' but the method is called');
is ($server->store ('base', 'service/admin', 'stuff'), undef,
    ' and now store fails');
is ($server->error,
    "cannot store base:service/admin: object type is immutable",
    ' with a different error message');
is ($server->acl ('base', 'service/admin', 'get', 'empty'), 1,
    'Setting the get ACL succeeds');
is ($server->get ('base', 'service/admin'), undef, ' and get now fails');
is ($server->error, "$admin not authorized to get base:service/admin",
    ' with the right error');
is ($server->store ('base', 'service/admin', 'stuff'), undef,
    ' but store fails');
is ($server->error,
    "cannot store base:service/admin: object type is immutable",
    ' with the same error message');
is ($server->acl ('base', 'service/admin', 'store', 'empty'), 1,
    ' until we do the same thing with store');
is ($server->store ('base', 'service/admin', 'stuff'), undef,
    ' and now store fails');
is ($server->error, "$admin not authorized to store base:service/admin",
    ' due to permissions');
is ($server->acl ('base', 'service/admin', 'store', ''), 1,
    'Clearing the store ACL works');
is ($server->store ('base', 'service/admin', 'stuff'), undef,
    ' and fixes that');
is ($server->error,
    "cannot store base:service/admin: object type is immutable",
    ' since we are back to immutable');
is ($server->owner ('base', 'service/admin', ''), 1,
    ' but clearing the owner works');
is ($server->store ('base', 'service/admin', 'stuff'), undef,
    ' and now store fails');
is ($server->error, "$admin not authorized to store base:service/admin",
    ' due to permissions again');

# Now let's set up some additional ACLs for future tests.
is ($server->owner ('base', 'service/user1', 'user1'), 1, 'Set user1 owner');
is ($server->owner ('base', 'service/user2', 'user2'), 1, 'Set user2 owner');
is ($server->owner ('base', 'service/both', 'both'), 1, 'Set both owner');
is ($server->acl ('base', 'service/both', 'show', 'user1'), 1, ' and show');
is ($server->acl ('base', 'service/both', 'destroy', 'user2'), 1,
    ' and destroy');

# Okay, now we can switch users and be sure we don't have admin rights.
$server = eval { Wallet::Server->new ($user1, $host) };
is ($@, '', 'Switching users works');
is ($server->acl_create ('new'), undef, ' and now we cannot create ACLs');
is ($server->error, "$user1 not authorized to create ACL", ' with error');
is ($server->acl_rename ('user1', 'alice'), undef, ' or rename ACLs');
is ($server->error, "$user1 not authorized to rename ACL user1",
    ' with error');
is ($server->acl_destroy ('user2'), undef, ' or destroy ACLs');
is ($server->error, "$user1 not authorized to destroy ACL user2",
    ' with error');
is ($server->acl_add ('user1', 'krb5', $user2), undef, ' or add to ACLs');
is ($server->error, "$user1 not authorized to add to ACL user1",
    ' with error');
is ($server->acl_remove ('user1', 'krb5', $user1), undef,
    ' or remove from ACLs');
is ($server->error, "$user1 not authorized to remove from ACL user1",
    ' with error');
is ($server->create ('base', 'service/test'), undef,
    ' nor can we create objects');
is ($server->error, "$user1 not authorized to create base:service/test",
    ' with error');
is ($server->destroy ('base', 'service/user1'), undef,
    ' or destroy objects');
is ($server->error, "$user1 not authorized to destroy base:service/user1",
    ' with error');
is ($server->owner ('base', 'service/user1', 'user2'), undef,
    ' or set the owner');
is ($server->error,
    "$user1 not authorized to set owner for base:service/user1",
    ' with error');
is ($server->expires ('base', 'service/user1', $now), undef,
    ' or set expires');
is ($server->error,
    "$user1 not authorized to set expires for base:service/user1",
    ' with error');
is ($server->acl ('base', 'service/user1', 'get', 'user1'), undef,
    ' or set an ACL');
is ($server->error,
    "$user1 not authorized to set ACL for base:service/user1",
    ' with error');

# However, we can perform object actions on things we own.
$result = eval { $server->get ('base', 'service/user1') };
is ($result, undef, 'We can get an object we own');
is ($@, "Do not instantiate Wallet::Object::Base directly\n",
    ' and the method is called');
is ($server->store ('base', 'service/user1', 'stuff'), undef,
    ' or store an object we own');
is ($server->error,
    "cannot store base:service/user1: object type is immutable",
    ' and the method is called');
$show = $server->show ('base', 'service/user1');
$show =~ s/(Created on:) \d+$/$1 0/;
$expected = <<"EOO";
           Type: base
           Name: service/user1
          Owner: user1
     Created by: $admin
   Created from: $host
     Created on: 0
EOO
is ($show, $expected, ' and show an object we own');

# But not on things we don't own.
is ($server->get ('base', 'service/user2'), undef,
    'But we cannot get an object we do not own');
is ($server->error, "$user1 not authorized to get base:service/user2",
    ' with the right error');
is ($server->store ('base', 'service/user2', 'stuff'), undef,
    ' or store it');
is ($server->error, "$user1 not authorized to store base:service/user2",
    ' with the right error');
is ($server->show ('base', 'service/user2'), undef, ' or show it');
is ($server->error, "$user1 not authorized to show base:service/user2",
    ' with the right error');

# And only some things on an object we own with some ACLs.
$result = eval { $server->get ('base', 'service/both') };
is ($result, undef, 'We can get an object we jointly own');
is ($@, "Do not instantiate Wallet::Object::Base directly\n",
    ' and the method is called');
is ($server->store ('base', 'service/both', 'stuff'), undef,
    ' or store an object we jointly own');
is ($server->error,
    "cannot store base:service/both: object type is immutable",
    ' and the method is called');
$show = $server->show ('base', 'service/both');
$show =~ s/(Created on:) \d+$/$1 0/;
$expected = <<"EOO";
           Type: base
           Name: service/both
          Owner: both
       Show ACL: user1
    Destroy ACL: user2
     Created by: $admin
   Created from: $host
     Created on: 0
EOO
is ($show, $expected, ' and show an object we jointly own');
is ($server->destroy ('base', 'service/both'), undef,
    ' but not destroy it');
is ($server->error, "$user1 not authorized to destroy base:service/both",
    ' due to permissions');

# Now switch to the other user and make sure we can do things on objects we
# own.
$server = eval { Wallet::Server->new ($user2, $host) };
is ($@, '', 'Switching users works');
$result = eval { $server->get ('base', 'service/user2') };
is ($result, undef, 'We can get an object we own');
is ($@, "Do not instantiate Wallet::Object::Base directly\n",
    ' and the method is called');
is ($server->store ('base', 'service/user2', 'stuff'), undef,
    ' or store an object we own');
is ($server->error,
    "cannot store base:service/user2: object type is immutable",
    ' and the method is called');
$show = $server->show ('base', 'service/user2');
$show =~ s/(Created on:) \d+$/$1 0/;
$expected = <<"EOO";
           Type: base
           Name: service/user2
          Owner: user2
     Created by: $admin
   Created from: $host
     Created on: 0
EOO
is ($show, $expected, ' and show an object we own');

# But not on things we don't own.
is ($server->get ('base', 'service/user1'), undef,
    'But we cannot get an object we do not own');
is ($server->error, "$user2 not authorized to get base:service/user1",
    ' with the right error');
is ($server->store ('base', 'service/user1', 'stuff'), undef,
    ' or store it');
is ($server->error, "$user2 not authorized to store base:service/user1",
    ' with the right error');
is ($server->show ('base', 'service/user1'), undef, ' or show it');
is ($server->error, "$user2 not authorized to show base:service/user1",
    ' with the right error');

# And only some things on an object we own with some ACLs.
$result = eval { $server->get ('base', 'service/both') };
is ($result, undef, 'We can get an object we jointly own');
is ($@, "Do not instantiate Wallet::Object::Base directly\n",
    ' and the method is called');
is ($server->store ('base', 'service/both', 'stuff'), undef,
    ' or store an object we jointly own');
is ($server->error,
    "cannot store base:service/both: object type is immutable",
    ' and the method is called');
is ($server->show ('base', 'service/both'), undef, ' but we cannot show it');
is ($server->error, "$user2 not authorized to show base:service/both",
    ' with the right error');
is ($server->destroy ('base', 'service/both'), 1, ' and we can destroy it');
is ($server->get ('base', 'service/both'), undef, ' and now cannot get it');
is ($server->error, 'cannot find base:service/both', ' because it is gone');
is ($server->store ('base', 'service/both', 'stuff'), undef,
    ' or store it');
is ($server->error, 'cannot find base:service/both', ' because it is gone');

# Now test handling of some configuration errors.
undef $Wallet::Config::DB_DRIVER;
$server = eval { Wallet::Server->new ($user2, $host) };
is ($@, "database connection information not configured\n",
    'Fail if DB_DRIVER is not set');
$Wallet::Config::DB_DRIVER = 'SQLite';
undef $Wallet::Config::DB_INFO;
$server = eval { Wallet::Server->new ($user2, $host) };
is ($@, "database connection information not configured\n",
    ' or if DB_INFO is not set');
$Wallet::Config::DB_INFO = 't';
$server = eval { Wallet::Server->new ($user2, $host) };
like ($@, qr/^cannot connect to database: /,
      ' or if the database connection fails');

# Clean up.
unlink 'wallet-db';
