#!/usr/bin/perl -w
# $Id$
#
# t/server.t -- Tests for the wallet server API.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007, 2008 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

use Test::More tests => 338;

use POSIX qw(strftime);
use Wallet::Admin;
use Wallet::Config;
use Wallet::Schema;
use Wallet::Server;

use lib 't/lib';
use Util;

# Some global defaults to use.
my $admin = 'admin@EXAMPLE.COM';
my $user1 = 'alice@EXAMPLE.COM';
my $user2 = 'bob@EXAMPLE.COM';
my $host = 'localhost';
my @trace = ($admin, $host);

# Use Wallet::Admin to set up the database.
db_setup;
my $setup = eval { Wallet::Admin->new };
is ($@, '', 'Database initialization did not die');
is ($setup->reinitialize ($admin), 1, 'Database initialization succeeded');

# Now test the new method.
$server = eval { Wallet::Server->new (@trace) };
is ($@, '', 'Reopening with new did not die');
ok ($server->isa ('Wallet::Server'), ' and returned the right class');
my $dbh = $server->dbh;
ok (defined ($dbh), ' and returns a defined database handle');

# Allow creation of base objects for testing purposes.
my $schema = Wallet::Schema->new;
$schema->register_object ($dbh, 'base', 'Wallet::Object::Base');

# We're currently running as the administrator, so everything should succeed.
# Set up a bunch of data for us to test with, starting with some ACLs.  Test
# the error handling while we're at it.
is ($server->acl_show ('ADMIN'),
    "Members of ACL ADMIN (id: 1) are:\n  krb5 $admin\n",
    'Showing the ADMIN ACL works');
is ($server->acl_show (1),
    "Members of ACL ADMIN (id: 1) are:\n  krb5 $admin\n",
    ' including by number');
my $history = <<"EOO";
DATE  create
    by $admin from $host
DATE  add krb5 $admin
    by $admin from $host
EOO
my $result = $server->acl_history ('ADMIN');
$result =~ s/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d/DATE/gm;
is ($result, $history, ' and displaying history works');
$result = $server->acl_history (1);
$result =~ s/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d/DATE/gm;
is ($result, $history, ' including by number');
is ($server->acl_create (3), undef, 'Cannot create ACL with a numeric name');
is ($server->error, 'ACL name may not be all numbers',
    ' and returns the right error');
is ($server->acl_create ('user1'), 1, 'Can create regular ACL');
is ($server->acl_show ('user1'), "Members of ACL user1 (id: 2) are:\n",
    ' and show works');
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
is ($server->acl_show ('test'), undef, ' and show fails');
is ($server->error, 'ACL test not found', ' and returns the right error');
is ($server->acl_history ('test'), undef, ' and history fails');
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
is ($server->acl_show ('both'),
    "Members of ACL both (id: 4) are:\n  krb5 $user1\n  krb5 $user2\n",
    ' and show returns the correct result');
$history = <<"EOO";
DATE  create
    by $admin from $host
DATE  add krb5 $user1
    by $admin from $host
DATE  add krb5 $user2
    by $admin from $host
EOO
$result = $server->acl_history ('both');
$result =~ s/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d/DATE/gm;
is ($result, $history, ' as does history');
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
is ($server->acl_show ('empty'),
    "Members of ACL empty (id: 5) are:\n  krb5 $user1\n",
    ' and show returns the correct status');
is ($server->acl_remove ('empty', 'krb5', $user1), 1,
    ' but removing a good one works');
is ($server->acl_remove ('empty', 'krb5', $user1), undef,
    ' but does not work twice');
is ($server->error,
    "cannot remove krb5:$user1 from 5: entry not found in ACL",
    ' and returns the right error');
is ($server->acl_show ('empty'), "Members of ACL empty (id: 5) are:\n",
    ' and show returns the correct status');

# Make sure we can't cripple the ADMIN ACL.
is ($server->acl_destroy ('ADMIN'), undef, 'Cannot destroy the ADMIN ACL');
is ($server->error, 'cannot destroy the ADMIN ACL', ' with the right error');
is ($server->acl_rename ('ADMIN', 'foo'), undef, ' or rename it');
is ($server->error, 'cannot rename the ADMIN ACL', ' with the right error');
is ($server->acl_remove ('ADMIN', 'krb5', $admin), undef,
    ' or remove its last entry');
is ($server->error, 'cannot remove last ADMIN ACL entry',
    ' with the right error');
is ($server->acl_add ('ADMIN', 'krb5', $user1), 1,
    ' but we can add another entry');
is ($server->acl_remove ('ADMIN', 'krb5', $user1), 1, ' and then remove it');
is ($server->acl_remove ('ADMIN', 'krb5', $user1), undef,
    ' and remove a user not on it');
is ($server->error,
    "cannot remove krb5:$user1 from 1: entry not found in ACL",
    ' and get the right error');

# Now, create a few objects to use for testing and test the object API while
# we're at it.
is ($server->create ('base', 'service/admin'), 1,
    'Creating an object works');
is ($server->create ('base', 'service/admin'), undef, ' but not twice');
like ($server->error, qr{^cannot create object base:service/admin: },
      ' and returns the right error');
is ($server->check ('base', 'service/admin'), 1, ' and check works');
is ($server->create ('srvtab', 'service.admin'), undef,
    'Creating an unknown object fails');
is ($server->error, 'unknown object type srvtab', ' with the right error');
is ($server->check ('srvtab', 'service.admin'), undef, ' and check fails');
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
is ($server->check ('base', 'service/test'), 0,
    ' and now check says it is not there');
is ($server->destroy ('base', 'service/test'), undef, ' but not twice');
is ($server->error, 'cannot find base:service/test', ' with the right error');

# Test manipulating expires.
my $now = strftime ('%Y-%m-%d %T', localtime time);
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

# Test attributes.
is ($server->attr ('base', 'service/admin', 'foo'), undef,
    'Getting an attribute fails');
is ($server->error, 'unknown attribute foo', ' but called the method');
is ($server->attr ('base', 'service/admin', 'foo', 'foo'), undef,
    ' and setting an attribute fails');
is ($server->error, 'unknown attribute foo', ' and called the method');

# Because we're admin, we should be able to show one of these objects, but we
# still shouldn't be able to get or store since there are no ACLs.
is ($server->show ('base', 'service/test'), undef,
    'Cannot show nonexistent object');
is ($server->error, 'cannot find base:service/test', ' with the right error');
my $show = $server->show ('base', 'service/admin');
$show =~ s/(Created on:) [\d-]+ [\d:]+$/$1 0/;
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
$result = eval { $server->get ('base', 'service/admin') };
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
is ($server->owner ('base', 'service/admin', 'ADMIN'), 1,
    ' and setting the owner again works');

# Test manipulating flags.
is ($server->flag_clear ('base', 'service/admin', 'locked'), undef,
    'Clearing an unset flag fails');
is ($server->error,
    "cannot clear flag locked on base:service/admin: flag not set",
    ' with the right error');
if ($server->flag_set ('base', 'service/admin', 'locked')) {
    ok (1, ' but setting it works');
} else {
    is ($server->error, '', ' but setting it works');
}
is ($server->store ('base', 'service/admin', 'stuff'), undef,
    ' now store fails');
is ($server->error, 'cannot store base:service/admin: object is locked',
    ' because the object is locked');
is ($server->expires ('base', 'service/admin', ''), undef,
    ' and expires fails');
is ($server->error, 'cannot modify base:service/admin: object is locked',
    ' because the object is locked');
is ($server->owner ('base', 'service/admin', ''), undef, ' and owner fails');
is ($server->error, 'cannot modify base:service/admin: object is locked',
    ' because the object is locked');
for my $acl (qw/get store show destroy flags/) {
    is ($server->acl ('base', 'service/admin', $acl, ''), undef,
        " and setting $acl ACL fails");
    is ($server->error, 'cannot modify base:service/admin: object is locked',
        ' for the same reason');
}
is ($server->flag_clear ('base', 'service/admin', 'locked'), 1,
    ' and then clearing it works');
is ($server->owner ('base', 'service/admin', ''), 1,
    ' and then clearing owner works');
is ($server->flag_set ('base', 'service/admin', 'unchanging'), 1,
    ' and setting unchanging works');
is ($server->flag_clear ('base', 'service/admin', 'locked'), undef,
    ' and clearing locked still does not');
is ($server->error,
    "cannot clear flag locked on base:service/admin: flag not set",
    ' with the right error');
is ($server->flag_clear ('base', 'service/admin', 'unchanging'), 1,
    ' and clearing unchanging works');

# Test history.
$history = <<"EOO";
DATE  create
    by $admin from $host
DATE  set expires to $now
    by $admin from $host
DATE  unset expires (was $now)
    by $admin from $host
DATE  set acl_get to 1
    by $admin from $host
DATE  unset acl_get (was 1)
    by $admin from $host
DATE  set acl_store to 1
    by $admin from $host
DATE  unset acl_store (was 1)
    by $admin from $host
DATE  set owner to 1
    by $admin from $host
DATE  set acl_get to 5
    by $admin from $host
DATE  set acl_store to 5
    by $admin from $host
DATE  unset acl_store (was 5)
    by $admin from $host
DATE  unset owner (was 1)
    by $admin from $host
DATE  set owner to 1
    by $admin from $host
DATE  set flag locked
    by $admin from $host
DATE  clear flag locked
    by $admin from $host
DATE  unset owner (was 1)
    by $admin from $host
DATE  set flag unchanging
    by $admin from $host
DATE  clear flag unchanging
    by $admin from $host
EOO
my $seen = $server->history ('base', 'service/admin');
$seen =~ s/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d/DATE/gm;
is ($seen, $history, 'History for service/admin is correct');

# Now let's set up some additional ACLs for future tests.
is ($server->owner ('base', 'service/user1', 'user1'), 1, 'Set user1 owner');
is ($server->owner ('base', 'service/user2', 'user2'), 1, 'Set user2 owner');
is ($server->owner ('base', 'service/both', 'both'), 1, 'Set both owner');
is ($server->acl ('base', 'service/both', 'show', 'user1'), 1, ' and show');
is ($server->acl ('base', 'service/both', 'destroy', 'user2'), 1,
    ' and destroy');
is ($server->acl ('base', 'service/both', 'flags', 'user1'), 1, ' and flags');
is ($server->acl ('base', 'service/admin', 'store', 'user1'), 1,
    'Set admin store');

# Okay, now we can switch users and be sure we don't have admin rights.
$server = eval { Wallet::Server->new ($user1, $host) };
is ($@, '', 'Switching users works');
is ($server->acl_create ('new'), undef, ' and now we cannot create ACLs');
is ($server->error, "$user1 not authorized to create ACL", ' with error');
is ($server->acl_rename ('user1', 'alice'), undef, ' or rename ACLs');
is ($server->error, "$user1 not authorized to rename ACL user1",
    ' with error');
is ($server->acl_show ('user1'), undef, ' or show ACLs');
is ($server->error, "$user1 not authorized to show ACL user1", ' with error');
is ($server->acl_history ('user1'), undef, ' or see history for ACLs');
is ($server->error, "$user1 not authorized to see history of ACL user1",
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
is ($server->flag_set ('base', 'service/user1', 'unchanging'), undef,
    ' or set flags');
is ($server->error,
    "$user1 not authorized to set flags for base:service/user1",
    ' with error');
is ($server->flag_clear ('base', 'service/user1', 'unchanging'), undef,
    ' or clear flags');
is ($server->error,
    "$user1 not authorized to set flags for base:service/user1",
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
$show =~ s/(Created on:) [\d-]+ [\d:]+$/$1 0/m;
$expected = <<"EOO";
           Type: base
           Name: service/user1
          Owner: user1
     Created by: $admin
   Created from: $host
     Created on: 0

Members of ACL user1 (id: 2) are:
  krb5 $user1
EOO
is ($show, $expected, ' and show an object we own');
$history = <<"EOO";
DATE  create
    by $admin from $host
DATE  set owner to 2
    by $admin from $host
EOO
$seen = $server->history ('base', 'service/user1');
$seen =~ s/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d/DATE/gm;
is ($seen, $history, ' and see history for an object we own');
is ($server->attr ('base', 'service/user1', 'foo'), undef,
    ' and getting an attribute fails');
is ($server->error, 'unknown attribute foo', ' but calls the method');
is ($server->attr ('base', 'service/user1', 'foo', 'foo'), undef,
    ' and setting an attribute fails');
is ($server->error, 'unknown attribute foo', ' but calls the method');

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
is ($server->history ('base', 'service/user2'), undef,
    ' or see history for it');
is ($server->error, "$user1 not authorized to show base:service/user2",
    ' with the right error');
is ($server->attr ('base', 'service/user2', 'foo'), undef,
    ' or get attributes');
is ($server->error,
    "$user1 not authorized to get attributes for base:service/user2",
    ' with the right error');
is ($server->attr ('base', 'service/user2', 'foo', ''), undef,
    ' and set attributes');
is ($server->error,
    "$user1 not authorized to set attributes for base:service/user2",
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
is ($server->flag_set ('base', 'service/both', 'unchanging'), 1,
    ' and set flags on an object we have an ACL');
is ($server->flag_set ('base', 'service/both', 'locked'), 1, ' both flags');
$show = $server->show ('base', 'service/both');
$show =~ s/(Created on:) [\d-]+ [\d:]+$/$1 0/m;
$expected = <<"EOO";
           Type: base
           Name: service/both
          Owner: both
       Show ACL: user1
    Destroy ACL: user2
      Flags ACL: user1
          Flags: locked unchanging
     Created by: $admin
   Created from: $host
     Created on: 0

Members of ACL both (id: 4) are:
  krb5 $user1
  krb5 $user2

Members of ACL user1 (id: 2) are:
  krb5 $user1

Members of ACL user2 (id: 3) are:
  krb5 $user2
EOO
is ($show, $expected, ' and show an object we jointly own');
$history = <<"EOO";
DATE  create
    by $admin from $host
DATE  set owner to 4
    by $admin from $host
DATE  set acl_show to 2
    by $admin from $host
DATE  set acl_destroy to 3
    by $admin from $host
DATE  set acl_flags to 2
    by $admin from $host
DATE  set flag unchanging
    by $user1 from $host
DATE  set flag locked
    by $user1 from $host
EOO
$seen = $server->history ('base', 'service/both');
$seen =~ s/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d/DATE/gm;
is ($seen, $history, ' and see history for an object we jointly own');
is ($server->store ('base', 'service/both', 'stuff'), undef,
    ' but not store data');
is ($server->error, 'cannot store base:service/both: object is locked',
    ' when the object is locked');
is ($server->flag_clear ('base', 'service/both', 'locked'), 1,
    ' and clear flags');
is ($server->destroy ('base', 'service/both'), undef,
    ' but not destroy it');
is ($server->error, "$user1 not authorized to destroy base:service/both",
    ' due to permissions');
is ($server->attr ('base', 'service/both', 'foo'), undef,
    'Getting an attribute fails');
is ($server->error, 'unknown attribute foo', ' but calls the method');
is ($server->attr ('base', 'service/both', 'foo', ''), undef,
    ' and setting an attribute fails');
is ($server->error, 'unknown attribute foo', ' but calls the method');
is ($server->attr ('base', 'service/admin', 'foo', ''), undef,
    ' but setting an attribute on service/admin fails');
is ($server->error, 'unknown attribute foo', ' and calls the method');
is ($server->attr ('base', 'service/admin', 'foo'), undef,
    ' while getting an attribute on service/admin fails');
is ($server->error,
    "$user1 not authorized to get attributes for base:service/admin",
    ' with a permission error');

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
$show =~ s/(Created on:) [\d-]+ [\d:]+$/$1 0/m;
$expected = <<"EOO";
           Type: base
           Name: service/user2
          Owner: user2
     Created by: $admin
   Created from: $host
     Created on: 0

Members of ACL user2 (id: 3) are:
  krb5 $user2
EOO
is ($show, $expected, ' and show an object we own');
$history = <<"EOO";
DATE  create
    by $admin from $host
DATE  set owner to 3
    by $admin from $host
EOO
$seen = $server->history ('base', 'service/user2');
$seen =~ s/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d/DATE/gm;
is ($seen, $history, ' and see history for an object we own');

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
is ($server->history ('base', 'service/user1'), undef,
    ' or see history for it');
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
is ($server->history ('base', 'service/both'), undef,
    ' or see history for it');
is ($server->error, "$user2 not authorized to show base:service/both",
    ' with the right error');
is ($server->flag_set ('base', 'service/both', 'locked'), undef,
    ' or set flags on it');
is ($server->error,
    "$user2 not authorized to set flags for base:service/both",
    ' with the right error');
is ($server->flag_clear ('base', 'service/both', 'unchanging'), undef,
    ' or clear flags on it');
is ($server->error,
    "$user2 not authorized to set flags for base:service/both",
    ' with the right error');
is ($server->attr ('base', 'service/both', 'foo'), undef,
    ' or getting an attribute');
is ($server->error,
    "$user2 not authorized to get attributes for base:service/both",
    ' with the right error');
is ($server->attr ('base', 'service/both', 'foo', 'foo'), undef,
    ' but setting an attribute fails');
is ($server->error, 'unknown attribute foo', ' but calls the method');
is ($server->destroy ('base', 'service/both'), 1, ' and we can destroy it');
is ($server->get ('base', 'service/both'), undef, ' and now cannot get it');
is ($server->error, "$user2 not authorized to create base:service/both",
    ' because it is gone');
is ($server->store ('base', 'service/both', 'stuff'), undef,
    ' or store it');
is ($server->error, "$user2 not authorized to create base:service/both",
    ' because it is gone');

# Test default ACLs on object creation.
#
# Create a default_acl sub that permits $user2 to create service/default with
# a default owner of default (the same as the both ACL), $user1 to create
# service/default-both with a default owner of both (but a different
# definition than the existing ACL), and $user2 to create service/default-2
# with a default owner of user2 (with the same definition as the existing
# ACL).
#
# Also add service/default-get and service/default-store to test auto-creation
# on get and store, and service/default-admin to test auto-creation when one
# is an admin.
package Wallet::Config;
sub default_owner {
    my ($type, $name) = @_;
    if ($type eq 'base' and $name eq 'service/default') {
        return ('default', [ 'krb5', $user1 ], [ 'krb5', $user2 ]);
    } elsif ($type eq 'base' and $name eq 'service/default-both') {
        return ('both', [ 'krb5', $user1 ]);
    } elsif ($type eq 'base' and $name eq 'service/default-2') {
        return ('user2', [ 'krb5', $user2 ]);
    } elsif ($type eq 'base' and $name eq 'service/default-get') {
        return ('user2', [ 'krb5', $user2 ]);
    } elsif ($type eq 'base' and $name eq 'service/default-store') {
        return ('user2', [ 'krb5', $user2 ]);
    } elsif ($type eq 'base' and $name eq 'service/default-admin') {
        return ('auto-admin', [ 'krb5', $admin ]);
    } elsif ($type eq 'base' and $name eq 'host/default') {
        return ('auto-host', [ 'krb5', $admin ]);
    } else {
        return;
    }
}
package main;

# We're still user2, so we should now be able to create service/default.  Make
# sure we can and that the ACLs all look good.
is ($server->create ('base', 'service/default'), 1,
    'Creating an object with the default ACL works');
is ($server->create ('base', 'service/foo'), undef, ' but not any object');
is ($server->error, "$user2 not authorized to create base:service/foo",
    ' with the right error');
$show = $server->show ('base', 'service/default');
if (defined $show) {
    $show =~ s/(Created on:) [\d-]+ [\d:]+$/$1 0/m;
    $expected = <<"EOO";
           Type: base
           Name: service/default
          Owner: default
     Created by: $user2
   Created from: $host
     Created on: 0

Members of ACL default (id: 7) are:
  krb5 $user1
  krb5 $user2
EOO
    is ($show, $expected, ' and the created object and ACL are correct');
} else {
    is ($server->error, undef, ' and the created object and ACL are correct');
}

# Try the other basic cases in default_owner.
is ($server->create ('base', 'service/default-both'), undef,
    'Creating an object with an ACL mismatch fails');
is ($server->error, "ACL both exists and doesn't match default",
    ' with the right error');
is ($server->create ('base', 'service/default-2'), 1,
    'Creating an object with an existing ACL works');
$show = $server->show ('base', 'service/default-2');
$show =~ s/(Created on:) [\d-]+ [\d:]+$/$1 0/m;
$expected = <<"EOO";
           Type: base
           Name: service/default-2
          Owner: user2
     Created by: $user2
   Created from: $host
     Created on: 0

Members of ACL user2 (id: 3) are:
  krb5 $user2
EOO
is ($show, $expected, ' and the created object and ACL are correct');

# Test auto-creation on get and store.
$result = eval { $server->get ('base', 'service/default-get') };
is ($result, undef, 'Auto-creation on get...');
is ($@, "Do not instantiate Wallet::Object::Base directly\n", ' ...works');
$show = $server->show ('base', 'service/default-get');
$show =~ s/(Created on:) [\d-]+ [\d:]+$/$1 0/m;
$expected = <<"EOO";
           Type: base
           Name: service/default-get
          Owner: user2
     Created by: $user2
   Created from: $host
     Created on: 0

Members of ACL user2 (id: 3) are:
  krb5 $user2
EOO
is ($show, $expected, ' and the created object and ACL are correct');
is ($server->get ('base', 'service/foo'), undef,
    ' but auto-creation of something else fails');
is ($server->error, "$user2 not authorized to create base:service/foo",
    ' with the right error');
is ($server->store ('base', 'service/default-store', 'stuff'), undef,
    'Auto-creation on store...');
is ($server->error,
    "cannot store base:service/default-store: object type is immutable",
    ' ...works');
$show = $server->show ('base', 'service/default-store');
$show =~ s/(Created on:) [\d-]+ [\d:]+$/$1 0/m;
$expected = <<"EOO";
           Type: base
           Name: service/default-store
          Owner: user2
     Created by: $user2
   Created from: $host
     Created on: 0

Members of ACL user2 (id: 3) are:
  krb5 $user2
EOO
is ($show, $expected, ' and the created object and ACL are correct');
is ($server->store ('base', 'service/foo', 'stuff'), undef,
    ' but auto-creation of something else fails');
is ($server->error, "$user2 not authorized to create base:service/foo",
    ' with the right error');

# Switch back to admin to test auto-creation.
$server = eval { Wallet::Server->new ($admin, $host) };
is ($@, '', 'Switching users back to admin works');
$result = eval { $server->get ('base', 'service/default-admin') };
is ($result, undef, 'Auto-creation on get...');
is ($@, "Do not instantiate Wallet::Object::Base directly\n", ' ...works');
$show = $server->show ('base', 'service/default-admin');
$show =~ s/(Created on:) [\d-]+ [\d:]+$/$1 0/m;
$expected = <<"EOO";
           Type: base
           Name: service/default-admin
          Owner: auto-admin
     Created by: $admin
   Created from: $host
     Created on: 0

Members of ACL auto-admin (id: 8) are:
  krb5 $admin
EOO
is ($show, $expected, ' and the created object and ACL are correct');
is ($server->destroy ('base', 'service/default-admin'), 1,
    ' and we can destroy it');

# Test naming enforcement.  Permit any base service/* name, but only permit
# base host/* if the host is fully qualified and ends in .example.edu.
package Wallet::Config;
sub verify_name {
    my ($type, $name) = @_;
    if ($type eq 'base' and $name =~ m,^service/,) {
        return;
    } elsif ($type eq 'base' and $name =~ m,^host/(.*),) {
        my $host = $1;
        return "host $host must be fully qualified (add .example.edu)"
            unless $host =~ /\./;
        return "host $host not in .example.edu domain"
            unless $host =~ /\.example\.edu$/;
        return;
    } else {
        return;
    }
}
package main;

# Recreate service/default-admin, which should succeed, and then try the
# various host/* principals.
is ($server->create ('base', 'service/default-admin'), 1,
    'Creating default/admin succeeds');
if ($server->create ('base', 'host/default.example.edu')) {
    ok (1, ' as does creating host/default.example.edu');
} else {
    is ($server->error, '', ' as does creating host/default.example.edu');
}
is ($server->create ('base', 'host/default'), undef,
    ' but an unqualified host fails');
is ($server->error, 'base:host/default rejected: host default must be fully'
    . ' qualified (add .example.edu)', ' with the right error');
is ($server->acl_show ('auto-host'), undef, ' and the ACL is not present');
is ($server->error, 'ACL auto-host not found', ' with the right error');
is ($server->create ('base', 'host/default.stanford.edu'), undef,
    ' and a host in the wrong domain fails');
is ($server->error, 'base:host/default.stanford.edu rejected: host'
    . ' default.stanford.edu not in .example.edu domain',
    ' with the right error');

# Clean up.
$setup->destroy;
unlink 'wallet-db';

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
