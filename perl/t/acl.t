#!/usr/bin/perl -w
#
# Tests for the wallet ACL API.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007, 2008 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

use POSIX qw(strftime);
use Test::More tests => 101;

use Wallet::ACL;
use Wallet::Admin;
use Wallet::Server;

use lib 't/lib';
use Util;

# Some global defaults to use.
my $admin = 'admin@EXAMPLE.COM';
my $user1 = 'alice@EXAMPLE.COM';
my $user2 = 'bob@EXAMPLE.COM';
my $host = 'localhost';
my @trace = ($admin, $host, time);

# Use Wallet::Admin to set up the database.
db_setup;
my $setup = eval { Wallet::Admin->new };
is ($@, '', 'Database connection succeeded');
is ($setup->reinitialize ($setup), 1, 'Database initialization succeeded');
my $schema = $setup->schema;

# Test create and new.
my $acl = eval { Wallet::ACL->create ('test', $schema, @trace) };
ok (defined ($acl), 'ACL creation');
is ($@, '', ' with no exceptions');
ok ($acl->isa ('Wallet::ACL'), ' and the right class');
is ($acl->name, 'test', ' and the right name');
is ($acl->id, 2, ' and the right ID');
$acl = eval { Wallet::ACL->create (3, $schema, @trace) };
ok (!defined ($acl), 'Creating with a numeric name');
is ($@, "ACL name may not be all numbers\n", ' with the right error message');
$acl = eval { Wallet::ACL->create ('test', $schema, @trace) };
ok (!defined ($acl), 'Creating a duplicate object');
like ($@, qr/^cannot create ACL test: /, ' with the right error message');
$acl = eval { Wallet::ACL->new ('test2', $schema) };
ok (!defined ($acl), 'Searching for a non-existent ACL');
is ($@, "ACL test2 not found\n", ' with the right error message');
$acl = eval { Wallet::ACL->new ('test', $schema) };
ok (defined ($acl), 'Searching for the test ACL by name');
is ($@, '', ' with no exceptions');
ok ($acl->isa ('Wallet::ACL'), ' and the right class');
is ($acl->id, 2, ' and the right ID');
$acl = eval { Wallet::ACL->new (2, $schema) };
ok (defined ($acl), 'Searching for the test ACL by ID');
is ($@, '', ' with no exceptions');
ok ($acl->isa ('Wallet::ACL'), ' and the right class');
is ($acl->name, 'test', ' and the right name');

# Test rename.
if ($acl->rename ('example')) {
    ok (1, 'Renaming the ACL');
} else {
    is ($acl->error, '', 'Renaming the ACL');
}
is ($acl->name, 'example', ' and the new name is right');
is ($acl->id, 2, ' and the ID did not change');
$acl = eval { Wallet::ACL->new ('test', $schema) };
ok (!defined ($acl), ' and it cannot be found under the old name');
is ($@, "ACL test not found\n", ' with the right error message');
$acl = eval { Wallet::ACL->new ('example', $schema) };
ok (defined ($acl), ' and it can be found with the new name');
is ($@, '', ' with no exceptions');
is ($acl->name, 'example', ' and the right name');
is ($acl->id, 2, ' and the right ID');
$acl = eval { Wallet::ACL->new (2, $schema) };
ok (defined ($acl), ' and it can still found by ID');
is ($@, '', ' with no exceptions');
is ($acl->name, 'example', ' and the right name');
is ($acl->id, 2, ' and the right ID');
ok (! $acl->rename ('ADMIN'), ' but renaming to an existing name fails');
like ($acl->error, qr/^cannot rename ACL 2 to ADMIN: /,
      ' with the right error');

# Test add, check, remove, list, and show.
my @entries = $acl->list;
is (scalar (@entries), 0, 'ACL starts empty');
is ($acl->check ($user1), 0, ' so check fails');
is (scalar ($acl->check_errors), '', ' with no errors');
ok (! $acl->add ('example', 'foo', @trace), ' and cannot add bad scheme');
is ($acl->error, 'unknown ACL scheme example', ' with the right error');
if ($acl->add ('krb5', $user1, @trace)) {
    ok (1, ' and can add a good scheme');
} else {
    is ($acl->error, '', ' and can add a good scheme');
}
@entries = $acl->list;
is (scalar (@entries), 1, ' and now there is one element');
is ($entries[0][0], 'krb5', ' with the right scheme');
is ($entries[0][1], $user1, ' and identifier');
is ($acl->check ($user1), 1, ' so check succeeds');
is (scalar ($acl->check_errors), '', ' with no errors');
is ($acl->check ($user2), 0, ' but the second user still fails');
is (scalar ($acl->check_errors), '', ' with no errors');
if ($acl->add ('krb5', $user2, @trace)) {
    ok (1, ' and can add a second entry');
} else {
    is ($acl->error, '', ' and can add a second entry');
}
is ($acl->check ($user2), 1, ' and now the second user checks');
is (scalar ($acl->check_errors), '', ' with no errors');
is ($acl->check ($user1), 1, ' and the first one still checks');
is (scalar ($acl->check_errors), '', ' with no errors');
@entries = sort { $a->[1] cmp $b->[1] } $acl->list;
is (scalar (@entries), 2, ' and now there are two entries');
is ($entries[0][0], 'krb5', ' with the right scheme for 1');
is ($entries[0][1], $user1, ' and the right identifier for 1');
is ($entries[1][0], 'krb5', ' and the right scheme for 2');
is ($entries[1][1], $user2, ' and the right identifier for 2');
my $expected = <<"EOE";
Members of ACL example (id: 2) are:
  krb5 $user1
  krb5 $user2
EOE
is ($acl->show, $expected, ' and show returns correctly');
ok (! $acl->remove ('krb5', $admin, @trace),
    'Removing a nonexistent entry fails');
is ($acl->error, "cannot remove krb5:$admin from 2: entry not found in ACL",
    ' with the right error');
if ($acl->remove ('krb5', $user1, @trace)) {
    ok (1, ' but removing the first user works');
} else {
    is ($acl->error, '', ' but removing the first user works');
}
is ($acl->check ($user1), 0, ' and now they do not check');
is (scalar ($acl->check_errors), '', ' with no errors');
@entries = $acl->list;
is (scalar (@entries), 1, ' and now there is one entry');
is ($entries[0][0], 'krb5', ' with the right scheme');
is ($entries[0][1], $user2, ' and the right identifier');
ok (! $acl->add ('krb5', $user2), 'Adding the same entry again fails');
like ($acl->error, qr/^cannot add \Qkrb5:$user2\E to 2: /,
      ' with the right error');
if ($acl->add ('krb5', '', @trace)) {
    ok (1, 'Adding a bad entry works');
} else {
    is ($acl->error, '', 'Adding a bad entry works');
}
@entries = sort { $a->[1] cmp $b->[1] } $acl->list;
is (scalar (@entries), 2, ' and now there are two entries');
is ($entries[0][0], 'krb5', ' with the right scheme for 1');
is ($entries[0][1], '', ' and the right identifier for 1');
is ($entries[1][0], 'krb5', ' and the right scheme for 2');
is ($entries[1][1], $user2, ' and the right identifier for 2');
$expected = <<"EOE";
Members of ACL example (id: 2) are:
  krb5 
  krb5 $user2
EOE
is ($acl->show, $expected, ' and show returns correctly');
is ($acl->check ($user2), 1, ' and checking the good entry still works');
is (scalar ($acl->check_errors), "malformed krb5 ACL\n",
    ' but now with the right error');
my @errors = $acl->check_errors;
is (scalar (@errors), 1, ' and the error return is right in list context');
is ($errors[0], 'malformed krb5 ACL', ' with the same text');
is ($acl->check (''), undef, 'Checking with an empty principal fails');
is ($acl->error, 'no principal specified', ' with the right error');
if ($acl->remove ('krb5', $user2, @trace)) {
    ok (1, 'Removing the second user works');
} else {
    is ($acl->error, '', 'Removing the second user works');
}
is ($acl->check ($user2), 0, ' and now the second user check fails');
is (scalar ($acl->check_errors), "malformed krb5 ACL\n",
    ' with the right error');
if ($acl->remove ('krb5', '', @trace)) {
    ok (1, 'Removing the bad entry works');
} else {
    is ($acl->error, '', 'Removing the bad entry works');
}
@entries = $acl->list;
is (scalar (@entries), 0, ' and now there are no entries');
is ($acl->show, "Members of ACL example (id: 2) are:\n", ' and show concurs');
is ($acl->check ($user2), 0, ' and the second user check fails');
is (scalar ($acl->check_errors), '', ' with no error message');

# Test history.
my $date = strftime ('%Y-%m-%d %H:%M:%S', localtime $trace[2]);
my $history = <<"EOO";
$date  create
    by $admin from $host
$date  add krb5 $user1
    by $admin from $host
$date  add krb5 $user2
    by $admin from $host
$date  remove krb5 $user1
    by $admin from $host
$date  add krb5 
    by $admin from $host
$date  remove krb5 $user2
    by $admin from $host
$date  remove krb5 
    by $admin from $host
EOO
is ($acl->history, $history, 'History is correct');

# Test destroy.
if ($acl->destroy (@trace)) {
    ok (1, 'Destroying the ACL works');
} else {
    is ($acl->error, '', 'Destroying the ACL works');
}
$acl = eval { Wallet::ACL->new ('example', $schema) };
ok (!defined ($acl), ' and now cannot be found');
is ($@, "ACL example not found\n", ' with the right error message');
$acl = eval { Wallet::ACL->new (2, $schema) };
ok (!defined ($acl), ' or by ID');
is ($@, "ACL 2 not found\n", ' with the right error message');
$acl = eval { Wallet::ACL->create ('example', $schema, @trace) };
ok (defined ($acl), ' and creating another with the same name works');
is ($@, '', ' with no exceptions');
is ($acl->name, 'example', ' and the right name');
is ($acl->id, 3, ' and a new ID');

# Clean up.
$setup->destroy;
unlink 'wallet-db';
