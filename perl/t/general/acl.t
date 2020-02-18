#!/usr/bin/perl
#
# Tests for the wallet ACL API.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2007-2008, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# SPDX-License-Identifier: MIT

use strict;
use warnings;

use POSIX qw(strftime);
use Test::More tests => 122;

use Wallet::ACL;
use Wallet::Admin;
use Wallet::Config;
use Wallet::Object::Base;

use lib 't/lib';
use Util;

# Some global defaults to use.
my $admin = 'admin@EXAMPLE.COM';
my $user1 = 'alice@EXAMPLE.COM';
my $user2 = 'bob@EXAMPLE.COM';
my $host = 'localhost';
my @trace = ($admin, $host, time);
my $TZ = DateTime::TimeZone->new( name => 'local' );

# Use Wallet::Admin to set up the database. This setup destroys the
# database, so we turn off version checking during the initial setup since
# we are ging to be destroying the tables anyway. This avoids some
# unpleasant unversioned schema errors.
# DBIx::Class::Schema::Versioned::_on_connect(): Your DB is currently unversioned.
db_setup;
my $setup = setup_initialize();
is ($@, '', 'Database connection succeeded');
is ($setup->reinitialize ($admin), 1, 'Database initialization succeeded');
my $schema = $setup->schema;

# #### ## #### ## #### ## #### ## #### ## #### ## #### ## #### #

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
ok (!defined ($acl), 'Creating a duplicate acl');
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
Members of ACL test (id: 2) are:
  krb5 $user1
  krb5 $user2
EOE
is ($acl->show, $expected, ' and show returns correctly');
ok (! $acl->remove ('krb5', $admin, @trace),
    'Removing a nonexistent entry fails');
is ($acl->error, "cannot remove krb5:$admin from test: entry not found in ACL",
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
like ($acl->error, qr/^cannot add \Qkrb5:$user2\E to test: /,
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
Members of ACL test (id: 2) are:
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
is ($acl->show, "Members of ACL test (id: 2) are:\n", ' and show concurs');
is ($acl->check ($user2), 0, ' and the second user check fails');
is (scalar ($acl->check_errors), '', ' with no error message');

# Test nesting.
my $acl_nest = eval { Wallet::ACL->create ('test-nesting', $schema, @trace) };
ok (defined ($acl_nest), 'ACL creation for setting up nested');
if ($acl_nest->add ('nested', 'test', @trace)) {
    ok (1, ' and adding the nesting');
} else {
    is ($acl_nest->error, '', ' and adding the nesting');
}

# Test rename. Rename
if ($acl->rename ('example', @trace)) {
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
ok (! $acl->rename ('ADMIN', @trace),
    ' but renaming to an existing name fails');
like ($acl->error, qr/^cannot rename ACL example to ADMIN: /,
      ' with the right error');
@entries = $acl_nest->list;
is ($entries[0][1], 'example', ' and the name in a nested ACL updated');

# Test history.
my $date = DateTime->from_epoch(epoch => $trace[2], time_zone => $TZ)->strftime('%Y-%m-%d %H:%M:%S');
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
$date  rename from test
    by $admin from $host
EOO
is ($acl->history, $history, 'History is correct');

# Test destroy.
$acl->destroy (@trace);
is ($acl->error, 'cannot destroy ACL example: ACL is nested in ACL test-nesting',
    'Destroying a nested ACL fails');
if ($acl_nest->remove ('nested', 'example', @trace)) {
    ok (1, ' and removing the nesting succeeds');
} else {
    is ($acl_nest->error, '', 'and removing the nesting succeeds');
}
if ($acl->destroy (@trace)) {
    ok (1, ' and now destroying the ACL works');
} else {
    is ($acl->error, '', ' and now destroying the ACL works');
}
$acl = eval { Wallet::ACL->new ('example', $schema) };
ok (!defined ($acl), ' and now cannot be found');
is ($@, "ACL example not found\n", ' with the right error message');
$acl = eval { Wallet::ACL->new (2, $schema) };
ok (!defined ($acl), ' or by ID');
is ($@, "ACL 2 not found\n", ' with the right error message');
@entries = $acl_nest->list;
is (scalar (@entries), 0, ' and it is no longer a nested entry');
$acl = eval { Wallet::ACL->create ('example', $schema, @trace) };
ok (defined ($acl), ' and creating another with the same name works');
is ($@, '', ' with no exceptions');
is ($acl->name, 'example', ' and the right name');
# Keep in mind that when testing against MySQL failed inserts use up auto-incremented
# primary keys. Thus, the id for this acl in MySQL will be larger than in
# SQLite. Thuse we allow this id to be wither 4 or 5.
like ($acl->id, qr{\A[45]\z}, ' and an ID of 4 or 5');

# Test replace. by creating three acls, then assigning two objects to the
# first, one to the second, and another to the third.  Then replace the first
# acl with the second, so that we can verify that multiple objects are moved,
# that an object already belonging to the new acl is okay, and that the
# objects with unrelated ACL are unaffected.
my ($acl_old, $acl_new, $acl_other, $obj_old_one, $obj_old_two, $obj_new,
    $obj_unrelated);
eval {
    $acl_old   = Wallet::ACL->create ('example-old', $schema, @trace);
    $acl_new   = Wallet::ACL->create ('example-new', $schema, @trace);
    $acl_other = Wallet::ACL->create ('example-other', $schema, @trace);
};
is ($@, '', 'ACLs needed for testing replace are created');
eval {
    $obj_old_one   = Wallet::Object::Base->create ('keytab',
                                                   'service/test1@EXAMPLE.COM',
                                                   $schema, @trace);
    $obj_old_two   = Wallet::Object::Base->create ('keytab',
                                                   'service/test2@EXAMPLE.COM',
                                                   $schema, @trace);
    $obj_new       = Wallet::Object::Base->create ('keytab',
                                                   'service/test3@EXAMPLE.COM',
                                                   $schema, @trace);
    $obj_unrelated = Wallet::Object::Base->create ('keytab',
                                                   'service/test4@EXAMPLE.COM',
                                                   $schema, @trace);
};
is ($@, '', ' and so were needed objects');
if ($obj_old_one->owner ('example-old', @trace)
    && $obj_old_two->owner ('example-old', @trace)
    && $obj_new->owner ('example-new', @trace)
    && $obj_unrelated->owner ('example-other', @trace)) {

    ok (1, ' and setting initial ownership on the objects succeeds');
}
is ($acl_old->replace('example-new', @trace), 1,
    ' and replace ran successfully');
eval {
    $obj_old_one   = Wallet::Object::Base->new ('keytab',
                                                'service/test1@EXAMPLE.COM',
                                                $schema);
    $obj_old_two   = Wallet::Object::Base->new ('keytab',
                                                'service/test2@EXAMPLE.COM',
                                                $schema);
    $obj_new       = Wallet::Object::Base->new ('keytab',
                                                'service/test3@EXAMPLE.COM',
                                                $schema);
    $obj_unrelated = Wallet::Object::Base->new ('keytab',
                                                'service/test4@EXAMPLE.COM',
                                                $schema);
};
is ($obj_old_one->owner, 'example-new', ' and first replace is correct');
is ($obj_old_two->owner, 'example-new', ' and second replace is correct');
is ($obj_new->owner, 'example-new',
    ' and object already with new acl is correct');
is ($obj_unrelated->owner, 'example-other',
    ' and unrelated object ownership is correct');

# Test ACL comments.
my $comment;
$acl = eval { Wallet::ACL->create ('test-comment', $schema, @trace) };
ok (defined ($acl), 'ACL creation for setting up comment');
if (!defined($acl->comment)) {
    ok (1, ' new ACL has no comment defined');
} else {
    is ($acl->error, undef, ' new ACL has no comment defined');
}
$comment = 'this is an ACL comment';
if ($acl->set_comment($comment)) {
    ok (1, ' added ACL comment');
} else {
    is ($acl->error, 1, ' added ACL comment');
}
ok (($acl->comment() eq $comment), ' store ACL comment correctly');
$comment = q{};
if ($acl->set_comment($comment)) {
    ok (1, ' added ACL comment');
} else {
    is ($acl->error, 1, ' added ACL comment');
}
ok (!defined($acl->comment()), ' stored empty ACL comment correctly');

# Test a long comment; should raise an exception.
$comment = '0' x 259 ;
eval { ($acl->set_comment($comment)) } ;
is ($acl->error, 'comment cannot be longer than 255 characters');

$acl->destroy (@trace);

# Clean up.
$setup->destroy;
END {
    unlink 'wallet-db';
}
