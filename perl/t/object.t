#!/usr/bin/perl -w
# $Id$
#
# t/object.t -- Tests for the basic object implementation.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

use POSIX qw(strftime);
use Test::More tests => 131;

use Wallet::ACL;
use Wallet::Config;
use Wallet::Object::Base;
use Wallet::Server;

use lib 't/lib';
use Util;

# Some global defaults to use.
my $user = 'admin@EXAMPLE.COM';
my $host = 'localhost';
my @trace = ($user, $host, time);
my $princ = 'service/test@EXAMPLE.COM';

# Use Wallet::Server to set up the database.
db_setup;
my $server = eval { Wallet::Server->reinitialize ($user) };
is ($@, '', 'Database initialization did not die');
ok ($server->isa ('Wallet::Server'), ' and returned the right class');
my $dbh = $server->dbh;

# Okay, now we have a database.  Test create and new.  We make believe this is
# a keytab object; it won't matter for what we're doing.
my $object = eval {
    Wallet::Object::Base->create ('keytab', $princ, $dbh, @trace)
  };
is ($@, '', 'Object creation did not die');
ok ($object->isa ('Wallet::Object::Base'), ' and returned the right class');
my $other = eval {
    Wallet::Object::Base->create ('keytab', $princ, $dbh, @trace)
  };
like ($@, qr/^cannot create object \Qkeytab:$princ: /, 'Repeating fails');
$other = eval { Wallet::Object::Base->create ('', $princ, $dbh, @trace) };
is ($@, "invalid object type\n", 'Using an empty type fails');
$other = eval { Wallet::Object::Base->create ('keytab', '', $dbh, @trace) };
is ($@, "invalid object name\n", ' as does an empty name');
$object = eval { Wallet::Object::Base->new ('keytab', "a$princ", $dbh) };
is ($@, "cannot find keytab:a$princ\n", 'Searching for unknown object fails');
$object = eval { Wallet::Object::Base->new ('keytab', $princ, $dbh) };
is ($@, '', 'Object new did not die');
ok ($object->isa ('Wallet::Object::Base'), ' and returned the right class');

# Simple accessor tests.
is ($object->type, 'keytab', 'Type accessor works');
is ($object->name, $princ, 'Name accessor works');

# We'll use this for later tests.
my $acl = Wallet::ACL->new ('ADMIN', $dbh);

# Owner.
is ($object->owner, undef, 'Owner is not set to start');
if ($object->owner ('ADMIN', @trace)) {
    ok (1, ' and setting it to ADMIN works');
} else {
    is ($object->error, '', ' and setting it to ADMIN works');
}
is ($object->owner, $acl->id, ' at which point it is ADMIN');
ok (! $object->owner ('unknown', @trace),
    ' but setting it to something bogus fails');
is ($object->error, 'ACL unknown not found', ' with the right error');
if ($object->owner ('', @trace)) {
    ok (1, ' and clearing it works');
} else {
    is ($object->error, '', ' and clearing it works');
}
is ($object->owner, undef, ' at which point it is cleared');
is ($object->owner ('ADMIN', @trace), 1, ' and setting it again works');

# Expires.
is ($object->expires, undef, 'Expires is not set to start');
my $now = time;
if ($object->expires ($now, @trace)) {
    ok (1, ' and setting it works');
} else {
    is ($object->error, '', ' and setting it works');
}
is ($object->expires, $now, ' at which point it matches');
ok (! $object->expires ('13/13/13 13:13:13', @trace),
    ' but setting it to something bogus fails');
is ($object->error, 'malformed expiration time 13/13/13 13:13:13',
    ' with the right error');
if ($object->expires ('', @trace)) {
    ok (1, ' and clearing it works');
} else {
    is ($object->error, '', ' and clearing it works');
}
is ($object->expires, undef, ' at which point it is cleared');
is ($object->expires ($now, @trace), 1, ' and setting it again works');

# ACLs.
for my $type (qw/get store show destroy flags/) {
    is ($object->acl ($type), undef, "ACL $type is not set to start");
    if ($object->acl ($type, $acl->id, @trace)) {
        ok (1, ' and setting it to ADMIN (numeric) works');
    } else {
        is ($object->error, '', ' and setting it to ADMIN (numeric) works');
    }
    is ($object->acl ($type), $acl->id, ' at which point it is ADMIN');
    ok (! $object->acl ($type, 22, @trace),
        ' but setting it to something bogus fails');
    is ($object->error, 'ACL 22 not found', ' with the right error');
    if ($object->acl ($type, '', @trace)) {
        ok (1, ' and clearing it works');
    } else {
        is ($object->error, '', ' and clearing it works');
    }
    is ($object->acl ($type), undef, ' at which point it is cleared');
    is ($object->acl ($type, $acl->id, @trace), 1,
        ' and setting it again works');
}

# Flags.
my @flags = $object->flag_list;
is (scalar (@flags), 0, 'No flags set to start');
is ($object->flag_check ('locked'), 0, ' and locked is not set');
is ($object->flag_set ('locked', @trace), 1, ' and setting locked works');
is ($object->flag_check ('locked'), 1, ' and now locked is set');
@flags = $object->flag_list;
is (scalar (@flags), 1, ' and there is one flag');
is ($flags[0], 'locked', ' which is locked');
is ($object->flag_set ('locked', @trace), undef, 'Setting locked again fails');
is ($object->error,
    "cannot set flag locked on keytab:$princ: flag already set",
    ' with the right error');
is ($object->flag_set ('unchanging', @trace), 1,
    ' but setting unchanging works');
is ($object->flag_check ('unchanging'), 1, ' and unchanging is now set');
@flags = $object->flag_list;
is (scalar (@flags), 2, ' and there are two flags');
is ($flags[0], 'locked', ' which are locked');
is ($flags[1], 'unchanging', ' and unchanging');
is ($object->flag_clear ('locked', @trace), 1, 'Clearing locked works');
is ($object->flag_check ('locked'), 0, ' and now it is not set');
is ($object->flag_check ('unchanging'), 1, ' but unchanging still is');
is ($object->flag_clear ('locked', @trace), undef,
    ' and clearing it again fails');
is ($object->error,
    "cannot clear flag locked on keytab:$princ: flag not set",
    ' with the right error');
if ($object->flag_set ('locked', @trace)) {
    ok (1, ' and setting it again works');
} else {
    is ($object->error, '', ' and setting it again works');
}

# Attributes.  Very boring.
is ($object->attr ('foo'), undef, 'Retrieving an attribute fails');
is ($object->error, 'unknown attribute foo', ' with the right error');
is ($object->attr ('foo', [ 'foo' ], @trace), undef, ' and setting fails');
is ($object->error, 'unknown attribute foo', ' with the right error');

# Test stub methods and locked status.
is ($object->store ("Some data", @trace), undef, 'Store fails');
is ($object->error, "cannot store keytab:${princ}: object is locked",
    ' because the object is locked');
is ($object->owner ('', @trace), undef, ' and setting owner fails');
is ($object->error, "cannot modify keytab:${princ}: object is locked",
    ' for the same reason');
is ($object->owner, 1, ' but retrieving the owner works');
is ($object->expires ('', @trace), undef, ' and setting expires fails');
is ($object->error, "cannot modify keytab:${princ}: object is locked",
    ' for the same reason');
is ($object->expires, $now, ' but retrieving expires works');
for my $acl (qw/get store show destroy flags/) {
    is ($object->acl ($acl, '', @trace), undef, " and setting $acl ACL fails");
    is ($object->error, "cannot modify keytab:${princ}: object is locked",
        ' for the same reason');
    is ($object->acl ($acl), 1, " but retrieving $acl ACL works");
}
is ($object->flag_check ('locked'), 1, ' and checking flags works');
@flags = $object->flag_list;
is (scalar (@flags), 2, ' and listing flags works');
is ("@flags", 'locked unchanging', ' and returns the right data');
is ($object->flag_clear ('locked', @trace), 1, 'Clearing locked succeeds');
eval { $object->get (@trace) };
is ($@, "Do not instantiate Wallet::Object::Base directly\n",
    'Get fails with the right error');
ok (! $object->store ("Some data", @trace), 'Store fails');
is ($object->error, "cannot store keytab:$princ: object type is immutable",
    ' with the right error');

# Test show.
my $output = <<"EOO";
           Type: keytab
           Name: $princ
          Owner: ADMIN
        Get ACL: ADMIN
      Store ACL: ADMIN
       Show ACL: ADMIN
    Destroy ACL: ADMIN
      Flags ACL: ADMIN
        Expires: $now
          Flags: unchanging
     Created by: $user
   Created from: $host
     Created on: $trace[2]

Members of ACL ADMIN (id: 1) are:
  krb5 $user
EOO
is ($object->show, $output, 'Show output is correct');
is ($object->flag_set ('locked', @trace), 1, ' and setting locked works');
$output = <<"EOO";
           Type: keytab
           Name: $princ
          Owner: ADMIN
        Get ACL: ADMIN
      Store ACL: ADMIN
       Show ACL: ADMIN
    Destroy ACL: ADMIN
      Flags ACL: ADMIN
        Expires: $now
          Flags: locked unchanging
     Created by: $user
   Created from: $host
     Created on: $trace[2]

Members of ACL ADMIN (id: 1) are:
  krb5 $user
EOO
is ($object->show, $output, ' and show still works and is correct');

# Test destroy.
is ($object->destroy (@trace), undef, 'Destroy fails');
is ($object->error, "cannot destroy keytab:${princ}: object is locked",
    ' because of the locked status');
is ($object->flag_clear ('locked', @trace), 1,
    ' and clearing locked status works');
if ($object->destroy (@trace)) {
    ok (1, 'Destroy is successful');
} else {
    is ($object->error, '', 'Destroy is successful');
}
$object = eval { Wallet::Object::Base->new ('keytab', $princ, $dbh) };
is ($@, "cannot find keytab:$princ\n", ' and object is all gone');

# Test history.
$object = eval {
    Wallet::Object::Base->create ('keytab', $princ, $dbh, @trace)
  };
ok (defined ($object), 'Recreating the object succeeds');
my $date = strftime ('%Y-%m-%d %H:%M:%S', localtime $trace[2]);
$output = <<"EOO";
$date  create
    by $user from $host
$date  set owner to 1
    by $user from $host
$date  unset owner (was 1)
    by $user from $host
$date  set owner to 1
    by $user from $host
$date  set expires to $now
    by $user from $host
$date  unset expires (was $now)
    by $user from $host
$date  set expires to $now
    by $user from $host
$date  set acl_get to 1
    by $user from $host
$date  unset acl_get (was 1)
    by $user from $host
$date  set acl_get to 1
    by $user from $host
$date  set acl_store to 1
    by $user from $host
$date  unset acl_store (was 1)
    by $user from $host
$date  set acl_store to 1
    by $user from $host
$date  set acl_show to 1
    by $user from $host
$date  unset acl_show (was 1)
    by $user from $host
$date  set acl_show to 1
    by $user from $host
$date  set acl_destroy to 1
    by $user from $host
$date  unset acl_destroy (was 1)
    by $user from $host
$date  set acl_destroy to 1
    by $user from $host
$date  set acl_flags to 1
    by $user from $host
$date  unset acl_flags (was 1)
    by $user from $host
$date  set acl_flags to 1
    by $user from $host
$date  set flag locked
    by $user from $host
$date  set flag unchanging
    by $user from $host
$date  clear flag locked
    by $user from $host
$date  set flag locked
    by $user from $host
$date  clear flag locked
    by $user from $host
$date  set flag locked
    by $user from $host
$date  clear flag locked
    by $user from $host
$date  destroy
    by $user from $host
$date  create
    by $user from $host
EOO
is ($object->history, $output, ' and the history is correct');

# Clean up.
my $schema = Wallet::Schema->new;
$schema->drop ($dbh);
unlink 'wallet-db';
