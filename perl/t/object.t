#!/usr/bin/perl -w
# $Id$
#
# t/object.t -- Tests for the basic object implementation.

use Test::More tests => 93;

use Wallet::ACL;
use Wallet::Config;
use Wallet::Object::Base;
use Wallet::Server;

# Use a local SQLite database for testing.
$Wallet::Config::DB_DRIVER = 'SQLite';
$Wallet::Config::DB_INFO = 'wallet-db';
unlink 'wallet-db';

# Some global defaults to use.
my $user = 'admin@EXAMPLE.COM';
my $host = 'localhost';
my @trace = ($user, $host);
my $princ = 'service/test@EXAMPLE.COM';

# Use Wallet::Server to set up the database.
my $server = eval { Wallet::Server->initialize ($user) };
is ($@, '', 'Database initialization did not die');
ok ($server->isa ('Wallet::Server'), ' and returned the right class');
my $dbh = $server->dbh;

# Okay, now we have a database.  Test create and new.  We make believe this is
# a keytab object; it won't matter for what we're doing.
my $created = time;
my $object = eval { Wallet::Object::Base->create ('keytab', $princ, $dbh,
                                                  @trace, $created) };
is ($@, '', 'Object creation did not die');
ok ($object->isa ('Wallet::Object::Base'), ' and returned the right class');
my $other =
    eval { Wallet::Object::Base->create ('keytab', $princ, $dbh, @trace) };
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

# Test stub methods.
eval { $object->get };
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
          Flags: locked unchanging
     Created by: $user
   Created from: $host
     Created on: $created

Members of ACL ADMIN (id: 1) are:
  krb5 $user
EOO
is ($object->show, $output, 'Show output is correct');

# Test destroy.
if ($object->destroy (@trace)) {
    ok (1, 'Destroy is successful');
} else {
    is ($object->error, '', 'Destroy is successful');
}
$object = eval { Wallet::Object::Base->new ('keytab', $princ, $dbh) };
is ($@, "cannot find keytab:$princ\n", ' and object is all gone');

# Clean up.
unlink 'wallet-db';
