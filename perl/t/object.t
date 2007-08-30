#!/usr/bin/perl -w
# $Id$
#
# t/object.t -- Tests for the basic object implementation.

use Test::More tests => 51;

use DBD::SQLite;
use Wallet::Config;
use Wallet::Object::Base;
use Wallet::Server;

# Use a local SQLite database for testing.
$Wallet::Config::DB_DRIVER = 'SQLite';
$Wallet::Config::DB_INFO = 'wallet-db';

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
my $repeat =
    eval { Wallet::Object::Base->create ('keytab', $princ, $dbh, @trace) };
like ($@, qr/^cannot create object \Qkeytab:$princ: /, 'Repeating fails');
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
     Created by: $user
   Created from: $host
     Created on: $created
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
