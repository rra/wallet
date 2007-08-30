#!/usr/bin/perl -w
# $Id$
#
# t/api.t -- Tests for the wallet ACL API.

use Test::More tests => 41;

use DBD::SQLite;
use Wallet::ACL;
use Wallet::Config;
use Wallet::Server;

# Use a local SQLite database for testing.
$Wallet::Config::DB_DRIVER = 'SQLite';
$Wallet::Config::DB_INFO = 'wallet-db';

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
my $dbh = $server->dbh;

# Test create and new.
my $acl = eval { Wallet::ACL->create ('test', $dbh, @trace) };
ok (defined ($acl), 'ACL creation');
is ($@, '', ' with no exceptions');
ok ($acl->isa ('Wallet::ACL'), ' and the right class');
is ($acl->name, 'test', ' and the right name');
is ($acl->id, 2, ' and the right ID');
$acl = eval { Wallet::ACL->create (3, $dbh, @trace) };
ok (!defined ($acl), 'Creating with a numeric name');
is ($@, "ACL name may not be all numbers\n", ' with the right error message');
$acl = eval { Wallet::ACL->create ('test', $dbh, @trace) };
ok (!defined ($acl), 'Creating a duplicate object');
like ($@, qr/^cannot create ACL test: /, ' with the right error message');
$acl = eval { Wallet::ACL->new ('test2', $dbh) };
ok (!defined ($acl), 'Searching for a non-existent ACL');
is ($@, "ACL test2 not found\n", ' with the right error message');
$acl = eval { Wallet::ACL->new ('test', $dbh) };
ok (defined ($acl), 'Searching for the test ACL by name');
is ($@, '', ' with no exceptions');
ok ($acl->isa ('Wallet::ACL'), ' and the right class');
is ($acl->id, 2, ' and the right ID');
$acl = eval { Wallet::ACL->new (2, $dbh) };
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
$acl = eval { Wallet::ACL->new ('test', $dbh) };
ok (!defined ($acl), ' and it cannot be found under the old name');
is ($@, "ACL test not found\n", ' with the right error message');
$acl = eval { Wallet::ACL->new ('example', $dbh) };
ok (defined ($acl), ' and it can be found with the new name');
is ($@, '', ' with no exceptions');
is ($acl->name, 'example', ' and the right name');
is ($acl->id, 2, ' and the right ID');

# Test add, check, remove, and list.
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

# Clean up.
unlink 'wallet-db';
