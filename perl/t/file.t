#!/usr/bin/perl -w
#
# Tests for the file object implementation.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2008 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

use POSIX qw(strftime);
use Test::More tests => 56;

use Wallet::Admin;
use Wallet::Config;
use Wallet::Object::File;

use lib 't/lib';
use Util;

# Some global defaults to use.
my $user = 'admin@EXAMPLE.COM';
my $host = 'localhost';
my @trace = ($user, $host, time);

# Flush all output immediately.
$| = 1;

# Use Wallet::Admin to set up the database.
system ('rm -rf test-files') == 0 or die "cannot remove test-files\n";
db_setup;
my $admin = eval { Wallet::Admin->new };
is ($@, '', 'Database connection succeeded');
is ($admin->reinitialize ($user), 1, 'Database initialization succeeded');
my $dbh = $admin->dbh;

# Use this to accumulate the history traces so that we can check history.
my $history = '';
my $date = strftime ('%Y-%m-%d %H:%M:%S', localtime $trace[2]);

# Test error handling in the absence of configuration.
$object = eval {
    Wallet::Object::File->create ('file', 'test', $dbh, @trace)
  };
ok (defined ($object), 'Creating a basic file object succeeds');
ok ($object->isa ('Wallet::Object::File'), ' and is the right class');
is ($object->get (@trace), undef, ' and get fails');
is ($object->error, 'file support not configured', ' with the right error');
is ($object->store (@trace), undef, ' and store fails');
is ($object->error, 'file support not configured', ' with the right error');
is ($object->destroy (@trace), 1, ' but destroy succeeds');

# Set up our configuration.
mkdir 'test-files' or die "cannot create test-files: $!\n";
$Wallet::Config::FILE_BUCKET = 'test-files';

# Okay, now we can test.  First, the basic object without store.
$object = eval {
    Wallet::Object::File->create ('file', 'test', $dbh, @trace)
  };
ok (defined ($object), 'Creating a basic file object succeeds');
ok ($object->isa ('Wallet::Object::File'), ' and is the right class');
is ($object->get (@trace), undef, ' and get fails');
is ($object->error, 'cannot get file:test: object has not been stored',
    ' with the right error');
is ($object->destroy (@trace), 1, ' but destroying the object succeeds');

# Now store something and be sure that we get something reasonable.
$object = eval {
    Wallet::Object::File->create ('file', 'test', $dbh, @trace)
  };
ok (defined ($object), 'Recreating the object succeeds');
is ($object->store ("foo\n", @trace), 1, ' and storing data in it succeeds');
ok (-d 'test-files/09', ' and the hash bucket was created');
ok (-f 'test-files/09/test', ' and the file exists');
is (contents ('test-files/09/test'), 'foo', ' with the right contents');
is ($object->get (@trace), "foo\n", ' and get returns correctly');
unlink 'test-files/09/test';
is ($object->get (@trace), undef, ' and get fails if we delete it');
is ($object->error, 'cannot get file:test: object has not been stored',
    ' as if it had not been stored');
is ($object->store ("bar\n\0baz\n", @trace), 1, ' but storing again works');
ok (-f 'test-files/09/test', ' and the file exists');
is (contents ('test-files/09/test'), 'bar', ' with the right contents');
is ($object->get (@trace), "bar\n\0baz\n", ' and get returns correctly');

# Try exceeding the store size.
$Wallet::Config::FILE_MAX_SIZE = 1024;
is ($object->store ('x' x 1024, @trace), 1,
    ' and storing exactly 1024 characters works');
is ($object->get (@trace), 'x' x 1024, ' and get returns the right thing');
is ($object->store ('x' x 1025, @trace), undef,
    ' but storing 1025 characters fails');
is ($object->error, 'data exceeds maximum of 1024 bytes',
    ' with the right error');

# Try storing the empty data object.
is ($object->store ('', @trace), 1, 'Storing the empty object works');
is ($object->get (@trace), '', ' and get returns the right thing');

# Test destruction.
is ($object->destroy (@trace), 1, 'Destroying the object works');
ok (! -f 'test-files/09/test', ' and the file is gone');

# Now try some aggressive names.
$object = eval {
    Wallet::Object::File->create ('file', '../foo', $dbh, @trace)
  };
ok (defined ($object), 'Creating ../foo succeeds');
is ($object->store ("foo\n", @trace), 1, ' and storing data in it succeeds');
ok (-d 'test-files/39', ' and the hash bucket was created');
ok (-f 'test-files/39/%2E%2E%2Ffoo', ' and the file exists');
is (contents ('test-files/39/%2E%2E%2Ffoo'), 'foo',
    ' with the right contents');
is ($object->get (@trace), "foo\n", ' and get returns correctly');
is ($object->destroy (@trace), 1, 'Destroying the object works');
ok (! -f 'test-files/39/%2E%2E%2Ffoo', ' and the file is gone');
$object = eval {
    Wallet::Object::File->create ('file', "\0", $dbh, @trace)
  };
ok (defined ($object), 'Creating nul succeeds');
is ($object->store ("foo\n", @trace), 1, ' and storing data in it succeeds');
ok (-d 'test-files/93', ' and the hash bucket was created');
ok (-f 'test-files/93/%00', ' and the file exists');
is (contents ('test-files/93/%00'), 'foo',
    ' with the right contents');
is ($object->get (@trace), "foo\n", ' and get returns correctly');
is ($object->destroy (@trace), 1, 'Destroying the object works');
ok (! -f 'test-files/93/%00', ' and the file is gone');

# Test error handling in the file store.
system ('rm -r test-files') == 0 or die "cannot remove test-files\n";
$object = eval {
    Wallet::Object::File->create ('file', 'test', $dbh, @trace)
  };
ok (defined ($object), 'Recreating the object succeeds');
is ($object->store ("foo\n", @trace), undef,
    ' and storing data in it fails');
like ($object->error, qr/^cannot create file bucket 09: /,
      ' with the right error');
is ($object->get (@trace), undef, ' and get fails');
like ($object->error, qr/^cannot create file bucket 09: /,
      ' with the right error');
is ($object->destroy (@trace), 1, ' but destroying the object succeeds');

# Clean up.
$admin->destroy;
unlink ('wallet-db');
