#!/usr/bin/perl
#
# Tests for the password object implementation.  Only includes tests that are
# basic or different from the file object implementation.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2015
#     The Board of Trustees of the Leland Stanford Junior University
#
# SPDX-License-Identifier: MIT

use strict;
use warnings;

use POSIX qw(strftime);
use Test::More tests => 33;

use Wallet::Admin;
use Wallet::Config;
use Wallet::Object::Password;

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
my $admin = setup_initialize();
is ($@, '', 'Database connection succeeded');
is ($admin->reinitialize ($user), 1, 'Database initialization succeeded');
my $schema = $admin->schema;

# Use this to accumulate the history traces so that we can check history.
my $history = '';
my $date = strftime ('%Y-%m-%d %H:%M:%S', localtime $trace[2]);

$Wallet::Config::PWD_FILE_BUCKET = undef;

# Test error handling in the absence of configuration.
my $object = eval {
    Wallet::Object::Password->create ('password', 'test', $schema, @trace)
  };
ok (defined ($object), 'Creating a basic password object succeeds');
ok ($object->isa ('Wallet::Object::Password'), ' and is the right class');
is ($object->get (@trace), undef, ' and get fails');
is ($object->error, 'password support not configured',
    ' with the right error');
is ($object->store (@trace), undef, ' and store fails');
is ($object->error, 'password support not configured',
    ' with the right error');
is ($object->destroy (@trace), 1, ' but destroy succeeds');

# Set up our configuration.
mkdir 'test-files' or die "cannot create test-files: $!\n";
$Wallet::Config::PWD_FILE_BUCKET = 'test-files';
$Wallet::Config::PWD_LENGTH_MIN = 10;
$Wallet::Config::PWD_LENGTH_MAX = 10;

# Okay, now we can test.  First, the basic object without store.
$object = eval {
    Wallet::Object::Password->create ('password', 'test', $schema, @trace)
  };
ok (defined ($object), 'Creating a basic password object succeeds');
ok ($object->isa ('Wallet::Object::Password'), ' and is the right class');
my $pwd = $object->get (@trace);
like ($pwd, qr{^.{$Wallet::Config::PWD_LENGTH_MIN}$},
      ' and get creates a random password string of the right length');
ok (-d 'test-files/09', ' and the hash bucket was created');
ok (-f 'test-files/09/test', ' and the file exists');
is (contents ('test-files/09/test'), $pwd, ' with the right contents');
my $pwd2 = $object->get (@trace);
is ($pwd, $pwd2, ' and getting again gives the same string');
is ($object->destroy (@trace), 1, ' and destroying the object succeeds');

# Now check to see if the password length is adjusted.
$Wallet::Config::PWD_LENGTH_MIN = 20;
$Wallet::Config::PWD_LENGTH_MAX = 20;
$object = eval {
    Wallet::Object::Password->create ('password', 'test', $schema, @trace)
  };
ok (defined ($object), 'Recreating the object succeeds');
$pwd = $object->get (@trace);
like ($pwd, qr{^.{$Wallet::Config::PWD_LENGTH_MIN}$},
      ' and get creates a random password string of a longer length');
is ($object->destroy (@trace), 1, ' and destroying the object succeeds');

# Now store something and be sure that we get something reasonable.
$object = eval {
    Wallet::Object::Password->create ('password', 'test', $schema, @trace)
  };
ok (defined ($object), 'Recreating the object succeeds');
is ($object->store ("foo\n", @trace), 1, ' and storing data in it succeeds');
ok (-f 'test-files/09/test', ' and the file exists');
is (contents ('test-files/09/test'), 'foo', ' with the right contents');
is ($object->get (@trace), "foo\n", ' and get returns correctly');
unlink 'test-files/09/test';
is ($object->get (@trace), undef,
    ' and get will not autocreate a password if there used to be data');
is ($object->error, 'cannot get password:test: object has not been stored',
    ' as if it had not been stored');
is ($object->store ("bar\n\0baz\n", @trace), 1, ' but storing again works');
ok (-f 'test-files/09/test', ' and the file exists');
is (contents ('test-files/09/test'), 'bar', ' with the right contents');
is ($object->get (@trace), "bar\n\0baz\n", ' and get returns correctly');

# And check to make sure update changes the contents.
$pwd = $object->update (@trace);
isnt ($pwd, "bar\n\0baz\n", 'Update changes the contents');
like ($pwd, qr{^.{$Wallet::Config::PWD_LENGTH_MIN}$},
      ' to a random password string of the right length');

# Clean up.
$admin->destroy;
END {
    system ('rm -r test-files') == 0 or die "cannot remove test-files\n";
    unlink ('wallet-db');
}
