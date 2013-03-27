#!/usr/bin/perl
#
# Tests for the WebAuth keyring object implementation.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use POSIX qw(strftime);
use Test::More tests => 68;
use WebAuth 3.06 qw(WA_KEY_AES WA_AES_128);
use WebAuth::Key 1.01 ();
use WebAuth::Keyring 1.02 ();

BEGIN {
    use_ok('Wallet::Admin');
    use_ok('Wallet::Config');
    use_ok('Wallet::Object::WAKeyring');
}

use lib 't/lib';
use Util;

# Some global defaults to use.
my $user = 'admin@EXAMPLE.COM';
my $host = 'localhost';
my @trace = ($user, $host, time);

# Flush all output immediately.
$| = 1;

# Use Wallet::Admin to set up the database.
system ('rm -rf test-keyrings') == 0 or die "cannot remove test-keyrings\n";
db_setup;
my $admin = eval { Wallet::Admin->new };
is ($@, '', 'Database connection succeeded');
is ($admin->reinitialize ($user), 1, 'Database initialization succeeded');
my $schema = $admin->schema;

# Create a WebAuth context to use.
my $wa = WebAuth->new;

# Test error handling in the absence of configuration.
my $object = eval {
    Wallet::Object::WAKeyring->create ('wa-keyring', 'test', $schema, @trace)
  };
ok (defined ($object), 'Creating a basic WebAuth keyring object succeeds');
ok ($object->isa ('Wallet::Object::WAKeyring'), ' and is the right class');
is ($object->get (@trace), undef, ' and get fails');
is ($object->error, 'WebAuth keyring support not configured',
    ' with the right error');
is ($object->store (@trace), undef, ' and store fails');
is ($object->error, 'WebAuth keyring support not configured',
    ' with the right error');
is ($object->destroy (@trace), 1, ' but destroy succeeds');

# Set up our configuration.
mkdir 'test-keyrings' or die "cannot create test-keyrings: $!\n";
$Wallet::Config::WAKEYRING_BUCKET = 'test-keyrings';

# Okay, now we can test.  First, the basic object without store.
$object = eval {
    Wallet::Object::WAKeyring->create ('wa-keyring', 'test', $schema, @trace)
  };
ok (defined ($object), 'Creating a basic WebAuth keyring object succeeds');
ok ($object->isa ('Wallet::Object::WAKeyring'), ' and is the right class');
my $data = $object->get (@trace);
ok ($data, ' and get succeeds');
my $keyring = WebAuth::Keyring->decode ($wa, $data);
ok ($keyring->isa ('WebAuth::Keyring'), ' and resulting keyring decodes');
my @entries = $keyring->entries;
is (scalar (@entries), 3, ' and has three entries');
is ($entries[0]->creation, 0, 'First has good creation');
is ($entries[0]->key->type, WA_KEY_AES, ' and key type');
is ($entries[0]->key->length, WA_AES_128, ' and key length');
is ($entries[0]->valid_after, 0, ' and validity');
ok ((time - $entries[1]->creation) < 2, 'Second has good creation');
is ($entries[1]->key->type, WA_KEY_AES, ' and key type');
is ($entries[1]->key->length, WA_AES_128, ' and key length');
ok (($entries[1]->valid_after - time) <= 60 * 60 * 24,
    ' and validity (upper)');
ok (($entries[1]->valid_after - time) > 60 * 60 * 24 - 2,
    ' and validity (lower)');
ok ((time - $entries[2]->creation) < 2, 'Third has good creation');
is ($entries[2]->key->type, WA_KEY_AES, ' and key type');
is ($entries[2]->key->length, WA_AES_128, ' and key length');
ok (($entries[2]->valid_after - time) <= 2 * 60 * 60 * 24,
    ' and validity (upper)');
ok (($entries[2]->valid_after - time) > 2 * 60 * 60 * 24 - 2,
    ' and validity (lower)');
my $data2 = $object->get (@trace);
is ($data2, $data, 'Getting the object again returns the same data');
is ($object->error, undef, ' with no error');
is ($object->destroy (@trace), 1, 'Destroying the object succeeds');

# Now store something and be sure that we get something reasonable.
$object = eval {
    Wallet::Object::WAKeyring->create ('wa-keyring', 'test', $schema, @trace)
  };
ok (defined ($object), 'Recreating the object succeeds');
my $key = WebAuth::Key->new ($wa, WA_KEY_AES, WA_AES_128);
$keyring = WebAuth::Keyring->new ($wa, $key);
$data = $keyring->encode;
is ($object->store ($data, @trace), 1, ' and storing data in it succeeds');
ok (-d 'test-keyrings/09', ' and the hash bucket was created');
ok (-f 'test-keyrings/09/test', ' and the file exists');
is (contents ('test-keyrings/09/test'), $data, ' with the right contents');
$data = $object->get (@trace);
$keyring = WebAuth::Keyring->decode ($wa, $data);
ok ($keyring->isa ('WebAuth::Keyring'), ' and get returns a valid keyring');
@entries = $keyring->entries;
is (scalar (@entries), 2, ' and has three entries');
is ($entries[0]->creation, 0, 'First has good creation');
is ($entries[0]->key->type, WA_KEY_AES, ' and key type');
is ($entries[0]->key->length, WA_AES_128, ' and key length');
is ($entries[0]->valid_after, 0, ' and validity');
is ($entries[0]->key->data, $key->data, ' and matches the original key');
ok ((time - $entries[1]->creation) < 2, 'Second has good creation');
is ($entries[1]->key->type, WA_KEY_AES, ' and key type');
is ($entries[1]->key->length, WA_AES_128, ' and key length');
ok (($entries[1]->valid_after - time) <= 2 * 60 * 60 * 24,
    ' and validity (upper)');
ok (($entries[1]->valid_after - time) > 2 * 60 * 60 * 24 - 2,
    ' and validity (lower)');

# Test pruning.  Add another old key and a couple of more current keys to the
# current keyring.
$key = WebAuth::Key->new ($wa, WA_KEY_AES, WA_AES_128);
$keyring->add (0, 0, $key);
$key = WebAuth::Key->new ($wa, WA_KEY_AES, WA_AES_128);
$keyring->add (time - 24 * 60 * 60, time - 24 * 60 * 60, $key);
$key = WebAuth::Key->new ($wa, WA_KEY_AES, WA_AES_128);
$keyring->add (time, time, $key);
$data = $keyring->encode;
is ($object->store ($data, @trace), 1, 'Storing modified keyring succeeds');
$data = $object->get (@trace);
$keyring = WebAuth::Keyring->decode ($wa, $data);
ok ($keyring->isa ('WebAuth::Keyring'), ' and get returns a valid keyring');
@entries = $keyring->entries;
is (scalar (@entries), 3, ' and has three entries');
ok ((time - $entries[0]->creation) < 2, 'First has good creation');
ok (($entries[0]->valid_after - time) <= 2 * 60 * 60 * 24,
    ' and validity (upper)');
ok (($entries[0]->valid_after - time) > 2 * 60 * 60 * 24 - 2,
    ' and validity (lower)');
ok ((time - $entries[1]->creation) < 24 * 60 * 60 + 2,
    'Second has good creation');
ok ((time - $entries[1]->valid_after) <= 60 * 60 * 24 + 2,
    ' and validity');
ok ((time - $entries[2]->creation) < 2, 'Third has good creation');
ok ((time - $entries[2]->valid_after) < 2, ' and validity');
is ($object->destroy (@trace), 1, 'Destroying the object succeeds');

# Test error handling in the file store.
system ('rm -r test-keyrings') == 0 or die "cannot remove test-keyrings\n";
$object = eval {
    Wallet::Object::WAKeyring->create ('wa-keyring', 'test', $schema, @trace)
  };
ok (defined ($object), 'Recreating the object succeeds');
is ($object->get (@trace), undef, ' but retrieving it fails');
like ($object->error, qr/^cannot create keyring bucket 09: /,
      ' with the right error');
is ($object->store ("foo\n", @trace), undef, ' and store fails');
like ($object->error, qr/^cannot create keyring bucket 09: /,
      ' with the right error');
is ($object->destroy (@trace), 1, ' but destroying the object succeeds');

# Clean up.
$admin->destroy;
unlink ('wallet-db');
