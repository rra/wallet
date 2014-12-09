#!/usr/bin/perl
#
# Tests for the Duo Auth proxy LDAP integration object implementation.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use POSIX qw(strftime);
use Test::More;

BEGIN {
    eval 'use Net::Duo';
    plan skip_all => 'Net::Duo required for testing duo'
      if $@;
    eval 'use Net::Duo::Mock::Agent';
    plan skip_all => 'Net::Duo::Mock::Agent required for testing duo'
      if $@;
}

BEGIN {
    use_ok('Wallet::Admin');
    use_ok('Wallet::Config');
    use_ok('Wallet::Object::Duo::LDAPProxy');
}

use lib 't/lib';
use Util;

# Some global defaults to use.
my $user = 'admin@EXAMPLE.COM';
my $host = 'localhost';
my @trace = ($user, $host, time);
my $date = strftime ('%Y-%m-%d %H:%M:%S', localtime $trace[2]);

# Flush all output immediately.
$| = 1;

# Use Wallet::Admin to set up the database.
db_setup;
my $admin = eval { Wallet::Admin->new };
is ($@, '', 'Database connection succeeded');
is ($admin->reinitialize ($user), 1, 'Database initialization succeeded');
my $schema = $admin->schema;

# Create a mock object to use for Duo calls.
my $mock = Net::Duo::Mock::Agent->new ({ key_file => 't/data/duo/keys.json' });

# Test error handling in the absence of configuration.
my $object = eval {
    Wallet::Object::Duo::LDAPProxy->new ('duo-ldap', 'test', $schema);
};
is ($object, undef, 'Wallet::Object::Duo::LDAPProxy new with no config failed');
is ($@, "duo object implementation not configured\n", '...with correct error');
$object = eval {
    Wallet::Object::Duo::LDAPProxy->create ('duo-ldap', 'test', $schema,
                                            @trace);
};
is ($object, undef, 'Wallet::Object::Duo::LDAPProxy creation with no config failed');
is ($@, "duo object implementation not configured\n", '...with correct error');

# Set up the Duo configuration.
$Wallet::Config::DUO_AGENT    = $mock;
$Wallet::Config::DUO_KEY_FILE = 't/data/duo/keys.json';

# Test creating an integration.
note ('Test creating an integration');
my $expected = {
    name  => 'test (ldapproxy)',
    notes => 'Managed by wallet',
    type  => 'ldapproxy',
};
$mock->expect (
    {
        method        => 'POST',
        uri           => '/admin/v1/integrations',
        content       => $expected,
        response_file => 't/data/duo/integration.json',
    }
);
$object = Wallet::Object::Duo::LDAPProxy->create ('duo-ldap', 'test', $schema,
                                            @trace);
isa_ok ($object, 'Wallet::Object::Duo::LDAPProxy');

# Check the metadata about the new wallet object.
$expected = <<"EOO";
           Type: duo-ldap
           Name: test
        Duo key: DIRWIH0ZZPV4G88B37VQ
     Created by: $user
   Created from: $host
     Created on: $date
EOO
is ($object->show, $expected, 'Show output is correct');

# Test retrieving the integration information.
note ('Test retrieving an integration');
$mock->expect (
    {
        method        => 'GET',
        uri           => '/admin/v1/integrations/DIRWIH0ZZPV4G88B37VQ',
        response_file => 't/data/duo/integration-ldap.json',
    }
);
my $data = $object->get (@trace);
ok (defined ($data), 'Retrieval succeeds');
$expected = <<'EOO';
[ldap_server_challenge]
ikey     = DIRWIH0ZZPV4G88B37VQ
skey     = QO4ZLqQVRIOZYkHfdPDORfcNf8LeXIbCWwHazY7o
api_host = example-admin.duosecurity.com
EOO
is ($data, $expected, '...and integration data is correct');

# Ensure that we can't retrieve the object when locked.
is ($object->flag_set ('locked', @trace), 1,
    'Setting object to locked succeeds');
is ($object->get, undef, '...and now get fails');
is ($object->error, 'cannot get duo-ldap:test: object is locked',
    '...with correct error');
is ($object->flag_clear ('locked', @trace), 1,
    '...and clearing locked flag works');

# Create a new object by wallet type and name.
$object = Wallet::Object::Duo::LDAPProxy->new ('duo-ldap', 'test', $schema);

# Test deleting an integration.  We can't test this entirely properly because
# currently Net::Duo::Mock::Agent doesn't support stacking multiple expected
# calls and delete makes two calls.
note ('Test deleting an integration');
$mock->expect (
    {
        method        => 'GET',
        uri           => '/admin/v1/integrations/DIRWIH0ZZPV4G88B37VQ',
        response_file => 't/data/duo/integration.json',
    }
);
TODO: {
    local $TODO = 'Net::Duo::Mock::Agent not yet capable';

    is ($object->destroy (@trace), 1, 'Duo object deletion succeeded');
    $object = eval { Wallet::Object::Duo::LDAPProxy->new ('duo-ldap', 'test',
                                                          $schema) };
    is ($object, undef, '...and now object cannot be retrieved');
    is ($@, "cannot find duo:test\n", '...with correct error');
}

# Clean up.
$admin->destroy;
END {
    unlink ('wallet-db');
}

# Done testing.
done_testing ();
