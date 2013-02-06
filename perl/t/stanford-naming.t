#!/usr/bin/perl
#
# Tests for the Stanford naming policy.
#
# The naming policy code is included primarily an example for non-Stanford
# sites, but it's used at Stanford and this test suite is used to verify
# behavior at Stanford.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use 5.008;
use strict;
use warnings;

use Test::More tests => 97;

use lib 't/lib';
use Util;

# Load the naming policy module.
BEGIN {
    use_ok('Wallet::Admin');
    use_ok('Wallet::Policy::Stanford', qw(default_owner verify_name));
    use_ok('Wallet::Server');
}

# Various valid keytab names.
my @VALID_KEYTABS = qw(host/example.stanford.edu HTTP/example.stanford.edu
    service/example example/cgi class-example01/cgi dept-01example/cgi
    group-example-01/cgi);

# Various invalid keytab names.
my @INVALID_KEYTABS = qw(example host/example service/example.stanford.edu
    thisistoolong/cgi not-valid/cgi unknown/example.stanford.edu);

# Various valid file names.
my @VALID_FILES = qw(htpasswd/example.stanford.edu/web
    password-ipmi/example.stanford.edu
    password-root/example.stanford.edu
    password-tivoli/example.stanford.edu
    ssh-dsa/example.stanford.edu
    ssh-rsa/example.stanford.edu
    ssl-key/example.stanford.edu
    ssl-key/example.stanford.edu/mysql
    tivoli-key/example.stanford.edu
    config/its-idg/example/foo
    db/its-idg/example/s_foo
    gpg-key/its-idg/debian
    password/its-idg/example/backup
    properties/its-idg/accounts
    properties/its-idg/accounts/sponsorship
    ssl-keystore/its-idg/accounts
    ssl-keystore/its-idg/accounts/sponsorship
    ssl-pkcs12/its-idg/accounts
    ssl-pkcs12/its-idg/accounts/sponsorship);

# Various valid legacy file names.
my @VALID_LEGACY_FILES = qw(apps-example-config-file crcsg-example-db-s_example
    idg-debian-gpg-key idg-devnull-password-root sulair-accounts-properties
    idg-accounts-ssl-keystore idg-accounts-ssl-pkcs12
    crcsg-example-htpasswd-web sulair-example-password-ipmi
    sulair-example-password-root sulair-example-password-tivoli
    sulair-example-ssh-dsa sulair-example-ssh-rsa idg-mdm-ssl-key
    idg-openafs-tivoli-key);

# Various invalid file names.
my @INVALID_FILES = qw(unknown foo-example-ssh-rsa idg-accounts-foo !!bad
    htpasswd/example.stanford.edu htpasswd/example password-root/example
    password-root/example.stanford.edu/foo ssh-foo/example.stanford.edu
    tivoli-key/example.stanford.edu/foo tivoli-key config config/its-idg
    config/its-idg/example db/its-idg/example password/its-idg/example
    its-idg/password/example properties//accounts properties/its-idg/
    ssl-keystore/idg/accounts);

# Global variables for the wallet server setup.
my $ADMIN = 'admin@EXAMPLE.COM';
my $HOST = 'localhost';
my @TRACE = ($ADMIN, $HOST);

# Start by testing lots of straightforward naming validity.
for my $name (@VALID_KEYTABS) {
    is(verify_name('keytab', $name), undef, "Valid keytab $name");
}
for my $name (@INVALID_KEYTABS) {
    isnt(verify_name('keytab', $name), undef, "Invalid keytab $name");
}
for my $name (@VALID_FILES) {
    is(verify_name('file', $name), undef, "Valid file $name");
}
for my $name (@VALID_LEGACY_FILES) {
    is(verify_name('file', $name), undef, "Valid file $name");
}
for my $name (@INVALID_FILES) {
    isnt(verify_name('file', $name), undef, "Invalid file $name");
}

# Now we need an actual database.  Use Wallet::Admin to set it up.
db_setup;
my $setup = eval { Wallet::Admin->new };
is($@, q{}, 'Database initialization did not die');
is($setup->reinitialize($ADMIN), 1, 'Database initialization succeeded');
my $server = eval { Wallet::Server->new(@TRACE) };
is($@, q{}, 'Server creation did not die');

# Create a host/example.stanford.edu ACL that uses the netdb ACL type.
is($server->acl_create('host/example.stanford.edu'), 1, 'Created netdb ACL');
is(
    $server->acl_add('host/example.stanford.edu', 'netdb',
      'example.stanford.edu'),
    1,
    '...with netdb ACL line'
);
is(
    $server->acl_add('host/example.stanford.edu', 'krb5',
      'host/example.stanford.edu@stanford.edu'),
    1,
    '...and krb5 ACL line'
);

# Likewise for host/foo.example.edu with the netdb-root ACL type.
is($server->acl_create('host/foo.stanford.edu'), 1, 'Created netdb-root ACL');
is(
    $server->acl_add('host/foo.stanford.edu', 'netdb-root',
      'foo.stanford.edu'),
    1,
    '...with netdb-root ACL line'
);
is(
    $server->acl_add('host/foo.stanford.edu', 'krb5',
      'host/foo.stanford.edu@stanford.edu'),
    1,
    '...and krb5 ACL line'
);

# Create a group/its-idg ACL, which will be used for autocreation of file
# objects.
is($server->acl_create('group/its-idg'), 1, 'Created group/its-idg ACL');
is($server->acl_add('group/its-idg', 'krb5', $ADMIN), 1, '...with member');

# Now we can test default ACLs.  First, without a root instance.
local $ENV{REMOTE_USER} = $ADMIN;
is_deeply(
    [default_owner('keytab', 'host/bar.stanford.edu')],
    [
        'host/bar.stanford.edu',
        ['netdb', 'bar.stanford.edu'],
        ['krb5', 'host/bar.stanford.edu@stanford.edu']
    ],
    'Correct default owner for host-based keytab'
);
is_deeply(
    [default_owner('keytab', 'HTTP/example.stanford.edu')],
    [
        'host/example.stanford.edu',
        ['netdb', 'example.stanford.edu'],
        ['krb5', 'host/example.stanford.edu@stanford.edu']
    ],
    '...and when netdb ACL already exists'
);
is_deeply(
    [default_owner('keytab', 'webauth/foo.stanford.edu')],
    [
        'host/foo.stanford.edu',
        ['netdb-root', 'foo.stanford.edu'],
        ['krb5', 'host/foo.stanford.edu@stanford.edu']
    ],
    '...and when netdb-root ACL already exists'
);

# Now with a root instance.
local $ENV{REMOTE_USER} = 'admin/root@stanford.edu';
is_deeply(
    [default_owner('keytab', 'host/bar.stanford.edu')],
    [
        'host/bar.stanford.edu',
        ['netdb-root', 'bar.stanford.edu'],
        ['krb5', 'host/bar.stanford.edu@stanford.edu']
    ],
    'Correct default owner for host-based keytab for /root'
);
is_deeply(
    [default_owner('keytab', 'HTTP/example.stanford.edu')],
    [
        'host/example.stanford.edu',
        ['netdb-root', 'example.stanford.edu'],
        ['krb5', 'host/example.stanford.edu@stanford.edu']
    ],
    '...and when netdb ACL already exists'
);
is_deeply(
    [default_owner('keytab', 'webauth/foo.stanford.edu')],
    [
        'host/foo.stanford.edu',
        ['netdb-root', 'foo.stanford.edu'],
        ['krb5', 'host/foo.stanford.edu@stanford.edu']
    ],
    '...and when netdb-root ACL already exists'
);

# Check for a type that isn't host-based.
is(default_owner('keytab', 'service/foo'), undef,
    'No default owner for service/foo');

# Check for an unknown object type.
is(default_owner('unknown', 'foo'), undef,
    'No default owner for unknown type');

# Check for autocreation mappings for host-based file objects.
is_deeply(
    [default_owner('file', 'ssl-key/example.stanford.edu')],
    [
        'host/example.stanford.edu',
        ['netdb-root', 'example.stanford.edu'],
        ['krb5', 'host/example.stanford.edu@stanford.edu']
    ],
    'Default owner for file ssl-key/example.stanford.edu',
);
is_deeply(
    [default_owner('file', 'ssl-key/example.stanford.edu/mysql')],
    [
        'host/example.stanford.edu',
        ['netdb-root', 'example.stanford.edu'],
        ['krb5', 'host/example.stanford.edu@stanford.edu']
    ],
    'Default owner for file ssl-key/example.stanford.edu/mysql',
);

# Check for a file object that isn't host-based.
is_deeply(
    [default_owner('file', 'config/its-idg/example/foo')],
    ['group/its-idg', ['krb5', $ADMIN]],
    'Default owner for file config/its-idg/example/foo',
);

# Check for legacy autocreation mappings for file objects.
for my $type (qw(htpasswd ssh-rsa ssh-dsa ssl-key tivoli-key)) {
    my $name = "idg-example-$type";
    is_deeply(
        [default_owner('file', $name)],
        [
            'host/example.stanford.edu',
            ['netdb-root', 'example.stanford.edu'],
            ['krb5', 'host/example.stanford.edu@stanford.edu']
        ],
        "Default owner for file $name",
    );
}

# Clean up.
$setup->destroy;
unlink 'wallet-db';
