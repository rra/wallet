#!/usr/bin/perl -w
#
# Tests for wallet administrative interface.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2008, 2009, 2010, 2011, 2013, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use Test::More tests => 26;

use Wallet::Admin;
use Wallet::Report;
use Wallet::Schema;
use Wallet::Server;
use DBI;

use lib 't/lib';
use Util;

# We test database setup in init.t, so just do the basic setup here.
db_setup;
my $admin = eval { Wallet::Admin->new };
is ($@, '', 'Wallet::Admin creation did not die');
ok ($admin->isa ('Wallet::Admin'), ' and returned the right class');
is ($admin->initialize ('admin@EXAMPLE.COM'), 1,
    ' and initialization succeeds');
is ($admin->upgrade, 1, ' and upgrade succeeds (should do nothing)');
is ($admin->error, undef, ' and there is no error');

# We have an empty database, so we should see no objects and one ACL.
my $report = Wallet::Report->new;
my @objects = $report->objects;
is (scalar (@objects), 0, 'No objects in the database');
is ($report->error, undef, ' and no error');
my @acls = $report->acls;
is (scalar (@acls), 1, 'One ACL in the database');
is ($acls[0][0], 1, ' and that is ACL ID 1');
is ($acls[0][1], 'ADMIN', ' with the right name');

# Register a base object so that we can create a simple object.
is ($admin->register_object ('base', 'Wallet::Object::Base'), 1,
    'Registering Wallet::Object::Base works');
is ($admin->register_object ('base', 'Wallet::Object::Base'), undef,
    ' and cannot be registered twice');
my $server = eval { Wallet::Server->new ('admin@EXAMPLE.COM', 'localhost') };
is ($@, '', 'Creating a server instance did not die');
is ($server->create ('base', 'service/admin'), 1,
    ' and creating base:service/admin succeeds');

# Test registering a new ACL type.
is ($admin->register_verifier ('base', 'Wallet::ACL::Base'), 1,
    'Registering Wallet::ACL::Base works');
is ($admin->register_verifier ('base', 'Wallet::ACL::Base'), undef,
    ' and cannot be registered twice');
is ($server->acl_add ('ADMIN', 'base', 'foo'), 1,
    ' and adding a base ACL now works');

# Test re-initialization of the database.
$Wallet::Schema::VERSION = '0.07';
is ($admin->reinitialize ('admin@EXAMPLE.COM'), 1,
    ' and re-initialization succeeds');

# Test an upgrade.  Reinitialize to an older version, then test upgrade to the
# current version.
SKIP: {
    my @path = (split (':', $ENV{PATH}));
    my ($sqlite) = grep { -x $_ } map { "$_/sqlite3" } @path;
    skip 'sqlite3 not found', 5 unless $sqlite;

    # Delete all tables and then redump them straight from the SQL file to
    # avoid getting the version table.
    unlink 'wallet-db';
    my $status = system ('sqlite3', 'wallet-db',
                         '.read sql/Wallet-Schema-0.07-SQLite.sql');
    is ($status, 0, 'Reinstalling database from non-versioned SQL succeds');

    # Upgrade to 0.08.
    $Wallet::Schema::VERSION = '0.08';
    $admin = eval { Wallet::Admin->new };
    my $retval = $admin->upgrade;
    is ($retval, 1, ' and performing an upgrade to 0.08 succeeds');
    my $sql = "select version from dbix_class_schema_versions order by"
      . " version DESC";
    my $version = $admin->dbh->selectall_arrayref ($sql);
    is (@$version, 2, ' and versions table has correct number of rows');
    is (@{ $version->[0] }, 1, ' and correct number of columns');
    is ($version->[0][0], '0.08', ' and the schema version is correct');

    # Upgrade to 0.09.
    $Wallet::Schema::VERSION = '0.09';
    $admin = eval { Wallet::Admin->new };
    $retval = $admin->upgrade;
    is ($retval, 1, ' and performing an upgrade to 0.09 succeeds');
    $sql = "select version from dbix_class_schema_versions order by"
      . " version DESC";
    $version = $admin->dbh->selectall_arrayref ($sql);
    is ($version->[0][0], '0.09', ' and the schema version is correct');
}

# Clean up.
is ($admin->destroy, 1, 'Destruction succeeds');
END {
    unlink 'wallet-db';
}
