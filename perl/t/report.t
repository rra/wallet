#!/usr/bin/perl -w
#
# t/report.t -- Tests for the wallet reporting interface.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2008, 2009, 2010 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

use Test::More tests => 83;

use Wallet::Admin;
use Wallet::Report;
use Wallet::Server;

use lib 't/lib';
use Util;

# Use Wallet::Admin to set up the database.
db_setup;
my $admin = eval { Wallet::Admin->new };
is ($@, '', 'Wallet::Admin creation did not die');
is ($admin->reinitialize ('admin@EXAMPLE.COM'), 1,
    'Database initialization succeeded');
$admin->register_object ('base', 'Wallet::Object::Base');
$admin->register_verifier ('base', 'Wallet::ACL::Base');

# We have an empty database, so we should see no objects and one ACL.
my $report = eval { Wallet::Report->new };
is ($@, '', 'Wallet::Report creation did not die');
ok ($report->isa ('Wallet::Report'), ' and returned the right class');
my @objects = $report->objects;
is (scalar (@objects), 0, 'No objects in the database');
is ($report->error, undef, ' and no error');
my @acls = $report->acls;
is (scalar (@acls), 1, 'One ACL in the database');
is ($acls[0][0], 1, ' and that is ACL ID 1');
is ($acls[0][1], 'ADMIN', ' with the right name');

# Create an object.
$server = eval { Wallet::Server->new ('admin@EXAMPLE.COM', 'localhost') };
is ($@, '', 'Creating a server instance did not die');
is ($server->create ('base', 'service/admin'), 1,
    ' and creating base:service/admin succeeds');

# Now, we should see one object.
@objects = $report->objects;
is (scalar (@objects), 1, ' and now there is one object');
is ($objects[0][0], 'base', ' with the right type');
is ($objects[0][1], 'service/admin', ' and the right name');

# Create another ACL.
is ($server->acl_create ('first'), 1, 'ACL creation succeeds');
@acls = $report->acls;
is (scalar (@acls), 2, ' and now there are two ACLs');
is ($acls[0][0], 1, ' and the first ID is correct');
is ($acls[0][1], 'ADMIN', ' and the first name is correct');
is ($acls[1][0], 2, ' and the second ID is correct');
is ($acls[1][1], 'first', ' and the second name is correct');

# Delete that ACL and create another.
is ($server->acl_create ('second'), 1, 'Second ACL creation succeeds');
is ($server->acl_destroy ('first'), 1, ' and deletion of the first succeeds');
@acls = $report->acls;
is (scalar (@acls), 2, ' and there are still two ACLs');
is ($acls[0][0], 1, ' and the first ID is still the same');
is ($acls[0][1], 'ADMIN', ' and the first name is still the same');
is ($acls[1][0], 3, ' but the second ID has changed');
is ($acls[1][1], 'second', ' and the second name is correct');

# Currently, we have no owners, so we should get an empty owner report.
my @lines = $report->owners ('%', '%');
is (scalar (@lines), 0, 'Owner report is currently empty');
is ($report->error, undef, ' and there is no error');

# Set an owner and make sure we now see something in the report.
is ($server->owner ('base', 'service/admin', 'ADMIN'), 1,
    'Setting an owner works');
@lines = $report->owners ('%', '%');
is (scalar (@lines), 1, ' and now there is one owner in the report');
is ($lines[0][0], 'krb5', ' with the right scheme');
is ($lines[0][1], 'admin@EXAMPLE.COM', ' and the right identifier');
@lines = $report->owners ('keytab', '%');
is (scalar (@lines), 0, 'Owners of keytabs is empty');
is ($report->error, undef, ' with no error');
@lines = $report->owners ('base', 'foo/%');
is (scalar (@lines), 0, 'Owners of base foo/* objects is empty');
is ($report->error, undef, ' with no error');

# Create a second object with the same owner.
is ($server->create ('base', 'service/foo'), 1,
    'Creating base:service/foo succeeds');
is ($server->owner ('base', 'service/foo', 'ADMIN'), 1,
    ' and setting the owner to the same value works');
@lines = $report->owners ('base', 'service/%');
is (scalar (@lines), 1, ' and there is still owner in the report');
is ($lines[0][0], 'krb5', ' with the right scheme');
is ($lines[0][1], 'admin@EXAMPLE.COM', ' and the right identifier');

# Change the owner of the second object to an empty ACL.
is ($server->owner ('base', 'service/foo', 'second'), 1,
    ' and changing the owner to an empty ACL works');
@lines = $report->owners ('base', '%');
is (scalar (@lines), 1, ' and there is still owner in the report');
is ($lines[0][0], 'krb5', ' with the right scheme');
is ($lines[0][1], 'admin@EXAMPLE.COM', ' and the right identifier');

# Add a few things to the second ACL to see what happens.
is ($server->acl_add ('second', 'base', 'foo'), 1,
    'Adding an ACL line to the new ACL works');
is ($server->acl_add ('second', 'base', 'bar'), 1,
    ' and adding another ACL line to the new ACL works');
@lines = $report->owners ('base', '%');
is (scalar (@lines), 3, ' and now there are three owners in the report');
is ($lines[0][0], 'base', ' first has the right scheme');
is ($lines[0][1], 'bar', ' and the right identifier');
is ($lines[1][0], 'base', ' second has the right scheme');
is ($lines[1][1], 'foo', ' and the right identifier');
is ($lines[2][0], 'krb5', ' third has the right scheme');
is ($lines[2][1], 'admin@EXAMPLE.COM', ' and the right identifier');

# Test ownership and other ACL values.  Change one keytab to be not owned by
# ADMIN, but have group permission on it.  We'll need a third object neither
# owned by ADMIN or with any permissions from it.
is ($server->create ('base', 'service/null'), 1,
    'Creating base:service/null succeeds');
is ($server->acl ('base', 'service/foo', 'get', 'ADMIN'), 1,
    'Changing the get ACL for the search also does');
@lines = $report->objects ('owner', 'ADMIN');
is (scalar (@lines), 1, 'Searching for objects owned by ADMIN finds one');
is ($lines[0][0], 'base', ' and it has the right type');
is ($lines[0][1], 'service/admin', ' and the right name');
@lines = $report->objects ('owner', 'null');
is (scalar (@lines), 1, 'Searching for objects with no set ownerfinds one');
is ($lines[0][0], 'base', ' and it has the right type');
is ($lines[0][1], 'service/null', ' and the right name');
@lines = $report->objects ('acl', 'ADMIN');
is (scalar (@lines), 2, 'ADMIN has any rights at all on two objects');
is ($lines[0][0], 'base', ' and the first has the right type');
is ($lines[0][1], 'service/admin', ' and the right name');
is ($lines[1][0], 'base', ' and the second has the right type');
is ($lines[1][1], 'service/foo', ' and the right name');

# Listing objects of a specific type.
@lines = $report->objects ('type', 'base');
is (scalar (@lines), 3, 'Searching for all objects of type base finds three');
is ($lines[0][0], 'base', ' and the first has the right type');
is ($lines[0][1], 'service/admin', ' and the right name');
is ($lines[1][0], 'base', ' and the second has the right type');
is ($lines[1][1], 'service/foo', ' and the right name');
is ($lines[2][0], 'base', ' and the third has the right type');
is ($lines[2][1], 'service/null', ' and the right name');
@lines = $report->objects ('type', 'keytab');
is (scalar (@lines), 0, 'Searching for all objects of type keytab finds none');

# Test setting a flag, searching for objects with it, and then clearing it.
is ($server->flag_set ('base', 'service/admin', 'unchanging'), 1,
    'Setting a flag works');
@lines = $report->objects ('flag', 'unchanging');
is (scalar (@lines), 1, 'Searching for all objects with that flag finds one');
is ($lines[0][0], 'base', ' and it has the right type');
is ($lines[0][1], 'service/admin', ' and the right name');
is ($server->flag_clear ('base', 'service/admin', 'unchanging'), 1,
    'Clearing the flag works');
@lines = $report->objects ('flag', 'unchanging');
is (scalar (@lines), 0, ' and now there are no objects in the report');
is ($report->error, undef, ' with no error');

# Clean up.
$admin->destroy;
unlink 'wallet-db';
