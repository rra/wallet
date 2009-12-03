#!/usr/bin/perl -w
#
# t/admin.t -- Tests for wallet administrative interface.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2008, 2009 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

use Test::More tests => 77;

use Wallet::Admin;
use Wallet::Schema;
use Wallet::Server;

use lib 't/lib';
use Util;

# We test database setup in init.t, so just do the basic setup here.
db_setup;
my $admin = eval { Wallet::Admin->new };
is ($@, '', 'Wallet::Admin creation did not die');
ok ($admin->isa ('Wallet::Admin'), ' and returned the right class');
is ($admin->initialize ('admin@EXAMPLE.COM'), 1,
    ' and initialization succeeds');

# We have an empty database, so we should see no objects and one ACL.
my @objects = $admin->list_objects;
is (scalar (@objects), 0, 'No objects in the database');
is ($admin->error, undef, ' and no error');
my @acls = $admin->list_acls;
is (scalar (@acls), 1, 'One ACL in the database');
is ($acls[0][0], 1, ' and that is ACL ID 1');
is ($acls[0][1], 'ADMIN', ' with the right name');

# Register a base object so that we can create a simple object.
is ($admin->register_object ('base', 'Wallet::Object::Base'), 1,
    'Registering Wallet::Object::Base works');

# Create an object.
$server = eval { Wallet::Server->new ('admin@EXAMPLE.COM', 'localhost') };
is ($@, '', 'Creating a server instance did not die');
is ($server->create ('base', 'service/admin'), 1,
    ' and creating base:service/admin succeeds');

# Now, we should see one object.
@objects = $admin->list_objects;
is (scalar (@objects), 1, ' and now there is one object');
is ($objects[0][0], 'base', ' with the right type');
is ($objects[0][1], 'service/admin', ' and the right name');

# Test registering a new ACL type.  We don't have a good way of really using
# this right now.
is ($admin->register_verifier ('base', 'Wallet::ACL::Base'), 1,
    'Registering Wallet::ACL::Base works');

# Delete that ACL and create another.
is ($server->acl_create ('second'), 1, 'Second ACL creation succeeds');
is ($server->acl_destroy ('first'), 1, ' and deletion of the first succeeds');
@acls = $admin->list_acls;
is (scalar (@acls), 2, ' and there are still two ACLs');
is ($acls[0][0], 1, ' and the first ID is still the same');
is ($acls[0][1], 'ADMIN', ' and the first name is still the same');
is ($acls[1][0], 3, ' but the second ID has changed');
is ($acls[1][1], 'second', ' and the second name is correct');

# Currently, we have no owners, so we should get an empty owner report.
my @lines = $admin->report_owners ('%', '%');
is (scalar (@lines), 0, 'Owner report is currently empty');
is ($admin->error, undef, ' and there is no error');

# Set an owner and make sure we now see something in the report.
is ($server->owner ('base', 'service/admin', 'ADMIN'), 1,
    'Setting an owner works');
@lines = $admin->report_owners ('%', '%');
is (scalar (@lines), 1, ' and now there is one owner in the report');
is ($lines[0][0], 'krb5', ' with the right scheme');
is ($lines[0][1], 'admin@EXAMPLE.COM', ' and the right identifier');
@lines = $admin->report_owners ('keytab', '%');
is (scalar (@lines), 0, 'Owners of keytabs is empty');
is ($admin->error, undef, ' with no error');
@lines = $admin->report_owners ('base', 'foo/%');
is (scalar (@lines), 0, 'Owners of base foo/* objects is empty');
is ($admin->error, undef, ' with no error');

# Create a second object with the same owner.
is ($server->create ('base', 'service/foo'), 1,
    'Creating base:service/foo succeeds');
is ($server->owner ('base', 'service/foo', 'ADMIN'), 1,
    ' and setting the owner to the same value works');
@lines = $admin->report_owners ('base', 'service/%');
is (scalar (@lines), 1, ' and there is still owner in the report');
is ($lines[0][0], 'krb5', ' with the right scheme');
is ($lines[0][1], 'admin@EXAMPLE.COM', ' and the right identifier');

# Change the owner of the second object to an empty ACL.
is ($server->owner ('base', 'service/foo', 'second'), 1,
    ' and changing the owner to an empty ACL works');
@lines = $admin->report_owners ('base', '%');
is (scalar (@lines), 1, ' and there is still owner in the report');
is ($lines[0][0], 'krb5', ' with the right scheme');
is ($lines[0][1], 'admin@EXAMPLE.COM', ' and the right identifier');

# Add a few things to the second ACL to see what happens.
is ($server->acl_add ('second', 'base', 'foo'), 1,
    'Adding an ACL line to the new ACL works');
is ($server->acl_add ('second', 'base', 'bar'), 1,
    ' and adding another ACL line to the new ACL works');
@lines = $admin->report_owners ('base', '%');
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
@lines = $admin->list_objects ('owner', 'ADMIN');
is (scalar (@lines), 1, 'Searching for objects owned by ADMIN finds one');
is ($lines[0][0], 'base', ' and it has the right type');
is ($lines[0][1], 'service/admin', ' and the right name');
@lines = $admin->list_objects ('owner', 'null');
is (scalar (@lines), 1, 'Searching for objects with no set ownerfinds one');
is ($lines[0][0], 'base', ' and it has the right type');
is ($lines[0][1], 'service/null', ' and the right name');
@lines = $admin->list_objects ('acl', 'ADMIN');
is (scalar (@lines), 2, 'ADMIN has any rights at all on two objects');
is ($lines[0][0], 'base', ' and the first has the right type');
is ($lines[0][1], 'service/admin', ' and the right name');
is ($lines[1][0], 'base', ' and the second has the right type');
is ($lines[1][1], 'service/foo', ' and the right name');

# Listing objects of a specific type.
@lines = $admin->list_objects ('type', 'base');
is (scalar (@lines), 3, 'Searching for all objects of type base finds three');
is ($lines[0][0], 'base', ' and the first has the right type');
is ($lines[0][1], 'service/admin', ' and the right name');
is ($lines[1][0], 'base', ' and the second has the right type');
is ($lines[1][1], 'service/foo', ' and the right name');
is ($lines[2][0], 'base', ' and the third has the right type');
is ($lines[2][1], 'service/null', ' and the right name');
@lines = $admin->list_objects ('type', 'keytab');
is (scalar (@lines), 0, 'Searching for all objects of type keytab finds none');

# Test setting a flag, searching for objects with it, and then clearing it.
is ($server->flag_set ('base', 'service/admin', 'unchanging'), 1, 
    'Setting a flag works');
@lines = $admin->list_objects ('flag', 'unchanging');
is (scalar (@lines), 1, 'Searching for all objects with that flag finds one');
is ($lines[0][0], 'base', ' and it has the right type');
is ($lines[0][1], 'service/admin', ' and the right name');
is ($server->flag_clear ('base', 'service/admin', 'unchanging'), 1,
    'Clearing the flag works');

# Clean up.
is ($admin->destroy, 1, 'Destruction succeeds');
unlink 'wallet-db';
