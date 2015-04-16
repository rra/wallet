#!/usr/bin/perl
#
# Tests for the wallet reporting interface.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2008, 2009, 2010, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use strict;
use warnings;

use Test::More tests => 218;

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

# Check to see that we have all types that we expect.
my @types = $report->types;
is (scalar (@types), 10, 'There are ten types created');
is ($types[0][0], 'base', ' and the first member is correct');
is ($types[1][0], 'duo', ' and the second member is correct');
is ($types[2][0], 'duo-ldap', ' and the third member is correct');
is ($types[3][0], 'duo-pam', ' and the fourth member is correct');
is ($types[4][0], 'duo-radius', ' and the fifth member is correct');
is ($types[5][0], 'duo-rdp', ' and the sixth member is correct');
is ($types[6][0], 'file', ' and the seventh member is correct');
is ($types[7][0], 'keytab', ' and the eighth member is correct');
is ($types[8][0], 'password', ' and the nineth member is correct');
is ($types[9][0], 'wa-keyring', ' and the tenth member is correct');

# And that we have all schemes that we expect.
my @schemes = $report->acl_schemes;
is (scalar (@schemes), 6, 'There are six acl schemes created');
is ($schemes[0][0], 'base', ' and the first member is correct');
is ($schemes[1][0], 'krb5', ' and the second member is correct');
is ($schemes[2][0], 'krb5-regex', ' and the third member is correct');
is ($schemes[3][0], 'ldap-attr', ' and the fourth member is correct');
is ($schemes[4][0], 'netdb', ' and the fifth member is correct');
is ($schemes[5][0], 'netdb-root', ' and the sixth member is correct');

# Create an object.
my $server = eval { Wallet::Server->new ('admin@EXAMPLE.COM', 'localhost') };
is ($@, '', 'Creating a server instance did not die');
is ($server->create ('base', 'service/admin'), 1,
    ' and creating base:service/admin succeeds');

# Now, we should see one object.
@objects = $report->objects;
is (scalar (@objects), 1, ' and now there is one object');
is ($objects[0][0], 'base', ' with the right type');
is ($objects[0][1], 'service/admin', ' and the right name');

# That object should be unused.
@objects = $report->objects ('unused');
is (scalar (@objects), 1, ' and that object is unused');
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

# Both objects should now show as unused.
@objects = $report->objects ('unused');
is (scalar (@objects), 2, 'There are now two unused objects');
is ($objects[0][0], 'base', ' and the first has the right type');
is ($objects[0][1], 'service/admin', ' and the right name');
is ($objects[1][0], 'base', ' and the second has the right type');
is ($objects[1][1], 'service/foo', ' and the right name');

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
is (scalar (@lines), 1, 'Searching for objects with no set owner finds one');
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

# All of our ACLs should be in use.
@lines = $report->acls ('unused');
is (scalar (@lines), 0, 'Searching for unused ACLs returns nothing');
is ($report->error, undef, ' with no error');

# Create some unused ACLs that should show up in the report.
is ($server->acl_create ('third'), 1, 'Creating an empty ACL succeeds');
is ($server->acl_create ('fourth'), 1, ' and creating another succeeds');
@lines = $report->acls ('unused');
is (scalar (@lines), 2, ' and now we see two unused ACLs');
is ($server->error, undef, ' with no error');
is ($lines[0][0], 4, ' and the first has the right ID');
is ($lines[0][1], 'third', ' and the right name');
is ($lines[1][0], 5, ' and the second has the right ID');
is ($lines[1][1], 'fourth', ' and the right name');

# Use one of those ACLs and ensure it drops out of the report.  Test that we
# try all of the possible ACL types.
for my $type (qw/get store show destroy flags/) {
    is ($server->acl ('base', 'service/admin', $type, 'fourth'), 1,
        "Setting ACL $type to fourth succeeds");
    @lines = $report->acls ('unused');
    is (scalar (@lines), 1, ' and now we see only one unused ACL');
    is ($lines[0][0], 4, ' with the right ID');
    is ($lines[0][1], 'third', ' and the right name');
    is ($server->acl ('base', 'service/admin', $type, ''), 1,
        ' and clearing the ACL succeeds');
    @lines = $report->acls ('unused');
    is (scalar (@lines), 2, ' and now we see two unused ACLs');
    is ($lines[0][0], 4, ' and the first has the right ID');
    is ($lines[0][1], 'third', ' and the right name');
    is ($lines[1][0], 5, ' and the second has the right ID');
    is ($lines[1][1], 'fourth', ' and the right name');
}

# The naming audit returns nothing if there's no naming policy.
@lines = $report->audit ('objects', 'name');
is (scalar (@lines), 0, 'Searching for naming violations finds none');
is ($report->error, undef, ' with no error');

# Set a naming policy and then look for objects that fail that policy.  We
# have to deactivate this policy until now so that it doesn't prevent the
# creation of that name originally, which is the reason for the variable
# reference.
our $naming_active = 1;
package Wallet::Config;
sub verify_name {
    my ($type, $name) = @_;
    return unless $naming_active;
    return 'admin not allowed' if $name eq 'service/admin';
    return;
}
package main;
@lines = $report->audit ('objects', 'name');
is (scalar (@lines), 1, 'Searching for naming violations finds one');
is ($lines[0][0], 'base', ' and the first has the right type');
is ($lines[0][1], 'service/admin', ' and the right name');

# Set an ACL naming policy and then look for objects that fail that policy.
# Use the same deactivation trick as above.
package Wallet::Config;
sub verify_acl_name {
    my ($name) = @_;
    return unless $naming_active;
    return 'second not allowed' if $name eq 'second';
    return;
}
package main;
@lines = $report->audit ('acls', 'name');
is (scalar (@lines), 1, 'Searching for ACL naming violations finds one');
is ($lines[0][0], 3, ' and the first has the right ID');
is ($lines[0][1], 'second', ' and the right name');

# Set a host-based object matching script so that we can test the host report.
# The deactivation trick isn't needed here.
package Wallet::Config;
sub is_for_host {
    my ($type, $name, $host) = @_;
    my ($service, $principal) = split ('/', $name, 2);
    return 0 unless $service && $principal;
    return 1 if $host eq $principal;
    return 0;
}
package main;
@lines = $report->objects_hostname ('host', 'admin');
is (scalar (@lines), 1, 'Searching for host-based objects finds one');
is ($lines[0][0], 'base', ' and the first has the right type');
is ($lines[0][1], 'service/admin', ' and the right name');

# Set up a file bucket so that we can create an object we can retrieve.
system ('rm -rf test-files') == 0 or die "cannot remove test-files\n";
mkdir 'test-files' or die "cannot create test-files: $!\n";
$Wallet::Config::FILE_BUCKET = 'test-files';

# Create a file object and ensure that it shows up in the unused list.
is ($server->create ('file', 'test'), 1, 'Creating file:test succeeds');
is ($server->owner ('file', 'test', 'ADMIN'), 1,
    ' and setting its owner works');
@objects = $report->objects ('unused');
is (scalar (@objects), 4, 'There are now four unused objects');
is ($objects[0][0], 'base', ' and the first has the right type');
is ($objects[0][1], 'service/admin', ' and the right name');
is ($objects[1][0], 'base', ' and the second has the right type');
is ($objects[1][1], 'service/foo', ' and the right name');
is ($objects[2][0], 'base', ' and the third has the right type');
is ($objects[2][1], 'service/null', ' and the right name');
is ($objects[3][0], 'file', ' and the fourth has the right type');
is ($objects[3][1], 'test', ' and the right name');

# Store something and retrieve it, and then check that the file object fell
# off of the list.
is ($server->store ('file', 'test', 'Some data'), 1,
    'Storing data in file:test succeeds');
is ($server->get ('file', 'test'), 'Some data', ' and retrieving it works');
@objects = $report->objects ('unused');
is (scalar (@objects), 3, ' and now there are three unused objects');
is ($objects[0][0], 'base', ' and the first has the right type');
is ($objects[0][1], 'service/admin', ' and the right name');
is ($objects[1][0], 'base', ' and the second has the right type');
is ($objects[1][1], 'service/foo', ' and the right name');
is ($objects[2][0], 'base', ' and the third has the right type');
is ($objects[2][1], 'service/null', ' and the right name');

# The third and fourth ACLs are both empty and should show up as duplicate.
@acls = $report->acls ('duplicate');
is (scalar (@acls), 1, 'There is one set of duplicate ACLs');
is (scalar (@{ $acls[0] }), 2, ' with two members');
is ($acls[0][0], 'fourth', ' and the first member is correct');
is ($acls[0][1], 'third', ' and the second member is correct');

# Add the same line to both ACLs.  They should still show up as duplicate.
is ($server->acl_add ('fourth', 'base', 'bar'), 1,
    'Adding a line to the fourth ACL works');
is ($server->acl_add ('third', 'base', 'bar'), 1,
    ' and adding a line to the third ACL works');
@acls = $report->acls ('duplicate');
is (scalar (@acls), 1, 'There is one set of duplicate ACLs');
is (scalar (@{ $acls[0] }), 2, ' with two members');
is ($acls[0][0], 'fourth', ' and the first member is correct');
is ($acls[0][1], 'third', ' and the second member is correct');

# Add another line to the third ACL.  Now we match second.
is ($server->acl_add ('third', 'base', 'foo'), 1,
    'Adding another line to the third ACL works');
@acls = $report->acls ('duplicate');
is (scalar (@acls), 1, 'There is one set of duplicate ACLs');
is (scalar (@{ $acls[0] }), 2, ' with two members');
is ($acls[0][0], 'second', ' and the first member is correct');
is ($acls[0][1], 'third', ' and the second member is correct');

# Add yet another line to the third ACL.  Now all ACLs are distinct.
is ($server->acl_add ('third', 'base', 'baz'), 1,
    'Adding another line to the third ACL works');
@acls = $report->acls ('duplicate');
is (scalar (@acls), 0, 'There are no duplicate ACLs');
is ($report->error, undef, ' and no error');

# Clean up.
$admin->destroy;
system ('rm -r test-files') == 0 or die "cannot remove test-files\n";
END {
    unlink 'wallet-db';
}
