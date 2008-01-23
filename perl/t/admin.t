#!/usr/bin/perl -w
# $Id$
#
# t/admin.t -- Tests for wallet administrative interface.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2008 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

use Test::More tests => 22;

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
is ($acls[0], 1, ' and that is ACL ID 1');

# Register a base object so that we can create a simple object.
my $schema = Wallet::Schema->new;
$schema->register_object ($admin->dbh, 'base', 'Wallet::Object::Base');

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

# Create another ACL.
is ($server->acl_create ('first'), 1, 'ACL creation succeeds');
@acls = $admin->list_acls;
is (scalar (@acls), 2, ' and now there are two ACLs');
is ($acls[0], 1, ' and the first ID is correct');
is ($acls[1], 2, ' and the second ID is correct');

# Delete that ACL and create another.
is ($server->acl_create ('second'), 1, 'Second ACL creation succeeds');
is ($server->acl_destroy ('first'), 1, ' and deletion of the first succeeds');
@acls = $admin->list_acls;
is (scalar (@acls), 2, ' and there are still two ACLs');
is ($acls[0], 1, ' and the first ID is still the same');
is ($acls[1], 3, ' but the second ID has changed');

# Clean up.
is ($admin->destroy, 1, 'Destruction succeeds');
unlink 'wallet-db';
