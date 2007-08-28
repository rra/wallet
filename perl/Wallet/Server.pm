# Wallet::Server -- Wallet system server implementation.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007 Board of Trustees, Leland Stanford Jr. University
#
# See README for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Server;
require 5.006;

use strict;
use vars qw(%MAPPING $VERSION);

use Wallet::ACL;
use Wallet::Object::Keytab;

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.01';

# This is a mapping of object types to class names, used to determine which
# object implementation should be instantiated for a given object type.
# Currently, there's no dynamic way to recognize new object types, so if you
# extend the wallet system to add new object types, you need to modify this
# list.
%MAPPING = (keytab => 'Wallet::Object::Keytab');

##############################################################################
# Utility methods
##############################################################################

# Create a new wallet server object.  A new server should be created for each
# user who is making changes to the wallet.  Takes the database handle that
# will be used for all of the wallet metadata and the principal and host who
# are sending wallet requests.  We also instantiate the administrative ACL,
# which we'll use for various things.  Throw an exception if anything goes
# wrong.
sub new {
    my ($class, $dbh, $user, $host) = @_;
    my $acl = Wallet::ACL->new ('ADMIN');
    my $self = {
        dbh   => $dbh,
        user  => $user,
        host  => $host,
        admin => $acl,
    };
    bless ($self, $class);
    return $self;
}

# Returns the error from the previous failed operation.
sub error {
    my ($self) = @_;
    return $self->{error};
}

##############################################################################
# Object methods
##############################################################################

# Create a new object and returns that object.  On error, returns undef and
# sets the internal error.
#
# For the time being, we hard-code an ACL named ADMIN to use to authorize
# object creation.  This needs more work later.
sub create {
    my ($self, $name, $type) = @_;
    unless ($MAPPING{$type}) {
        $self->{error} = "unknown object type $type";
        return undef;
    }
    my $class = $MAPPING{$type};
    my $dbh = $self->{dbh};
    my $user = $self->{user};
    my $host = $self->{host};
    unless ($self->{admin}->check ($user)) {
        $self->{error} = "$user not authorized to create ${type}:${name}";
        return undef;
    }
    my $object = eval { $class->create ($name, $type, $dbh, $user, $host) };
    if ($@) {
        $self->{error} = $@;
        return undef;
    } else {
        return $object;
    }
}

# Given the name and type of an object, returns a Perl object representing it
# or returns undef and sets the internal error.
sub retrieve {
    my ($self, $name, $type) = @_;
    unless ($MAPPING{$type}) {
        $self->{error} = "unknown object type $type";
        return undef;
    }
    my $class = $MAPPING{$type};
    my $object = eval { $class->new ($name, $type, $self->{dbh}) };
    if ($@) {
        $self->{error} = $@;
        return undef;
    } else {
        return $object;
    }
}

# Sets the internal error variable to the correct message for permission
# denied on an object.
sub object_error {
    my ($self, $object, $action) = @_;
    my $user = $self->{user};
    my $id = $object->type . ':' . $object->name;
    if ($action !~ /^(create|get|set|show|destroy)\z/) {
        $action = "set $action for";
    }
    $self->{error} = "$self->{user} not authorized to $action $id";
}

# Given an object and an action, checks if the current user has access to
# perform that object.  If so, returns true.  If not, returns undef and sets
# the internal error message.
sub acl_check {
    my ($self, $object, $action) = @_;
    unless ($action =~ /^(get|store|show|destroy|flags)\z/) {
        $self->{error} = "unknown action $action";
        return undef;
    }
    return 1 if $self->{admin}->check ($self->{user});
    my $id = $object->acl ($action);
    if (not defined $id && $action =~ /^(get|store|show)\z/) {
        $id = $object->owner;
    }
    unless (defined $id) {
        $self->object_error ($object, $action);
        return undef;
    }
    my $acl = eval { Wallet::ACL->new ($id) };
    if ($@) {
        $self->{error} = $@;
        return undef;
    }
    my $status = $acl->check ($self->{user});
    if ($status == 1) {
        return 1;
    } elsif (not defined $status) {
        $self->{error} = $acl->error;
        return undef;
    } else {
        $self->object_error ($object, $action);
        return undef;
    }
}

# Retrieves or sets an ACL on an object.
sub acl {
    my ($self, $name, $type, $acl, $id) = @_;
    my $object = $self->retrieve ($name, $type);
    return undef unless defined $object;
    unless ($self->{admin}->check ($self->{user})) {
        $self->object_error ($object, 'ACL');
        return undef;
    }
    if ($id) {
        return $object->acl ($acl, $id, $self->{user}, $self->{host});
    } else {
        return $object->acl ($acl);
    }
}

# Retrieves or sets the expiration of an object.
sub expires {
    my ($self, $name, $type, $expires) = @_;
    my $object = $self->retrieve ($name, $type);
    return undef unless defined $object;
    unless ($self->{admin}->check ($self->{user})) {
        $self->object_error ($object, 'expires');
        return undef;
    }
    if ($expires) {
        return $object->expires ($expires, $self->{user}, $self->{host});
    } else {
        return $object->expires;
    }
}

# Retrieves or sets the owner of an object.
sub owner {
    my ($self, $name, $type, $owner) = @_;
    my $object = $self->retrieve ($name, $type);
    return undef unless defined $object;
    unless ($self->{admin}->check ($self->{user})) {
        $self->object_error ($object, 'owner');
        return undef;
    }
    if ($owner) {
        return $object->owner ($owner, $self->{user}, $self->{host});
    } else {
        return $object->owner;
    }
}

# Retrieve the information associated with an object, or returns undef and
# sets the internal error if the retrieval fails or if the user isn't
# authorized.
sub get {
    my ($self, $name, $type) = @_;
    my $object = $self->retrieve ($name, $type);
    return undef unless defined $object;
    return undef unless $self->acl_check ($object, 'get');
    return $object->get ($self->{user}, $self->{host});
}

# Store new data in an object, or returns undef and sets the internal error if
# the object can't be found or if the user isn't authorized.
sub store {
    my ($self, $name, $type) = @_;
    my $object = $self->retrieve ($name, $type);
    return undef unless defined $object;
    return undef unless $self->acl_check ($object, 'store');
    return $object->get ($self->{user}, $self->{host});
}

# Return a human-readable description of the object's metadata, or returns
# undef and sets the internal error if the object can't be found or if the
# user isn't authorized.
sub show {
    my ($self, $name, $type) = @_;
    my $object = $self->retrieve ($name, $type);
    return undef unless defined $object;
    return undef unless $self->acl_check ($object, 'show');
    return $object->show;
}

# Destroys the object, or returns undef and sets the internal error if the
# object can't be found or if the user isn't authorized.
sub destroy {
    my ($self, $name, $type) = @_;
    my $object = $self->retrieve ($name, $type);
    return undef unless defined $object;
    unless ($self->{admin}->check ($self->{user})) {
        $self->object_error ($object, 'owner');
        return undef;
    }
    return $object->destroy ($self->{user}, $self->{host});
}

##############################################################################
# ACL methods
##############################################################################

# Create a new empty ACL in the database.  Returns the new ACL object on
# success and undef on failure, setting the internal error.
sub acl_create {
    my ($self, $name) = @_;
    unless ($self->{admin}->check ($self->{user})) {
        $self->{error} = "$self->{user} not authorized to create ACL";
        return undef;
    }
    my $dbh = $self->{dbh};
    my $user = $self->{user};
    my $host = $self->{host};
    my $acl = eval { Wallet::ACL->create ($name, $dbh, $user, $host) };
    if ($@) {
        $self->{error} = $@;
        return undef;
    } else {
        return $acl;
    }
}

# Sets the internal error variable to the correct message for permission
# denied on an ACL.
sub acl_error {
    my ($self, $acl, $action) = @_;
    my $user = $self->{user};
    if ($action eq 'add') {
        $action = 'add to';
    } elsif ($action eq 'remove') {
        $action = 'remove from';
    }
    $self->{error} = "$self->{user} not authorized to $action ACL $acl";
}

# Change the human-readable name of an ACL or return undef and set the
# internal error.
sub acl_rename {
    my ($self, $id, $name) = @_;
    unless ($self->{admin}->check ($self->{user})) {
        $self->acl_error ($id, 'rename');
        return undef;
    }
    my $acl = { Wallet::ACL->new ($id, $self->{dbh}) };
    if ($@) {
        $self->{error} = $@;
        return undef;
    }
    unless ($acl->rename ($name)) {
        $self->{error} = $acl->error;
        return undef;
    }
    return 1;
}

# Destroy an ACL, deleting it out of the database.  Returns true on success.
# On failure, returns undef, setting the internal error.
sub acl_destroy {
    my ($self, $id) = @_;
    unless ($self->{admin}->check ($self->{user})) {
        $self->acl_error ($id, 'destroy');
        return undef;
    }
    my $acl = { Wallet::ACL->new ($id, $self->{dbh}) };
    if ($@) {
        $self->{error} = $@;
        return undef;
    }
    unless ($acl->destroy ($self->{user}, $self->{host})) {
        $self->{error} = $acl->error;
        return undef;
    }
    return 1;
}

# Add an ACL entry to an ACL.  Returns true on success.  On failure, returns
# undef, setting the internal error.
sub acl_add {
    my ($self, $id, $scheme, $identifier) = @_;
    unless ($self->{admin}->check ($self->{user})) {
        $self->acl_error ($id, 'add');
        return undef;
    }
    my $acl = { Wallet::ACL->new ($id, $self->{dbh}) };
    if ($@) {
        $self->{error} = $@;
        return undef;
    }
    unless ($acl->add ($scheme, $identifier, $self->{user}, $self->{host})) {
        $self->{error} = $acl->error;
        return undef;
    }
    return 1;
}

# Remove an ACL entry to an ACL.  Returns true on success.  On failure,
# returns undef, setting the internal error.
sub acl_remove {
    my ($self, $id, $scheme, $identifier) = @_;
    unless ($self->{admin}->check ($self->{user})) {
        $self->acl_error ($id, 'remove');
        return undef;
    }
    my $acl = { Wallet::ACL->new ($id, $self->{dbh}) };
    if ($@) {
        $self->{error} = $@;
        return undef;
    }
    my $user = $self->{user};
    my $host = $self->{host};
    unless ($acl->remove ($scheme, $identifier, $user, $host)) {
        $self->{error} = $acl->error;
        return undef;
    }
    return 1;
}

1;
__END__
