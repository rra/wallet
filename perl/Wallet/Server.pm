# Wallet::Server -- Wallet system server implementation.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007, 2008, 2010, 2011
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Server;
require 5.006;

use strict;
use vars qw(%MAPPING $VERSION);

use Wallet::ACL;
use Wallet::Config;
use Wallet::Database;
use Wallet::Schema;

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.10';

##############################################################################
# Utility methods
##############################################################################

# Create a new wallet server object.  A new server should be created for each
# user who is making changes to the wallet.  Takes the principal and host who
# are sending wallet requests.  Opens a connection to the database that will
# be used for all of the wallet metadata based on the wallet configuration
# information.  We also instantiate the administrative ACL, which we'll use
# for various things.  Throw an exception if anything goes wrong.
sub new {
    my ($class, $user, $host) = @_;
    my $dbh = Wallet::Database->connect;
    my $acl = Wallet::ACL->new ('ADMIN', $dbh);
    my $self = {
        dbh   => $dbh,
        user  => $user,
        host  => $host,
        admin => $acl,
    };
    bless ($self, $class);
    return $self;
}

# Returns the database handle (used mostly for testing).
sub dbh {
    my ($self) = @_;
    return $self->{dbh};
}

# Set or return the error stashed in the object.
sub error {
    my ($self, @error) = @_;
    if (@error) {
        my $error = join ('', @error);
        chomp $error;
        1 while ($error =~ s/ at \S+ line \d+\.?\z//);
        $self->{error} = $error;
    }
    return $self->{error};
}

# Disconnect the database handle on object destruction to avoid warnings.
sub DESTROY {
    my ($self) = @_;
    if ($self->{dbh} and not $self->{dbh}->{InactiveDestroy}) {
        $self->{dbh}->disconnect;
    }
}

##############################################################################
# Object methods
##############################################################################

# Given an object type, return the mapping to a class by querying the
# database, or undef if no mapping exists.  Also load the relevant module.
sub type_mapping {
    my ($self, $type) = @_;
    my $class;
    eval {
        my $sql = 'select ty_class from types where ty_name = ?';
        ($class) = $self->{dbh}->selectrow_array ($sql, undef, $type);
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ($@);
        $self->{dbh}->rollback;
        return;
    }
    if (defined $class) {
        eval "require $class";
        if ($@) {
            $self->error ($@);
            return;
        }
    }
    return $class;
}

# Given an object which doesn't currently exist, check whether a default_owner
# function is defined and, if so, if it returns an ACL for that object.  If
# so, create the ACL and check if the current user is authorized by that ACL.
# Returns true if so, false if not, setting the internal error as appropriate.
#
# This leaves those new ACLs in the database, which may not be the best
# behavior, but it's the simplest given the current Wallet::ACL API.  This
# should probably be revisited later.
sub create_check {
    my ($self, $type, $name) = @_;
    my $user = $self->{user};
    my $host = $self->{host};
    my $dbh = $self->{dbh};
    unless (defined (&Wallet::Config::default_owner)) {
        $self->error ("$user not authorized to create ${type}:${name}");
        return;
    }
    my ($aname, @acl) = Wallet::Config::default_owner ($type, $name);
    unless (defined $aname) {
        $self->error ("$user not authorized to create ${type}:${name}");
        return;
    }
    my $acl = eval { Wallet::ACL->new ($aname, $dbh) };
    if ($@) {
        $acl = eval { Wallet::ACL->create ($aname, $dbh, $user, $host) };
        if ($@) {
            $self->error ($@);
            return;
        }
        for my $entry (@acl) {
            unless ($acl->add ($entry->[0], $entry->[1], $user, $host)) {
                $self->error ($acl->error);
                return;
            }
        }
    } else {
        my @entries = $acl->list;
        if (not @entries and $acl->error) {
            $self->error ($acl->error);
            return;
        }
        @entries = sort { $$a[0] cmp $$b[0] && $$a[1] cmp $$b[1] } @entries;
        @acl     = sort { $$a[0] cmp $$b[0] && $$a[1] cmp $$b[1] } @acl;
        my $okay = 1;
        if (@entries != @acl) {
            $okay = 0;
        } else {
            for my $i (0 .. $#entries) {
                $okay = 0 unless ($entries[$i][0] eq $acl[$i][0]);
                $okay = 0 unless ($entries[$i][1] eq $acl[$i][1]);
            }
        }
        unless ($okay) {
            $self->error ("ACL $aname exists and doesn't match default");
            return;
        }
    }
    if ($acl->check ($user)) {
        return $aname;
    } else {
        $self->error ("$user not authorized to create ${type}:${name}");
        return;
    }
}

# Create an object and returns it.  This function is called by both create and
# autocreate and assumes that permissions and names have already been checked.
# On error, returns undef and sets the internal error.
sub create_object {
    my ($self, $type, $name) = @_;
    my $class = $self->type_mapping ($type);
    unless ($class) {
        $self->error ("unknown object type $type");
        return;
    }
    my $dbh = $self->{dbh};
    my $user = $self->{user};
    my $host = $self->{host};
    my $object = eval { $class->create ($type, $name, $dbh, $user, $host) };
    if ($@) {
        $self->error ($@);
        return;
    }
    return $object;
}

# Create a new object and returns that object.  This method can only be called
# by wallet administrators.  autocreate should be used by regular users who
# may benefit from default ACLs.  On error, returns undef and sets the
# internal error.
sub create {
    my ($self, $type, $name) = @_;
    unless ($self->{admin}->check ($self->{user})) {
        my $id = $type . ':' . $name;
        $self->error ("$self->{user} not authorized to create $id");
        return;
    }
    if (defined (&Wallet::Config::verify_name)) {
        my $error = Wallet::Config::verify_name ($type, $name, $self->{user});
        if ($error) {
            $self->error ("${type}:${name} rejected: $error");
            return;
        }
    }
    return unless $self->create_object ($type, $name);
    return 1;
}

# Attempt to auto-create an object based on default ACLs.  This method is
# called by the wallet client when trying to get an object that doesn't
# already exist.  On error, returns undef and sets the internal error.
sub autocreate {
    my ($self, $type, $name) = @_;
    if (defined (&Wallet::Config::verify_name)) {
        my $error = Wallet::Config::verify_name ($type, $name, $self->{user});
        if ($error) {
            $self->error ("${type}:${name} rejected: $error");
            return;
        }
    }
    my $acl = $self->create_check ($type, $name);
    return unless $acl;
    my $object = $self->create_object ($type, $name);
    return unless $object;
    unless ($object->owner ($acl, $self->{user}, $self->{host})) {
        $self->error ($object->error);
        return;
    }
    return 1;
}

# Given the name and type of an object, returns a Perl object representing it
# or returns undef and sets the internal error.
sub retrieve {
    my ($self, $type, $name) = @_;
    my $class = $self->type_mapping ($type);
    unless ($class) {
        $self->error ("unknown object type $type");
        return;
    }
    my $object = eval { $class->new ($type, $name, $self->{dbh}) };
    if ($@) {
        $self->error ($@);
        return;
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
    if ($action eq 'getattr') {
        $action = "get attributes for";
    } elsif ($action eq 'setattr') {
        $action = "set attributes for";
    } elsif ($action !~ /^(create|get|store|show|destroy)\z/) {
        $action = "set $action for";
    }
    $self->error ("$self->{user} not authorized to $action $id");
}

# Given an object and an action, checks if the current user has access to
# perform that object.  If so, returns true.  If not, returns undef and sets
# the internal error message.  Note that we do not allow any special access to
# admins for get and store; if they want to do that with objects, they need to
# set the ACL accordingly.
sub acl_check {
    my ($self, $object, $action) = @_;
    my %actions = map { $_ => 1 }
        qw(get store show destroy flags setattr getattr comment);
    unless ($actions{$action}) {
        $self->error ("unknown action $action");
        return;
    }
    if ($action ne 'get' and $action ne 'store') {
        return 1 if $self->{admin}->check ($self->{user});
    }
    my $id;
    if ($action eq 'getattr') {
        $id = $object->acl ('show');
    } elsif ($action eq 'setattr') {
        $id = $object->acl ('store');
    } elsif ($action ne 'comment') {
        $id = $object->acl ($action);
    }
    if (! defined ($id) and $action ne 'flags' and $action ne 'destroy') {
        $id = $object->owner;
    }
    unless (defined $id) {
        $self->object_error ($object, $action);
        return;
    }
    my $acl = eval { Wallet::ACL->new ($id, $self->{dbh}) };
    if ($@) {
        $self->error ($@);
        return;
    }
    my $status = $acl->check ($self->{user});
    if ($status == 1) {
        return 1;
    } elsif (not defined $status) {
        $self->error ($acl->error);
        return;
    } else {
        $self->object_error ($object, $action);
        return;
    }
}

# Retrieves or sets an ACL on an object.
sub acl {
    my ($self, $type, $name, $acl, $id) = @_;
    undef $self->{error};
    my $object = $self->retrieve ($type, $name);
    return unless defined $object;
    unless ($self->{admin}->check ($self->{user})) {
        $self->object_error ($object, 'ACL');
        return;
    }
    my $result;
    if (defined $id) {
        $result = $object->acl ($acl, $id, $self->{user}, $self->{host});
    } else {
        $result = $object->acl ($acl);
    }
    if (not defined ($result) and $object->error) {
        $self->error ($object->error);
    }
    return $result;
}

# Retrieves or sets an attribute on an object.
sub attr {
    my ($self, $type, $name, $attr, @values) = @_;
    undef $self->{error};
    my $object = $self->retrieve ($type, $name);
    return unless defined $object;
    my $user = $self->{user};
    my $host = $self->{host};
    if (@values) {
        return unless $self->acl_check ($object, 'setattr');
        if (@values == 1 and $values[0] eq '') {
            @values = ();
        }
        my $result = $object->attr ($attr, [ @values ], $user, $host);
        $self->error ($object->error) unless $result;
        return $result;
    } else {
        return unless $self->acl_check ($object, 'getattr');
        my @result = $object->attr ($attr);
        if (not @result and $object->error) {
            $self->error ($object->error);
            return;
        } else {
            return @result;
        }
    }
}

# Retrieves or sets the comment of an object.
sub comment {
    my ($self, $type, $name, $comment) = @_;
    undef $self->{error};
    my $object = $self->retrieve ($type, $name);
    return unless defined $object;
    my $result;
    if (defined $comment) {
        return unless $self->acl_check ($object, 'comment');
        $result = $object->comment ($comment, $self->{user}, $self->{host});
    } else {
        return unless $self->acl_check ($object, 'show');
        $result = $object->comment;
    }
    if (not defined ($result) and $object->error) {
        $self->error ($object->error);
    }
    return $result;
}

# Retrieves or sets the expiration of an object.
sub expires {
    my ($self, $type, $name, $expires) = @_;
    undef $self->{error};
    my $object = $self->retrieve ($type, $name);
    return unless defined $object;
    unless ($self->{admin}->check ($self->{user})) {
        $self->object_error ($object, 'expires');
        return;
    }
    my $result;
    if (defined $expires) {
        $result = $object->expires ($expires, $self->{user}, $self->{host});
    } else {
        $result = $object->expires;
    }
    if (not defined ($result) and $object->error) {
        $self->error ($object->error);
    }
    return $result;
}

# Retrieves or sets the owner of an object.
sub owner {
    my ($self, $type, $name, $owner) = @_;
    undef $self->{error};
    my $object = $self->retrieve ($type, $name);
    return unless defined $object;
    unless ($self->{admin}->check ($self->{user})) {
        $self->object_error ($object, 'owner');
        return;
    }
    my $result;
    if (defined $owner) {
        $result = $object->owner ($owner, $self->{user}, $self->{host});
    } else {
        $result = $object->owner;
    }
    if (not defined ($result) and $object->error) {
        $self->error ($object->error);
    }
    return $result;
}

# Checks for the existence of an object.  Returns 1 if it does, 0 if it
# doesn't, and undef if there was an error in checking the existence of the
# object.
sub check {
    my ($self, $type, $name) = @_;
    my $object = $self->retrieve ($type, $name);
    if (not defined $object) {
        if ($self->error =~ /^cannot find/) {
            return 0;
        } else {
            return;
        }
    }
    return 1;
}

# Retrieve the information associated with an object, or returns undef and
# sets the internal error if the retrieval fails or if the user isn't
# authorized.  If the object doesn't exist, attempts dynamic creation of the
# object using the default ACL mappings (if any).
sub get {
    my ($self, $type, $name) = @_;
    my $object = $self->retrieve ($type, $name);
    return unless defined $object;
    return unless $self->acl_check ($object, 'get');
    my $result = $object->get ($self->{user}, $self->{host});
    $self->error ($object->error) unless defined $result;
    return $result;
}

# Store new data in an object, or returns undef and sets the internal error if
# the object can't be found or if the user isn't authorized.  Also don't
# permit storing undef, although storing the empty string is fine.  If the
# object doesn't exist, attempts dynamic creation of the object using the
# default ACL mappings (if any).
sub store {
    my ($self, $type, $name, $data) = @_;
    my $object = $self->retrieve ($type, $name);
    return unless defined $object;
    return unless $self->acl_check ($object, 'store');
    if (not defined ($data)) {
        $self->{error} = "no data supplied to store";
        return;
    }
    my $result = $object->store ($data, $self->{user}, $self->{host});
    $self->error ($object->error) unless defined $result;
    return $result;
}

# Return a human-readable description of the object's metadata, or returns
# undef and sets the internal error if the object can't be found or if the
# user isn't authorized.
sub show {
    my ($self, $type, $name) = @_;
    my $object = $self->retrieve ($type, $name);
    return unless defined $object;
    return unless $self->acl_check ($object, 'show');
    my $result = $object->show;
    $self->error ($object->error) unless defined $result;
    return $result;
}

# Return a human-readable description of the object history, or returns undef
# and sets the internal error if the object can't be found or if the user
# isn't authorized.
sub history {
    my ($self, $type, $name) = @_;
    my $object = $self->retrieve ($type, $name);
    return unless defined $object;
    return unless $self->acl_check ($object, 'show');
    my $result = $object->history;
    $self->error ($object->error) unless defined $result;
    return $result;
}

# Destroys the object, or returns undef and sets the internal error if the
# object can't be found or if the user isn't authorized.
sub destroy {
    my ($self, $type, $name) = @_;
    my $object = $self->retrieve ($type, $name);
    return unless defined $object;
    return unless $self->acl_check ($object, 'destroy');
    my $result = $object->destroy ($self->{user}, $self->{host});
    $self->error ($object->error) unless defined $result;
    return $result;
}

##############################################################################
# Object flag methods
##############################################################################

# Clear a flag on an object.  Takes the object and the flag.  Returns true on
# success or undef and sets the internal error on failure.
sub flag_clear {
    my ($self, $type, $name, $flag) = @_;
    my $object = $self->retrieve ($type, $name);
    return unless defined $object;
    return unless $self->acl_check ($object, 'flags');
    my $result = $object->flag_clear ($flag, $self->{user}, $self->{host});
    $self->error ($object->error) unless defined $result;
    return $result;
}

# Set a flag on an object.  Takes the object and the flag.  Returns true on
# success or undef and sets the internal error on failure.
sub flag_set {
    my ($self, $type, $name, $flag) = @_;
    my $object = $self->retrieve ($type, $name);
    return unless defined $object;
    return unless $self->acl_check ($object, 'flags');
    my $result = $object->flag_set ($flag, $self->{user}, $self->{host});
    $self->error ($object->error) unless defined $result;
    return $result;
}

##############################################################################
# ACL methods
##############################################################################

# Create a new empty ACL in the database.  Returns true on success and undef
# on failure, setting the internal error.
sub acl_create {
    my ($self, $name) = @_;
    unless ($self->{admin}->check ($self->{user})) {
        $self->error ("$self->{user} not authorized to create ACL");
        return;
    }
    my $user = $self->{user};
    my $host = $self->{host};
    if (defined (&Wallet::Config::verify_acl_name)) {
        my $error = Wallet::Config::verify_acl_name ($name, $user);
        if ($error) {
            $self->error ("$name rejected: $error");
            return;
        }
    }
    my $dbh = $self->{dbh};
    my $acl = eval { Wallet::ACL->create ($name, $dbh, $user, $host) };
    if ($@) {
        $self->error ($@);
        return;
    } else {
        return 1;
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
    } elsif ($action eq 'history') {
        $action = 'see history of';
    }
    $self->error ("$self->{user} not authorized to $action ACL $acl");
}

# Display the history of an ACL or return undef and set the internal error.
sub acl_history {
    my ($self, $id) = @_;
    unless ($self->{admin}->check ($self->{user})) {
        $self->acl_error ($id, 'history');
        return;
    }
    my $acl = eval { Wallet::ACL->new ($id, $self->{dbh}) };
    if ($@) {
        $self->error ($@);
        return;
    }
    my $result = $acl->history;
    if (not defined $result) {
        $self->error ($acl->error);
        return;
    }
    return $result;
}

# Display the membership of an ACL or return undef and set the internal error.
sub acl_show {
    my ($self, $id) = @_;
    unless ($self->{admin}->check ($self->{user})) {
        $self->acl_error ($id, 'show');
        return;
    }
    my $acl = eval { Wallet::ACL->new ($id, $self->{dbh}) };
    if ($@) {
        $self->error ($@);
        return;
    }
    my $result = $acl->show;
    if (not defined $result) {
        $self->error ($acl->error);
        return;
    }
    return $result;
}

# Change the human-readable name of an ACL or return undef and set the
# internal error.
sub acl_rename {
    my ($self, $id, $name) = @_;
    unless ($self->{admin}->check ($self->{user})) {
        $self->acl_error ($id, 'rename');
        return;
    }
    my $acl = eval { Wallet::ACL->new ($id, $self->{dbh}) };
    if ($@) {
        $self->error ($@);
        return;
    }
    if ($acl->name eq 'ADMIN') {
        $self->error ('cannot rename the ADMIN ACL');
        return;
    }
    if (defined (&Wallet::Config::verify_acl_name)) {
        my $error = Wallet::Config::verify_acl_name ($name, $self->{user});
        if ($error) {
            $self->error ("$name rejected: $error");
            return;
        }
    }
    unless ($acl->rename ($name)) {
        $self->error ($acl->error);
        return;
    }
    return 1;
}

# Destroy an ACL, deleting it out of the database.  Returns true on success.
# On failure, returns undef, setting the internal error.
sub acl_destroy {
    my ($self, $id) = @_;
    unless ($self->{admin}->check ($self->{user})) {
        $self->acl_error ($id, 'destroy');
        return;
    }
    my $acl = eval { Wallet::ACL->new ($id, $self->{dbh}) };
    if ($@) {
        $self->error ($@);
        return;
    }
    if ($acl->name eq 'ADMIN') {
        $self->error ('cannot destroy the ADMIN ACL');
        return;
    }
    unless ($acl->destroy ($self->{user}, $self->{host})) {
        $self->error ($acl->error);
        return;
    }
    return 1;
}

# Add an ACL entry to an ACL.  Returns true on success.  On failure, returns
# undef, setting the internal error.
sub acl_add {
    my ($self, $id, $scheme, $identifier) = @_;
    unless ($self->{admin}->check ($self->{user})) {
        $self->acl_error ($id, 'add');
        return;
    }
    my $acl = eval { Wallet::ACL->new ($id, $self->{dbh}) };
    if ($@) {
        $self->error ($@);
        return;
    }
    unless ($acl->add ($scheme, $identifier, $self->{user}, $self->{host})) {
        $self->error ($acl->error);
        return;
    }
    return 1;
}

# Remove an ACL entry to an ACL.  Returns true on success.  On failure,
# returns undef, setting the internal error.
sub acl_remove {
    my ($self, $id, $scheme, $identifier) = @_;
    unless ($self->{admin}->check ($self->{user})) {
        $self->acl_error ($id, 'remove');
        return;
    }
    my $acl = eval { Wallet::ACL->new ($id, $self->{dbh}) };
    if ($@) {
        $self->error ($@);
        return;
    }
    if ($acl->name eq 'ADMIN') {
        my @e = $acl->list;
        if (not @e and $acl->error) {
            $self->error ($acl->error);
            return;
        } elsif (@e == 1 && $e[0][0] eq $scheme && $e[0][1] eq $identifier) {
            $self->error ('cannot remove last ADMIN ACL entry');
            return;
        }
    }
    my $user = $self->{user};
    my $host = $self->{host};
    unless ($acl->remove ($scheme, $identifier, $user, $host)) {
        $self->error ($acl->error);
        return;
    }
    return 1;
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=head1 NAME

Wallet::Server - Wallet system server implementation

=for stopwords
keytabs metadata backend HOSTNAME ACL timestamp ACL's nul Allbery
backend-specific wallet-backend

=head1 SYNOPSIS

    use Wallet::Server;
    my $server = Wallet::Server->new ($user, $host);
    $server->create ('keytab', 'host/example.com@EXAMPLE.COM');

=head1 DESCRIPTION

Wallet::Server is the top-level class that implements the wallet server.
The wallet is a system for storing, generating, and retrieving secure
information such as Kerberos keytabs.  The server maintains metadata about
the objects, checks access against ACLs, and dispatches requests for
objects to backend implementations for that object type.

Wallet::Server is normally instantiated and used by B<wallet-backend>, a
thin wrapper around this object that determines the authenticated remote
user and gets user input and then calls the appropriate method of this
object.

To use this object, several configuration variables must be set (at least
the database configuration).  For information on those variables and how
to set them, see L<Wallet::Config>.

=head1 CLASS METHODS

=over 4

=item new(PRINCIPAL, HOSTNAME)

Creates a new wallet server object for actions from the user PRINCIPAL
connecting from HOSTNAME.  PRINCIPAL and HOSTNAME will be used for logging
history information for all subsequent operations.  new() opens the
database, using the database configuration as set by Wallet::Config and
ensures that the C<ADMIN> ACL exists.  That ACL will be used to authorize
privileged operations.

On any error, this method throws an exception.

=back

=head1 INSTANCE METHODS

For all methods that can fail, the caller should call error() after a
failure to get the error message.

=over 4

=item acl(TYPE, NAME, ACL [, ID])

Gets or sets the ACL type ACL to ID for the object identified by TYPE and
NAME.  ACL should be one of C<get>, C<store>, C<show>, C<destroy>, or
C<flags>.  If ID is not given, returns the current setting of that ACL as
a numeric ACL ID or undef if that ACL isn't set or on failure.  To
distinguish between an ACL that isn't set and a failure to retrieve the
ACL, the caller should call error() after an undef return.  If error()
also returns undef, that ACL wasn't set; otherwise, error() will return
the error message.

If ID is given, sets the specified ACL to ID, which can be either the name
of an ACL or a numeric ACL ID.  To clear the ACL, pass in an empty string
as the ID.  To set or clear an ACL, the current user must be authorized by
the ADMIN ACL.  Returns true for success and false for failure.

ACL settings are checked before the owner and override the owner setting.

=item acl_add(ID, SCHEME, IDENTIFIER)

Adds an ACL entry with scheme SCHEME and identifier IDENTIFIER to the ACL
identified by ID.  ID may be either the ACL name or the numeric ACL ID.
SCHEME must be a valid ACL scheme for which the wallet system has an ACL
verifier implementation.  To add an entry to an ACL, the current user must
be authorized by the ADMIN ACL.  Returns true for success and false for
failure.

=item acl_create(NAME)

Create a new ACL with the specified NAME, which must not be all-numeric.
The newly created ACL will be empty.  To create an ACL, the current user
must be authorized by the ADMIN ACL.  Returns true on success and false on
failure.

=item acl_destroy(ID)

Destroys the ACL identified by ID, which may be either the ACL name or its
numeric ID.  This call will fail if the ACL is still referenced by any
object.  The ADMIN ACL may not be destroyed.  To destroy an ACL, the
current user must be authorized by the ADMIN ACL.  Returns true on success
and false on failure.

=item acl_history(ID)

Returns the history of the ACL identified by ID, which may be either the
ACL name or its numeric ID.  To see the history of an ACL, the current
user must be authorized by the ADMIN ACL.  Each change that modifies the
ACL (not counting changes in the name of the ACL) will be represented by
two lines.  The first line will have a timestamp of the change followed by
a description of the change, and the second line will give the user who
made the change and the host from which the change was made.  Returns
undef on failure.

=item acl_remove(ID, SCHEME, IDENTIFIER)

Removes from the ACL identified by ID the entry matching SCHEME and
IDENTIFIER.  ID may be either the name of the ACL or its numeric ID.  The
last entry in the ADMIN ACL cannot be removed.  To remove an entry from an
ACL, the current user must be authorized by the ADMIN ACL.  Returns true
on success and false on failure.

=item acl_rename(OLD, NEW)

Renames the ACL identified by OLD to NEW.  This changes the human-readable
name, not the underlying numeric ID, so the ACL's associations with
objects will be unchanged.  The ADMIN ACL may not be renamed.  OLD may be
either the current name or the numeric ID.  NEW must not be all-numeric.
To rename an ACL, the current user must be authorized by the ADMIN ACL.
Returns true on success and false on failure.

=item acl_show(ID)

Returns a human-readable description, including membership, of the ACL
identified by ID, which may be either the ACL name or its numeric ID.  To
show an ACL, the current user must be authorized by the ADMIN ACL
(although be aware that anyone with show access to an object can see the
membership of ACLs associated with that object through the show() method).
Returns the human-readable description on success and undef on failure.

=item attr(TYPE, NAME, ATTRIBUTE [, VALUE ...])

Sets or retrieves a given object attribute.  Attributes are used to store
backend-specific information for a particular object type and ATTRIBUTE
must be an attribute type known to the underlying object implementation.

If VALUE is not given, returns the values of that attribute, if any, as a
list.  On error, returns the empty list.  To distinguish between an error
and an empty return, call error() afterward.  It is guaranteed to return
undef unless there was an error.  To retrieve an attribute setting, the
user must be authorized by the ADMIN ACL, the show ACL if set, or the
owner ACL if the show ACL is not set.

If VALUE is given, sets the given ATTRIBUTE values to VALUE, which is one
or more attribute values.  Pass the empty string as the only VALUE to
clear the attribute values.  Returns true on success and false on failure.
To set an attribute value, the user must be authorized by the ADMIN ACL,
the store ACL if set, or the owner ACL if the store ACL is not set.

=item autocreate(TYPE, NAME)

Creates a new object of type TYPE and name NAME.  TYPE must be a
recognized type for which the wallet system has a backend implementation.
Returns true on success and false on failure.

To create an object using this method, the current user must be authorized
by the default owner as determined by the wallet configuration.  For more
information on how to map new objects to default owners, see
Wallet::Config(3).  Wallet administrators should use the create() method
to create objects.

=item check(TYPE, NAME)

Check whether an object of type TYPE and name NAME exists.  Returns 1 if
it does, 0 if it doesn't, and undef if some error occurred while checking
for the existence of the object.

=item comment(TYPE, NAME, [COMMENT])

Gets or sets the comment for the object identified by TYPE and NAME.  If
COMMENT is not given, returns the current comment or undef if no comment
is set or on an error.  To distinguish between an expiration that isn't
set and a failure to retrieve the expiration, the caller should call
error() after an undef return.  If error() also returns undef, no comment
was set; otherwise, error() will return the error message.

If COMMENT is given, sets the comment to COMMENT.  Pass in the empty
string for COMMENT to clear the comment.  To set a comment, the current
user must be the object owner or be on the ADMIN ACL.  Returns true for
success and false for failure.

=item create(TYPE, NAME)

Creates a new object of type TYPE and name NAME.  TYPE must be a
recognized type for which the wallet system has a backend implementation.
Returns true on success and false on failure.

To create an object using this method, the current user must be authorized
by the ADMIN ACL.  Use autocreate() to create objects based on the default
owner as determined by the wallet configuration.

=item destroy(TYPE, NAME)

Destroys the object identified by TYPE and NAME.  This destroys any data
that the wallet had saved about the object, may remove the underlying
object from other external systems, and destroys the wallet database entry
for the object.  To destroy an object, the current user must be authorized
by the ADMIN ACL or the destroy ACL on the object; the owner ACL is not
sufficient.  Returns true on success and false on failure.

=item dbh()

Returns the database handle of a Wallet::Server object.  This is used
mostly for testing; normally, clients should perform all actions through
the Wallet::Server object to ensure that authorization and history logging
is done properly.

=item error()

Returns the error of the last failing operation or undef if no operations
have failed.  Callers should call this function to get the error message
after an undef return from any other instance method.

=item expires(TYPE, NAME [, EXPIRES])

Gets or sets the expiration for the object identified by TYPE and NAME.
If EXPIRES is not given, returns the current expiration or undef if no
expiration is set or on an error.  To distinguish between an expiration
that isn't set and a failure to retrieve the expiration, the caller should
call error() after an undef return.  If error() also returns undef, the
expiration wasn't set; otherwise, error() will return the error message.

If EXPIRES is given, sets the expiration to EXPIRES.  EXPIRES must be in
the format C<YYYY-MM-DD +HH:MM:SS>, although the time portion may be
omitted.  Pass in the empty string for EXPIRES to clear the expiration
date.  To set an expiration, the current user must be authorized by the
ADMIN ACL.  Returns true for success and false for failure.

=item flag_clear(TYPE, NAME, FLAG)

Clears the flag FLAG on the object identified by TYPE and NAME.  To clear
a flag, the current user must be authorized by the ADMIN ACL or the flags
ACL on the object.

=item flag_set(TYPE, NAME, FLAG)

Sets the flag FLAG on the object identified by TYPE and NAME.  To set a
flag, the current user must be authorized by the ADMIN ACL or the flags
ACL on the object.

=item get(TYPE, NAME)

Returns the data associated with the object identified by TYPE and NAME.
Depending on the object TYPE, this may generate new data and invalidate
any existing data or it may return data previously stored or generated.
Note that this data may be binary and may contain nul characters.  To get
an object, the current user must either be authorized by the owner ACL or
authorized by the get ACL; however, if the get ACL is set, the owner ACL
will not be checked.  Being a member of the ADMIN ACL does not provide any
special privileges to get objects.

Returns undef on failure.  The caller should be careful to distinguish
between undef and the empty string, which is valid object data.

=item history(TYPE, NAME)

Returns (as a string) the human-readable history of the object identified
by TYPE and NAME, or undef on error.  To see the object history, the
current user must be a member of the ADMIN ACL, authorized by the show
ACL, or authorized by the owner ACL; however, if the show ACL is set, the
owner ACL will not be checked.

=item owner(TYPE, NAME [, OWNER])

Gets or sets the owner for the object identified by TYPE and NAME.  If
OWNER is not given, returns the current owner as a numeric ACL ID or undef
if no owner is set or on an error.  To distinguish between an owner that
isn't set and a failure to retrieve the owner, the caller should call
error() after an undef return.  If error() also returns undef, that ACL
wasn't set; otherwise, error() will return the error message.

If OWNER is given, sets the owner to OWNER, which may be either the name
of an ACL or a numeric ACL ID.  To set an owner, the current user must be
authorized by the ADMIN ACL.  Returns true for success and false for
failure.

The owner of an object is permitted to get, store, and show that object,
but cannot destroy or set flags on that object without being listed on
those ACLs as well.

=item show(TYPE, NAME)

Returns (as a string) a human-readable representation of the metadata
stored for the object identified by TYPE and NAME, or undef on error.
Included is the metadata and entries of any ACLs associated with the
object.  To show an object, the current user must be a member of the ADMIN
ACL, authorized by the show ACL, or authorized by the owner ACL; however,
if the show ACL is set, the owner ACL will not be checked.

=item store(TYPE, NAME, DATA)

Stores DATA for the object identified with TYPE and NAME for later
retrieval with get.  Not all object types support this.  Note that DATA
may be binary and may contain nul characters.  To store an object, the
current user must either be authorized by the owner ACL or authorized by
the store ACL; however, if the store ACL is set, the owner ACL is not
checked.  Being a member of the ADMIN ACL does not provide any special
privileges to store objects.  Returns true on success and false on
failure.

=back

=head1 SEE ALSO

wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <rra@stanford.edu>

=cut
