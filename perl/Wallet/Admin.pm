# Wallet::Admin -- Wallet system administrative interface.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2008, 2009 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Admin;
require 5.006;

use strict;
use vars qw($VERSION);

use Wallet::ACL;
use Wallet::Database;
use Wallet::Schema;

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.04';

##############################################################################
# Constructor, destructor, and accessors
##############################################################################

# Create a new wallet administrator object.  Opens a connection to the
# database that will be used for all of the wallet configuration information.
# Throw an exception if anything goes wrong.
sub new {
    my ($class) = @_;
    my $dbh = Wallet::Database->connect;
    my $self = { dbh => $dbh };
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
    $self->{dbh}->disconnect unless $self->{dbh}->{InactiveDestroy};
}

##############################################################################
# Database initialization
##############################################################################

# Initializes the database by populating it with our schema and then creates
# and returns a new wallet server object.  This is used only for initial
# database creation.  Takes the Kerberos principal who will be the default
# administrator so that we can create an initial administrator ACL.  Returns
# true on success and false on failure, setting the object error.
sub initialize {
    my ($self, $user) = @_;
    my $schema = Wallet::Schema->new;
    eval { $schema->create ($self->{dbh}) };
    if ($@) {
        $self->error ($@);
        return;
    }
    my $acl = Wallet::ACL->create ('ADMIN', $self->{dbh}, $user, 'localhost');
    unless ($acl->add ('krb5', $user, $user, 'localhost')) {
        $self->error ($acl->error);
        return;
    }
    return 1;
}

# The same as initialize, but also drops any existing tables first before
# creating the schema.  Takes the same arguments.  Returns true on success and
# false on failure.
sub reinitialize {
    my ($self, $user) = @_;
    return unless $self->destroy;
    return $self->initialize ($user);
}

# Drop the database, including all of its data.  Returns true on success and
# false on failure.
sub destroy {
    my ($self) = @_;
    my $schema = Wallet::Schema->new;
    eval { $schema->drop ($self->{dbh}) };
    if ($@) {
        $self->error ($@);
        return;
    }
    return 1;
}

##############################################################################
# Reporting
##############################################################################

# Given an ACL name, translate it to the ID for that ACL and return it.
# Often this is unneeded and could be done with a join, but by doing it in a
# separate step, we can give an error for the specific case of someone
# searching for a non-existant ACL.
sub acl_name_to_id {
    my ($self, $acl) = @_;
    my ($id);
    eval {
        my $sql = 'select ac_id from acls where ac_name = ?';
        my $sth = $self->{dbh}->prepare ($sql);
        $sth->execute ($acl);
        while (defined (my $row = $sth->fetchrow_hashref)) {
            $id = $row->{ac_id};
        }
        $self->{dbh}->commit;
    };
    if (!defined $id || $id !~ /^\d+$/) {
        $self->error ("could not find the acl $acl");
        return '';
    }
    return $id;
}

# Return the SQL statement to find every object in the database.
sub list_objects_all {
    my ($self) = @_;
    my $sql = 'select ob_type, ob_name from objects order by ob_type,
        ob_name';
    return $sql;
}

# Return the SQL statement and the search field required to find all objects
# matching a specific type.
sub list_objects_type {
    my ($self, $type) = @_;
    my $sql = 'select ob_type, ob_name from objects where ob_type=? order
        by ob_type, ob_name';
    return ($sql, $type);
}

# Return the SQL statement and search field required to find all objects
# owned by a given ACL.  If the requested owner is 'null', then we ignore
# this and do a different search for IS NULL.  If the requested owner does
# not actually match any ACLs, set an error and return the empty string.
sub list_objects_owner {
    my ($self, $owner) = @_;
    my ($sth);
    if ($owner =~ /^null$/i) {
        my $sql = 'select ob_type, ob_name from objects where ob_owner is null
            order by objects.ob_type, objects.ob_name';
        return ($sql);
    } else {
        my $id = $self->acl_name_to_id ($owner);
        return '' unless $id;
        my $sql = 'select ob_type, ob_name from objects where ob_owner = ?
            order by objects.ob_type, objects.ob_name';
        return ($sql, $id);
    }
}

# Return the SQL statement and search field required to find all objects
# that have a specific flag set.
sub list_objects_flag {
    my ($self, $flag) = @_;
    my $sql = 'select ob_type, ob_name from objects left join flags on
        (objects.ob_type = flags.fl_type and objects.ob_name = flags.fl_name)
        where flags.fl_flag = ? order by objects.ob_type, objects.ob_name';
    return ($sql, $flag);
}

# Return the SQL statement and search field required to find all objects
# that a given ACL has any permissions on.  This expands from
# list_objects_owner in that it will also match any records that have the ACL
# set for get, store, show, destroy, or flags.  If the requested owner does
# not actually match any ACLs, set an error and return the empty string.
sub list_objects_acl {
    my ($self, $acl) = @_;
    my $id = $self->acl_name_to_id ($acl);
    return '' unless $id;
    my $sql = 'select ob_type, ob_name from objects where ob_owner = ? or
        ob_acl_get = ? or ob_acl_store = ? or ob_acl_show = ? or
        ob_acl_destroy = ? or ob_acl_flags = ? order by objects.ob_type,
        objects.ob_name';
    return ($sql, $id, $id, $id, $id, $id, $id);
}

# Returns a list of all objects stored in the wallet database in the form of
# type and name pairs.  On error and for an empty database, the empty list
# will be returned.  To distinguish between an empty list and an error, call
# error(), which will return undef if there was no error.  Farms out specific
# statement to another subroutine for specific search types, but each case
# should return ob_type and ob_name in that order.
sub list_objects {
    my ($self, $type, @args) = @_;
    undef $self->{error};

    # Find the SQL statement and the arguments to use.
    my $sql = '';
    my @search = ();
    if (!defined $type || $type eq '') {
        ($sql) = $self->list_objects_all ();
    } else {
        if (@args != 1) {
            $self->error ("object searches require an argument to search");
        } elsif ($type eq 'type') {
            ($sql, @search) = $self->list_objects_type (@args);
        } elsif ($type eq 'owner') {
            ($sql, @search) = $self->list_objects_owner (@args);
        } elsif ($type eq 'flag') {
            ($sql, @search) = $self->list_objects_flag (@args);
        } elsif ($type eq 'acl') {
            ($sql, @search) = $self->list_objects_acl (@args);
        } else {
            $self->error ("do not know search type: $type");
        }
        return unless $sql;
    }

    my @objects;
    eval {
        my $object;
        my $sth = $self->{dbh}->prepare ($sql);
        $sth->execute (@search);
        while (defined ($object = $sth->fetchrow_arrayref)) {
            push (@objects, [ @$object ]);
        }
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ("cannot list objects: $@");
        $self->{dbh}->rollback;
        return;
    } else {
        return @objects;
    }
}

# Returns the SQL statement required to find and return all ACLs in the db.
sub list_acls_all {
    my ($self) = @_;
    my $sql = 'select ac_id, ac_name from acls order by ac_id';
    return ($sql);
}

# Returns the SQL statement required to find and returned all empty ACLs in
# the db.
sub list_acls_empty {
    my ($self) = @_;
    my $sql = 'select ac_id, ac_name from acls left join acl_entries
        on (acls.ac_id = acl_entries.ae_id) where ae_id is null';
    return ($sql);
}

# Returns the SQL statement and the field required to search the ACLs and
# return only those entries which contain a entries with identifiers
# matching a particular given string.
sub list_acls_entry {
    my ($self, $type, $identifier) = @_;
    my $sql = 'select distinct ac_id, ac_name from acl_entries left join acls
        on (ae_id = ac_id) where ae_scheme = ? and ae_identifier like ? order
        by ac_id';
    $identifier = '%'.$identifier.'%';
    return ($sql, $type, $identifier);
}

# Returns a list of all ACLs stored in the wallet database as a list of pairs
# of ACL IDs and ACL names.  On error and for an empty database, the empty
# list will be returned; however, this is unlikely since any valid database
# will have at least an ADMIN ACL.  Still, to distinguish between an empty
# list and an error, call error(), which will return undef if there was no
# error.
sub list_acls {
    my ($self, $type, @args) = @_;
    undef $self->{error};

    # Find the SQL statement and the arguments to use.
    my $sql = '';
    my @search = ();
    if (!defined $type || $type eq '') {
        ($sql) = $self->list_acls_all ();
    } else {
        if ($type eq 'entry') {
            if (@args == 0) {
                $self->error ("acl searches require an argument to search");
            } else {
                ($sql, @search) = $self->list_acls_entry (@args);
            }
        } elsif ($type eq 'empty') {
            ($sql) = $self->list_acls_empty ();
        } else {
            $self->error ("do not know search type: $type");
        }
        return unless $sql;
    }

    my @acls;
    eval {
        my $sth = $self->{dbh}->prepare ($sql);
        $sth->execute (@search);
        my $object;
        while (defined ($object = $sth->fetchrow_arrayref)) {
            push (@acls, [ @$object ]);
        }
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ("cannot list ACLs: $@");
        $self->{dbh}->rollback;
        return;
    } else {
        return @acls;
    }
}

# Returns a report of all ACL lines contained in owner ACLs for matching
# objects.  Objects are specified by type and name, which may be SQL wildcard
# expressions.  Each list member will be a pair of ACL scheme and ACL
# identifier, with duplicates removed.  On error and for no matching entries,
# the empty list will be returned.  To distinguish between an empty return and
# an error, call error(), which will return undef if there was no error.
sub report_owners {
    my ($self, $type, $name) = @_;
    undef $self->{error};
    my @lines;
    eval {
        my $sql = 'select distinct ae_scheme, ae_identifier from acl_entries,
            acls, objects where ae_id = ac_id and ac_id = ob_owner and
            ob_type like ? and ob_name like ? order by ae_scheme,
            ae_identifier';
        my $sth = $self->{dbh}->prepare ($sql);
        $sth->execute ($type, $name);
        my $object;
        while (defined ($object = $sth->fetchrow_arrayref)) {
            push (@lines, [ @$object ]);
        }
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ("cannot report on owners: $@");
        $self->{dbh}->rollback;
        return;
    } else {
        return @lines;
    }
}

##############################################################################
# Object registration
##############################################################################

# Given an object type and class name, add a new class mapping to that
# database for the given object type.  This is used to register new object
# types.  Returns true on success, false on failure, and sets the internal
# error on failure.
sub register_object {
    my ($self, $type, $class) = @_;
    eval {
        my $sql = 'insert into types (ty_name, ty_class) values (?, ?)';
        $self->{dbh}->do ($sql, undef, $type, $class);
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ("cannot register $class for $type: $@");
        $self->{dbh}->rollback;
        return;
    }
    return 1;
}

# Given an ACL verifier scheme and class name, add a new class mapping to that
# database for the given ACL verifier scheme.  This is used to register new
# ACL schemes.  Returns true on success, false on failure, and sets the
# internal error on failure.
sub register_verifier {
    my ($self, $scheme, $class) = @_;
    eval {
        my $sql = 'insert into acl_schemes (as_name, as_class) values (?, ?)';
        $self->{dbh}->do ($sql, undef, $scheme, $class);
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ("cannot registery $class for $scheme: $@");
        $self->{dbh}->rollback;
        return;
    }
    return 1;
}

1;
__DATA__

##############################################################################
# Documentation
##############################################################################

=head1 NAME

Wallet::Admin - Wallet system administrative interface

=head1 SYNOPSIS

    use Wallet::Admin;
    my $admin = Wallet::Admin->new;
    unless ($admin->initialize ('user/admin@EXAMPLE.COM')) {
        die $admin->error;
    }

=head1 DESCRIPTION

Wallet::Admin implements the administrative interface to the wallet server
and database.  It is normally instantiated and used by B<wallet-admin>, a
thin wrapper around this object that provides a command-line interface to
its actions.

To use this object, several configuration variables must be set (at least
the database configuration).  For information on those variables and how to
set them, see Wallet::Config(3).  For more information on the normal user
interface to the wallet server, see Wallet::Server(3).

=head1 CLASS METHODS

=over 4

=item new()

Creates a new wallet administrative object and connects to the database.
On any error, this method throws an exception.

=back

=head1 INSTANCE METHODS

For all methods that can fail, the caller should call error() after a
failure to get the error message.

=over 4

=item destroy()

Destroys the database, deleting all of its data and all of the tables used
by the wallet server.  Returns true on success and false on failure.

=item error()

Returns the error of the last failing operation or undef if no operations
have failed.  Callers should call this function to get the error message
after an undef return from any other instance method.

=item initialize(PRINCIPAL)

Initializes the database as configured in Wallet::Config and loads the
wallet database schema.  Then, creates an ACL with the name ADMIN and adds
an ACL entry of scheme C<krb5> and instance PRINCIPAL to that ACL.  This
bootstraps the authorization system and lets that Kerberos identity make
further changes to the ADMIN ACL and the rest of the wallet database.
Returns true on success and false on failure.

initialize() uses C<localhost> as the hostname and PRINCIPAL as the user
when logging the history of the ADMIN ACL creation and for any subsequent
actions on the object it returns.

=item list_acls()

Returns a list of all ACLs in the database.  The return value is a list of
references to pairs of ACL ID and name.  For example, if there are two
ACLs in the database, one with name "ADMIN" and ID 1 and one with name
"group/admins" and ID 3, list_acls() would return:

    ([ 1, 'ADMIN' ], [ 3, 'group/admins' ])

Returns the empty list on failure.  Any valid wallet database should have
at least one ACL, but an error can be distinguished from the odd case of a
database with no ACLs by calling error().  error() is guaranteed to return
the error message if there was an error and undef if there was no error.

=item list_objects()

Returns a list of all objects in the database.  The return value is a list
of references to pairs of type and name.  For example, if two objects
existed in the database, both of type "keytab" and with values
"host/example.com" and "foo", list_objects() would return:

    ([ 'keytab', 'host/example.com' ], [ 'keytab', 'foo' ])

Returns the empty list on failure.  To distinguish between this and a
database containing no objects, the caller should call error().  error()
is guaranteed to return the error message if there was an error and undef
if there was no error.

=item register_object (TYPE, CLASS)

Register in the database a mapping from the object type TYPE to the class
CLASS.  Returns true on success and false on failure (including when the
verifier is already registered).

=item register_verifier (SCHEME, CLASS)

Register in the database a mapping from the ACL scheme SCHEME to the class
CLASS.  Returns true on success and false on failure (including when the
verifier is already registered).

=item reinitialize(PRINCIPAL)

Performs the same actions as initialize(), but first drops any existing
wallet database tables from the database, allowing this function to be
called on a prior wallet database.  All data stored in the database will
be deleted and a fresh set of wallet database tables will be created.
This method is equivalent to calling destroy() followed by initialize().
Returns true on success and false on failure.

=item report_owners(TYPE, NAME)

Returns a list of all ACL lines contained in owner ACLs for objects
matching TYPE and NAME, which are interpreted as SQL patterns using C<%>
as a wildcard.  The return value is a list of references to pairs of
schema and identifier, with duplicates removed.

Returns the empty list on failure.  To distinguish between this and no
matches, the caller should call error().  error() is guaranteed to return
the error message if there was an error and undef if there was no error.

=back

=head1 SEE ALSO

wallet-admin(8)

This module is part of the wallet system.  The current version is available
from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <rra@stanford.edu>

=cut
