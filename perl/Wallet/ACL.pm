# Wallet::ACL -- Implementation of ACLs in the wallet system.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::ACL;
require 5.006;

use strict;
use vars qw($VERSION);

use DBI;
use POSIX qw(strftime);
use Wallet::ACL::Krb5;

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.03';

##############################################################################
# Constructors
##############################################################################

# Initialize a new ACL from the database.  Verify that the ACL already exists
# in the database and, if so, return a new blessed object.  Stores the ACL ID
# and the database handle to use for future operations.  If the object
# doesn't exist, throws an exception.
sub new {
    my ($class, $id, $dbh) = @_;
    $dbh->{RaiseError} = 1;
    $dbh->{PrintError} = 0;
    $dbh->{AutoCommit} = 0;
    my ($sql, $data, $name);
    if ($id =~ /^\d+\z/) {
        $sql = 'select ac_id, ac_name from acls where ac_id = ?';
    } else {
        $sql = 'select ac_id, ac_name from acls where ac_name = ?';
    }
    eval {
        ($data, $name) = $dbh->selectrow_array ($sql, undef, $id);
        $dbh->commit;
    };
    if ($@) {
        $dbh->rollback;
        die "cannot search for ACL $id: $@\n";
    } elsif (not defined $data) {
        die "ACL $id not found\n";
    }
    my $self = {
        dbh  => $dbh,
        id   => $data,
        name => $name,
    };
    bless ($self, $class);
    return $self;
}

# Create a new ACL in the database with the given name and return a new
# blessed ACL object for it.  Stores the database handle to use and the ID of
# the newly created ACL in the object.  On failure, throws an exception.
sub create {
    my ($class, $name, $dbh, $user, $host, $time) = @_;
    if ($name =~ /^\d+\z/) {
        die "ACL name may not be all numbers\n";
    }
    $dbh->{RaiseError} = 1;
    $dbh->{PrintError} = 0;
    $dbh->{AutoCommit} = 0;
    $time ||= time;
    my $id;
    eval {
        my $sql = 'insert into acls (ac_name) values (?)';
        $dbh->do ($sql, undef, $name);
        $id = $dbh->last_insert_id (undef, undef, 'acls', 'ac_id');
        die "unable to retrieve new ACL ID" unless defined $id;
        my $date = strftime ('%Y-%m-%d %T', localtime $time);
        $sql = "insert into acl_history (ah_acl, ah_action, ah_by, ah_from,
            ah_on) values (?, 'create', ?, ?, ?)";
        $dbh->do ($sql, undef, $id, $user, $host, $date);
        $dbh->commit;
    };
    if ($@) {
        $dbh->rollback;
        die "cannot create ACL $name: $@\n";
    }
    my $self = {
        dbh  => $dbh,
        id   => $id,
        name => $name,
    };
    bless ($self, $class);
    return $self;
}

##############################################################################
# Utility functions
##############################################################################

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

# Returns the ID of an ACL.
sub id {
    my ($self) = @_;
    return $self->{id};
}

# Returns the name of the ACL.
sub name {
    my ($self)= @_;
    return $self->{name};
}

# Given an ACL scheme, return the mapping to a class by querying the
# database, or undef if no mapping exists.
sub scheme_mapping {
    my ($self, $scheme) = @_;
    my $class;
    eval {
        my $sql = 'select as_class from acl_schemes where as_name = ?';
        ($class) = $self->{dbh}->selectrow_array ($sql, undef, $scheme);
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ($@);
        $self->{dbh}->rollback;
        return;
    }
    return $class;
}

# Record a change to an ACL.  Takes the type of change, the scheme and
# identifier of the entry, and the trace information (user, host, and time).
# This function does not commit and does not catch exceptions.  It should
# normally be called as part of a larger transaction that implements the
# change and should be committed with that change.
sub log_acl {
    my ($self, $action, $scheme, $identifier, $user, $host, $time) = @_;
    unless ($action =~ /^(add|remove)\z/) {
        die "invalid history action $action";
    }
    my $date = strftime ('%Y-%m-%d %T', localtime $time);
    my $sql = 'insert into acl_history (ah_acl, ah_action, ah_scheme,
        ah_identifier, ah_by, ah_from, ah_on) values (?, ?, ?, ?, ?, ?, ?)';
    $self->{dbh}->do ($sql, undef, $self->{id}, $action, $scheme, $identifier,
                      $user, $host, $date);
}

##############################################################################
# ACL manipulation
##############################################################################

# Changes the human-readable name of the ACL.  Note that this operation is not
# logged since it isn't a change to any of the data stored in the wallet.
# Returns true on success, false on failure.
sub rename {
    my ($self, $name) = @_;
    if ($name =~ /^\d+\z/) {
        $self->error ("ACL name may not be all numbers");
        return;
    }
    eval {
        my $sql = 'update acls set ac_name = ? where ac_id = ?';
        $self->{dbh}->do ($sql, undef, $name, $self->{id});
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ("cannot rename ACL $self->{id} to $name: $@");
        $self->{dbh}->rollback;
        return;
    }
    $self->{name} = $name;
    return 1;
}

# Destroy the ACL, deleting it out of the database.  Returns true on success,
# false on failure.
sub destroy {
    my ($self, $user, $host, $time) = @_;
    $time ||= time;
    eval {
        my $sql = 'delete from acl_entries where ae_id = ?';
        $self->{dbh}->do ($sql, undef, $self->{id});
        $sql = 'delete from acls where ac_id = ?';
        $self->{dbh}->do ($sql, undef, $self->{id});
        $sql = "insert into acl_history (ah_acl, ah_action, ah_by, ah_from,
            ah_on) values (?, 'destroy', ?, ?, ?)";
        $self->{dbh}->do ($sql, undef, $self->{id}, $user, $host, $time);
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ("cannot destroy ACL $self->{id}: $@");
        $self->{dbh}->rollback;
        return;
    }
    return 1;
}

##############################################################################
# ACL entry manipulation
##############################################################################

# Add an ACL entry to this ACL.  Returns true on success and false on failure.
sub add {
    my ($self, $scheme, $identifier, $user, $host, $time) = @_;
    $time ||= time;
    unless ($self->scheme_mapping ($scheme)) {
        $self->error ("unknown ACL scheme $scheme");
        return;
    }
    eval {
        my $sql = 'insert into acl_entries (ae_id, ae_scheme, ae_identifier)
            values (?, ?, ?)';
        $self->{dbh}->do ($sql, undef, $self->{id}, $scheme, $identifier);
        $self->log_acl ('add', $scheme, $identifier, $user, $host, $time);
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ("cannot add $scheme:$identifier to $self->{id}: $@");
        $self->{dbh}->rollback;
        return;
    }
    return 1;
}

# Remove an ACL entry to this ACL.  Returns true on success and false on
# failure.  Detect the case where no such row exists before doing the delete
# so that we can provide a good error message.
sub remove {
    my ($self, $scheme, $identifier, $user, $host, $time) = @_;
    $time ||= time;
    eval {
        my $sql = 'select * from acl_entries where ae_id = ? and ae_scheme = ?
            and ae_identifier = ?';
        my ($data) = $self->{dbh}->selectrow_array ($sql, undef, $self->{id},
                                                    $scheme, $identifier);
        unless (defined $data) {
            die "entry not found in ACL\n";
        }
        $sql = 'delete from acl_entries where ae_id = ? and ae_scheme = ?
            and ae_identifier = ?';
        $self->{dbh}->do ($sql, undef, $self->{id}, $scheme, $identifier);
        $self->log_acl ('remove', $scheme, $identifier, $user, $host, $time);
        $self->{dbh}->commit;
    };
    if ($@) {
        my $entry = "$scheme:$identifier";
        $self->error ("cannot remove $entry from $self->{id}: $@");
        $self->{dbh}->rollback;
        return;
    }
    return 1;
}

##############################################################################
# ACL checking
##############################################################################

# List all of the entries in an ACL.  Returns an array of tuples, each of
# which contains a scheme and identifier, or an array containing undef on
# error.  Sets the internal error string on error.
sub list {
    my ($self) = @_;
    undef $self->{error};
    my @entries;
    eval {
        my $sql = 'select ae_scheme, ae_identifier from acl_entries where
            ae_id = ?';
        my $sth = $self->{dbh}->prepare ($sql);
        $sth->execute ($self->{id});
        my $entry;
        while (defined ($entry = $sth->fetchrow_arrayref)) {
            push (@entries, [ @$entry ]);
        }
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ("cannot retrieve ACL $self->{id}: $@");
        $self->{dbh}->rollback;
        return;
    } else {
        return @entries;
    }
}

# Return as a string a human-readable description of an ACL, including its
# membership.  This method is only for human-readable output; use the list()
# method if you are using the results in other code.  Returns undef on
# failure.
sub show {
    my ($self) = @_;
    my @entries = $self->list;
    if (not @entries and $self->error) {
        return;
    }
    my $name = $self->name;
    my $id = $self->id;
    my $output = "Members of ACL $name (id: $id) are:\n";
    for my $entry (sort { $$a[0] cmp $$b[0] or $$a[1] cmp $$b[1] } @entries) {
        my ($scheme, $identifier) = @$entry;
        $output .= "  $scheme $identifier\n";
    }
    return $output;
}

# Return as a string the history of an ACL.  Returns undef on failure.
sub history {
    my ($self) = @_;
    my $output = '';
    eval {
        my $sql = 'select ah_action, ah_scheme, ah_identifier, ah_by, ah_from,
            ah_on from acl_history where ah_acl = ? order by ah_on';
        my $sth = $self->{dbh}->prepare ($sql);
        $sth->execute ($self->{id});
        my @data;
        while (@data = $sth->fetchrow_array) {
            $output .= "$data[5]  ";
            if ($data[0] eq 'add' or $data[0] eq 'remove') {
                $output .= "$data[0] $data[1] $data[2]";
            } else {
                $output .= $data[0];
            }
            $output .= "\n    by $data[3] from $data[4]\n";
        }
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ("cannot read history for $self->{id}: $@");
        $self->{dbh}->rollback;
        return;
    }
    return $output;
}

# Given a principal, a scheme, and an identifier, check whether that ACL
# scheme and identifier grant access to that principal.  Return 1 if access
# was granted, 0 if access was deined, and undef on some error.  On error, the
# error message is also added to the check_errors variable.  This method is
# internal to the class.
#
# Maintain ACL verifiers for all schemes we've seen in the local %verifier
# hash so that we can optimize repeated ACL checks.
{
    my %verifier;
    sub check_line {
        my ($self, $principal, $scheme, $identifier) = @_;
        unless ($verifier{$scheme}) {
            my $class = $self->scheme_mapping ($scheme);
            unless ($class) {
                push (@{ $self->{check_errors} }, "unknown scheme $scheme");
                return;
            }
            $verifier{$scheme} = $class->new;
            unless (defined $verifier{$scheme}) {
                push (@{ $self->{check_errors} }, "cannot verify $scheme");
                return;
            }
        }
        my $result = ($verifier{$scheme})->check ($principal, $identifier);
        if (not defined $result) {
            push (@{ $self->{check_errors} }, ($verifier{$scheme})->error);
            return;
        } else {
            return $result;
        }
    }
}

# Given a principal, check whether it should be granted access according to
# this ACL.  Returns 1 if access was granted, 0 if access was denied, and
# undef on some error.  Errors from ACL verifiers do not cause an error
# return, but are instead accumulated in the check_errors variable returned by
# the check_errors() method.
sub check {
    my ($self, $principal) = @_;
    unless ($principal) {
        $self->error ('no principal specified');
        return;
    }
    my @entries = $self->list;
    return undef if (not @entries and $self->error);
    my %verifier;
    $self->{check_errors} = [];
    for my $entry (@entries) {
        my ($scheme, $identifier) = @$entry;
        my $result = $self->check_line ($principal, $scheme, $identifier);
        return 1 if $result;
    }
    return 0;
}

# Returns the errors from the last ACL verification as an array in array
# context or as a string with newlines after each error in a scalar context.
sub check_errors {
    my ($self) = @_;
    my @errors;
    if ($self->{check_errors}) {
        @errors = @{ $self->{check_errors} };
    }
    return wantarray ? @errors : join ("\n", @errors, '');
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=head1 NAME

Wallet::ACL - Implementation of ACLs in the wallet system

=head1 SYNOPSIS

    my $acl = Wallet::ACL->create ('group:sysadmin');
    $acl->rename ('group:unix');
    $acl->add ('krb5', 'alice@EXAMPLE.COM', $admin, $host);
    $acl->add ('krb5', 'bob@EXAMPLE.COM', $admin, $host);
    if ($acl->check ($user)) {
        print "Permission granted\n";
        warn scalar ($acl->check_errors) if $acl->check_errors;
    }
    $acl->remove ('krb5', 'bob@EXAMPLE.COM', $admin, $host);
    my @entries = $acl->list;
    my $summary = $acl->show;
    my $history = $acl->history;
    $acl->destroy ($admin, $host);

=head1 DESCRIPTION

Wallet::ACL implements the ACL system for the wallet: the methods to create,
find, rename, and destroy ACLs; the methods to add and remove entries from
an ACL; and the methods to list the contents of an ACL and check a principal
against it.

An ACL is a list of zero or more ACL entries, each of which consists of a
scheme and an identifier.  Each scheme is associated with a verifier module
that checks Kerberos principals against identifiers for that scheme and
returns whether the principal should be permitted access by that identifier.
The interpretation of the identifier is entirely left to the scheme.  This
module maintains the ACLs and dispatches check operations to the appropriate
verifier module.

Each ACL is identified by a human-readable name and a persistant unique
numeric identifier.  The numeric identifier (ID) should be used to refer to
the ACL so that it can be renamed as needed without breaking external
references.

=head1 CLASS METHODS

=over 4

=item new(ACL, DBH)

Instantiate a new ACL object with the given ACL ID or name.  Takes the
database handle to use for retrieving metadata from the wallet database.
Returns a new ACL object if the ACL was found and throws an exception if it
wasn't or on any other error.

=item create(NAME, DBH, PRINCIPAL, HOSTNAME [, DATETIME])

Similar to new() in that it instantiates a new ACL object, but instead of
finding an existing one, creates a new ACL record in the database with the
given NAME.  NAME must not be all-numeric, since that would conflict with
the automatically assigned IDs.  Returns the new object on success and
throws an exception on failure.  PRINCIPAL, HOSTNAME, and DATETIME are
stored as history information.  PRINCIPAL should be the user who is creating
the ACL.  If DATETIME isn't given, the current time is used.

=back

=head1 INSTANCE METHODS

=over 4

=item add(SCHEME, INSTANCE, PRINCIPAL, HOSTNAME [, DATETIME])

Add the given ACL entry (given by SCHEME and INSTANCE) to this ACL.  Returns
true on success and false on failure.  On failure, the caller should call
error() to get the error message.  PRINCIPAL, HOSTNAME, and DATETIME are
stored as history information.  PRINCIPAL should be the user who is adding
the ACL entry.  If DATETIME isn't given, the current time is used.

=item check(PRINCIPAL)

Checks whether the given PRINCIPAL should be allowed access given ACL.
Returns 1 if access was granted, 0 if access is declined, and undef on
error.  On error, the caller should call error() to get the error text.  Any
errors found by the individual ACL verifiers can be retrieved by calling
check_errors().  Errors from individual ACL verifiers will not result in an
error return from check(); instead, the check will continue with the next
entry in the ACL.

check() returns success as soon as an entry in the ACL grants access to
PRINCIPAL.  There is no provision for negative ACLs or exceptions.

=item check_errors()

Return (as a list in array context and a string with newlines between errors
and at the end of the last error in scalar context) the errors, if any,
returned by ACL verifiers for the last check operation.  If there were no
errors from the last check() operation, returns the empty list in array
context and undef in scalar context.

=item destroy(PRINCIPAL, HOSTNAME [, DATETIME])

Destroys this ACL from the database.  Note that this will fail due to
integrity constraint errors if the ACL is still referenced by any object;
the ACL must be removed from all objects first.  Returns true on success and
false on failure.  On failure, the caller should call error() to get the
error message.  PRINCIPAL, HOSTNAME, and DATETIME are stored as history
information.  PRINCIPAL should be the user who is destroying the ACL.  If
DATETIME isn't given, the current time is used.

=item error()

Returns the error of the last failing operation or undef if no operations
have failed.  Callers should call this function to get the error message
after an undef return from any other instance method.

=item history()

Returns the human-readable history of this ACL.  Each action that changes
the ACL (not including changes to the name of the ACL) will be represented
by two lines.  The first line will have a timestamp of the change followed
by a description of the change, and the second line will give the user who
made the change and the host from which the change was made.  On failure,
returns undef, and the caller should call error() to get the error message.

=item id()

Returns the numeric system-generated ID of this ACL.

=item list()

Returns all the entries of this ACL.  The return value will be a list of
references to pairs of scheme and identifier.  For example, for an ACL
containing two entries, both of scheme C<krb5> and with values
C<alice@EXAMPLE.COM> and C<bob@EXAMPLE.COM>, list() would return:

    ([ 'krb5', 'alice@EXAMPLE.COM' ], [ 'krb5', 'bob@EXAMPLE.COM' ])

Returns the empty list on failure.  To distinguish between this and the
ACL containing no entries, the caller should call error().  error() is
guaranteed to return the error message if there was an error and undef if
there was no error.

=item name()

Returns the human-readable name of this ACL.

=item remove(SCHEME, INSTANCE, PRINCIPAL, HOSTNAME [, DATETIME])

Remove the given ACL line (given by SCHEME and INSTANCE) from this ACL.
Returns true on success and false on failure.  On failure, the caller should
call error() to get the error message.  PRINCIPAL, HOSTNAME, and DATETIME
are stored as history information.  PRINCIPAL should be the user who is
removing the ACL entry.  If DATETIME isn't given, the current time is used.

=item rename(NAME)

Rename this ACL.  This changes the name used for human convenience but not
the system-generated ACL ID that is used to reference this ACL.  The new
NAME must not be all-numeric, since that would conflict with
system-generated ACL IDs.  Returns true on success and false on failure.  On
failure, the caller should call error() to get the error message.

Note that rename() operations are not logged in the ACL history.

=item show()

Returns a human-readable description of this ACL, including its membership.
This method should only be used for display of the ACL to humans.  Use the
list(), name(), and id() methods instead to get ACL information for use in
other code.  On failure, returns undef, and the caller should call error()
to get the error message.

=back

=head1 SEE ALSO

Wallet::ACL::Base(3), wallet-backend(8)

This module is part of the wallet system.  The current version is available
from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <rra@stanford.edu>

=cut
