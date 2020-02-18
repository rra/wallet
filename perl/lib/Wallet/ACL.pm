# Wallet::ACL -- Implementation of ACLs in the wallet system
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2016 Russ Allbery <eagle@eyrie.org>
# Copyright 2007-2008, 2010, 2013-2015
#     The Board of Trustees of the Leland Stanford Junior University
#
# SPDX-License-Identifier: MIT

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::ACL;

use 5.008;
use strict;
use warnings;

use DateTime;
use Wallet::Object::Base;

our $VERSION = '1.04';

my $TZ = DateTime::TimeZone->new( name => 'local' );

##############################################################################
# Constructors
##############################################################################

# Initialize a new ACL from the database.  Verify that the ACL already exists
# in the database and, if so, return a new blessed object.  Stores the ACL ID
# and the database handle to use for future operations.  If the object
# doesn't exist, throws an exception.
sub new {
    my ($class, $id, $schema) = @_;
    my (%search, $data, $name);
    if ($id =~ /^\d+\z/) {
        $search{ac_id} = $id;
    } else {
        $search{ac_name} = $id;
    }
    eval {
        $data = $schema->resultset('Acl')->find (\%search);
    };
    if ($@) {
        die "cannot search for ACL $id: $@\n";
    } elsif (not defined $data) {
        die "ACL $id not found\n";
    }
    my $self = {
        schema  => $schema,
        id      => $data->ac_id,
        name    => $data->ac_name,
        comment => $data->ac_comment,
    };
    bless ($self, $class);
    return $self;
}

# Create a new ACL in the database with the given name and return a new
# blessed ACL object for it.  Stores the database handle to use and the ID of
# the newly created ACL in the object.  On failure, throws an exception.
sub create {
    my ($class, $name, $schema, $user, $host, $time) = @_;
    if ($name =~ /^\d+\z/) {
        die "ACL name may not be all numbers\n";
    }
    $time ||= time;
    my $id;
    eval {
        my $guard = $schema->txn_scope_guard;

        # Create the new record.
        my %record = (ac_name => $name);
        my $acl = $schema->resultset('Acl')->create (\%record);
        $id = $acl->ac_id;
        die "unable to retrieve new ACL ID" unless defined $id;

        # Add to the history table.
        my $date = DateTime->from_epoch (epoch => $time, time_zone => $TZ);
        %record = (ah_acl    => $id,
                   ah_name   => $name,
                   ah_action => 'create',
                   ah_by     => $user,
                   ah_from   => $host,
                   ah_on     => $date);
        my $history = $schema->resultset('AclHistory')->create (\%record);
        die "unable to create new history entry" unless defined $history;
        $guard->commit;
    };
    if ($@) {
        die "cannot create ACL $name: $@\n";
    }
    my $self = {
        schema => $schema,
        id     => $id,
        name   => $name,
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

# Returns the comment of the ACL.
sub comment {
    my ($self)= @_;
    return $self->{comment};
}

# Given an ACL scheme, return the mapping to a class by querying the
# database, or undef if no mapping exists.  Also load the relevant module.
sub scheme_mapping {
    my ($self, $scheme) = @_;
    my $class;
    eval {
        my %search = (as_name => $scheme);
        my $scheme_rec = $self->{schema}->resultset('AclScheme')
            ->find (\%search);
        $class = $scheme_rec->as_class;
    };
    if ($@) {
        $self->error ($@);
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

# Record a change to an ACL.  Takes the type of change, the scheme and
# identifier of the entry, and the trace information (user, host, and time).
# This function does not commit and does not catch exceptions.  It should
# normally be called as part of a larger transaction that implements the
# change and should be committed with that change.
sub log_acl {
    my ($self, $action, $scheme, $identifier, $user, $host, $time) = @_;
    unless ($action =~ /^(add|remove|rename)\z/) {
        die "invalid history action $action";
    }
    my $date = DateTime->from_epoch (epoch => $time, time_zone => $TZ);
    my %record = (ah_acl        => $self->{id},
                  ah_name       => $self->{name},
                  ah_action     => $action,
                  ah_scheme     => $scheme,
                  ah_identifier => $identifier,
                  ah_by         => $user,
                  ah_from       => $host,
                  ah_on         => $date);
    $self->{schema}->resultset('AclHistory')->create (\%record);
}

##############################################################################
# ACL manipulation
##############################################################################

# Changes the human-readable name of the ACL.  Note that this operation is not
# logged since it isn't a change to any of the data stored in the wallet.
# Returns true on success, false on failure.
sub rename {
    my ($self, $name, $user, $host, $time) = @_;
    $time ||= time;
    if ($name =~ /^\d+\z/) {
        $self->error ("ACL name may not be all numbers");
        return;
    }
    eval {
        my $guard = $self->{schema}->txn_scope_guard;
        my %search = (ac_id => $self->{id});
        my $acls = $self->{schema}->resultset('Acl')->find (\%search);
        $acls->ac_name ($name);
        $acls->update;
        $self->log_acl ('rename', undef, undef, $user, $host, $time);

        # Find any references to this being used as a nested verifier and
        # update the name.  This really breaks out of the normal flow, but
        # it's hard to do otherwise.
        %search = (ae_scheme     => 'nested',
                   ae_identifier => $self->{name},
                  );
        my @entries = $self->{schema}->resultset('AclEntry')->search(\%search);
        for my $entry (@entries) {
            $entry->ae_identifier ($name);
            $entry->update;
        }

        $guard->commit;
    };
    if ($@) {
        $self->error ("cannot rename ACL $self->{name} to $name: $@");
        return;
    }
    $self->{name} = $name;
    return 1;
}

# Moves everything owned by one ACL to instead be owned by another.  You'll
# normally want to use rename, but this exists for cases where the replacing
# ACL already exists and has things assigned to it.  Returns true on success,
# false on failure.
sub replace {
    my ($self, $replace_id, $user, $host, $time) = @_;
    $time ||= time;

    my %search = (ob_owner => $self->{id});
    my @objects = $self->{schema}->resultset('Object')->search (\%search);
    if (@objects) {
        for my $object (@objects) {
            my $type   = $object->ob_type;
            my $name   = $object->ob_name;
            my $object = eval {
                Wallet::Object::Base->new($type, $name, $self->{schema});
            };
            $object->owner ($replace_id, $user, $host, $time);
        }
    } else {
        $self->error ("no objects found for ACL $self->{name}");
        return;
    }
    return 1;
}

# Destroy the ACL, deleting it out of the database.  Returns true on success,
# false on failure.
#
# Checks to ensure that the ACL is not referenced anywhere in the database,
# since we may not have referential integrity enforcement.  It's not clear
# that this is the right place to do this; it's a bit of an abstraction
# violation, since it's a query against the object table.
sub destroy {
    my ($self, $user, $host, $time) = @_;
    $time ||= time;
    eval {
        my $guard = $self->{schema}->txn_scope_guard;

        # Make certain no one is using the ACL.
        my @search = ({ ob_owner       => $self->{id} },
                      { ob_acl_get     => $self->{id} },
                      { ob_acl_store   => $self->{id} },
                      { ob_acl_show    => $self->{id} },
                      { ob_acl_destroy => $self->{id} },
                      { ob_acl_flags   => $self->{id} });
        my @entries = $self->{schema}->resultset('Object')->search (\@search);
        if (@entries) {
            my ($entry) = @entries;
            die "ACL in use by ".$entry->ob_type.":".$entry->ob_name;
        }

        # Also make certain the ACL isn't being nested in another.
        my %search = (ae_scheme     => 'nested',
                      ae_identifier => $self->{name});
        my %options = (join     => 'acls',
                       prefetch => 'acls');
        @entries = $self->{schema}->resultset('AclEntry')->search(\%search,
                                                                  \%options);
        if (@entries) {
            my ($entry) = @entries;
            die "ACL is nested in ACL ".$entry->acls->ac_name;
        }

        # Delete any entries (there may or may not be any).
        %search = (ae_id => $self->{id});
        @entries = $self->{schema}->resultset('AclEntry')->search(\%search);
        for my $entry (@entries) {
            $entry->delete;
        }

        # There should definitely be an ACL record to delete.
        %search = (ac_id => $self->{id});
        my $entry = $self->{schema}->resultset('Acl')->find(\%search);
        $entry->delete if defined $entry;

        # Create new history line for the deletion.
        my $date = DateTime->from_epoch (epoch => $time, time_zone => $TZ);
        my %record = (ah_acl    => $self->{id},
                      ah_name   => $self->{name},
                      ah_action => 'destroy',
                      ah_by     => $user,
                      ah_from   => $host,
                      ah_on     => $date);
        $self->{schema}->resultset('AclHistory')->create (\%record);
        $guard->commit;
    };
    if ($@) {
        $self->error ("cannot destroy ACL $self->{name}: $@");
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

    # Check to make sure that this entry has a valid name for the scheme.
    my $class = $self->scheme_mapping ($scheme);
    my $object = eval {
        $class->new ($identifier, $self->{schema});
    };
    if ($@) {
        $self->error ("cannot create ACL verifier: $@");
        return;
    }
    unless ($object && $object->syntax_check ($identifier)) {
        $self->error ("invalid ACL identifier $identifier for $scheme");
        return;
    };

    # Actually create the scheme.
    eval {
        my $guard = $self->{schema}->txn_scope_guard;
        my %record = (ae_id         => $self->{id},
                      ae_scheme     => $scheme,
                      ae_identifier => $identifier);
        my $entry = $self->{schema}->resultset('AclEntry')->create (\%record);
        $self->log_acl ('add', $scheme, $identifier, $user, $host, $time);
        $guard->commit;
    };
    if ($@) {
        $self->error ("cannot add $scheme:$identifier to $self->{name}: $@");
        return;
    }
    return 1;
}

# Get the comment of an ACL.
sub get_comment {
    my ($self) = @_;
    return $self->comment();
}

# Set the comment of an ACL.
sub set_comment {
    my ($self, $comment) = @_;

    if (defined($comment)) {
        if ($comment eq q{}) {
            $comment = undef;
        } else {
            if (length($comment) > 255) {
                $self->error ('comment cannot be longer than 255 characters');
                return;
            }
        }
        eval {
            my $guard = $self->{schema}->txn_scope_guard;
            my %search = (ac_id => $self->{id});
            my $acl = $self->{schema}->resultset('Acl')->find (\%search);
            $acl->ac_comment($comment);
            $acl->update;
            $guard->commit;

            # Re-read (comment field may have been truncated)
            $acl = $self->{schema}->resultset('Acl')->find (\%search);
            $self->{comment} = $acl->ac_comment;
        };
        if ($@) {
            $self->error ("cannot update comment for ACL $self->{name}: $@");
            return;
        }
    } else {
        $self->error ("missing comment in set_comment for ACL $self->{name}");
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
        my $guard = $self->{schema}->txn_scope_guard;
        my %search = (ae_id         => $self->{id},
                      ae_scheme     => $scheme,
                      ae_identifier => $identifier);
        my $entry = $self->{schema}->resultset('AclEntry')->find (\%search);
        unless (defined $entry) {
            die "entry not found in ACL\n";
        }
        $entry->delete;
        $self->log_acl ('remove', $scheme, $identifier, $user, $host, $time);
        $guard->commit;
    };
    if ($@) {
        my $entry = "$scheme:$identifier";
        $self->error ("cannot remove $entry from $self->{name}: $@");
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
        my $guard = $self->{schema}->txn_scope_guard;
        my %search = (ae_id => $self->{id});
        my %options = (order_by => { -asc => [qw/ah_on ah_id/] });
        my @entry_recs = $self->{schema}->resultset('AclEntry')
            ->search (\%search);
        for my $entry (@entry_recs) {
            push (@entries, [ $entry->ae_scheme, $entry->ae_identifier ]);
        }
        $guard->commit;
    };
    if ($@) {
        $self->error ("cannot retrieve ACL $self->{name}: $@");
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
        if ($identifier) {
            $output .= "  $scheme $identifier\n";
        } else {
            $output .= "  $scheme\n";
        }
    }

    my $comment = $self->comment;
    if ($comment) {
        $output .= "comment: $comment\n";
    }

    return $output;
}

# Return as a string the history of an ACL.  Returns undef on failure.
sub history {
    my ($self) = @_;
    my $output = '';
    eval {
        my $guard = $self->{schema}->txn_scope_guard;
        my %search  = (ah_acl => $self->{id});
        my %options = (order_by => { -asc => [qw/ah_on ah_id/] });
        my @data = $self->{schema}->resultset('AclHistory')
            ->search (\%search, \%options);
        for my $data (@data) {
            my $date = $data->ah_on;
            $date->set_time_zone ('local');
            $output .= sprintf ("%s %s  ", $date->ymd, $date->hms);
            if ($data->ah_action eq 'add' || $data->ah_action eq 'remove') {
                if ($data->ah_identifier) {
                    $output .= sprintf ("%s %s %s", $data->ah_action,
                                        $data->ah_scheme, $data->ah_identifier);
                } else {
                    $output .= sprintf ("%s %s", $data->ah_action, $data->ah_scheme);
                }
            } elsif ($data->ah_action eq 'rename') {
                $output .= 'rename from ' . $data->ah_name;
            } else {
                $output .= $data->ah_action;
            }
            $output .= sprintf ("\n    by %s from %s\n", $data->ah_by,
                                $data->ah_from);
        }
        $guard->commit;
    };
    if ($@) {
        $self->error ("cannot read history for $self->{name}: $@");
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
        my ($self, $principal, $scheme, $identifier, $type, $name) = @_;
        unless ($verifier{$scheme}) {
            my $class = $self->scheme_mapping ($scheme);
            unless ($class) {
                push (@{ $self->{check_errors} }, "unknown scheme $scheme");
                return;
            }
            $verifier{$scheme} = $class->new ($identifier, $self->{schema});
            unless (defined $verifier{$scheme}) {
                push (@{ $self->{check_errors} }, "cannot verify $scheme");
                return;
            }
        }
        my $result = ($verifier{$scheme})->check ($principal, $identifier,
                                                  $type, $name);
        if (not defined $result) {
            push (@{ $self->{check_errors} }, ($verifier{$scheme})->error);
            return;
        } else {
            return $result;
        }
    }
}

# Given a principal, object type, and object name, check whether that
# principal should be granted access according to this ACL.  Returns 1 if
# access was granted, 0 if access was denied, and undef on some error.  Errors
# from ACL verifiers do not cause an error return, but are instead accumulated
# in the check_errors variable returned by the check_errors() method.
sub check {
    my ($self, $principal, $type, $name) = @_;
    unless ($principal) {
        $self->error ('no principal specified');
        return;
    }
    my @entries = $self->list;
    return if (not @entries and $self->error);
    my %verifier;
    $self->{check_errors} = [];
    for my $entry (@entries) {
        my ($scheme, $identifier) = @$entry;
        my $result = $self->check_line ($principal, $scheme, $identifier,
                                        $type, $name);
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

=for stopwords
ACL DBH metadata HOSTNAME DATETIME timestamp Allbery verifier verifiers

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

Wallet::ACL implements the ACL system for the wallet: the methods to
create, find, rename, and destroy ACLs; the methods to add and remove
entries from an ACL; and the methods to list the contents of an ACL and
check a principal against it.

An ACL is a list of zero or more ACL entries, each of which consists of a
scheme and an identifier.  Each scheme is associated with a verifier
module that checks Kerberos principals against identifiers for that scheme
and returns whether the principal should be permitted access by that
identifier.  The interpretation of the identifier is entirely left to the
scheme.  This module maintains the ACLs and dispatches check operations to
the appropriate verifier module.

Each ACL is identified by a human-readable name and a persistent unique
numeric identifier.  The numeric identifier (ID) should be used to refer
to the ACL so that it can be renamed as needed without breaking external
references.

=head1 CLASS METHODS

=over 4

=item new(ACL, SCHEMA)

Instantiate a new ACL object with the given ACL ID or name.  Takes the
Wallet::Schema object to use for retrieving metadata from the wallet
database.  Returns a new ACL object if the ACL was found and throws an
exception if it wasn't or on any other error.

=item create(NAME, SCHEMA, PRINCIPAL, HOSTNAME [, DATETIME])

Similar to new() in that it instantiates a new ACL object, but instead of
finding an existing one, creates a new ACL record in the database with the
given NAME.  NAME must not be all-numeric, since that would conflict with
the automatically assigned IDs.  Returns the new object on success and
throws an exception on failure.  PRINCIPAL, HOSTNAME, and DATETIME are
stored as history information.  PRINCIPAL should be the user who is
creating the ACL.  If DATETIME isn't given, the current time is used.

=back

=head1 INSTANCE METHODS

=over 4

=item add(SCHEME, INSTANCE, PRINCIPAL, HOSTNAME [, DATETIME])

Add the given ACL entry (given by SCHEME and INSTANCE) to this ACL.
Returns true on success and false on failure.  On failure, the caller
should call error() to get the error message.  PRINCIPAL, HOSTNAME, and
DATETIME are stored as history information.  PRINCIPAL should be the user
who is adding the ACL entry.  If DATETIME isn't given, the current time is
used.

=item check(PRINCIPAL)

Checks whether the given PRINCIPAL should be allowed access given ACL.
Returns 1 if access was granted, 0 if access is declined, and undef on
error.  On error, the caller should call error() to get the error text.
Any errors found by the individual ACL verifiers can be retrieved by
calling check_errors().  Errors from individual ACL verifiers will not
result in an error return from check(); instead, the check will continue
with the next entry in the ACL.

check() returns success as soon as an entry in the ACL grants access to
PRINCIPAL.  There is no provision for negative ACLs or exceptions.

=item check_errors()

Return (as a list in array context and a string with newlines between
errors and at the end of the last error in scalar context) the errors, if
any, returned by ACL verifiers for the last check operation.  If there
were no errors from the last check() operation, returns the empty list in
array context and undef in scalar context.

=item destroy(PRINCIPAL, HOSTNAME [, DATETIME])

Destroys this ACL from the database.  Note that this will fail if the ACL
is still referenced by any object; the ACL must be removed from all
objects first.  Returns true on success and false on failure.  On failure,
the caller should call error() to get the error message.  PRINCIPAL,
HOSTNAME, and DATETIME are stored as history information.  PRINCIPAL
should be the user who is destroying the ACL.  If DATETIME isn't given,
the current time is used.

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
returns undef, and the caller should call error() to get the error
message.

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
Returns true on success and false on failure.  On failure, the caller
should call error() to get the error message.  PRINCIPAL, HOSTNAME, and
DATETIME are stored as history information.  PRINCIPAL should be the user
who is removing the ACL entry.  If DATETIME isn't given, the current time
is used.

=item rename(NAME)

Rename this ACL.  This changes the name used for human convenience but not
the system-generated ACL ID that is used to reference this ACL.  The new
NAME must not be all-numeric, since that would conflict with
system-generated ACL IDs.  Returns true on success and false on failure.
On failure, the caller should call error() to get the error message.

Note that rename() operations are not logged in the ACL history.

=item replace(ID)

Replace this ACL with another.  This goes through each object owned by
the ACL and changes its ownership to the new ACL, leaving this ACL owning
nothing (and probably then needing to be deleted).  Returns true on
success and false on failure.  On failure, the caller should call error()
to get the error message.

=item show()

Returns a human-readable description of this ACL, including its
membership.  This method should only be used for display of the ACL to
humans.  Use the list(), name(), and id() methods instead to get ACL
information for use in other code.  On failure, returns undef, and the
caller should call error() to get the error message.

=back

=head1 SEE ALSO

Wallet::ACL::Base(3), wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<https://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=cut
