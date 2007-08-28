# Wallet::ACL -- Implementation of ACLs in the wallet system.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007 Board of Trustees, Leland Stanford Jr. University
#
# See README for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::ACL;
require 5.006;

use strict;
use vars qw(%MAPPING $VERSION);

use DBI;
use Wallet::ACL::Krb5;

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.01';

# This is a mapping of schemes to class names, used to determine which ACL
# verifier should be instantiated for a given ACL scheme.  Currently, there's
# no dynamic way to recognize new ACL verifiers, so if you extend the wallet
# system to add new verifiers, you need to modify this list.
%MAPPING = (krb5 => 'Wallet::ACL::Krb5');

##############################################################################
# Constructors
##############################################################################

# Initialize a new ACL from the database.  Verify that the ACL already exists
# in the database and, if so, return a new blessed object.  Stores the ACL ID
# and the database handle to use for future operations.  If the object
# doesn't exist, throws an exception.
sub new {
    my ($class, $id, $dbh) = @_;
    $dbh->{AutoCommit} = 0;
    $dbh->{RaiseError} = 1;
    $dbh->{PrintError} = 0;
    my ($sql, $data);
    if ($id =~ /^\d+\z/) {
        $sql = 'select ac_id from acls where ac_id = ?';
    } else {
        $sql = 'select ac_id from acls where ac_name = ?';
    }
    eval {
        $data = $dbh->selectrow_array ($sql, undef, $id);
    };
    if ($@) {
        die "cannot search for ACL $id: $@\n";
    } elsif (not defined $data) {
        die "ACL $id not found\n";
    }
    my $self = {
        dbh => $dbh,
        id  => $data,
    };
    bless ($self, $class);
    return $self;
}

# Create a new ACL in the database with the given name and return a new
# blessed ACL object for it.  Stores the database handle to use and the ID of
# the newly created ACL in the object.  On failure, throws an exception.
sub create {
    my ($class, $name, $dbh, $user, $host, $time) = @_;
    $dbh->{AutoCommit} = 0;
    $dbh->{RaiseError} = 1;
    $dbh->{PrintError} = 0;
    $time ||= time;
    my $id;
    eval {
        my $sql = 'insert into acls (ac_name) values (?)';
        $dbh->do ($sql, undef, $name);
        $id = $dbh->last_insert_id;
        die "unable to retrieve new ACL ID" unless defined $id;
        $sql = "insert into acl_history (ah_acl, ah_action, ah_by, ah_from,
            ah_on) values (?, 'create', ?, ?, ?)";
        $dbh->do ($sql, undef, $id, $user, $host, $time);
        $dbh->commit;
    };
    if ($@) {
        $dbh->rollback;
        die "cannot create ACL $name: $@\n";
    }
    my $self = {
        dbh => $dbh,
        id  => $id,
    };
    bless ($self, $class);
    return $self;
}

##############################################################################
# Utility functions
##############################################################################

# Returns the current error message of the object, if any.
sub error {
    my ($self) = @_;
    return $self->{error};
}

# Returns the ID of an ACL.
sub id {
    my ($self) = @_;
    return $self->{id};
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
    my $sql = 'insert into acl_history (ah_acl, ah_action, ah_scheme,
        ah_identifier, ah_by, ah_from, ah_on) values (?, ?, ?, ?, ?, ?, ?)';
    $self->{dbh}->do ($sql, undef, $self->{id}, $action, $scheme, $identifier,
                      $user, $host, $time);
}

##############################################################################
# ACL manipulation
##############################################################################

# Changes the human-readable name of the ACL.  Note that this operation is not
# logged since it isn't a change to any of the data stored in the wallet.
# Returns true on success, false on failure.
sub rename {
    my ($self, $name) = @_;
    eval {
        my $sql = 'update acls set ac_name = ? where ac_id = ?';
        $self->{dbh}->do ($sql, undef, $name, $self->{id});
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->{error} = "cannot rename ACL $self->{id} to $name: $@";
        $self->{dbh}->rollback;
        return undef;
    }
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
        $self->{error} = "cannot destroy ACL $self->{id}: $@";
        $self->{dbh}->rollback;
        return undef;
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
    unless ($MAPPING{$scheme}) {
        $self->{error} = "unknown ACL scheme $scheme";
        return undef;
    }
    eval {
        my $sql = 'insert into acl_entries (ae_id, ae_scheme, ae_identifier)
            values (?, ?, ?)';
        $self->{dbh}->do ($sql, undef, $self->{id}, $scheme, $identifier);
        $self->log_acl ('add', $scheme, $identifier, $user, $host, $time);
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->{error} = "cannot add $scheme:$identifier to $self->{id}: $@";
        $self->{dbh}->rollback;
        return undef;
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
            die "entry not found in ACL";
        }
        $sql = 'delete from acl_entries where ae_id = ? and ae_scheme = ?
            and ae_identifier = ?';
        $self->{dbh}->do ($sql, undef, $self->{id}, $scheme, $identifier);
        $self->log_acl ('remove', $scheme, $identifier, $user, $host, $time);
        $self->{dbh}->commit;
    };
    if ($@) {
        my $entry = "$scheme:$identifier";
        $self->{error} = "cannot remove $entry from $self->{id}: $@";
        $self->{dbh}->rollback;
        return undef;
    }
    return 1;
}

##############################################################################
# ACL checking
##############################################################################

# Given a principal, check whether it should be granted access according to
# this ACL.  Returns 1 if access was granted, 0 if access was denied, and
# undef on some error.  Errors from ACL verifiers do not cause an error
# return, but are instead accumulated in the check_errors variable returned by
# the check_errors() method.
#
# This routine is currently rather inefficient when it comes to instantiating
# verifier objects.  They're created anew for each check.  Ideally, we should
# globally cache verifiers in some way.
sub check {
    my ($self, $principal) = @_;
    my (%verifier, @entries);
    eval {
        my $sql = 'select ae_scheme, ae_identifier from acl_entries where
            ae_id = ?';
        my $sth = $self->{dbh}->prepare ($sql);
        $sth->execute;
        my $entry;
        while (defined ($entry = $sth->fetchrow_arrayref)) {
            push (@entries, $entry);
        }
    };
    if ($@) {
        $self->{error} = "cannot retrieve ACL $self->{id}: $@";
        return undef;
    }
    $self->{check_errors} = [];
    for my $entry (@entries) {
        my ($scheme, $identifier) = @$entry;
        unless ($verifier{$scheme}) {
            unless ($MAPPING{$scheme}) {
                push (@{ $self->{check_errors} }, "unknown scheme $scheme");
                next;
            }
            $verifier{$scheme} = ($MAPPING{$scheme})->new;
            unless (defined $verifier{$scheme}) {
                push (@{ $self->{check_errors} }, "cannot verify $scheme");
                next;
            }
        }
        my $result = ($verifier{$scheme})->check ($principal, $identifier);
        if (not defined $result) {
            push (@{ $self->{check_errors} }, ($verifier{$scheme})->error);
        } elsif ($result == 1) {
            return 1;
        }
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
