# Wallet::ACL::Nested - ACL class for nesting ACLs
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2015
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::ACL::Nested;
require 5.006;

use strict;
use warnings;
use vars qw($VERSION @ISA);

use Wallet::ACL::Base;

@ISA = qw(Wallet::ACL::Base);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.01';

##############################################################################
# Interface
##############################################################################

# Creates a new persistant verifier, taking a database handle to use for
# syntax check validation.
sub new {
    my $type = shift;
    my ($name, $schema) = @_;
    my $self = {
        schema   => $schema,
        expanded => {},
    };
    bless ($self, $type);
    return $self;
}

# Name checking requires checking that there's an existing ACL already by
# this name.  Try to create the ACL object and use that to determine.
sub syntax_check {
    my ($self, $group) = @_;

    my $acl;
    eval { $acl = Wallet::ACL->new ($group, $self->{schema}) };
    return 0 if $@;
    return 0 unless $acl;
    return 1;
}

# For checking a nested ACL, we need to expand each entry and then check
# that entry.  We also want to keep track of things already checked in order
# to avoid any loops.
sub check {
    my ($self, $principal, $group) = @_;
    unless ($principal) {
        $self->error ('no principal specified');
        return;
    }
    unless ($group) {
        $self->error ('malformed nested ACL');
        return;
    }

    # Make an ACL object just so that we can use it to drop back into the
    # normal ACL validation after we have expanded the nesting.
    my $acl;
    eval { $acl = Wallet::ACL->new ($group, $self->{schema}) };

    # Get the list of all nested acl entries within this entry, and use it
    # to go through each entry and decide if the given acl has access.
    my @members = $self->get_membership ($group);
    for my $entry (@members) {
        my ($type, $name) = @{ $entry };
        my $result = $acl->check_line ($principal, $type, $name);
        return 1 if $result;
    }
    return 0;
}

# Get the membership of a group recursively.  The final result will be a list
# of arrayrefs like that from Wallet::ACL->list, but expanded for full
# membership.
sub get_membership {
    my ($self, $group) = @_;

    # Get the list of members for this nested acl.  Consider any missing acls
    # as empty.
    my $schema = $self->{schema};
    my @members;
    eval {
        my $acl  = Wallet::ACL->new ($group, $schema);
        @members = $acl->list;
    };

    # Now go through and expand any other nested groups into their own
    # memberships.
    my @expanded;
    for my $entry (@members) {
        my ($type, $name) = @{ $entry };
        if ($type eq 'nested') {

            # Keep track of things we've already expanded and don't look them
            # up again.
            next if exists $self->{expanded}{$name};
            $self->{expanded}{$name} = 1;
            push (@expanded, $self->get_membership ($name));

        } else {
            push (@expanded, $entry);
        }
    }

    return @expanded;
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=for stopwords
ACL Allbery verifier verifiers

=head1 NAME

Wallet::ACL::Base - Generic parent class for wallet ACL verifiers

=head1 SYNOPSIS

    package Wallet::ACL::Simple
    @ISA = qw(Wallet::ACL::Base);
    sub check {
        my ($self, $principal, $acl) = @_;
        return ($principal eq $acl) ? 1 : 0;
    }

=head1 DESCRIPTION

Wallet::ACL::Base is the generic parent class for wallet ACL verifiers.
It provides default functions and behavior and all ACL verifiers should
inherit from it.  It is not used directly.

=head1 METHODS

=over 4

=item new()

Creates a new ACL verifier.  The generic function provided here just
creates and blesses an object.

=item check(PRINCIPAL, ACL)

This method should always be overridden by child classes.  The default
implementation just declines all access.

=item error([ERROR ...])

Returns the error of the last failing operation or undef if no operations
have failed.  Callers should call this function to get the error message
after an undef return from any other instance method.

For the convenience of child classes, this method can also be called with
one or more error strings.  If so, those strings are concatenated
together, trailing newlines are removed, any text of the form S<C< at \S+
line \d+\.?>> at the end of the message is stripped off, and the result is
stored as the error.  Only child classes should call this method with an
error string.

=back

=head1 SEE ALSO

Wallet::ACL(3), wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=cut
