# Wallet::ACL::Nested - ACL class for nesting ACLs
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2016 Russ Allbery <eagle@eyrie.org>
# Copyright 2015
#     The Board of Trustees of the Leland Stanford Junior University
#
# SPDX-License-Identifier: MIT

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::ACL::Nested;

use 5.008;
use strict;
use warnings;

use Wallet::ACL::Base;

our @ISA     = qw(Wallet::ACL::Base);
our $VERSION = '1.04';

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
    my ($self, $principal, $group, $type, $name) = @_;
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
        my ($scheme, $identifier) = @{ $entry };
        my $result = $acl->check_line ($principal, $scheme, $identifier,
                                       $type, $name);
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

Wallet::ACL::Nested - Wallet ACL verifier to check another ACL

=head1 SYNOPSIS

    my $verifier = Wallet::ACL::Nested->new;
    my $status = $verifier->check ($principal, $acl);
    if (not defined $status) {
        die "Something failed: ", $verifier->error, "\n";
    } elsif ($status) {
        print "Access granted\n";
    } else {
        print "Access denied\n";
    }

=head1 DESCRIPTION

Wallet::ACL::Nested checks whether the principal is permitted by another
named ACL and, if so, returns success.  It is used to nest one ACL inside
another.

=head1 METHODS

=over 4

=item new()

Creates a new ACL verifier.

=item check(PRINCIPAL, ACL)

Returns true if PRINCIPAL is granted access according to the nested ACL,
specified by name.  Returns false if it is not, and undef on error.

=item error([ERROR ...])

Returns the error of the last failing operation or undef if no operations
have failed.  Callers should call this function to get the error message
after an undef return from any other instance method.  The returned errors
will generally come from the nested child ACL.

=back

=head1 SEE ALSO

Wallet::ACL(3), wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<https://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Jon Robertson <jonrober@stanford.edu>

=cut
