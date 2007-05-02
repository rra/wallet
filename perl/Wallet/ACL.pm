# Wallet::ACL -- Parent class for wallet ACL verifiers.
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
use vars qw($VERSION);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.01';

##############################################################################
# Interface
##############################################################################

# Creates a new persistant verifier, taking a database handle.  This parent
# class just creates an empty object and ignores the handle.  Child classes
# should override if there are necessary initialization tasks or if the handle
# will be used by the verifier.
sub new {
    my $type = shift;
    my $self = {};
    bless ($self, $type);
    return $self;
}

# The default check method denies all access.
sub check {
    return 0;
}

# Return the error stashed in the object.
sub error {
    my ($self) = @_;
    return $self->{error};
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=head1 NAME

Wallet::ACL - Generic parent class for wallet ACL verifiers

=head1 SYNOPSIS

    package Wallet::ACL::Simple
    @ISA = qw(Wallet::ACL);
    sub check {
        my ($self, $principal, $acl) = @_;
        return ($principal eq $acl) ? 1 : 0;
    }

=head1 DESCRIPTION

Wallet::ACL is the generic parent class for wallet ACL verifiers.  It
provides default functions and behavior and all ACL verifiers should inherit
from it.  It is not used directly.

=head1 METHODS

=over 4

=item new(DBH)

Creates a new ACL verifier.  The generic function provided here just creates
and blesses an object and ignores the provided database handle.

=item check(PRINCIPAL, ACL)

This method should always be overridden by child classes.  The default
implementation just declines all access.

=item error()

Returns whatever is stored in the error key of the object hash.  Child
classes should store error messages in that key when returning undef from
check().

=back

=head1 SEE ALSO

walletd(8)

This module is part of the wallet system.  The current version is available
from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <rra@stanford.edu>

=cut
