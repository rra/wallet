# Wallet::ACL::Base -- Parent class for wallet ACL verifiers.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007, 2010 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::ACL::Base;
require 5.006;

use strict;
use vars qw($VERSION);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.02';

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

Russ Allbery <rra@stanford.edu>

=cut
