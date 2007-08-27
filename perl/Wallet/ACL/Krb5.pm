# Wallet::ACL::Krb5 -- Wallet Kerberos v5 principal ACL verifier.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007 Board of Trustees, Leland Stanford Jr. University
#
# See README for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::ACL::Krb5;
require 5.006;

use strict;
use vars qw(@ISA $VERSION);

@ISA = qw(Wallet::ACL::Base);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.01';

##############################################################################
# Interface
##############################################################################

# The most trivial ACL verifier.  Returns true if the provided principal
# matches the ACL.
sub check {
    my ($self, $principal, $acl) = @_;
    unless ($principal) {
        $self->{error} = 'no principal specified';
        return undef;
    }
    unless ($acl) {
        $self->{error} = 'malformed krb5 ACL';
        return undef;
    }
    return ($principal eq $acl) ? 1 : 0;
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=head1 NAME

Wallet::ACL::Krb5 - Simple wallet ACL verifier for Kerberos principals

=head1 SYNOPSIS

    my $verifier = Wallet::ACL::Krb5->new;
    my $status = $verifier->check ($principal, $acl);
    if (not defined $status) {
        die "Something failed: ", $verifier->error, "\n";
    } elsif ($status) {
        print "Access granted\n";
    } else {
        print "Access denied\n";
    }

=head1 DESCRIPTION

Wallet::ACL::Krb5 is the simplest wallet ACL verifier, used to verify ACL
lines of type krb5.  The value of such an ACL is a simple Kerberos
principal in its text display form, and the ACL grants access to a given
principal if and only if the principal exactly matches the ACL.

=head1 METHODS

=over 4

=item new(DBH)

Creates a new ACL verifier.  The database handle is not used.

=item check(PRINCIPAL, ACL)

Returns true if PRINCIPAL matches ACL, false if not, and undef on an error
(see L<"DIAGNOSTICS"> below).

=item error()

Returns the error if check() returned undef.

=back

=head1 DIAGNOSTICS

=over 4

=item malformed krb5 ACL

The ACL parameter to check() was malformed.  Currently, this error is only
given if ACL is undefined or the empty string.

=item no principal specified

The PRINCIPAL parameter to check() was undefined or the empty string.

=back

=head1 SEE ALSO

walletd(8)

This module is part of the wallet system.  The current version is available
from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <rra@stanford.edu>

=cut
