# Wallet::ACL::Krb5 -- Wallet Kerberos v5 principal ACL verifier
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2016 Russ Allbery <eagle@eyrie.org>
# Copyright 2007, 2010, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::ACL::Krb5;

use 5.008;
use strict;
use warnings;

use Wallet::ACL::Base;

our @ISA     = qw(Wallet::ACL::Base);
our $VERSION = '1.03';

##############################################################################
# Interface
##############################################################################

# The most trivial ACL verifier.  Returns true if the provided principal
# matches the ACL.
sub check {
    my ($self, $principal, $acl) = @_;
    unless ($principal) {
        $self->error ('no principal specified');
        return;
    }
    unless ($acl) {
        $self->error ('malformed krb5 ACL');
        return;
    }
    return ($principal eq $acl) ? 1 : 0;
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=for stopwords
ACL krb5 Allbery verifier

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
lines of type C<krb5>.  The value of such an ACL is a simple Kerberos
principal in its text display form, and the ACL grants access to a given
principal if and only if the principal exactly matches the ACL.

=head1 METHODS

=over 4

=item new()

Creates a new ACL verifier.  For this verifier, there is no setup work.

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

Wallet::ACL(3), Wallet::ACL::Base(3), wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=cut
