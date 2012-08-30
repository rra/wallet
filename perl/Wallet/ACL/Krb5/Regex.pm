# Wallet::ACL::Krb5::Regex -- Wallet Kerberos v5 principal regex ACL verifier
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007, 2010 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::ACL::Krb5::Regex;
require 5.006;

use strict;
use vars qw(@ISA $VERSION);

use Wallet::ACL::Krb5;

@ISA = qw(Wallet::ACL::Krb5);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.01';

##############################################################################
# Interface
##############################################################################

# Returns true if the Perl regular expression specified by the ACL matches
# the provided Kerberos principal.
sub check {
    my ($self, $principal, $acl) = @_;
    unless ($principal) {
        $self->error ('no principal specified');
        return;
    }
    unless ($acl) {
        $self->error ('no ACL specified');
        return;
    }
    my $regex = eval { qr/$acl/ };
    if ($@) {
        $self->error ('malformed krb5-regex ACL');
        return;
    }
    return ($principal =~ m/$regex/) ? 1 : 0;
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=for stopwords
ACL krb5-regex Durkacz Allbery verifier

=head1 NAME

Wallet::ACL::Krb5::Regex - Regex wallet ACL verifier for Kerberos principals

=head1 SYNOPSIS

    my $verifier = Wallet::ACL::Krb5::Regex->new;
    my $status = $verifier->check ($principal, $acl);
    if (not defined $status) {
        die "Something failed: ", $verifier->error, "\n";
    } elsif ($status) {
        print "Access granted\n";
    } else {
        print "Access denied\n";
    }

=head1 DESCRIPTION

Wallet::ACL::Krb5::Regex is the wallet ACL verifier used to verify ACL
lines of type C<krb5-regex>.  The value of such an ACL is a Perl regular
expression, and the ACL grants access to a given Kerberos principal if and
only if the regular expression matches that principal.

=head1 METHODS

=over 4

=item new()

Creates a new ACL verifier.  For this verifier, there is no setup work.

=item check(PRINCIPAL, ACL)

Returns true if the Perl regular expression specified by the ACL matches the
PRINCIPAL, false if not, and undef on an error (see L<"DIAGNOSTICS"> below).

=item error()

Returns the error if check() returned undef.

=back

=head1 DIAGNOSTICS

=over 4

=item malformed krb5-regex ACL

The ACL parameter to check() was a malformed Perl regular expression.

=item no principal specified

The PRINCIPAL parameter to check() was undefined or the empty string.

=item no ACL specified

The ACL parameter to check() was undefined or the empty string.

=back

=head1 SEE ALSO

Wallet::ACL(3), Wallet::ACL::Base(3), Wallet::ACL::Krb5(3), wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Ian Durkacz

=cut
