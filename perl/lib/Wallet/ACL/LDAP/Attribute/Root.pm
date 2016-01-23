# Wallet::ACL::LDAP::Attribute::Root -- Wallet root instance LDAP ACL verifier
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Based on Wallet::ACL::NetDB::Root by Russ Allbery <eagle@eyrie.org>
# Copyright 2016 Russ Allbery <eagle@eyrie.org>
# Copyright 2015
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::ACL::LDAP::Attribute::Root;

use 5.008;
use strict;
use warnings;

use Wallet::ACL::LDAP::Attribute;

our @ISA     = qw(Wallet::ACL::LDAP::Attribute);
our $VERSION = '1.04';

##############################################################################
# Interface
##############################################################################

# Override the check method of Wallet::ACL::LDAP::Attribute to require that
# the principal be a root instance and to strip /root out of the principal
# name before checking roles.
sub check {
    my ($self, $principal, $acl) = @_;
    undef $self->{error};
    unless ($principal) {
        $self->error ('no principal specified');
        return;
    }
    unless ($principal =~ s%^([^/\@]+)/root(\@|\z)%$1$2%) {
        return 0;
    }
    return $self->SUPER::check ($principal, $acl);
}

##############################################################################
# Documentation
##############################################################################

=for stopwords
ACL Allbery LDAP verifier

=head1 NAME

Wallet::ACL::LDAP::Attribute::Root - Wallet ACL verifier for LDAP attributes (root instances)

=head1 SYNOPSIS

    my $verifier = Wallet::ACL::LDAP::Attribute::Root->new;
    my $status = $verifier->check ($principal, "$attr=$value");
    if (not defined $status) {
        die "Something failed: ", $verifier->error, "\n";
    } elsif ($status) {
        print "Access granted\n";
    } else {
        print "Access denied\n";
    }

=head1 DESCRIPTION

Wallet::ACL::LDAP::Attribute::Root works identically to
Wallet::ACL::LDAP::Attribute except that it requires the principal to
be a root instance (in other words, to be in the form
<principal>/root@<realm>) and strips the C</root> portion from the
principal before checking against the LDAP attribute and value.  As
with the base LDAP Attribute ACL verifier, the value of such a
C<ldap-attr-root> ACL is an attribute followed by an equal sign and a
value, and the ACL grants access to a given principal if and only if
the LDAP entry for that principal (with C</root> stripped) has that
attribute set to that value.

To use this object, the same configuration parameters must be set as for
Wallet::ACL::LDAP::Attribute.  See Wallet::Config(3) for details on
those configuration parameters and information about how to set wallet
configuration.

=head1 METHODS

=over 4

=item check(PRINCIPAL, ACL)

Returns true if PRINCIPAL is granted access according to ACL, false if
not, and undef on an error (see L<"DIAGNOSTICS"> below).  ACL must be an
attribute name and a value, separated by an equal sign (with no
whitespace).  PRINCIPAL will be granted access if it has an instance of
C<root> and if (with C</root> stripped off)  its LDAP entry contains
that attribute with that value

=back

=head1 DIAGNOSTICS

Same as for Wallet::ACL::LDAP::Attribute.

=head1 CAVEATS

The instance to strip is not currently configurable.

=head1 SEE ALSO

Net::Remctl(3), Wallet::ACL(3), Wallet::ACL::Base(3),
Wallet::ACL::LDAP::Attribute(3), Wallet::Config(3), wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHORS

Jon Robertson <jonrober@stanford.edu>
Russ Allbery <eagle@eyrie.org>

=cut
