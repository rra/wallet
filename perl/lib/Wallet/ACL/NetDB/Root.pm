# Wallet::ACL::NetDB::Root -- Wallet NetDB role ACL verifier (root instances)
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2016 Russ Allbery <eagle@eyrie.org>
# Copyright 2007, 2010, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# SPDX-License-Identifier: MIT

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::ACL::NetDB::Root;

use 5.008;
use strict;
use warnings;

use Wallet::ACL::NetDB;

our @ISA     = qw(Wallet::ACL::NetDB);
our $VERSION = '1.04';

##############################################################################
# Interface
##############################################################################

# Override the check method of Wallet::ACL::NetDB to require that the
# principal be a root instance and to strip /root out of the principal name
# before checking roles.
sub check {
    my ($self, $principal, $acl) = @_;
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
ACL NetDB DNS DHCP Allbery verifier

=head1 NAME

Wallet::ACL::NetDB::Root - Wallet ACL verifier for NetDB roles (root instances)

=head1 SYNOPSIS

    my $verifier = Wallet::ACL::NetDB::Root->new;
    my $status = $verifier->check ($principal, $node);
    if (not defined $status) {
        die "Something failed: ", $verifier->error, "\n";
    } elsif ($status) {
        print "Access granted\n";
    } else {
        print "Access denied\n";
    }

=head1 DESCRIPTION

Wallet::ACL::NetDB::Root works identically to Wallet::ACL::NetDB except
that it requires the principal to be a root instance (in other words, to
be in the form <principal>/root@<realm>) and strips the C</root> portion
from the principal before checking against NetDB roles.  As with the base
NetDB ACL verifier, the value of a C<netdb-root> ACL is a node, and the
ACL grants access to a given principal if and only if the that principal
(with C</root> stripped) has one of the roles user, admin, or team for
that node.

To use this object, the same configuration parameters must be set as for
Wallet::ACL::NetDB.  See Wallet::Config(3) for details on those
configuration parameters and information about how to set wallet
configuration.

=head1 METHODS

=over 4

=item check(PRINCIPAL, ACL)

Returns true if PRINCIPAL is granted access according to ACL, false if
not, and undef on an error (see L<"DIAGNOSTICS"> below).  ACL is a node,
and PRINCIPAL will be granted access if it has an instance of C<root> and
if (with C</root> stripped off and the realm stripped off if configured)
has the user, admin, or team role for that node.

=back

=head1 DIAGNOSTICS

Same as for Wallet::ACL::NetDB.

=head1 CAVEATS

The instance to strip is not currently configurable.

The list of possible NetDB roles that should be considered sufficient to
grant access is not currently configurable.

=head1 SEE ALSO

Net::Remctl(3), Wallet::ACL(3), Wallet::ACL::Base(3),
Wallet::ACL::NetDB(3), Wallet::Config(3), wallet-backend(8)

NetDB is a free software system for managing DNS, DHCP, and related
machine information for large organizations.  For more information on
NetDB, see L<https://web.stanford.edu/group/networking/netdb/>.

This module is part of the wallet system.  The current version is
available from L<https://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=cut
