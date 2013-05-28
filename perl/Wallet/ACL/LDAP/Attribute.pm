# Wallet::ACL::LDAP::Attribute -- Wallet LDAP attribute ACL verifier.
#
# Written by Russ Allbery
# Copyright 2012, 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::ACL::LDAP::Attribute;
require 5.006;

use strict;
use vars qw(@ISA $VERSION);

use Authen::SASL ();
use Net::LDAP qw(LDAP_COMPARE_TRUE);
use Wallet::ACL::Base;
use Wallet::Config;

@ISA = qw(Wallet::ACL::Base);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.01';

##############################################################################
# Interface
##############################################################################

# Create a new persistant verifier.  Load the Net::LDAP module and open a
# persistant LDAP server connection that we'll use for later calls.
sub new {
    my $type = shift;
    my $host = $Wallet::Config::LDAP_HOST;
    my $base = $Wallet::Config::LDAP_BASE;
    unless ($host and defined ($base) and $Wallet::Config::LDAP_CACHE) {
        die "LDAP attribute ACL support not configured\n";
    }

    # Ensure the required Perl modules are available and bind to the directory
    # server.  Catch any errors with a try/catch block.
    my $ldap;
    eval {
        local $ENV{KRB5CCNAME} = $Wallet::Config::LDAP_CACHE;
        my $sasl = Authen::SASL->new (mechanism => 'GSSAPI');
        $ldap = Net::LDAP->new ($host, onerror => 'die');
        my $mesg = eval { $ldap->bind (undef, sasl => $sasl) };
    };
    if ($@) {
        my $error = $@;
        chomp $error;
        1 while ($error =~ s/ at \S+ line \d+\.?\z//);
        die "LDAP attribute ACL support not available: $error\n";
    }

    # We successfully bound, so create our object and return it.
    my $self = { ldap => $ldap };
    bless ($self, $type);
    return $self;
}

# Check whether a given principal has the required LDAP attribute.  We first
# map the principal to a DN by doing a search for that principal (and bailing
# if we get more than one entry).  Then, we do a compare to see if that DN has
# the desired attribute and value.
#
# If the ldap_map_principal sub is defined in Wallet::Config, call it on the
# principal first to map it to the value for which we'll search.
#
# The connection is configured to die on any error, so we do all the work in a
# try/catch block to report errors.
sub check {
    my ($self, $principal, $acl) = @_;
    undef $self->{error};
    unless ($principal) {
        $self->error ('no principal specified');
        return;
    }
    my ($attr, $value);
    if ($acl) {
        ($attr, $value) = split ('=', $acl, 2);
    }
    unless (defined ($attr) and defined ($value)) {
        $self->error ('malformed ldap-attr ACL');
        return;
    }
    my $ldap = $self->{ldap};

    # Map the principal name to an attribute value for our search if we're
    # doing a custom mapping.
    if (defined &Wallet::Config::ldap_map_principal) {
        eval { $principal = Wallet::Config::ldap_map_principal ($principal) };
        if ($@) {
            $self->error ("mapping principal to LDAP failed: $@");
            return;
        }
    }

    # Now, map the user to a DN by doing a search.
    my $entry;
    eval {
        my $fattr = $Wallet::Config::LDAP_FILTER_ATTR || 'krb5PrincipalName';
        my $filter = "($fattr=$principal)";
        my $base = $Wallet::Config::LDAP_BASE;
        my @options = (base => $base, filter => $filter, attrs => [ 'dn' ]);
        my $search = $ldap->search (@options);
        if ($search->count == 1) {
            $entry = $search->pop_entry;
        } elsif ($search->count > 1) {
            die $search->count . " LDAP entries found for $principal";
        }
    };
    if ($@) {
        $self->error ("cannot search for $principal in LDAP: $@");
        return;
    }
    return 0 unless $entry;

    # We have a user entry.  We can now check whether that user has the
    # desired attribute and value.
    my $result;
    eval {
        my $mesg = $ldap->compare ($entry, attr => $attr, value => $value);
        $result = $mesg->code;
    };
    if ($@) {
        $self->error ("cannot check LDAP attribute $attr for $principal: $@");
        return;
    }
    return ($result == LDAP_COMPARE_TRUE) ? 1 : 0;
}

1;

##############################################################################
# Documentation
##############################################################################

=for stopwords
ACL Allbery verifier LDAP PRINCIPAL's DN ldap-attr

=head1 NAME

Wallet::ACL::LDAP::Attribute - Wallet ACL verifier for LDAP attribute compares

=head1 SYNOPSIS

    my $verifier = Wallet::ACL::LDAP::Attribute->new;
    my $status = $verifier->check ($principal, "$attr=$value");
    if (not defined $status) {
        die "Something failed: ", $verifier->error, "\n";
    } elsif ($status) {
        print "Access granted\n";
    } else {
        print "Access denied\n";
    }

=head1 DESCRIPTION

Wallet::ACL::LDAP::Attribute checks whether the LDAP record for the entry
corresponding to a principal contains an attribute with a particular
value.  It is used to verify ACL lines of type C<ldap-attr>.  The value of
such an ACL is an attribute followed by an equal sign and a value, and the
ACL grants access to a given principal if and only if the LDAP entry for
that principal has that attribute set to that value.

To use this object, several configuration parameters must be set.  See
L<Wallet::Config> for details on those configuration parameters and
information about how to set wallet configuration.

=head1 METHODS

=over 4

=item new()

Creates a new ACL verifier.  Opens and binds the connection to the LDAP
server.

=item check(PRINCIPAL, ACL)

Returns true if PRINCIPAL is granted access according to ACL, false if
not, and undef on an error (see L<"DIAGNOSTICS"> below).  ACL must be an
attribute name and a value, separated by an equal sign (with no
whitespace).  PRINCIPAL will be granted access if its LDAP entry contains
that attribute with that value.

=item error()

Returns the error if check() returned undef.

=back

=head1 DIAGNOSTICS

The new() method may fail with one of the following exceptions:

=over 4

=item LDAP attribute ACL support not available: %s

Attempting to connect or bind to the LDAP server failed.

=item LDAP attribute ACL support not configured

The required configuration parameters were not set.  See Wallet::Config(3)
for the required configuration parameters and how to set them.

=back

Verifying an LDAP attribute ACL may fail with the following errors
(returned by the error() method):

=over 4

=item cannot check LDAP attribute %s for %s: %s

The LDAP compare to check for the required attribute failed.  The
attribute may have been misspelled, or there may be LDAP directory
permission issues.  This error indicates that PRINCIPAL's entry was
located in LDAP, but the check failed during the compare to verify the
attribute value.

=item cannot search for %s in LDAP: %s

Searching for PRINCIPAL (possibly after ldap_map_principal() mapping)
failed.  This is often due to LDAP directory permissions issues.  This
indicates a failure during the mapping of PRINCIPAL to an LDAP DN.

=item malformed ldap-attr ACL

The ACL parameter to check() was malformed.  Usually this means that
either the attribute or the value were empty or the required C<=> sign
separating them was missing.

=item mapping principal to LDAP failed: %s

There was an ldap_map_principal() function defined in the wallet
configuration, but calling it for the PRINCIPAL argument failed.

=item no principal specified

The PRINCIPAL parameter to check() was undefined or the empty string.

=back

=head1 SEE ALSO

Wallet::ACL(3), Wallet::ACL::Base(3), Wallet::Config(3), wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <rra@stanford.edu>

=cut
