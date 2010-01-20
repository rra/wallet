# Wallet::Kadmin -- Kadmin module wrapper for the wallet.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2009 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Kadmin;
require 5.006;

use strict;
use vars qw($VERSION);

use Wallet::Config ();

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.02';

##############################################################################
# Public methods
##############################################################################

# Validate a principal with a submodule's validator.  We can also do this via
# creating an object with new and then running valid_principal from that,
# but there are times we might wish to run it without going through the
# object creation.
sub valid_principal {
    my ($class, $principal) = @_;
    if ($Wallet::Config::KEYTAB_KRBTYPE eq 'MIT') {
        require Wallet::Kadmin::MIT;
        return Wallet::Kadmin::MIT->valid_principal ($principal);
    } elsif ($Wallet::Config::KEYTAB_KRBTYPE eq 'Heimdal') {
        require Wallet::Kadmin::Heimdal;
        return Wallet::Kadmin::Heimdal->valid_principal ($principal);
    }
}

# Create a new kadmin object, by finding the type requested in the wallet
# config and passing off to the proper module.  Returns the object directly
# from the specific Wallet::Kadmin::* module.
sub new {
    my ($class) = @_;
    my ($kadmin);
    if ($Wallet::Config::KEYTAB_KRBTYPE eq 'MIT') {
        require Wallet::Kadmin::MIT;
        $kadmin = Wallet::Kadmin::MIT->new ();
    } elsif ($Wallet::Config::KEYTAB_KRBTYPE eq 'Heimdal') {
        require Wallet::Kadmin::Heimdal;
        $kadmin = Wallet::Kadmin::Heimdal->new ();
    } else {
        die "keytab krb server type not set to a valid value\n";
    }

    return $kadmin;
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=head1 NAME

Wallet::Kadmin - Kadmin module wrapper for wallet keytabs

=head1 SYNOPSIS

    my $kadmin = Wallet::Kadmin->new ();
    $kadmin->addprinc ("host/shell.example.com");
    $kadmin->ktadd ("host/shell.example.com", "aes256-cts");
    my $exists = $kadmin->exists ("host/oldshell.example.com");
    $kadmin->delprinc ("host/oldshell.example.com") if $exists;

=head1 DESCRIPTION

Wallet::Kadmin is a wrapper to modules that provide an interface for keytab
integration with the wallet.  Each module is meant to interface with a
specific type of Kerberos implementation, such as MIT Kerberos or Heimdal
Kerberos, and provide a standndard set of API calls used to interact with
that implementation's kadmind.

The class simply uses Wallet::Config to find which type of kadmind we have
requested to use, and then returns an object to use for interacting with
that kadmind.

A keytab is an on-disk store for the key or keys for a Kerberos principal.
Keytabs are used by services to verify incoming authentication from clients
or by automated processes that need to authenticate to Kerberos.  To create
a keytab, the principal has to be created in Kerberos and then a keytab is
generated and stored in a file on disk.

To use this object, several configuration parameters must be set.  See
Wallet::Config(3) for details on those configuration parameters and
information about how to set wallet configuration.

=head1 METHODS

=over 4

=item new()

Finds the proper Kerberos implementation and calls the new() constructor for
that implementation's module, returning the result.  If the implementation
is not recognized or set, die with an error message.

=item valid_principal(PRINCIPAL)

Finds the proper Kerberos implementation and calls its own valid_principal
method, returning the result.  This tells whether a principal is valid for
that implementation.  This can be achieved by using new() and then directly
calling valid_principal on the returned object -- this method is a shortcut
in case we want to check validity without creating the object and worrying
about proper setup.

=head1 SEE ALSO

kadmin(8), Wallet::Config(3), Wallet::Object::Keytab(3), wallet-backend(8)

This module is part of the wallet system.  The current version is available
from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHORS

Jon Robertson <jonrober@stanford.edu>

=cut
