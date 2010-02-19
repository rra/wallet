# Wallet::Kadmin -- Kadmin module wrapper for the wallet.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2009, 2010 Board of Trustees, Leland Stanford Jr. University
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
$VERSION = '0.03';

##############################################################################
# Public methods
##############################################################################

# Create a new kadmin object, by finding the type requested in the wallet
# config and passing off to the proper module.  Returns the object directly
# from the specific Wallet::Kadmin::* module.
sub new {
    my ($class) = @_;
    my ($kadmin);
    if (not $Wallet::Config::KEYTAB_KRBTYPE) {
        die "keytab object implementation not configured\n";
    } elsif (lc ($Wallet::Config::KEYTAB_KRBTYPE) eq 'mit') {
        require Wallet::Kadmin::MIT;
        $kadmin = Wallet::Kadmin::MIT->new;
    } elsif (lc ($Wallet::Config::KEYTAB_KRBTYPE) eq 'heimdal') {
        require Wallet::Kadmin::Heimdal;
        $kadmin = Wallet::Kadmin::Heimdal->new;
    } else {
        my $type = $Wallet::Config::KEYTAB_KRBTYPE;
        die "unknown KEYTAB_KRBTYPE setting: $type\n";
    }

    return $kadmin;
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

# Set a callback to be called for forked kadmin processes.  This does nothing
# by default but may be overridden by subclasses that need special behavior
# (such as the current Wallet::Kadmin::MIT module).
sub fork_callback { }

1;
__END__

##############################################################################
# Documentation
##############################################################################

=for stopwords
Kadmin keytabs keytab Heimdal API kadmind kadmin

=head1 NAME

Wallet::Kadmin - Kadmin module wrapper for wallet keytabs

=head1 SYNOPSIS

    my $kadmin = Wallet::Kadmin->new ();
    $kadmin->addprinc ("host/shell.example.com");
    $kadmin->ktadd ("host/shell.example.com", "aes256-cts-hmac-sha1-96");
    my $exists = $kadmin->exists ("host/oldshell.example.com");
    $kadmin->delprinc ("host/oldshell.example.com") if $exists;

=head1 DESCRIPTION

Wallet::Kadmin is a wrapper to modules that provide an interface for
keytab integration with wallet.  Each module is meant to interface with a
specific type of Kerberos implementation, such as MIT Kerberos or Heimdal,
and provide a standard set of API calls used to interact with that
implementation's kadmin interface.

The class uses Wallet::Config to find which type of kadmin interface is in
use and then returns an object to use for interacting with that interface.

A keytab is an on-disk store for the key or keys for a Kerberos principal.
Keytabs are used by services to verify incoming authentication from
clients or by automated processes that need to authenticate to Kerberos.
To create a keytab, the principal has to be created in Kerberos and then a
keytab is generated and stored in a file on disk.

To use this object, several configuration parameters must be set.  See
Wallet::Config(3) for details on those configuration parameters and
information about how to set wallet configuration.

=head1 CLASS METHODS

=over 4

=item new()

Finds the proper Kerberos implementation and calls the new() constructor
for that implementation's module, returning the resulting object.  If the
implementation is not recognized or set, die with an error message.

=back

=head1 INSTANCE METHODS

=over 4

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

=item fork_callback(CALLBACK)

If the module has to fork an external process for some reason, such as a
kadmin command-line client, the sub CALLBACK will be called in the child
process before running the program.  This can be used to, for example,
properly clean up shared database handles.

=back

=head1 SEE ALSO

kadmin(8), Wallet::Config(3), Wallet::Object::Keytab(3), wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHORS

Jon Robertson <jonrober@stanford.edu>

=cut
