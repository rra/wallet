# Wallet::Kadmin -- Kerberos administration API for wallet keytab backend
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2016 Russ Allbery <eagle@eyrie.org>
# Copyright 2009, 2010, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Kadmin;

use 5.008;
use strict;
use warnings;

use Wallet::Config;

our $VERSION = '1.03';

##############################################################################
# Utility functions for child classes
##############################################################################

# Read the entirety of a possibly binary file and return the contents,
# deleting the file after reading it.  If reading the file fails, set the
# error message and return undef.
sub read_keytab {
    my ($self, $file) = @_;
    local *TMPFILE;
    unless (open (TMPFILE, '<', $file)) {
        $self->error ("cannot open temporary file $file: $!");
        return;
    }
    local $/;
    undef $!;
    my $data = <TMPFILE>;
    if ($!) {
        $self->error ("cannot read temporary file $file: $!");
        unlink $file;
        return;
    }
    close TMPFILE;
    unlink $file;
    return $data;
}

##############################################################################
# Public methods
##############################################################################

# Create a new kadmin object, by finding the type requested in the wallet
# config and passing off to the proper module.  Returns the object directly
# from the specific Wallet::Kadmin::* module.
sub new {
    my ($class) = @_;
    my $kadmin;
    if (not $Wallet::Config::KEYTAB_KRBTYPE) {
        die "keytab object implementation not configured\n";
    } elsif (lc ($Wallet::Config::KEYTAB_KRBTYPE) eq 'mit') {
        require Wallet::Kadmin::MIT;
        $kadmin = Wallet::Kadmin::MIT->new;
    } elsif (lc ($Wallet::Config::KEYTAB_KRBTYPE) eq 'heimdal') {
        require Wallet::Kadmin::Heimdal;
        $kadmin = Wallet::Kadmin::Heimdal->new;
    } elsif (lc ($Wallet::Config::KEYTAB_KRBTYPE) eq 'ad') {
        require Wallet::Kadmin::AD;
        $kadmin = Wallet::Kadmin::AD->new;
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
backend Kadmin keytabs keytab Heimdal API kadmind kadmin KDC ENCTYPE
enctypes enctype Allbery

=head1 NAME

Wallet::Kadmin - Kerberos administration API for wallet keytab backend

=head1 SYNOPSIS

    my $kadmin = Wallet::Kadmin->new;
    $kadmin->create ('host/foo.example.com');
    my $data = $kadmin->keytab_rekey ('host/foo.example.com',
                                      'aes256-cts-hmac-sha1-96');
    $data = $kadmin->keytab ('host/foo.example.com');
    my $exists = $kadmin->exists ('host/oldshell.example.com');
    $kadmin->destroy ('host/oldshell.example.com') if $exists;

=head1 DESCRIPTION

Wallet::Kadmin is a wrapper and base class for modules that provide an
interface for wallet to do Kerberos administration, specifically create
and delete principals and create keytabs for a principal.  Each subclass
administers a specific type of Kerberos implementation, such as MIT
Kerberos or Heimdal, providing a standard set of API calls used to
interact with that implementation's kadmin interface.

The class uses Wallet::Config to find which type of kadmin interface is in
use and then returns an object to use for interacting with that interface.
See L<Wallet::Config/"KEYTAB OBJECT CONFIGURATION"> for details on how to
configure this module.

=head1 CLASS METHODS

=over 4

=item new()

Finds the proper Kerberos implementation and calls the new() constructor
for that implementation's module, returning the resulting object.  If the
implementation is not recognized or set, die with an error message.

=back

=head1 INSTANCE METHODS

These methods are provided by any object returned by new(), regardless of
the underlying kadmin interface.  They are implemented by the child class
appropriate for the configured Kerberos implementation.

=over 4

=item create(PRINCIPAL)

Adds a new principal with a given name.  The principal is created with a
random password, and any other flags set by Wallet::Config.  Returns true
on success and false on failure.  If the principal already exists, return
true as we are bringing our expectations in line with reality.

=item destroy(PRINCIPAL)

Removes a principal with the given name.  Returns true on success or false
on failure.  If the principal does not exist, return true as we are
bringing our expectations in line with reality.

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

=item exists(PRINCIPAL)

Returns true if the given principal exists in the KDC and C<0> if it
doesn't.  If an error is encountered in checking whether the principal
exists, exists() returns undef.

=item fork_callback(CALLBACK)

If the module has to fork an external process for some reason, such as a
kadmin command-line client, the sub CALLBACK will be called in the child
process before running the program.  This can be used to, for example,
properly clean up shared database handles.

=item keytab(PRINCIPAL)

keytab() creates a keytab for the given principal, storing it in the given
file.  A keytab is an on-disk store for the key or keys for a Kerberos
principal.  Keytabs are used by services to verify incoming authentication
from clients or by automated processes that need to authenticate to
Kerberos.  To create a keytab, the principal has to have previously been
created in the Kerberos KDC.  Returns the keytab as binary data on success
and undef on failure.

=item keytab_rekey(PRINCIPAL [, ENCTYPE ...])

Like keytab(), but randomizes the key for the principal before generating
the keytab and writes it to the given file.  This will invalidate any
existing keytabs for that principal.  This method can also limit the
encryption types of the keys for that principal via the optional ENCTYPE
arguments.  The enctype values must be enctype strings recognized by the
Kerberos implementation (strings like C<aes256-cts-hmac-sha1-96> or
C<des-cbc-crc>).  If none are given, the KDC defaults will be used.
Returns the keytab as binary data on success and undef on failure.

=back

The following methods are utility methods to aid with child class
implementation and should only be called by child classes.

=over 4

=item read_keytab(FILE)

Reads the contents of the keytab stored in FILE into memory and returns it
as binary data.  On failure, returns undef and sets the object error.

=back

=head1 SEE ALSO

kadmin(8), Wallet::Config(3), Wallet::Object::Keytab(3), wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHORS

Jon Robertson <jonrober@stanford.edu> and Russ Allbery <eagle@eyrie.org>

=cut
