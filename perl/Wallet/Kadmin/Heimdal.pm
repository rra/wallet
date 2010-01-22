# Wallet::Kadmin::Heimdal -- Heimdal Kadmin interactions for the wallet.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2009 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Kadmin::Heimdal;
require 5.006;

use strict;
use vars qw($VERSION);

use Heimdal::Kadm5 qw(KRB5_KDB_DISALLOW_ALL_TIX);
use Wallet::Config ();

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.02';

##############################################################################
# kadmin Interaction
##############################################################################

# Create a Heimdal::Kadm5 client object and return it.  It should load
# configuration from Wallet::Config.
sub kadmin_client {
    unless (defined ($Wallet::Config::KEYTAB_PRINCIPAL)
            and defined ($Wallet::Config::KEYTAB_FILE)
            and defined ($Wallet::Config::KEYTAB_REALM)) {
        die "keytab object implementation not configured\n";
    }
    my $server = $Wallet::Config::KEYTAB_HOST || 'localhost';
    my @options = (RaiseErrors => 1,
                   Server      => $server,
                   Principal   => $Wallet::Config::KEYTAB_PRINCIPAL,
                   Realm       => $Wallet::Config::KEYTAB_REALM,
                   Keytab      => $Wallet::Config::KEYTAB_FILE);
    my $client = Heimdal::Kadm5::Client->new (@options);
    return $client;
}

##############################################################################
# Public interfaces
##############################################################################

# Check whether a given principal already exists in Kerberos.  Returns true if
# so, false otherwise.  Throws an exception if an error.
sub exists {
    my ($self, $principal) = @_;
    if ($Wallet::Config::KEYTAB_REALM) {
        $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    }
    my $kadmin = $self->{client};
    my $princdata = $kadmin->getPrincipal ($principal);
    return $princdata ? 1 : 0;
}

# Create a principal in Kerberos.  Since this is only called by create, it
# throws an exception on failure rather than setting the error and returning
# undef.
sub addprinc {
    my ($self, $principal) = @_;

    my $exists = eval { $self->exists ($principal) };
    if ($Wallet::Config::KEYTAB_REALM) {
        $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    }
    die "error adding principal $principal: $@\n" if $@;
    return 1 if $exists;

    # The way Heimdal::Kadm5 works, we create a principal object, create the
    # actual principal set inactive, then randomize it and activate it.
    # TODO - Paranoia makes me want to set the password to something random
    #        on creation even if it is inactive until after randomized by
    #        module.
    my $kadmin = $self->{client};
    my $princdata = $kadmin->makePrincipal ($principal);

    # Disable the principal before creating, until we've randomized the
    # password.
    my $attrs = $princdata->getAttributes;
    $attrs |= KRB5_KDB_DISALLOW_ALL_TIX;
    $princdata->setAttributes ($attrs);

    my $password = 'inactive';
    eval {
        $kadmin->createPrincipal ($princdata, $password, 0);
        $kadmin->randKeyPrincipal ($principal);
        $kadmin->enablePrincipal ($principal);
    };
    die "error adding principal $principal: $@" if $@;
    return 1;
}

# Create a keytab from a principal.  Takes the principal, the file, and
# optionally a list of encryption types to which to limit the keytab.  Return
# true if successful, false otherwise.  If the keytab creation fails, sets the
# error.
sub ktadd {
    my ($self, $principal, $file, @enctypes) = @_;
    if ($Wallet::Config::KEYTAB_REALM) {
        $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    }

    # The way Heimdal works, you can only remove enctypes from a principal,
    # not add them back in.  So we need to run randkeyPrincipal first each
    # time to restore all possible enctypes and then whittle them back down
    # to those we have been asked for this time.
    my $kadmin = $self->{client};
    eval { $kadmin->randKeyPrincipal ($principal) };
    die "error creating keytab for $principal: could not reinit enctypes: $@\n"
        if $@;
    my $princdata = eval { $kadmin->getPrincipal ($principal) };
    if ($@) {
        die "error creating keytab for $principal: $@\n";
    } elsif (!$princdata) {
        die "error creating keytab for $principal: principal does not exist\n";
    }

    # Now actually remove any non-requested enctypes, if we requested any.
    if (@enctypes) {
        my (%wanted);
        my $alltypes = $princdata->getKeytypes ();
        foreach (@enctypes) { $wanted{$_} = 1 }
        foreach my $key (@{$alltypes}) {
            my $keytype = ${$key}[0];
            next if exists $wanted{$keytype};
            eval { $princdata->delKeytypes ($keytype) };
            die "error removing keytype $keytype from the keytab: $@\n" if $@;
        }
        eval { $kadmin->modifyPrincipal ($princdata) };
    }

    eval { $kadmin->extractKeytab ($princdata, $file) };
    die "error creating keytab for principal: $@\n" if $@;

    return 1;
}

# Delete a principal from Kerberos.  Return true if successful, false
# otherwise.  If the deletion fails, sets the error.  If the principal doesn't
# exist, return success; we're bringing reality in line with our expectations.
sub delprinc {
    my ($self, $principal) = @_;
    my $exists = eval { $self->exists ($principal) };
    die $@ if $@;
    if (not $exists) {
        return 1;
    }
    if ($Wallet::Config::KEYTAB_REALM) {
        $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    }

    my $kadmin = $self->{client};
    my $retval = eval { $kadmin->deletePrincipal ($principal) };
    die "error deleting $principal: $@\n" if $@;
    return 1;
}

##############################################################################
# Documentation
##############################################################################

# Create a new MIT kadmin object.  Very empty for the moment, but later it
# will probably fill out if we go to using a module rather than calling
# kadmin directly.
sub new {
    my ($class) = @_;
    my $self = {
        client => kadmin_client (),
    };
    bless ($self, $class);
    return $self;
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=head1 NAME

Wallet::Kadmin::MIT - MIT admin interactions for wallet keytabs

=head1 SYNOPSIS

    my $kadmin = Wallet::Kadmin::MIT->new ();
    $kadmin->addprinc ("host/shell.example.com");
    $kadmin->ktadd ("host/shell.example.com", "aes256-cts");
    my $exists = $kadmin->exists ("host/oldshell.example.com");
    $kadmin->delprinc ("host/oldshell.example.com") if $exists;

=head1 DESCRIPTION

Wallet::Kadmin::MIT is an interface for keytab integration with the wallet,
specifically for using kadmin to create, delete, and add enctypes to keytabs.
It implments the wallet kadmin API and provides the necessary glue to MIT
Kerberos installs for each of these functions, while allowing the wallet
to keep the details of what type of Kerberos installation is being used
abstracted.

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

=item addprinc(PRINCIPAL)

Adds a new principal with a given name.  The principal is created with a
random password, and any other flags set by Wallet::Config.  Returns true on
success, or throws an error if there was a failure in adding the principal.
If the principal already exists, return true as we are bringing our
expectations in line with reality.

=item addprinc(PRINCIPAL)

Removes a principal with the given name.  Returns true on success, or throws
an error if there was a failure in removing the principal.  If the principal
does not exist, return true as we are bringing our expectations in line with
reality.

=item ktadd(PRINCIPAL, FILE, ENCTYPES)

Creates a new keytab for the given principal, as the given file, limited to
the enctypes supplied.  The enctype values must be enctype strings recognized
by Kerberos (strings like C<aes256-cts> or C<des-cbc-crc>).  An error is
thrown on failure or if the creation fails, otherwise true is returned.

=back

=head1 LIMITATIONS

Currently, this implementation calls an external B<kadmin> program rather
 than using a native Perl module and therefore requires B<kadmin> be
installed and parses its output.  It may miss some error conditions if the
output of B<kadmin> ever changes.

=head1 SEE ALSO

kadmin(8), Wallet::Config(3), Wallet::Object::Keytab(3), wallet-backend(8)

This module is part of the wallet system.  The current version is available
from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHORS

Russ Allbery <rra@stanford.edu>
Jon Robertson <jonrober@stanford.edu>

=cut
