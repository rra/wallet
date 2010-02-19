# Wallet::Kadmin::Heimdal -- Wallet Kerberos administration API for Heimdal.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2009, 2010 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Kadmin::Heimdal;
require 5.006;

use strict;
use vars qw(@ISA $VERSION);

use Heimdal::Kadm5 qw(KRB5_KDB_DISALLOW_ALL_TIX);
use Wallet::Config ();
use Wallet::Kadmin ();

@ISA = qw(Wallet::Kadmin);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.03';

##############################################################################
# Utility functions
##############################################################################

# Add the realm to the end of the principal if no realm is currently present.
sub canonicalize_principal {
    my ($self, $principal) = @_;
    if ($Wallet::Config::KEYTAB_REALM && $principal !~ /\@/) {
        $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    }
    return $principal;
}

##############################################################################
# Public interfaces
##############################################################################

# Check whether a given principal already exists in Kerberos.  Returns true if
# so, false otherwise.
sub exists {
    my ($self, $principal) = @_;
    $principal = $self->canonicalize_principal ($principal);
    my $kadmin = $self->{client};
    my $princdata = eval { $kadmin->getPrincipal ($principal) };
    if ($@) {
        $self->error ("error getting principal: $@");
        return;
    }
    return $princdata ? 1 : 0;
}

# Create a principal in Kerberos.  If there is an error, return undef and set
# the error.  Return 1 on success or the principal already existing.
sub create {
    my ($self, $principal) = @_;
    $principal = $self->canonicalize_principal ($principal);
    my $exists = eval { $self->exists ($principal) };
    if ($@) {
        $self->error ("error adding principal $principal: $@");
        return;
    }
    return 1 if $exists;

    # The way Heimdal::Kadm5 works, we create a principal object, create the
    # actual principal set inactive, then randomize it and activate it.
    #
    # TODO - Paranoia makes me want to set the password to something random
    #        on creation even if it is inactive until after randomized by
    #        module.
    my $kadmin = $self->{client};
    eval {
        my $princdata = $kadmin->makePrincipal ($principal);
        my $attrs = $princdata->getAttributes;
        $attrs |= KRB5_KDB_DISALLOW_ALL_TIX;
        $princdata->setAttributes ($attrs);
        my $password = 'inactive';
        $kadmin->createPrincipal ($princdata, $password, 0);
        $kadmin->randKeyPrincipal ($principal);
        $kadmin->enablePrincipal ($principal);
    };
    if ($@) {
        $self->error ("error adding principal $principal: $@");
        return;
    }
    return 1;
}

# Create a keytab for a principal.  Returns the keytab as binary data or undef
# on failure, setting the error.
sub keytab {
    my ($self, $principal) = @_;
    $principal = $self->canonicalize_principal ($principal);
    my $kadmin = $self->{client};
    my $file = $Wallet::Config::KEYTAB_TMP . "/keytab.$$";
    unlink $file;
    my $princdata = eval { $kadmin->getPrincipal ($principal) };
    if ($@) {
        $self->error ("error creating keytab for $principal: $@");
        return;
    } elsif (!$princdata) {
        $self->error ("error creating keytab for $principal: principal does"
                      . " not exist");
        return;
    }
    eval { $kadmin->extractKeytab ($princdata, $file) };
    if ($@) {
        $self->error ("error creating keytab for principal: $@");
        return;
    }
    return $self->read_keytab ($file);
}

# Create a keytab for a principal, randomizing the keys for that principal at
# the same time.  Takes the principal and an optional list of encryption types
# to which to limit the keytab.  Return the keytab data on success and undef
# on failure.  If the keytab creation fails, sets the error.
sub keytab_rekey {
    my ($self, $principal, @enctypes) = @_;
    $principal = $self->canonicalize_principal ($principal);

    # The way Heimdal works, you can only remove enctypes from a principal,
    # not add them back in.  So we need to run randkeyPrincipal first each
    # time to restore all possible enctypes and then whittle them back down
    # to those we have been asked for this time.
    my $kadmin = $self->{client};
    eval { $kadmin->randKeyPrincipal ($principal) };
    if ($@) {
        $self->error ("error creating keytab for $principal: could not"
                      . " reinit enctypes: $@");
        return;
    }
    my $princdata = eval { $kadmin->getPrincipal ($principal) };
    if ($@) {
        $self->error ("error creating keytab for $principal: $@");
        return;
    } elsif (!$princdata) {
        $self->error ("error creating keytab for $principal: principal does"
                      . " not exist");
        return;
    }

    # Now actually remove any non-requested enctypes, if we requested any.
    if (@enctypes) {
        my $alltypes = $princdata->getKeytypes;
        my %wanted = map { $_ => 1 } @enctypes;
        for my $key (@{ $alltypes }) {
            my $keytype = $key->[0];
            next if exists $wanted{$keytype};
            eval { $princdata->delKeytypes ($keytype) };
            if ($@) {
                $self->error ("error removing keytype $keytype from the"
                              . " keytab: $@");
                return;
            }
        }
        eval { $kadmin->modifyPrincipal ($princdata) };
        if ($@) {
            $self->error ("error saving principal modifications: $@");
            return;
        }
    }

    # Create the keytab.
    my $file = $Wallet::Config::KEYTAB_TMP . "/keytab.$$";
    unlink $file;
    eval { $kadmin->extractKeytab ($princdata, $file) };
    if ($@) {
        $self->error ("error creating keytab for principal: $@");
        return;
    }
    return $self->read_keytab ($file);
}

# Delete a principal from Kerberos.  Return true if successful, false
# otherwise.  If the deletion fails, sets the error.  If the principal doesn't
# exist, return success; we're bringing reality in line with our expectations.
sub destroy {
    my ($self, $principal) = @_;
    $principal = $self->canonicalize_principal ($principal);
    my $exists = eval { $self->exists ($principal) };
    if ($@) {
        $self->error ("error checking principal existance: $@");
        return;
    } elsif (not $exists) {
        return 1;
    }
    my $kadmin = $self->{client};
    my $retval = eval { $kadmin->deletePrincipal ($principal) };
    if ($@) {
        $self->error ("error deleting $principal: $@");
        return;
    }
    return 1;
}

# Create a new Wallet::Kadmin::Heimdal object and its underlying
# Heimdal::Kadm5 object.
sub new {
    my ($class) = @_;
    unless (defined ($Wallet::Config::KEYTAB_PRINCIPAL)
            and defined ($Wallet::Config::KEYTAB_FILE)
            and defined ($Wallet::Config::KEYTAB_REALM)) {
        die "keytab object implementation not configured\n";
    }
    unless (defined ($Wallet::Config::KEYTAB_TMP)) {
        die "KEYTAB_TMP configuration variable not set\n";
    }
    my @options = (RaiseError => 1,
                   Principal  => $Wallet::Config::KEYTAB_PRINCIPAL,
                   Realm      => $Wallet::Config::KEYTAB_REALM,
                   Keytab     => $Wallet::Config::KEYTAB_FILE);
    if ($Wallet::Config::KEYTAB_HOST) {
        push (@options, Server => $Wallet::Config::KEYTAB_HOST);
    }
    my $client = Heimdal::Kadm5::Client->new (@options);
    my $self = { client => $client };
    bless ($self, $class);
    return $self;
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=for stopwords
keytabs keytab kadmin KDC API Allbery Heimdal

=head1 NAME

Wallet::Kadmin::Heimdal - Wallet Kerberos administration API for Heimdal

=head1 SYNOPSIS

    my $kadmin = Wallet::Kadmin::Heimdal->new;
    $kadmin->create ('host/foo.example.com');
    $kadmin->keytab_rekey ('host/foo.example.com', 'keytab',
                           'aes256-cts-hmac-sha1-96');
    my $data = $kadmin->keytab ('host/foo.example.com');
    my $exists = $kadmin->exists ('host/oldshell.example.com');
    $kadmin->destroy ('host/oldshell.example.com') if $exists;

=head1 DESCRIPTION

Wallet::Kadmin::Heimdal implements the Wallet::Kadmin API for Heimdal,
providing an interface to create and delete principals and create keytabs.
It provides the API documented in Wallet::Kadmin(3) for a Heimdal KDC.

To use this class, several configuration parameters must be set.  See
L<Wallet::Config/"KEYTAB OBJECT CONFIGURATION"> for details.

=head1 FILES

=over 4

=item KEYTAB_TMP/keytab.<pid>

The keytab is created in this file and then read into memory.  KEYTAB_TMP
is set in the wallet configuration, and <pid> is the process ID of the
current process.  The file is unlinked after being read.

=back

=head1 SEE ALSO

kadmin(8), Wallet::Config(3), Wallet::Kadmin(3),
Wallet::Object::Keytab(3), wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHORS

Russ Allbery <rra@stanford.edu> and Jon Robertson <jonrober@stanford.edu>.

=cut
