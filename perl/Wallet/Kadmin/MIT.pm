# Wallet::Kadmin::MIT -- MIT Kadmin interactions for the wallet.
#
# Written by Russ Allbery <rra@stanford.edu>
# Pulled into a module by Jon Robertson <jonrober@stanford.edu>
# Copyright 2007, 2008, 2009 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Kadmin::MIT;
require 5.006;

use strict;
use vars qw($VERSION);

use Wallet::Config ();

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.02';

##############################################################################
# Utility functions
##############################################################################

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

# Set a callback to be called for forked kadmin processes.
sub fork_callback {
    my ($self, $callback) = @_;
    $self->{fork_callback} = $callback;
}

##############################################################################
# kadmin Interaction
##############################################################################

# Make sure that principals are well-formed and don't contain characters that
# will cause us problems when talking to kadmin.  Takes a principal and
# returns true if it's okay, false otherwise.  Note that we do not permit
# realm information here.
sub valid_principal {
    my ($self, $principal) = @_;
    return scalar ($principal =~ m,^[\w-]+(/[\w_.-]+)?\z,);
}

# Run a kadmin command and capture the output.  Returns the output, either as
# a list of lines or, in scalar context, as one string.  The exit status of
# kadmin is often worthless.
sub kadmin {
    my ($self, $command) = @_;
    unless (defined ($Wallet::Config::KEYTAB_PRINCIPAL)
            and defined ($Wallet::Config::KEYTAB_FILE)
            and defined ($Wallet::Config::KEYTAB_REALM)) {
        die "keytab object implementation not configured\n";
    }
    my @args = ('-p', $Wallet::Config::KEYTAB_PRINCIPAL, '-k', '-t',
                $Wallet::Config::KEYTAB_FILE, '-q', $command);
    push (@args, '-s', $Wallet::Config::KEYTAB_HOST)
        if $Wallet::Config::KEYTAB_HOST;
    push (@args, '-r', $Wallet::Config::KEYTAB_REALM)
        if $Wallet::Config::KEYTAB_REALM;
    my $pid = open (KADMIN, '-|');
    if (not defined $pid) {
        $self->error ("cannot fork: $!");
        return;
    } elsif ($pid == 0) {
        $self->{fork_callback} ();
        unless (open (STDERR, '>&STDOUT')) {
            warn "wallet: cannot dup stdout: $!\n";
            exit 1;
        }
        unless (exec ($Wallet::Config::KEYTAB_KADMIN, @args)) {
            warn "wallet: cannot run $Wallet::Config::KEYTAB_KADMIN: $!\n";
            exit 1;
        }
    }
    local $_;
    my @output;
    while (<KADMIN>) {
        if (/^wallet: cannot /) {
            s/^wallet: //;
            $self->error ($_);
            return;
        }
        push (@output, $_) unless /Authenticating as principal/;
    }
    close KADMIN;
    return wantarray ? @output : join ('', @output);
}

##############################################################################
# Public interfaces
##############################################################################

# Check whether a given principal already exists in Kerberos.  Returns true if
# so, false otherwise.  Returns undef if kadmin fails, with the error already
# set by kadmin.
sub exists {
    my ($self, $principal) = @_;
    return unless $self->valid_principal ($principal);
    if ($Wallet::Config::KEYTAB_REALM) {
        $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    }
    my $output = $self->kadmin ("getprinc $principal");
    if (!defined $output) {
        return;
    } elsif ($output =~ /^get_principal: /) {
        return 0;
    } else {
        return 1;
    }
}

# Create a principal in Kerberos.  Sets the error and returns undef on failure,
# and returns 1 on either success or the principal already existing.
sub addprinc {
    my ($self, $principal) = @_;
    unless ($self->valid_principal ($principal)) {
        $self->error ("invalid principal name $principal");
        return;
    }
    return 1 if $self->exists ($principal);
    if ($Wallet::Config::KEYTAB_REALM) {
        $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    }
    my $flags = $Wallet::Config::KEYTAB_FLAGS || '';
    my $output = $self->kadmin ("addprinc -randkey $flags $principal");
    if (!defined $output) {
        return;
    } elsif ($output =~ /^add_principal: (.*)/m) {
        $self->error ("error adding principal $principal: $1");
        return;
    }
    return 1;
}

# Create a keytab from a principal.  Takes the principal, the file, and
# optionally a list of encryption types to which to limit the keytab.  Return
# true if successful, false otherwise.  If the keytab creation fails, sets the
# error.
sub ktadd {
    my ($self, $principal, $file, @enctypes) = @_;
    unless ($self->valid_principal ($principal)) {
        $self->error ("invalid principal name: $principal");
        return;
    }
    if ($Wallet::Config::KEYTAB_REALM) {
        $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    }
    my $command = "ktadd -q -k $file";
    if (@enctypes) {
        @enctypes = map { /:/ ? $_ : "$_:normal" } @enctypes;
        $command .= ' -e "' . join (' ', @enctypes) . '"';
    }
    my $output = $self->kadmin ("$command $principal");
    if (!defined $output) {
        return;
    } elsif ($output =~ /^(?:kadmin|ktadd): (.*)/m) {
        $self->error ("error creating keytab for $principal: $1");
        return;
    }
    return 1;
}

# Delete a principal from Kerberos.  Return true if successful, false
# otherwise.  If the deletion fails, sets the error.  If the principal doesn't
# exist, return success; we're bringing reality in line with our expectations.
sub delprinc {
    my ($self, $principal) = @_;
    unless ($self->valid_principal ($principal)) {
        $self->error ("invalid principal name: $principal");
    }
    my $exists = $self->exists ($principal);
    if (!defined $exists) {
        return;
    } elsif (not $exists) {
        return 1;
    }
    if ($Wallet::Config::KEYTAB_REALM) {
        $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    }
    my $output = $self->kadmin ("delprinc -force $principal");
    if (!defined $output) {
        return;
    } elsif ($output =~ /^delete_principal: (.*)/m) {
        $self->error ("error deleting $principal: $1");
        return;
    }
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
    my $self = {};
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

Russ Allbery <rra@stanford.edu> and Jon Robertson <jonrober@stanford.edu>.

=cut
