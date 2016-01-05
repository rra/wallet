# Wallet::Kadmin::MIT -- Wallet Kerberos administration API for MIT.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Pulled into a module by Jon Robertson <jonrober@stanford.edu>
# Copyright 2007, 2008, 2009, 2010, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Kadmin::MIT;
require 5.006;

use strict;
use warnings;
use vars qw(@ISA $VERSION);

use POSIX qw(_exit);
use Wallet::Config ();
use Wallet::Kadmin ();

@ISA = qw(Wallet::Kadmin);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.03';

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
        $self->{fork_callback} () if $self->{fork_callback};
        unless (open (STDERR, '>&STDOUT')) {
            warn "wallet: cannot dup stdout: $!\n";
            _exit(1);
        }
        unless (exec ($Wallet::Config::KEYTAB_KADMIN, @args)) {
            warn "wallet: cannot run $Wallet::Config::KEYTAB_KADMIN: $!\n";
            _exit(1);
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

# Set a callback to be called for forked kadmin processes.
sub fork_callback {
    my ($self, $callback) = @_;
    $self->{fork_callback} = $callback;
}

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
sub create {
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

# Retrieve an existing keytab from the KDC via a remctl call.  The KDC needs
# to be running the keytab-backend script and support the keytab retrieve
# remctl command.  In addition, the user must have configured us with the path
# to a ticket cache and the host to which to connect with remctl.  Returns the
# keytab on success and undef on failure.
sub keytab {
    my ($self, $principal) = @_;
    my $host = $Wallet::Config::KEYTAB_REMCTL_HOST;
    unless ($host and $Wallet::Config::KEYTAB_REMCTL_CACHE) {
        $self->error ('keytab unchanging support not configured');
        return;
    }
    eval { require Net::Remctl };
    if ($@) {
        $self->error ("keytab unchanging support not available: $@");
        return;
    }
    if ($principal !~ /\@/ && $Wallet::Config::KEYTAB_REALM) {
        $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    }
    local $ENV{KRB5CCNAME} = $Wallet::Config::KEYTAB_REMCTL_CACHE;
    my $port = $Wallet::Config::KEYTAB_REMCTL_PORT || 0;
    my $remctl_princ = $Wallet::Config::KEYTAB_REMCTL_PRINCIPAL || '';
    my @command = ('keytab', 'retrieve', $principal);
    my $result = Net::Remctl::remctl ($host, $port, $remctl_princ, @command);
    if ($result->error) {
        $self->error ("cannot retrieve keytab for $principal: ",
                      $result->error);
        return;
    } elsif ($result->status != 0) {
        my $error = $result->stderr;
        $error =~ s/\s+$//;
        $error =~ s/\n/ /g;
        $self->error ("cannot retrieve keytab for $principal: $error");
        return;
    } else {
        return $result->stdout;
    }
}

# Create a keytab for a principal, randomizing the keys for that principal
# in the process.  Takes the principal and an optional list of encryption
# types to which to limit the keytab.  Return the keytab data on success
# and undef otherwise.  If the keytab creation fails, sets the error.
sub keytab_rekey {
    my ($self, $principal, @enctypes) = @_;
    unless ($self->valid_principal ($principal)) {
        $self->error ("invalid principal name: $principal");
        return;
    }
    if ($Wallet::Config::KEYTAB_REALM) {
        $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    }
    my $file = $Wallet::Config::KEYTAB_TMP . "/keytab.$$";
    unlink $file;
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
    return $self->read_keytab ($file);
}

# Delete a principal from Kerberos.  Return true if successful, false
# otherwise.  If the deletion fails, sets the error.  If the principal doesn't
# exist, return success; we're bringing reality in line with our expectations.
sub destroy {
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

# Create a new MIT kadmin object.  Very empty for the moment, but later it
# will probably fill out if we go to using a module rather than calling
# kadmin directly.
sub new {
    my ($class) = @_;
    unless (defined ($Wallet::Config::KEYTAB_TMP)) {
        die "KEYTAB_TMP configuration variable not set\n";
    }
    my $self = {};
    bless ($self, $class);
    return $self;
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=for stopwords
rekeying rekeys remctl backend keytabs keytab kadmin KDC API Allbery
unlinked

=head1 NAME

Wallet::Kadmin::MIT - Wallet Kerberos administration API for MIT

=head1 SYNOPSIS

    my $kadmin = Wallet::Kadmin::MIT->new;
    $kadmin->create ('host/foo.example.com');
    my $data = $kadmin->keytab_rekey ('host/foo.example.com',
                                      'aes256-cts-hmac-sha1-96');
    $data = $kadmin->keytab ('host/foo.example.com');
    my $exists = $kadmin->exists ('host/oldshell.example.com');
    $kadmin->destroy ('host/oldshell.example.com') if $exists;

=head1 DESCRIPTION

Wallet::Kadmin::MIT implements the Wallet::Kadmin API for MIT Kerberos,
providing an interface to create and delete principals and create keytabs.
It provides the API documented in L<Wallet::Kadmin> for an MIT Kerberos
KDC.

MIT Kerberos does not provide any method via the kadmin network protocol
to retrieve a keytab for a principal without rekeying it, so the keytab()
method (as opposed to keytab_rekey(), which rekeys the principal) is
implemented using a remctl backend.  For that method (used for unchanging
keytab objects) to work, the necessary wallet configuration and remctl
interface on the KDC must be set up.

To use this class, several configuration parameters must be set.  See
L<Wallet::Config/"KEYTAB OBJECT CONFIGURATION"> for details.

=head1 FILES

=over 4

=item KEYTAB_TMP/keytab.<pid>

The keytab is created in this file and then read into memory.  KEYTAB_TMP
is set in the wallet configuration, and <pid> is the process ID of the
current process.  The file is unlinked after being read.

=back

=head1 LIMITATIONS

Currently, this implementation calls an external B<kadmin> program rather
than using a native Perl module and therefore requires B<kadmin> be
installed and parses its output.  It may miss some error conditions if the
output of B<kadmin> ever changes.

=head1 SEE ALSO

kadmin(8), Wallet::Config(3), Wallet::Kadmin(3),
Wallet::Object::Keytab(3), wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHORS

Russ Allbery <eagle@eyrie.org> and Jon Robertson <jonrober@stanford.edu>.

=cut
