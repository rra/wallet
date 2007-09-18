# Wallet::Object::Keytab -- Keytab object implementation for the wallet.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007 Board of Trustees, Leland Stanford Jr. University
#
# See README for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Object::Keytab;
require 5.006;

use strict;
use vars qw(@ISA $VERSION);

use Wallet::Config ();
use Wallet::Object::Base;

@ISA = qw(Wallet::Object::Base);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.01';

##############################################################################
# kadmin Interaction
##############################################################################

# Make sure that principals are well-formed and don't contain characters that
# will cause us problems when talking to kadmin.  Takes a principal and
# returns true if it's okay, false otherwise.  Note that we do not permit
# realm information here.
sub _valid_principal {
    my ($self, $principal) = @_;
    if ($principal !~ m,^[\w-]+(/[\w_-]+)?\z,) {
        return undef;
    }
    return 1;
}

# Run a kadmin command and capture the output.  Returns the output, either as
# a list of lines or, in scalar context, as one string.  The exit status of
# kadmin is often worthless.
sub _kadmin {
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
        die "cannot fork: $!\n";
    } elsif ($pid == 0) {
        open (STDERR, '>&STDOUT') or die "cannot dup stdout: $!\n";

        # Don't use die here; it will get trapped as an exception.
        unless (exec ($Wallet::Config::KEYTAB_KADMIN, @args)) {
            warn "wallet: cannot run $Wallet::Config::KEYTAB_KADMIN: $!\n";
            exit 1;
        }
    }
    local $_;
    my @output;
    while (<KADMIN>) {
        if (/^wallet: cannot run /) {
            s/^wallet: //;
            die $_;
        }
        push (@output, $_) unless /Authenticating as principal/;
    }
    close KADMIN;
    return wantarray ? @output : join ('', @output);
}

# Check whether a given principal already exists in Kerberos.  Returns true if
# so, false otherwise.  Throws an exception if kadmin fails.
sub _kadmin_exists {
    my ($self, $principal) = @_;
    return undef unless $self->_valid_principal ($principal);
    if ($Wallet::Config::KEYTAB_REALM) {
        $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    }
    my $output = $self->_kadmin ("getprinc $principal");
    if ($output =~ /does not exist/) {
        return undef;
    } else {
        return 1;
    }
}

# Create a principal in Kerberos.  Since this is only called by create, it
# throws an exception on failure rather than setting the error and returning
# undef.
sub _kadmin_addprinc {
    my ($self, $principal) = @_;
    unless ($self->_valid_principal ($principal)) {
        die "invalid principal name $principal\n";
    }
    if ($Wallet::Config::KEYTAB_REALM) {
        $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    }
    my $flags = $Wallet::Config::KEYTAB_FLAGS || '';
    my $output = $self->_kadmin ("addprinc -randkey $flags $principal");
    if ($output =~ /^add_principal: (.*)/m) {
        die "error adding principal $principal: $!\n";
    }
    return 1;
}

# Create a keytab from a principal.  Return true if successful, false
# otherwise.  If the keytab creation fails, sets the error.
sub _kadmin_ktadd {
    my ($self, $principal, $file) = @_;
    unless ($self->_valid_principal ($principal)) {
        $self->error ("invalid principal name: $principal");
        return undef;
    }
    if ($Wallet::Config::KEYTAB_REALM) {
        $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    }
    my $output = eval { $self->_kadmin ("ktadd -q -k $file $principal") };
    if ($@) {
        $self->error ($@);
        return undef;
    } elsif ($output =~ /^(?:kadmin|ktadd): (.*)/m) {
        $self->error ("error creating keytab for $principal: $1");
        return undef;
    }
    return 1;
}

# Delete a principal from Kerberos.  Return true if successful, false
# otherwise.  If the deletion fails, sets the error.  If the principal doesn't
# exist, return success; we're bringing reality in line with our expectations.
sub _kadmin_delprinc {
    my ($self, $principal) = @_;
    unless ($self->_valid_principal ($principal)) {
        $self->error ("invalid principal name: $principal");
        return undef;
    }
    my $exists = eval { $self->_kadmin_exists ($principal) };
    if ($@) {
        $self->error ($@);
        return undef;
    } elsif (not $exists) {
        return 1;
    }
    if ($Wallet::Config::KEYTAB_REALM) {
        $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    }
    my $output = eval { $self->_kadmin ("delprinc -force $principal") };
    if ($@) {
        $self->error ($@);
        return undef;
    } elsif ($output =~ /^delete_principal: (.*)/m) {
        $self->error ("error deleting $principal: $1");
        return undef;
    }
    return 1;
}

##############################################################################
# Implementation
##############################################################################

# Override create to start by creating the principal in Kerberos and only
# create the entry in the database if that succeeds.  Error handling isn't
# great here since we don't have a way to communicate the error back to the
# caller.
sub create {
    my ($class, $type, $name, $dbh, $creator, $host, $time) = @_;
    $class->_kadmin_addprinc ($name);
    return $class->SUPER::create ($type, $name, $dbh, $creator, $host, $time);
}

# Override destroy to delete the principal out of Kerberos as well.
sub destroy {
    my ($self, $user, $host, $time) = @_;
    my $id = $self->{type} . ':' . $self->{name};
    if ($self->flag_check ('locked')) {
        $self->error ("cannot destroy $id: object is locked");
        return;
    }
    return undef if not $self->_kadmin_delprinc ($self->{name});
    return $self->SUPER::destroy ($user, $host, $time);
}

# Our get implementation.  Generate a keytab into a temporary file and then
# return that as the return value.
sub get {
    my ($self, $user, $host, $time) = @_;
    $time ||= time;
    my $id = $self->{type} . ':' . $self->{name};
    if ($self->flag_check ('locked')) {
        $self->error ("cannot get $id: object is locked");
        return;
    }
    unless (defined ($Wallet::Config::KEYTAB_TMP)) {
        $self->error ('KEYTAB_TMP configuration variable not set');
        return undef;
    }
    my $file = $Wallet::Config::KEYTAB_TMP . "/keytab.$$";
    return undef if not $self->_kadmin_ktadd ($self->{name}, $file);
    local *KEYTAB;
    unless (open (KEYTAB, '<', $file)) {
        my $princ = $self->{name};
        $self->error ("error opening keytab for principal $princ: $!");
        return undef;
    }
    local $/;
    undef $!;
    my $data = <KEYTAB>;
    if ($!) {
        my $princ = $self->{name};
        $self->error ("error reading keytab for principal $princ: $!");
        return undef;
    }
    close KEYTAB;
    unlink $file;
    $self->log_action ('get', $user, $host, $time);
    return $data;
}

1;
__END__;

##############################################################################
# Documentation
##############################################################################

=head1 NAME

Wallet::Object::Keytab - Keytab object implementation for wallet

=head1 SYNOPSIS

    my @name = qw(keytab host/shell.example.com);
    my @trace = ($user, $host, time);
    my $object = Wallet::Object::Keytab->create (@name, $dbh, @trace);
    my $keytab = $object->get (@trace);
    $object->destroy (@trace);

=head1 DESCRIPTION

Wallet::Object::Keytab is a representation of Kerberos keytab objects in the
wallet.  It implements then wallet object API and provides the necessary
glue to create principals in a Kerberos KDC, create and return keytabs for
those principals, and delete them out of Kerberos when the wallet object is
destroyed.

A keytab is an on-disk store for the key or keys for a Kerberos principal.
Keytabs are used by services to verify incoming authentication from clients
or by automated processes that need to authenticate to Kerberos.  To create
a keytab, the principal has to be created in Kerberos and then a keytab is
generated and stored in a file on disk.

This implementation generates a new random key (and hence invalidates all
existing keytabs) each time the keytab is retrieved with the get() method.

To use this object, several configuration parameters must be set.  See
Wallet::Config(3) for details on those configuration parameters and
information about how to set wallet configuration.

=head1 METHODS

This object mostly inherits from Wallet::Object::Base.  See the
documentation for that class for all generic methods.  Below are only those
methods that are overridden or behave specially for this implementation.

=over 4

=item create(TYPE, NAME, DBH, PRINCIPAL, HOSTNAME [, DATETIME])

This is a class method and should be called on the Wallet::Object::Keytab
class.  It creates a new object with the given TYPE and NAME (TYPE is
normally C<keytab> and must be for the rest of the wallet system to use the
right class, but this module doesn't check for ease of subclassing), using
DBH as the handle to the wallet metadata database.  PRINCIPAL, HOSTNAME, and
DATETIME are stored as history information.  PRINCIPAL should be the user
who is creating the object.  If DATETIME isn't given, the current time is
used.

When a new keytab object is created, the Kerberos principal designated by
NAME is also created in the Kerberos realm determined from the wallet
configuration.  If the Kerberos principal could not be created (including if
it already exists), create() fails.  The principal is created with the
C<-randkey> option to randomize its keys.  NAME must not contain the realm;
instead, the KEYTAB_REALM configuration variable should be set.  See
Wallet::Config(3) for more information.

If create() fails, it throws an exception.

=item destroy(PRINCIPAL, HOSTNAME [, DATETIME])

Destroys a keytab object by removing all record of it from the database and
deleting the principal out of Kerberos.  If deleting the principal fails,
destroy() fails, but destroy() succeeds if the principal didn't exist when
it was called (so that it can be used to clean up stranded entries).
Returns true on success and false on failure.  The caller should call
error() to get the error message after a failure.  PRINCIPAL, HOSTNAME, and
DATETIME are stored as history information.  PRINCIPAL should be the user
who is destroying the object.  If DATETIME isn't given, the current time is
used.

=item get(PRINCIPAL, HOSTNAME [, DATETIME])

Retrieves a keytab for this object and returns the keytab data or undef on
error.  The caller should call error() to get the error message if get()
returns undef.  The keytab is created with C<ktadd>, invalidating any
existing keytabs for that principal.  PRINCIPAL, HOSTNAME, and DATETIME are
stored as history information.  PRINCIPAL should be the user who is
downloading the keytab.  If DATETIME isn't given, the current time is used.

=back

=head1 FILES

=over 4

=item KEYTAB_TMP/keytab.<pid>

The keytab is created in this file using C<ktadd> and then read into memory.
KEYTAB_TMP is set in the wallet configuration, and <pid> is the process ID
of the current process.  The file is unlinked after being read.

=back

=head1 LIMITATIONS

Currently, this implementation only supports MIT Kerberos and needs
modifications to support Heimdal.  It calls an external B<kadmin> program
rather than using a native Perl module and therefore requires B<kadmin> be
installed and parses its output.  It may miss some error conditions if the
output of B<kadmin> ever changes.

Only one Kerberos realm is supported for a given wallet implementation and
all keytab objects stored must be in that realm.  Keytab names in the wallet
database do not have realm information.

=head1 SEE ALSO

Wallet::Config(3), Wallet::Object::Base(3), wallet-backend(8)

This module is part of the wallet system.  The current version is available
from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <rra@stanford.edu>

=cut
