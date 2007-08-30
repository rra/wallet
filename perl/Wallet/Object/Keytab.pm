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
    if ($principal !~ m,^[\w-]+(/[\w_-]+)?,) {
        return undef;
    }
    return 1;
}

# Run a kadmin command and capture the output.  Returns the output, either as
# a list of lines or, in scalar context, as one string.  The exit status of
# kadmin is often worthless.
sub _kadmin {
    my ($self, $command) = @_;
    my @args = ('-p', $Wallet::Config::KEYTAB_PRINCIPAL, '-k', '-t',
                $Wallet::Config::KEYTAB_FILE, '-q', $command);
    push (@args, '-s', $Wallet::Config::KEYTAB_HOST)
        if $Wallet::Config::KEYTAB_HOST;
    my $pid = open (KADMIN, '-|');
    if (not defined $pid) {
        die "error: cannot fork: $!\n";
    } elsif ($pid == 0) {
        open (STDERR, '>&STDOUT') or die "error: cannot dup stdout: $!\n";
        exec ($Wallet::Config::KEYTAB_KADMIN, @args)
            or die "error: cannot run $Wallet::Config::KEYTAB_KADMIN\n";
    }
    local $_;
    my @output;
    while (<KADMIN>) {
        push (@output, $_) unless /Authenticating as principal/;
    }
    close KADMIN;
    return wantarray ? @output : join ('', @output);
}

# Check whether a given principal already exists in Kerberos.  Returns true if
# so, false otherwise.
sub _kadmin_exists {
    my ($self, $principal) = @_;
    return undef unless $self->_valid_principal ($principal);
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
    my $flags = $Wallet::Config::KEYTAB_FLAGS;
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
        $self->{error} = "invalid principal name: $principal";
        return undef;
    }
    my $output = $self->_kadmin ("ktadd -q -k $file $principal");
    if ($output =~ /^ktadd: (.*)/m) {
        $self->{error} = "error creating keytab for $principal: $1";
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
        $self->{error} = "invalid principal name: $principal";
        return undef;
    }
    if (not $self->_kadmin_exists ($principal)) {
        return 1;
    }
    my $output = $self->_kadmin ("delprinc $principal");
    if ($output =~ /^delete_principal: (.*)/m) {
        $self->{error} = "error deleting $principal: $1";
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
    if ($name !~ /\@/ && $Wallet::Config::KEYTAB_REALM) {
        $name .= '@' . $Wallet::Config::KEYTAB_REALM;
    }
    $class->_kadmin_addprinc ($name);
    return $class->SUPER::create ($type, $name, $dbh, $creator, $host, $time);
}

# Override destroy to delete the principal out of Kerberos as well.
sub destroy {
    my ($self, $user, $host, $time) = @_;
    return undef if not $self->_kadmin_delprinc ($self->{name});
    return $self->SUPER::destroy ($user, $host, $time);
}

# Our get implementation.  Generate a keytab into a temporary file and then
# return that as the return value.
sub get {
    my ($self, $user, $host, $time) = @_;
    $time ||= time;
    my $file = $Wallet::Config::KEYTAB_TMP . "/keytab.$$";
    return undef if not $self->_kadmin_ktadd ($self->{name});
    local *KEYTAB;
    unless (open (KEYTAB, '<', $file)) {
        my $princ = $self->{name};
        $self->{error} = "error opening keytab for principal $princ: $!";
        return undef;
    }
    local $/;
    undef $!;
    my $data = <KEYTAB>;
    if ($!) {
        my $princ = $self->{name};
        $self->{error} = "error reading keytab for principal $princ: $!";
        return undef;
    }
    close KEYTAB;
    unlink $file;
    $self->log_action ('get', $user, $host, $time);
    return $data;
}

1;
__END__;
