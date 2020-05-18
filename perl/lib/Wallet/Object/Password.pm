# Wallet::Object::Password -- Password object implementation for the wallet
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2016 Russ Allbery <eagle@eyrie.org>
# Copyright 2015
#     The Board of Trustees of the Leland Stanford Junior University
#
# SPDX-License-Identifier: MIT

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Object::Password;

use 5.008;
use strict;
use warnings;

use Crypt::GeneratePassword qw(chars);
use Digest::MD5 qw(md5_hex);
use Wallet::Config;
use Wallet::Object::File;

our @ISA     = qw(Wallet::Object::File);
our $VERSION = '1.05';

##############################################################################
# File naming
##############################################################################

# Returns the path into which that password object will be stored or undef on
# error.  On error, sets the internal error.
sub file_path {
    my ($self) = @_;
    my $name = $self->{name};
    unless ($Wallet::Config::PWD_FILE_BUCKET) {
        $self->error ('password support not configured');
        return;
    }
    unless ($name) {
        $self->error ('password objects may not have empty names');
        return;
    }
    my $hash = substr (md5_hex ($name), 0, 2);
    $name =~ s/([^\w-])/sprintf ('%%%02X', ord ($1))/ge;
    my $parent = "$Wallet::Config::PWD_FILE_BUCKET/$hash";
    unless (-d $parent || mkdir ($parent, 0700)) {
        $self->error ("cannot create password bucket $hash: $!");
        return;
    }
    return "$Wallet::Config::PWD_FILE_BUCKET/$hash/$name";
}

##############################################################################
# Shared methods
##############################################################################

# Return the contents of the file.
sub retrieve {
    my ($self, $operation, $user, $host, $time) = @_;
    $time ||= time;
    my $id = $self->{type} . ':' . $self->{name};
    if ($self->flag_check ('locked')) {
        $self->error ("cannot get $id: object is locked");
        return;
    }
    my $path = $self->file_path;
    return unless $path;

    # If nothing is yet stored, or we have requested an update, generate a
    # random password and save it to the file.
    my $schema = $self->{schema};
    my %search = (ob_type => $self->{type},
                  ob_name => $self->{name});
    my $object = $schema->resultset('Object')->find (\%search);
    if (!$object->ob_stored_on || $operation eq 'update') {
        unless (open (FILE, '>', $path)) {
            $self->error ("cannot store initial settings for $id: $!\n");
            return;
        }
        my $pass = chars ($Wallet::Config::PWD_LENGTH_MIN,
                          $Wallet::Config::PWD_LENGTH_MAX);
        print FILE $pass;
        $self->log_action ('store', $user, $host, $time);
        unless (close FILE) {
            $self->error ("cannot get $id: $!");
            return;
        }
    }

    unless (open (FILE, '<', $path)) {
        $self->error ("cannot get $id: object has not been stored");
        return;
    }
    local $/;
    my $data = <FILE>;
    unless (close FILE) {
        $self->error ("cannot get $id: $!");
        return;
    }
    $self->log_action ($operation, $user, $host, $time);
    return $data;
}

##############################################################################
# Core methods
##############################################################################

# Return the contents of the file.
sub get {
    my ($self, $user, $host, $time) = @_;
    my $result = $self->retrieve ('get', $user, $host, $time);
    return $result;
}

# Return the contents of the file after resetting them to a random string.
sub update {
    my ($self, $user, $host, $time) = @_;
    my $result = $self->retrieve ('update', $user, $host, $time);
    return $result;
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=head1 NAME

Wallet::Object::Password - Password object implementation for wallet

=for stopwords
API HOSTNAME DATETIME keytab remctld backend nul Allbery wallet-backend

=head1 SYNOPSIS

    my @name = qw(file mysql-lsdb)
    my @trace = ($user, $host, time);
    my $object = Wallet::Object::Password->create (@name, $schema, @trace);
    unless ($object->store ("the-password\n")) {
        die $object->error, "\n";
    }
    my $password = $object->get (@trace);
    $object->destroy (@trace);

=head1 DESCRIPTION

Wallet::Object::Password is an extension of Wallet::Object::File,
acting as a representation of simple file objects in the wallet.  The
difference between the two is that if there is no data stored in a
password object when a user tries to get it for the first time, then a
random string suited for a password will be generated and put into the
object data.

It implements the wallet object API and provides the necessary
glue to store a file on the wallet server, retrieve it later, and delete
it when the password object is deleted.

To use this object, the configuration option specifying where on the
wallet server to store password objects must be set.  See
L<Wallet::Config> for details on this configuration parameter and
information about how to set wallet configuration.

=head1 METHODS

This object mostly inherits from Wallet::Object::File.  See the
documentation for that class for all generic methods.  Below are only
those methods that are overridden or behave specially for this
implementation.

=over 4

=item get(PRINCIPAL, HOSTNAME [, DATETIME])

Retrieves the current contents of the file object or undef on error.
store() must be called before get() will be successful.  The caller should
call error() to get the error message if get() returns undef.  PRINCIPAL,
HOSTNAME, and DATETIME are stored as history information.  PRINCIPAL
should be the user who is downloading the keytab.  If DATETIME isn't
given, the current time is used.

=back

=head1 FILES

=over 4

=item PWD_FILE_BUCKET/<hash>/<file>

Password files are stored on the wallet server under the directory
PWD_FILE_BUCKET as set in the wallet configuration.  <hash> is the
first two characters of the hex-encoded MD5 hash of the wallet password
object name, used to not put too many files in the same directory.
<file> is the name of the password object with all characters other
than alphanumerics, underscores, and dashes replaced by C<%> and the
hex code of the character.

=back

=head1 LIMITATIONS

The wallet implementation itself can handle arbitrary password object
names. However, due to limitations in the B<remctld> server usually
used to run B<wallet-backend>, password object names containing nul
characters (ASCII 0) may not be permitted.  The file system used for
storing file objects may impose a length limitation on the
password object name.

=head1 SEE ALSO

remctld(8), Wallet::Config(3), Wallet::Object::File(3),
wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<https://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Jon Robertson <jonrober@stanford.edu>

=cut
