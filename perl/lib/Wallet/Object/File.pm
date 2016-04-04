# Wallet::Object::File -- File object implementation for the wallet
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2016 Russ Allbery <eagle@eyrie.org>
# Copyright 2008, 2010, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Object::File;

use 5.006;
use strict;
use warnings;

use Digest::MD5 qw(md5_hex);
use File::Copy qw(move);
use Wallet::Config;
use Wallet::Object::Base;

our @ISA     = qw(Wallet::Object::Base);
our $VERSION = '1.04';

##############################################################################
# File naming
##############################################################################

# Returns the path into which that file object will be stored or undef on
# error.  On error, sets the internal error.
sub file_path {
    my ($self) = @_;
    my $name = $self->{name};
    unless ($Wallet::Config::FILE_BUCKET) {
        $self->error ('file support not configured');
        return;
    }
    unless ($name) {
        $self->error ('file objects may not have empty names');
        return;
    }
    my $hash = substr (md5_hex ($name), 0, 2);
    $name =~ s/([^\w-])/sprintf ('%%%02X', ord ($1))/ge;
    my $parent = "$Wallet::Config::FILE_BUCKET/$hash";
    unless (-d $parent || mkdir ($parent, 0700)) {
        $self->error ("cannot create file bucket $hash: $!");
        return;
    }
    return "$Wallet::Config::FILE_BUCKET/$hash/$name";
}

# Rename a file object.  This includes renaming both the object itself, and
# updating the file location for that object.
sub rename {
    my ($self, $new_name, $user, $host, $time) = @_;
    $time ||= time;

    my $old_name = $self->{name};
    my $type     = $self->{type};
    my $schema   = $self->{schema};
    my $old_path = $self->file_path;

    eval {

        # Find the current object record.
        my $guard = $schema->txn_scope_guard;
        my %search = (ob_type => $type,
                      ob_name => $old_name);
        my $object = $schema->resultset('Object')->find (\%search);
        die "cannot find ${type}:${old_name}\n"
            unless ($object and $object->ob_name eq $old_name);

        # Update the object name but don't yet commit.
        $object->ob_name ($new_name);

        # Update the file to the path for the new name, and die if we can't.
        # If the old path isn't there, then assume we haven't yet stored and
        # keep going.
        if ($old_path) {
            $self->{name} = $new_name;
            my $new_path = $self->file_path;
            move($old_path, $new_path) or die $!;
        }

        $object->update;
        $guard->commit;
    };
    if ($@) {
        $self->{name} = $old_name;
        $self->error ("cannot rename object $type $old_name: $!");
        return;
    }

    eval {
        $self->log_set ('name', $old_name, $new_name, $user, $host, $time);
    };
    if ($@) {
        $self->error ("object $type $old_name was renamed but not logged: $!");
        return 1;
    }

    return 1;
}

##############################################################################
# Core methods
##############################################################################

# Override destroy to delete the file as well.
sub destroy {
    my ($self, $user, $host, $time) = @_;
    my $id = $self->{type} . ':' . $self->{name};
    my $path = $self->file_path;
    if (defined ($path) && -f $path && !unlink ($path)) {
        $self->error ("cannot delete $id: $!");
        return;
    }
    return $self->SUPER::destroy ($user, $host, $time);
}

# Return the contents of the file.
sub get {
    my ($self, $user, $host, $time) = @_;
    $time ||= time;
    my $id = $self->{type} . ':' . $self->{name};
    if ($self->flag_check ('locked')) {
        $self->error ("cannot get $id: object is locked");
        return;
    }
    my $path = $self->file_path;
    return unless $path;
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
    $self->log_action ('get', $user, $host, $time);
    return $data;
}

# Store the file on the wallet server.
sub store {
    my ($self, $data, $user, $host, $time) = @_;
    $time ||= time;
    my $id = $self->{type} . ':' . $self->{name};
    if ($self->flag_check ('locked')) {
        $self->error ("cannot store $id: object is locked");
        return;
    }
    if ($Wallet::Config::FILE_MAX_SIZE) {
        my $max = $Wallet::Config::FILE_MAX_SIZE;
        if (length ($data) > $max) {
            $self->error ("data exceeds maximum of $max bytes");
            return;
        }
    }
    my $path = $self->file_path;
    return unless $path;
    unless (open (FILE, '>', $path)) {
        $self->error ("cannot store $id: $!");
        return;
    }
    unless (print FILE ($data) and close FILE) {
        $self->error ("cannot store $id: $!");
        close FILE;
        return;
    }
    $self->log_action ('store', $user, $host, $time);
    return 1;
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=head1 NAME

Wallet::Object::File - File object implementation for wallet

=for stopwords
API HOSTNAME DATETIME keytab remctld backend nul Allbery wallet-backend

=head1 SYNOPSIS

    my @name = qw(file mysql-lsdb)
    my @trace = ($user, $host, time);
    my $object = Wallet::Object::File->create (@name, $schema, @trace);
    unless ($object->store ("the-password\n")) {
        die $object->error, "\n";
    }
    my $password = $object->get (@trace);
    $object->destroy (@trace);

=head1 DESCRIPTION

Wallet::Object::File is a representation of simple file objects in the
wallet.  It implements the wallet object API and provides the necessary
glue to store a file on the wallet server, retrieve it later, and delete
it when the file object is deleted.  A file object must be stored before
it can be retrieved with get.

To use this object, the configuration option specifying where on the
wallet server to store file objects must be set.  See L<Wallet::Config>
for details on this configuration parameter and information about how to
set wallet configuration.

=head1 METHODS

This object mostly inherits from Wallet::Object::Base.  See the
documentation for that class for all generic methods.  Below are only
those methods that are overridden or behave specially for this
implementation.

=over 4

=item destroy(PRINCIPAL, HOSTNAME [, DATETIME])

Destroys a file object by removing it from the database and deleting the
corresponding file on the wallet server.  Returns true on success and
false on failure.  The caller should call error() to get the error message
after a failure.  PRINCIPAL, HOSTNAME, and DATETIME are stored as history
information.  PRINCIPAL should be the user who is destroying the object.
If DATETIME isn't given, the current time is used.

=item get(PRINCIPAL, HOSTNAME [, DATETIME])

Retrieves the current contents of the file object or undef on error.
store() must be called before get() will be successful.  The caller should
call error() to get the error message if get() returns undef.  PRINCIPAL,
HOSTNAME, and DATETIME are stored as history information.  PRINCIPAL
should be the user who is downloading the keytab.  If DATETIME isn't
given, the current time is used.

=item store(DATA, PRINCIPAL, HOSTNAME [, DATETIME])

Store DATA as the current contents of the file object.  Any existing data
will be overwritten.  Returns true on success and false on failure.  The
caller should call error() to get the error message after a failure.
PRINCIPAL, HOSTNAME, and DATETIME are stored as history information.
PRINCIPAL should be the user who is destroying the object.  If DATETIME
isn't given, the current time is used.

If FILE_MAX_SIZE is set in the wallet configuration, a store() of DATA
larger than that configuration setting will be rejected.

=back

=head1 FILES

=over 4

=item FILE_BUCKET/<hash>/<file>

Files are stored on the wallet server under the directory FILE_BUCKET as
set in the wallet configuration.  <hash> is the first two characters of
the hex-encoded MD5 hash of the wallet file object name, used to not put
too many files in the same directory.  <file> is the name of the file
object with all characters other than alphanumerics, underscores, and
dashes replaced by C<%> and the hex code of the character.

=back

=head1 LIMITATIONS

The wallet implementation itself can handle arbitrary file object names.
However, due to limitations in the B<remctld> server usually used to run
B<wallet-backend>, file object names containing nul characters (ASCII 0)
may not be permitted.  The file system used for storing file objects may
impose a length limitation on the file object name.

=head1 SEE ALSO

remctld(8), Wallet::Config(3), Wallet::Object::Base(3), wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=cut
