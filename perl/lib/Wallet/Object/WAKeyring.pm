# Wallet::Object::WAKeyring -- WebAuth keyring object implementation
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2016 Russ Allbery <eagle@eyrie.org>
# Copyright 2012, 2013, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Object::WAKeyring;

use 5.008;
use strict;
use warnings;

use Digest::MD5 qw(md5_hex);
use Fcntl qw(LOCK_EX);
use Wallet::Config;
use Wallet::Object::Base;
use WebAuth 3.06 qw(WA_KEY_AES WA_AES_128);

our @ISA     = qw(Wallet::Object::Base);
our $VERSION = '1.04';

##############################################################################
# File naming
##############################################################################

# Returns the path into which that keyring object will be stored or undef on
# error.  On error, sets the internal error.
sub file_path {
    my ($self) = @_;
    my $name = $self->{name};
    unless ($Wallet::Config::WAKEYRING_BUCKET) {
        $self->error ('WebAuth keyring support not configured');
        return;
    }
    unless ($name) {
        $self->error ('WebAuth keyring objects may not have empty names');
        return;
    }
    my $hash = substr (md5_hex ($name), 0, 2);
    $name =~ s/([^\w-])/sprintf ('%%%02X', ord ($1))/ge;
    my $parent = "$Wallet::Config::WAKEYRING_BUCKET/$hash";
    unless (-d $parent || mkdir ($parent, 0700)) {
        $self->error ("cannot create keyring bucket $hash: $!");
        return;
    }
    return "$Wallet::Config::WAKEYRING_BUCKET/$hash/$name";
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

# Update the keyring if needed, and then return the contents of the current
# keyring.
sub get {
    my ($self, $user, $host, $time) = @_;
    $time ||= time;
    my $id = $self->{type} . ':' . $self->{name};
    if ($self->flag_check ('locked')) {
        $self->error ("cannot get $id: object is locked");
        return;
    }
    my $path = $self->file_path;
    return unless defined $path;

    # Create a WebAuth context and ensure we can load the relevant modules.
    my $wa = eval { WebAuth->new };
    if ($@) {
        $self->error ("cannot initialize WebAuth: $@");
        return;
    }

    # Check if the keyring already exists.  If not, create a new one with a
    # single key that's immediately valid and two more that will become valid
    # in the future.
    #
    # If the keyring does already exist, get a lock on the file.  At the end
    # of this process, we'll do an atomic update and then drop our lock.
    #
    # FIXME: There are probably better ways to do this.  There are some race
    # conditions here, particularly with new keyrings.
    unless (open (FILE, '+<', $path)) {
        my $data;
        eval {
            my $key = $wa->key_create (WA_KEY_AES, WA_AES_128);
            my $ring = $wa->keyring_new ($key);
            $key = $wa->key_create (WA_KEY_AES, WA_AES_128);
            my $valid = time + $Wallet::Config::WAKEYRING_REKEY_INTERVAL;
            $ring->add (time, $valid, $key);
            $key = $wa->key_create (WA_KEY_AES, WA_AES_128);
            $valid += $Wallet::Config::WAKEYRING_REKEY_INTERVAL;
            $ring->add (time, $valid, $key);
            $data = $ring->encode;
            $ring->write ($path);
        };
        if ($@) {
            $self->error ("cannot create new keyring");
            return;
        };
        $self->log_action ('get', $user, $host, $time);
        return $data;
    }
    unless (flock (FILE, LOCK_EX)) {
        $self->error ("cannot get lock on keyring: $!");
        return;
    }

    # Read the keyring.
    my $ring = eval { WebAuth::Keyring->read ($wa, $path) };
    if ($@) {
        $self->error ("cannot read keyring: $@");
        return;
    }

    # If the most recent key has a valid-after older than now +
    # WAKEYRING_REKEY_INTERVAL, we generate a new key with a valid_after of
    # now + 2 * WAKEYRING_REKEY_INTERVAL.
    my ($count, $newest) = (0, 0);
    for my $entry ($ring->entries) {
        $count++;
        if ($entry->valid_after > $newest) {
            $newest = $entry->valid_after;
        }
    }
    eval {
        if ($newest <= time + $Wallet::Config::WAKEYRING_REKEY_INTERVAL) {
            my $valid = time + 2 * $Wallet::Config::WAKEYRING_REKEY_INTERVAL;
            my $key = $wa->key_create (WA_KEY_AES, WA_AES_128);
            $ring->add (time, $valid, $key);
        }
    };
    if ($@) {
        $self->error ("cannot add new key: $@");
        return;
    }

    # If there are any keys older than the purge interval, remove them, but
    # only do so if we have more than three keys (the one that's currently
    # active, the one that's going to come active in the rekey interval, and
    # the one that's going to come active after that.
    #
    # FIXME: Be sure that we don't remove the last currently-valid key.
    my $cutoff = time - $Wallet::Config::WAKEYRING_PURGE_INTERVAL;
    my $i = 0;
    my @purge;
    if ($count > 3) {
        for my $entry ($ring->entries) {
            if ($entry->creation < $cutoff) {
                push (@purge, $i);
            }
            $i++;
        }
    }
    if (@purge && $count - @purge >= 3) {
        eval {
            for my $key (reverse @purge) {
                $ring->remove ($key);
            }
        };
        if ($@) {
            $self->error ("cannot remove old keys: $@");
            return;
        }
    }

    # Encode the key.
    my $data = eval { $ring->encode };
    if ($@) {
        $self->error ("cannot encode keyring: $@");
        return;
    }

    # Write the new keyring to the path.
    eval { $ring->write ($path) };
    if ($@) {
        $self->error ("cannot store new keyring: $@");
        return;
    }
    close FILE;
    $self->log_action ('get', $user, $host, $time);
    return $data;
}

# Store the file on the wallet server.
#
# FIXME: Check the provided keyring for validity.
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

=for stopwords
WebAuth keyring keyrings API HOSTNAME DATETIME keytab AES rekey Allbery

=head1 NAME

Wallet::Object::WAKeyring - WebAuth keyring object implementation for wallet

=head1 SYNOPSIS

    my ($user, $host, $time);
    my @name = qw(wa-keyring www.stanford.edu);
    my @trace = ($user, $host, $time);
    my $object = Wallet::Object::WAKeyring->create (@name, $schema, $trace);
    my $keyring = $object->get (@trace);
    unless ($object->store ($keyring)) {
        die $object->error, "\n";
    }
    $object->destroy (@trace);

=head1 DESCRIPTION

Wallet::Object::WAKeyring is a representation of a WebAuth keyring in the
wallet.  It implements the wallet object API and provides the necessary
glue to store a keyring on the wallet server, retrieve it, update the
keyring with new keys automatically as needed, purge old keys
automatically, and delete the keyring when the object is deleted.

WebAuth keyrings hold one or more keys.  Each key has a creation time and
a validity time.  The key cannot be used until its validity time has been
reached.  This permits safe key rotation: a new key is added with a
validity time in the future, and then the keyring is updated everywhere it
needs to be before that validity time is reached.  This wallet object
automatically handles key rotation by adding keys with validity dates in
the future and removing keys with creation dates substantially in the
past.

To use this object, various configuration options specifying where to
store the keyrings and how to handle key rotation must be set.  See
Wallet::Config for details on these configuration parameters and
information about how to set wallet configuration.

=head1 METHODS

This object mostly inherits from Wallet::Object::Base.  See the
documentation for that class for all generic methods.  Below are only
those methods that are overridden or behave specially for this
implementation.

=over 4

=item destroy(PRINCIPAL, HOSTNAME [, DATETIME])

Destroys a WebAuth keyring object by removing it from the database and
deleting the corresponding file on the wallet server.  Returns true on
success and false on failure.  The caller should call error() to get the
error message after a failure.  PRINCIPAL, HOSTNAME, and DATETIME are
stored as history information.  PRINCIPAL should be the user who is
destroying the object.  If DATETIME isn't given, the current time is used.

=item get(PRINCIPAL, HOSTNAME [, DATETIME])

Either creates a new WebAuth keyring (if this object has not bee stored or
retrieved before) or does any necessary periodic maintenance on the
keyring and then returns its data.  The caller should call error() to get
the error message if get() returns undef.  PRINCIPAL, HOSTNAME, and
DATETIME are stored as history information.  PRINCIPAL should be the user
who is downloading the keytab.  If DATETIME isn't given, the current time
is used.

If this object has never been stored or retrieved before, a new keyring
will be created with three 128-bit AES keys: one that is immediately
valid, one that will become valid after the rekey interval, and one that
will become valid after twice the rekey interval.

If keyring data for this object already exists, the creation and validity
dates for each key in the keyring will be examined.  If the key with the
validity date the farthest into the future has a date that's less than or
equal to the current time plus the rekey interval, a new 128-bit AES key
will be added to the keyring with a validity time of twice the rekey
interval in the future.  Finally, all keys with a creation date older than
the configured purge interval will be removed provided that the keyring
has at least three keys

=item store(DATA, PRINCIPAL, HOSTNAME [, DATETIME])

Store DATA as the current contents of the WebAuth keyring object.  Note
that this is not checked for validity, just assumed to be a valid keyring.
Any existing data will be overwritten.  Returns true on success and false
on failure.  The caller should call error() to get the error message after
a failure.  PRINCIPAL, HOSTNAME, and DATETIME are stored as history
information.  PRINCIPAL should be the user who is destroying the object.
If DATETIME isn't given, the current time is used.

If FILE_MAX_SIZE is set in the wallet configuration, a store() of DATA
larger than that configuration setting will be rejected.

=back

=head1 FILES

=over 4

=item WAKEYRING_BUCKET/<hash>/<file>

WebAuth keyrings are stored on the wallet server under the directory
WAKEYRING_BUCKET as set in the wallet configuration.  <hash> is the first
two characters of the hex-encoded MD5 hash of the wallet file object name,
used to not put too many files in the same directory.  <file> is the name
of the file object with all characters other than alphanumerics,
underscores, and dashes replaced by "%" and the hex code of the character.

=back

=head1 SEE ALSO

Wallet::Config(3), Wallet::Object::Base(3), wallet-backend(8), WebAuth(3)

This module is part of the wallet system. The current version is available
from L<https://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=cut
