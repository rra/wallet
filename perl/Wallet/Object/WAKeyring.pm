# Wallet::Object::WAKeyring -- WebAuth keyring object implementation.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2012
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Object::WAKeyring;
require 5.006;

use strict;
use vars qw(@ISA $VERSION);

use Digest::MD5 qw(md5_hex);
use Fcntl qw(LOCK_EX);
use Wallet::Config ();
use Wallet::Object::Base;
use WebAuth qw(WA_KEY_AES WA_AES_128);

@ISA = qw(Wallet::Object::Base);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.01';

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
        $self->error ("cannot create file bucket $hash: $!");
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
    my $ring = eval { WebAuth::Keyring->read ($path) };
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
    if (@purge) {
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

Wallet::Object::WAKeyring - WebAuth keyring object implementation for wallet

=head1 DESCRIPTION

To be written.

=cut
