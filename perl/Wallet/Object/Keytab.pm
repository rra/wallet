# Wallet::Object::Keytab -- Keytab object implementation for the wallet.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007, 2008, 2009, 2010
#     Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Object::Keytab;
require 5.006;

use strict;
use vars qw(@ISA $VERSION);

use Wallet::Config ();
use Wallet::Object::Base;
use Wallet::Kadmin;

@ISA = qw(Wallet::Object::Base);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.08';

##############################################################################
# Enctype restriction
##############################################################################

# Set the enctype restrictions for a keytab.  Called by attr() and takes a
# reference to the encryption types to set.  Returns true on success and false
# on failure, setting the object error if it fails.
sub enctypes_set {
    my ($self, $enctypes, $user, $host, $time) = @_;
    $time ||= time;
    my @trace = ($user, $host, $time);
    my $name = $self->{name};
    my %enctypes = map { $_ => 1 } @$enctypes;
    eval {
        my $sql = 'select ke_enctype from keytab_enctypes where ke_name = ?';
        my $sth = $self->{dbh}->prepare ($sql);
        $sth->execute ($name);
        my (@current, $entry);
        while (defined ($entry = $sth->fetchrow_arrayref)) {
            push (@current, @$entry);
        }
        for my $enctype (@current) {
            if ($enctypes{$enctype}) {
                delete $enctypes{$enctype};
            } else {
                $sql = 'delete from keytab_enctypes where ke_name = ? and
                    ke_enctype = ?';
                $self->{dbh}->do ($sql, undef, $name, $enctype);
                $self->log_set ('type_data enctypes', $enctype, undef, @trace);
            }
        }

        # When inserting new enctypes, we unfortunately have to do the
        # consistency check against the enctypes table ourselves, since SQLite
        # doesn't enforce integrity constraints.  We do this in sorted order
        # to make it easier to test.
        for my $enctype (sort keys %enctypes) {
            $sql = 'select en_name from enctypes where en_name = ?';
            my $status = $self->{dbh}->selectrow_array ($sql, undef, $enctype);
            unless ($status) {
                die "unknown encryption type $enctype\n";
            }
            $sql = 'insert into keytab_enctypes (ke_name, ke_enctype) values
                (?, ?)';
            $self->{dbh}->do ($sql, undef, $name, $enctype);
            $self->log_set ('type_data enctypes', undef, $enctype, @trace);
        }
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ($@);
        $self->{dbh}->rollback;
        return;
    }
    return 1;
}

# Return a list of the encryption types current set for a keytab.  Called by
# attr() or get().  Returns the empty list on failure or on an empty list of
# enctype restrictions, but sets the object error on failure so the caller
# should use that to determine success.
sub enctypes_list {
    my ($self) = @_;
    my @enctypes;
    eval {
        my $sql = 'select ke_enctype from keytab_enctypes where ke_name = ?
            order by ke_enctype';
        my $sth = $self->{dbh}->prepare ($sql);
        $sth->execute ($self->{name});
        my $entry;
        while (defined ($entry = $sth->fetchrow_arrayref)) {
            push (@enctypes, @$entry);
        }
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ($@);
        $self->{dbh}->rollback;
        return;
    }
    return @enctypes;
}

##############################################################################
# Synchronization
##############################################################################

# Set a synchronization target or clear the targets if $targets is an
# empty list.  Returns true on success and false on failure.
#
# Currently, no synchronization targets are supported, but we preserve the
# ability to clear synchronization and the basic structure of the code so
# that they can be added later.
sub sync_set {
    my ($self, $targets, $user, $host, $time) = @_;
    $time ||= time;
    my @trace = ($user, $host, $time);
    if (@$targets > 1) {
        $self->error ('only one synchronization target supported');
        return;
    } elsif (@$targets) {
        my $target = $targets->[0];
        $self->error ("unsupported synchronization target $target");
        return;
    } else {
        eval {
            my $sql = 'select ks_target from keytab_sync where ks_name = ?';
            my $dbh = $self->{dbh};
            my $name = $self->{name};
            my ($result) = $dbh->selectrow_array ($sql, undef, $name);
            if ($result) {
                my $sql = 'delete from keytab_sync where ks_name = ?';
                $self->{dbh}->do ($sql, undef, $name);
                $self->log_set ('type_data sync', $result, undef, @trace);
            }
            $self->{dbh}->commit;
        };
        if ($@) {
            $self->error ($@);
            $self->{dbh}->rollback;
            return;
        }
    }
    return 1;
}

# Return a list of the current synchronization targets.  Returns the empty
# list on failure or on an empty list of enctype restrictions, but sets
# the object error on failure so the caller should use that to determine
# success.
sub sync_list {
    my ($self) = @_;
    my @targets;
    eval {
        my $sql = 'select ks_target from keytab_sync where ks_name = ?
            order by ks_target';
        my $sth = $self->{dbh}->prepare ($sql);
        $sth->execute ($self->{name});
        my $target;
        while (defined ($target = $sth->fetchrow_array)) {
            push (@targets, $target);
        }
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ($@);
        $self->{dbh}->rollback;
        return;
    }
    return @targets;
}

##############################################################################
# Core methods
##############################################################################

# Override attr to support setting the enctypes and sync attributes.  Note
# that the sync attribute has no supported targets at present and hence will
# always return an error, but the code is still here so that it doesn't have
# to be rewritten once a new sync target is added.
sub attr {
    my ($self, $attribute, $values, $user, $host, $time) = @_;
    $time ||= time;
    my @trace = ($user, $host, $time);
    my %known = map { $_ => 1 } qw(enctypes sync);
    undef $self->{error};
    unless ($known{$attribute}) {
        $self->error ("unknown attribute $attribute");
        return;
    }
    if ($values) {
        if ($attribute eq 'enctypes') {
            return $self->enctypes_set ($values, $user, $host, $time);
        } elsif ($attribute eq 'sync') {
            return $self->sync_set ($values, $user, $host, $time);
        }
    } else {
        if ($attribute eq 'enctypes') {
            return $self->enctypes_list;
        } elsif ($attribute eq 'sync') {
            return $self->sync_list;
        }
    }
}

# Override attr_show to display the enctypes and sync attributes.
sub attr_show {
    my ($self) = @_;
    my $output = '';
    my @targets = $self->attr ('sync');
    if (not @targets and $self->error) {
        return;
    } elsif (@targets) {
        $output .= sprintf ("%15s: %s\n", 'Synced with', "@targets");
    }
    my @enctypes = $self->attr ('enctypes');
    if (not @enctypes and $self->error) {
        return;
    } elsif (@enctypes) {
        $output .= sprintf ("%15s: %s\n", 'Enctypes', $enctypes[0]);
        shift @enctypes;
        for my $enctype (@enctypes) {
            $output .= (' ' x 17) . $enctype . "\n";
        }
    }
    return $output;
}

# Override new to start by creating a handle for the kadmin module we're
# using.
sub new {
    my ($class, $type, $name, $dbh) = @_;
     my $self = {
        dbh    => $dbh,
        kadmin => undef,
    };
    bless $self, $class;
    my $kadmin = Wallet::Kadmin->new ();
    $self->{kadmin} = $kadmin;

    # Set a callback for things to do after a fork, specifically for the MIT
    # kadmin module which forks to kadmin.
    my $callback = sub { $self->{dbh}->{InactiveDestroy} = 1 };
    $kadmin->fork_callback ($callback);

    $self = $class->SUPER::new ($type, $name, $dbh);
    $self->{kadmin} = $kadmin;
    return $self;
}

# Override create to start by creating the principal in Kerberos and only
# create the entry in the database if that succeeds.  Error handling isn't
# great here since we don't have a way to communicate the error back to the
# caller.
sub create {
    my ($class, $type, $name, $dbh, $creator, $host, $time) = @_;
    my $self = {
        dbh    => $dbh,
        kadmin => undef,
    };
    bless $self, $class;
    my $kadmin = Wallet::Kadmin->new ();
    $self->{kadmin} = $kadmin;

    # Set a callback for things to do after a fork, specifically for the MIT
    # kadmin module which forks to kadmin.
    my $callback = sub { $self->{dbh}->{InactiveDestroy} = 1 };
    $kadmin->fork_callback ($callback);

    if (not $kadmin->create ($name)) {
        die $kadmin->error, "\n";
    }
    $self = $class->SUPER::create ($type, $name, $dbh, $creator, $host, $time);
    $self->{kadmin} = $kadmin;
    return $self;
}

# Override destroy to delete the principal out of Kerberos as well.
sub destroy {
    my ($self, $user, $host, $time) = @_;
    my $id = $self->{type} . ':' . $self->{name};
    if ($self->flag_check ('locked')) {
        $self->error ("cannot destroy $id: object is locked");
        return;
    }
    eval {
        my $sql = 'delete from keytab_sync where ks_name = ?';
        $self->{dbh}->do ($sql, undef, $self->{name});
        $sql = 'delete from keytab_enctypes where ke_name = ?';
        $self->{dbh}->do ($sql, undef, $self->{name});
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ($@);
        $self->{dbh}->rollback;
        return;
    }
    my $kadmin = $self->{kadmin};
    if (not $kadmin->destroy ($self->{name})) {
        $self->error ($kadmin->error);
        return;
    }
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
    my $kadmin = $self->{kadmin};
    if ($self->flag_check ('unchanging')) {
        my $result = $kadmin->keytab ($self->{name});
        if (defined $result) {
            $self->log_action ('get', $user, $host, $time);
        }
        return $result;
    }
    unless (defined ($Wallet::Config::KEYTAB_TMP)) {
        $self->error ('KEYTAB_TMP configuration variable not set');
        return;
    }
    my $file = $Wallet::Config::KEYTAB_TMP . "/keytab.$$";
    unlink $file;
    my @enctypes = $self->attr ('enctypes');
    if (not $kadmin->keytab_rekey ($self->{name}, $file, @enctypes)) {
        $self->error ($kadmin->error);
        return;
    }
    local *KEYTAB;
    unless (open (KEYTAB, '<', $file)) {
        my $princ = $self->{name};
        $self->error ("error opening keytab for principal $princ: $!");
        return;
    }
    local $/;
    undef $!;
    my $data = <KEYTAB>;
    if ($!) {
        my $princ = $self->{name};
        $self->error ("error reading keytab for principal $princ: $!");
        unlink $file;
        return;
    }
    close KEYTAB;
    unlink $file;
    $self->log_action ('get', $user, $host, $time);
    return $data;
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=for stopwords
keytab API KDC keytabs HOSTNAME DATETIME enctypes enctype DBH metadata
unmanaged kadmin Allbery

=head1 NAME

Wallet::Object::Keytab - Keytab object implementation for wallet

=head1 SYNOPSIS

    my @name = qw(keytab host/shell.example.com);
    my @trace = ($user, $host, time);
    my $object = Wallet::Object::Keytab->create (@name, $dbh, @trace);
    my $keytab = $object->get (@trace);
    $object->destroy (@trace);

=head1 DESCRIPTION

Wallet::Object::Keytab is a representation of Kerberos keytab objects in
the wallet.  It implements the wallet object API and provides the
necessary glue to create principals in a Kerberos KDC, create and return
keytabs for those principals, and delete them out of Kerberos when the
wallet object is destroyed.

A keytab is an on-disk store for the key or keys for a Kerberos principal.
Keytabs are used by services to verify incoming authentication from
clients or by automated processes that need to authenticate to Kerberos.
To create a keytab, the principal has to be created in Kerberos and then a
keytab is generated and stored in a file on disk.

This implementation generates a new random key (and hence invalidates all
existing keytabs) each time the keytab is retrieved with the get() method.

To use this object, several configuration parameters must be set.  See
Wallet::Config(3) for details on those configuration parameters and
information about how to set wallet configuration.

=head1 METHODS

This object mostly inherits from Wallet::Object::Base.  See the
documentation for that class for all generic methods.  Below are only
those methods that are overridden or behave specially for this
implementation.

=over 4

=item attr(ATTRIBUTE [, VALUES, PRINCIPAL, HOSTNAME [, DATETIME]])

Sets or retrieves a given object attribute.  The following attribute is
supported:

=over 4

=item enctypes

Restricts the generated keytab to a specific set of encryption types.  The
values of this attribute must be enctype strings recognized by Kerberos
(strings like C<aes256-cts-hmac-sha1-96> or C<des-cbc-crc>).  Encryption
types must also be present in the list of supported enctypes stored in the
database database or the attr() method will reject them.  Note that the
salt should not be included; since the salt is irrelevant for keytab keys,
it will always be set to the default by the wallet.

If this attribute is set, the principal will be restricted to that
specific enctype list when get() is called for that keytab.  If it is not
set, the default set in the KDC will be used.

This attribute is ignored if the C<unchanging> flag is set on a keytab.
Keytabs retrieved with C<unchanging> set will contain all keys present in
the KDC for that Kerberos principal and therefore may contain different
enctypes than those requested by this attribute.

=item sync

This attribute is intended to set a list of external systems with which
data about this keytab is synchronized, but there are no supported targets
currently.  However, there is support for clearing this attribute or
returning its current value.

=back

If no other arguments besides ATTRIBUTE are given, returns the values of
that attribute, if any, as a list.  On error, returns the empty list.  To
distinguish between an error and an empty return, call error() afterward.
It is guaranteed to return undef unless there was an error.

If other arguments are given, sets the given ATTRIBUTE values to VALUES,
which must be a reference to an array (even if only one value is being
set).  Pass a reference to an empty array to clear the attribute values.
PRINCIPAL, HOSTNAME, and DATETIME are stored as history information.
PRINCIPAL should be the user who is destroying the object.  If DATETIME
isn't given, the current time is used.

=item create(TYPE, NAME, DBH, PRINCIPAL, HOSTNAME [, DATETIME])

This is a class method and should be called on the Wallet::Object::Keytab
class.  It creates a new object with the given TYPE and NAME (TYPE is
normally C<keytab> and must be for the rest of the wallet system to use
the right class, but this module doesn't check for ease of subclassing),
using DBH as the handle to the wallet metadata database.  PRINCIPAL,
HOSTNAME, and DATETIME are stored as history information.  PRINCIPAL
should be the user who is creating the object.  If DATETIME isn't given,
the current time is used.

When a new keytab object is created, the Kerberos principal designated by
NAME is also created in the Kerberos realm determined from the wallet
configuration.  If the principal already exists, create() still succeeds
(so that a previously unmanaged principal can be imported into the
wallet).  Otherwise, if the Kerberos principal could not be created,
create() fails.  The principal is created with the randomized keys.  NAME
must not contain the realm; instead, the KEYTAB_REALM configuration
variable should be set.  See Wallet::Config(3) for more information.

If create() fails, it throws an exception.

=item destroy(PRINCIPAL, HOSTNAME [, DATETIME])

Destroys a keytab object by removing it from the database and deleting the
principal out of Kerberos.  If deleting the principal fails, destroy()
fails, but destroy() succeeds if the principal didn't exist when it was
called (so that it can be used to clean up stranded entries).  Returns
true on success and false on failure.  The caller should call error() to
get the error message after a failure.  PRINCIPAL, HOSTNAME, and DATETIME
are stored as history information.  PRINCIPAL should be the user who is
destroying the object.  If DATETIME isn't given, the current time is used.

=item get(PRINCIPAL, HOSTNAME [, DATETIME])

Retrieves a keytab for this object and returns the keytab data or undef on
error.  The caller should call error() to get the error message if get()
returns undef.  The keytab is created with new randomized keys,
invalidating any existing keytabs for that principal, unless the
unchanging flag is set on the object.  PRINCIPAL, HOSTNAME, and DATETIME
are stored as history information.  PRINCIPAL should be the user who is
downloading the keytab.  If DATETIME isn't given, the current time is
used.

=back

=head1 FILES

=over 4

=item KEYTAB_TMP/keytab.<pid>

The keytab is created in this file and then read into memory.  KEYTAB_TMP
is set in the wallet configuration, and <pid> is the process ID of the
current process.  The file is unlinked after being read.

=back

=head1 LIMITATIONS

Only one Kerberos realm is supported for a given wallet implementation and
all keytab objects stored must be in that realm.  Keytab names in the
wallet database do not have realm information.

=head1 SEE ALSO

kadmin(8), Wallet::Config(3), Wallet::Object::Base(3), wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <rra@stanford.edu>

=cut
