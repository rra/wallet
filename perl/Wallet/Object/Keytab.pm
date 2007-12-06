# Wallet::Object::Keytab -- Keytab object implementation for the wallet.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007 Board of Trustees, Leland Stanford Jr. University
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

@ISA = qw(Wallet::Object::Base);

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
        die "cannot fork: $!\n";
    } elsif ($pid == 0) {
        # Don't use die here; it will get trapped as an exception.  Also be
        # careful about our database handles.  (We still lose if there's some
        # other database handle open we don't know about.)
        $self->{dbh}->{InactiveDestroy} = 1;
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
            die $_;
        }
        push (@output, $_) unless /Authenticating as principal/;
    }
    close KADMIN;
    return wantarray ? @output : join ('', @output);
}

# Check whether a given principal already exists in Kerberos.  Returns true if
# so, false otherwise.  Throws an exception if kadmin fails.
sub kadmin_exists {
    my ($self, $principal) = @_;
    return undef unless $self->valid_principal ($principal);
    if ($Wallet::Config::KEYTAB_REALM) {
        $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    }
    my $output = $self->kadmin ("getprinc $principal");
    if ($output =~ /^get_principal: /) {
        return;
    } else {
        return 1;
    }
}

# Create a principal in Kerberos.  Since this is only called by create, it
# throws an exception on failure rather than setting the error and returning
# undef.
sub kadmin_addprinc {
    my ($self, $principal) = @_;
    unless ($self->valid_principal ($principal)) {
        die "invalid principal name $principal\n";
    }
    return 1 if $self->kadmin_exists ($principal);
    if ($Wallet::Config::KEYTAB_REALM) {
        $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    }
    my $flags = $Wallet::Config::KEYTAB_FLAGS || '';
    my $output = $self->kadmin ("addprinc -randkey $flags $principal");
    if ($output =~ /^add_principal: (.*)/m) {
        die "error adding principal $principal: $!\n";
    }
    return 1;
}

# Create a keytab from a principal.  Takes the principal, the file, and
# optionally a list of encryption types to which to limit the keytab.  Return
# true if successful, false otherwise.  If the keytab creation fails, sets the
# error.
sub kadmin_ktadd {
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
    my $output = eval { $self->kadmin ("$command $principal") };
    if ($@) {
        $self->error ($@);
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
sub kadmin_delprinc {
    my ($self, $principal) = @_;
    unless ($self->valid_principal ($principal)) {
        $self->error ("invalid principal name: $principal");
        return;
    }
    my $exists = eval { $self->kadmin_exists ($principal) };
    if ($@) {
        $self->error ($@);
        return;
    } elsif (not $exists) {
        return 1;
    }
    if ($Wallet::Config::KEYTAB_REALM) {
        $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    }
    my $output = eval { $self->kadmin ("delprinc -force $principal") };
    if ($@) {
        $self->error ($@);
        return;
    } elsif ($output =~ /^delete_principal: (.*)/m) {
        $self->error ("error deleting $principal: $1");
        return;
    }
    return 1;
}

##############################################################################
# AFS kaserver synchronization
##############################################################################

# Given a Kerberos v5 principal name, convert it to a Kerberos v4 principal
# name.  Returns undef if it can't convert the name for some reason (right
# now, only if the principal has more than two parts).  Note that this mapping
# does not guarantee a unique result; multiple hosts in different domains can
# be mapped to the same Kerberos v4 principal name using this function.
sub kaserver_name {
    my ($self, $k5) = @_;
    my %host = map { $_ => 1 } qw(host ident imap pop smtp);
    $k5 =~ s/\@.*//;
    my @parts = split ('/', $k5);
    if (@parts > 2) {
        return;
    } elsif (@parts == 2 and $host{$parts[0]}) {
        $parts[1] =~ s/\..*//;
        $parts[0] = 'rcmd' if $parts[0] eq 'host';
    }
    my $k4 = join ('.', @parts);
    if ($Wallet::Config::KEYTAB_AFS_REALM) {
        $k4 .= '@' . $Wallet::Config::KEYTAB_AFS_REALM;
    }
    return $k4;
}

# Run kasetkey with the given arguments.  Returns true on success and false on
# failure.  On failure, sets the internal error to the error from kasetkey.
sub kaserver_kasetkey {
    my ($self, @args) = @_;
    my $admin = $Wallet::Config::KEYTAB_AFS_ADMIN;
    my $admin_srvtab = $Wallet::Config::KEYTAB_AFS_SRVTAB;
    my $kasetkey = $Wallet::Config::KEYTAB_AFS_KASETKEY;
    unless ($kasetkey and $admin and $admin_srvtab) {
        $self->error ('kaserver synchronization not configured');
        return;
    }
    my $pid = open (KASETKEY, '-|');
    if (not defined $pid) {
        $self->error ("cannot fork: $!");
        return;
    } elsif ($pid == 0) {
        # Don't use die here; it will get trapped as an exception.  Also be
        # careful about our database handles.  (We still lose if there's some
        # other database handle open we don't know about.)
        $self->{dbh}->{InactiveDestroy} = 1;
        unless (open (STDERR, '>&STDOUT')) {
            warn "cannot redirect stderr: $!\n";
            exit 1;
        }
        unless (exec ($kasetkey, '-k', $admin_srvtab, '-a', $admin, @args)) {
            warn "cannot exec $kasetkey: $!\n";
            exit 1;
        }
    } else {
        local $/;
        my $output = <KASETKEY>;
        close KASETKEY;
        if ($? != 0) {
            $output =~ s/\s+\z//;
            $output =~ s/\n/, /g;
            $output = ': ' . $output if $output;
            $self->error ("cannot synchronize key with kaserver$output");
            return;
        }
    }
    return 1;
}

# Given a keytab file name, the Kerberos v5 principal that's stored in that
# keytab, a srvtab file name, and the corresponding Kerberos v4 principal,
# write out a srvtab file containing the DES key in that keytab.  Fails if
# there is no DES key in the keytab.
sub kaserver_srvtab {
    my ($self, $keytab, $k5, $srvtab, $k4) = @_;

    # Gah.  Someday I will write Perl bindings for Kerberos that are less
    # broken.
    eval { require Authen::Krb5 };
    if ($@) {
        $self->error ("kaserver synchronization support not available: $@");
        return;
    }
    eval { Authen::Krb5::init_context() };
    if ($@ and not $@ =~ /^Authen::Krb5 already initialized/) {
        $self->error ('Kerberos initialization failed');
        return;
    }
    undef $@;

    # Do the interface dance.  We call kt_read_service_key with 0 for the kvno
    # to get any kvno, which works with MIT Kerberos at least.  Assume a DES
    # enctype of 1.  This code won't work with any enctype other than
    # des-cbc-crc.
    my $princ = Authen::Krb5::parse_name ($k5);
    unless (defined $princ) {
        my $error = Authen::Krb5::error();
        $self->error ("cannot parse $k5: $error");
        return;
    }
    my $key = Authen::Krb5::kt_read_service_key ($keytab, $princ, 0, 1);
    unless (defined $key) {
        my $error = Authen::Krb5::error();
        $self->error ("cannot find des-cbc-crc key in $keytab: $error");
        return;
    }
    unless (open (SRVTAB, '>', $srvtab)) {
        $self->error ("cannot create $srvtab: $!");
        return;
    }

    # srvtab format is nul-terminated name, nul-terminated instance,
    # nul-terminated realm, single character kvno (which we always set to 0),
    # and DES keyblock.
    my ($principal, $realm) = split ('@', $k4);
    $realm ||= '';
    my ($name, $inst) = split (/\./, $principal, 2);
    $inst ||= '';
    my $data = join ("\0", $name, $inst, $realm);
    $data .= "\0\0" . $key->contents;
    print SRVTAB $data;
    unless (close SRVTAB) {
        unlink $srvtab;
        $self->error ("cannot write to $srvtab: $!");
        return;
    }
    return 1;
}

# Given a principal name and a path to the keytab, synchronizes the key with a
# principal in an AFS kaserver.  Returns true on success and false on failure.
# On failure, sets the internal error.
sub kaserver_sync {
    my ($self, $principal, $keytab) = @_;
    if ($Wallet::Config::KEYTAB_REALM) {
        $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    }
    my $k4 = $self->kaserver_name ($principal);
    if (not defined $k4) {
        $self->error ("cannot convert $principal to Kerberos v4");
        return;
    }
    my $srvtab = $Wallet::Config::KEYTAB_TMP . "/srvtab.$$";
    unless ($self->kaserver_srvtab ($keytab, $principal, $srvtab, $k4)) {
        return;
    }
    unless ($self->kaserver_kasetkey ('-c', $srvtab, '-s', $k4)) {
        unlink $srvtab;
        return;
    }
    unlink $srvtab;
    return 1;
}

# Given a principal name, destroy the corresponding principal in the AFS
# kaserver.  Returns true on success and false on failure, setting the object
# error if it fails.
sub kaserver_destroy {
    my ($self, $principal) = @_;
    my $k4 = $self->kaserver_name ($principal);
    if (not defined $k4) {
        $self->error ("cannot convert $principal to Kerberos v4");
        return;
    }
    return $self->kaserver_kasetkey ('-D', $k4);
}

# Set the kaserver sync attribute.  Called by attr().  Returns true on success
# and false on failure, setting the object error if it fails.
sub kaserver_set {
    my ($self, $user, $host, $time) = @_;
    $time ||= time;
    my @trace = ($user, $host, $time);
    my $name = $self->{name};
    eval {
        my $sql = "select ks_name from keytab_sync where ks_name = ? and
            ks_target = 'kaserver'";
        my $result = $self->{dbh}->selectrow_array ($sql, undef, $name);
        if ($result) {
            die "kaserver synchronization already set\n";
        }
        $sql = "insert into keytab_sync (ks_name, ks_target)
            values (?, 'kaserver')";
        $self->{dbh}->do ($sql, undef, $name);
        $self->log_set ('type_data sync', undef, 'kaserver', @trace);
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ($@);
        $self->{dbh}->rollback;
        return;
    }
    return 1;
}

# Clear the kaserver sync attribute.  Called by attr().  Returns true on
# success and false on failure, setting the object error if it fails.
sub kaserver_clear {
    my ($self, $user, $host, $time) = @_;
    $time ||= time;
    my @trace = ($user, $host, $time);
    my $name = $self->{name};
    eval {
        my $sql = "select ks_name from keytab_sync where ks_name = ? and
            ks_target = 'kaserver'";
        my $result = $self->{dbh}->selectrow_array ($sql, undef, $name);
        unless ($result) {
            die "kaserver synchronization not set\n";
        }
        $sql = 'delete from keytab_sync where ks_name = ?';
        $self->{dbh}->do ($sql, undef, $name);
        $self->log_set ('type_data sync', 'kaserver', undef, @trace);
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ($@);
        $self->{dbh}->rollback;
        return;
    }
    return 1;
}

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
# Keytab retrieval
##############################################################################

# Retrieve an existing keytab from the KDC via a remctl call.  The KDC needs
# to be running the keytab-backend script and support the keytab retrieve
# remctl command.  In addition, the user must have configured us with the path
# to a ticket cache and the host to which to connect with remctl.  Returns the
# keytab on success and undef on failure.
sub keytab_retrieve {
    my ($self, $keytab) = @_;
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
    if ($Wallet::Config::KEYTAB_REALM) {
        $keytab .= '@' . $Wallet::Config::KEYTAB_REALM;
    }
    local $ENV{KRB5CCNAME} = $Wallet::Config::KEYTAB_REMCTL_CACHE;
    my $port = $Wallet::Config::KEYTAB_REMCTL_PORT;
    my $principal = $Wallet::Config::KEYTAB_REMCTL_PRINCIPAL;
    my @command = ('keytab', 'retrieve', $keytab);
    my $result = Net::Remctl::remctl ($host, $port, $principal, @command);
    if ($result->error) {
        $self->error ("cannot retrieve keytab for $keytab: ", $result->error);
        return;
    } elsif ($result->status != 0) {
        my $error = $result->stderr;
        $error =~ s/\s+$//;
        $error =~ s/\n/ /g;
        $self->error ("cannot retrieve keytab for $keytab: $error");
        return;
    } else {
        return $result->stdout;
    }
}

##############################################################################
# Core methods
##############################################################################

# Override attr to support setting the enctypes and sync attributes.
sub attr {
    my ($self, $attribute, $values, $user, $host, $time) = @_;
    my %known = map { $_ => 1 } qw(enctypes sync);
    undef $self->{error};
    unless ($known{$attribute}) {
        $self->error ("unknown attribute $attribute");
        return;
    }
    if ($values) {
        if ($attribute eq 'enctypes') {
            $self->enctypes_set ($values, $user, $host, $time);
        } elsif ($attribute eq 'sync') {
            if (@$values > 1) {
                $self->error ('only one synchronization target supported');
                return;
            } elsif (@$values and $values->[0] ne 'kaserver') {
                my $target = $values->[0];
                $self->error ("unsupported synchronization target $target");
                return;
            } elsif (@$values) {
                return $self->kaserver_set ($user, $host, $time);
            } else {
                return $self->kaserver_clear ($user, $host, $time);
            }
        }
    } else {
        if ($attribute eq 'enctypes') {
            return $self->enctypes_list;
        } elsif ($attribute eq 'sync') {
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

# Override create to start by creating the principal in Kerberos and only
# create the entry in the database if that succeeds.  Error handling isn't
# great here since we don't have a way to communicate the error back to the
# caller.
sub create {
    my ($class, $type, $name, $dbh, $creator, $host, $time) = @_;
    my $self = { dbh => $dbh };
    bless $self, $class;
    $self->kadmin_addprinc ($name);
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
    my @sync = $self->attr ('sync');
    if (grep { $_ eq 'kaserver' } @sync) {
        unless ($self->kaserver_destroy ($self->{name})) {
            return;
        }
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
    return undef if not $self->kadmin_delprinc ($self->{name});
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
    if ($self->flag_check ('unchanging')) {
        my $result = $self->keytab_retrieve ($self->{name});
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
    return undef if not $self->kadmin_ktadd ($self->{name}, $file, @enctypes);
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
    my @sync = $self->attr ('sync');
    if (grep { $_ eq 'kaserver' } @sync) {
        unless ($self->kaserver_sync ($self->{name}, $file)) {
            unlink $file;
            return;
        }
    } elsif ($Wallet::Config::KEYTAB_AFS_DESTROY) {
        $self->kaserver_destroy ($self->{name});
    }
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

=item attr(ATTRIBUTE [, VALUES, PRINCIPAL, HOSTNAME [, DATETIME]])

Sets or retrieves a given object attribute.  The following attributes are
supported:

=over 4

=item enctypes

Restricts the generated keytab to a specific set of encryption types.  The
values of this attribute must be enctype strings recognized by Kerberos
(strings like C<aes256-cts> or C<des-cbc-crc>).  Encryption types must also
be present in the list of supported enctypes stored in the database database
or the attr() method will reject them.  Note that the salt should not be
included; since the salt is irrelevant for keytab keys, it will always be
set to C<normal> by the wallet.

If this attribute is set, the specified enctype list will be passed to
ktadd when get() is called for that keytab.  If it is not set, the default
set in the KDC will be used.

This attribute is ignored if the C<unchanging> flag is set on a keytab.
Keytabs retrieved with C<unchanging> set will contain all keys present in
the KDC for that Kerberos principal and therefore may contain different
enctypes than those requested by this attribute.

=item sync

Sets the external systems to which the key of a given principal is
synchronized.  The only supported value for this attribute is C<kaserver>,
which says to synchronize the key with an AFS Kerberos v4 kaserver.

If this attribute is set on a keytab, whenever get() is called for that
keytab, the new DES key will be extracted from that keytab and set in the
configured AFS kaserver.  The Kerberos v4 principal name will be the same as
the Kerberos v5 principal name except that the components are separated by
C<.> instead of C</>; the second component is truncated after the first C<.>
if the first component is one of C<host>, C<ident>, C<imap>, C<pop>, or
C<smtp>; and the first component is C<rcmd> if the Kerberos v5 principal
component is C<host>.  The principal name must not contain more than two
components.

If this attribute is set, calling destroy() will also destroy the principal
from the AFS kaserver, with a principal mapping determined as above.

=back

If no other arguments besides ATTRIBUTE are given, returns the values of
that attribute, if any, as a list.  On error, returns the empty list.  To
distinguish between an error and an empty return, call error() afterwards.
It is guaranteed to return undef unless there was an error.

If other arguments are given, sets the given ATTRIBUTE values to VALUES,
which must be a reference to an array (even if only one value is being set).
Pass a reference to an empty array to clear the attribute values.
PRINCIPAL, HOSTNAME, and DATETIME are stored as history information.
PRINCIPAL should be the user who is destroying the object.  If DATETIME
isn't given, the current time is used.

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
configuration.  If the principal already exists, create() still succeeds (so
that a previously unmanaged principal can be imported into the wallet).
Otherwise, if the Kerberos principal could not be created, create() fails.
The principal is created with the C<-randkey> option to randomize its keys.
NAME must not contain the realm; instead, the KEYTAB_REALM configuration
variable should be set.  See Wallet::Config(3) for more information.

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
existing keytabs for that principal.  PRINCIPAL, HOSTNAME, and DATETIME
are stored as history information.  PRINCIPAL should be the user who is
downloading the keytab.  If DATETIME isn't given, the current time is
used.

If the configuration variable $KEYTAB_AFS_DESTROY is set and the C<sync>
attribute is not set to C<kaserver>, calling get() on a keytab object will
cause the corresponding Kerberos v4 principal to be destroyed.  This
variable is not set by default.

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
