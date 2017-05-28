# Wallet::Kadmin::AD -- Wallet Kerberos administration API for AD
#
# Written by Bill MacAllister <bill@ca-zephyr.org>
# Copyright 2016 Russ Allbery <eagle@eyrie.org>
# Copyright 2015 Dropbox, Inc.
# Copyright 2007, 2008, 2009, 2010, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Kadmin::AD;

use 5.008;
use strict;
use warnings;

use Authen::SASL;
use Net::LDAP;
use IPC::Run qw(run timeout);
use Sys::Syslog qw(:standard :macros);
use Wallet::Config;
use Wallet::Kadmin;

our @ISA     = qw(Wallet::Kadmin);
our $VERSION = '1.04';

##############################################################################
# kadmin Interaction
##############################################################################

# Send debugging output to syslog.

sub ad_debug {
    my ($self, $l, $m) = @_;
    if (!$self->{SYSLOG}) {
        openlog('wallet-server', 'ndelay,nofatal', 'local3');
        $self->{SYSLOG} = 1;
    }
    syslog($l, $m);
    return;
}

# Make sure that principals are well-formed and don't contain
# characters that will cause us problems when talking to kadmin.
# Takes a principal and returns true if it's okay, false otherwise.
# Note that we do not permit realm information here.
sub valid_principal {
    my ($self, $principal) = @_;
    my $valid = 0;
    if ($principal =~ m,^(host|service)(/[\w_.-]+)?\z,) {
        my $k_type = $1;
        my $k_id   = $2;
        if ($k_type eq 'host') {
            $valid = 1 if $k_id =~ m/[.]/xms;
        } elsif ($k_type eq 'service') {
            $valid = 1 if length($k_id) < 19;
        }
    }
    return $valid;
}

# Connect to the Active Directory server using LDAP. The connection is
# used to retrieve information about existing keytabs since msktutil
# does not have this functionality.
sub ldap_connect {
    my ($self) = @_;

    if (!-e $Wallet::Config::AD_CACHE) {
        die 'Missing kerberos ticket cache ' . $Wallet::Config::AD_CACHE;
    }

    my $ldap;
    eval {
        local $ENV{KRB5CCNAME} = $Wallet::Config::AD_CACHE;
        my $sasl = Authen::SASL->new(mechanism => 'GSSAPI');
        $ldap = Net::LDAP->new($Wallet::Config::KEYTAB_HOST, onerror => 'die');
        my $mesg = eval { $ldap->bind(undef, sasl => $sasl) };
    };
    if ($@) {
        my $error = $@;
        chomp $error;
        1 while ($error =~ s/ at \S+ line \d+\.?\z//);
        die "LDAP bind to AD failed: $error\n";
    }

    return $ldap;
}

# Construct a base filter for searching Active Directory.

sub ldap_base_filter {
    my ($self, $principal) = @_;
    my $base;
    my $filter;
    if ($principal =~ m,^host/(\S+),xms) {
        my $fqdn = $1;
        my $host = $fqdn;
        $host =~ s/[.].*//xms;
        $filter = "(samAccountName=${host}\$)";
        $base
          = $Wallet::Config::AD_COMPUTER_RDN . ',' $Wallet::Config::AD_BASE_DN;
    } elsif ($principal =~ m,^service/(\S+),xms) {
        my $id = $1;
        $filter = "(servicePrincipalName=service/${id})";
        $base
          = $Wallet::Config::AD_USER_RDN . ',' $Wallet::Config::AD_BASE_DN;
    }
    return ($base, $filter);
}

# TODO: Get a keytab from the keytab bucket.
sub get_ad_keytab {
    my ($self, $principal) = @_;
    return;
}

# Run a msktutil command and capture the output.  Returns the output,
# either as a list of lines or, in scalar context, as one string.
# Depending on the exit status of msktutil or on the eval trap to know
# when the msktutil command fails.  The error string returned from the
# call to run frequently contains information about a success rather
# that error output.
sub msktutil {
    my ($self, $args_ref) = @_;
    unless (defined($Wallet::Config::KEYTAB_HOST)
        and defined($Wallet::Config::KEYTAB_PRINCIPAL)
        and defined($Wallet::Config::KEYTAB_FILE)
        and defined($Wallet::Config::KEYTAB_REALM))
    {
        die "keytab object implementation not configured\n";
    }
    unless (-e $Wallet::Config::AD_MSKTUTIL
        and defined($Wallet::Config::AD_BASE_DN)
        and defined($Wallet::Config::AD_COMPUTER_RDN)
        and defined($Wallet::Config::AD_USER_RDN))
    {
        die "Active Directory support not configured\n";
    }
    my @args = @{$args_ref};
    my @cmd  = ($Wallet::Config::AD_MSKTUTIL);
    push @cmd, @args;
    if ($Wallet::Config::AD_DEBUG) {
        $self->ad_debug('debug', join(' ', @cmd));
    }

    my $in;
    my $out;
    my $err;
    my $err_msg;
    my $err_no;
    eval {
        local $ENV{KRB5CCNAME} = $Wallet::Config::AD_CACHE;
        run \@cmd, \$in, \$out, \$err, timeout(120);
        if ($?) {
            $err_no = $?;
        }
    };
    if ($@) {
        $err_msg .= "ERROR ($err_no): $@\n";
    }
    if ($err_no || $err_msg) {
        if ($err) {
            $err_msg .= "ERROR: $err\n";
            $err_msg .= 'Problem command: ' . join(' ', @cmd) . "\n";
        }
        die $err_msg;
    } else {
        if ($err) {
            $out .= "\n" . $err;
        }
    }
    if ($Wallet::Config::AD_DEBUG) {
        $self->ad_debug('debug', $out);
    }
    return $out;
}

# Either create or update a keytab for the principal.  Return the
# name of the keytab file created.
sub ad_create_update {
    my ($self, $principal, $action) = @_;
    my $keytab = $Wallet::Config::KEYTAB_TMP . "/keytab.$$";
    if (-e $keytab) {
        unlink $keytab or die "Problem deleting $keytab\n";
    }
    my @cmd = ('--' . $action);
    push @cmd, '--server',   $Wallet::Config::AD_SERVER;
    push @cmd, '--enctypes', '0x1C';
    push @cmd, '--keytab',   $keytab;
    push @cmd, '--realm',    $Wallet::Config::KEYTAB_REALM;

    if ($principal =~ m,^host/(\S+),xms) {
        my $fqdn = $1;
        my $host = $fqdn;
        $host =~ s/[.].*//xms;
        push @cmd, '--base', $Wallet::Config::COMPUTER_RDN;
        push @cmd, '--dont-expire-password';
        push @cmd, '--computer-name', $host;
        push @cmd, '--upn', "host/$fqdn";
        push @cmd, '--hostname', $fqdn;
    } elsif ($principal =~ m,^service/(\S+),xms) {
        my $service_id = $1;
        push @cmd, '--base', $Wallet::Config::USER_RDN;
        push @cmd, '--use-service-account';
        push @cmd, '--service', "service/$service_id";
        push @cmd, '--account-name', "srv-${service_id}";
        push @cmd, '--no-pac';
    }
    my $out = $self->msktutil(\@cmd);
    if ($out =~ /Error:\s+\S+\s+failed/xms) {
        $self->ad_delete($principal);
        my $m = "ERROR: problem creating keytab:\n" . $out;
        $m .= 'INFO: the keytab used to by wallet probably has'
          . " insufficient access to AD\n";
        die $m;
    }

    return $keytab;
}

##############################################################################
# Public interfaces
##############################################################################

# Set a callback to be called for forked kadmin processes.
sub fork_callback {
    my ($self, $callback) = @_;
    $self->{fork_callback} = $callback;
}

# Check whether a given principal already exists.  Returns true if so,
# false otherwise.  The best way to do this with AD is to perform an
# ldap query.
sub exists {
    my ($self, $principal) = @_;
    return unless $self->valid_principal($principal);

    my $ldap = $self->ldap_connect();
    my ($base, $filter) = $self->ldap_base_filter($principal);
    my @attrs = ('objectClass', 'msds-KeyVersionNumber');

    my $result;
    eval {
        $result = $ldap->search(
            base   => $base,
            scope  => 'subtree',
            filter => $filter,
            attrs  => \@attrs
        );
    };

    if ($@) {
        my $error = $@;
        die "LDAP search error: $error\n";
    }
    if ($result->code) {
        my $m;
        $m .= "INFO base:$base filter:$filter scope:subtree\n";
        $m .= 'ERROR:' . $result->error . "\n";
        die $m;
    }
    if ($result->count > 1) {
        my $m = "ERROR: too many AD entries for this keytab\n";
        for my $entry ($result->entries) {
            $m .= 'INFO: dn found ' . $entry->dn . "\n";
        }
        die $m;
    }
    if ($result->count) {
        for my $entry ($result->entries) {
            return $entry->get_value('msds-KeyVersionNumber');
        }
    } else {
        return 0;
    }
    return;
}

# Call msktutil to Create a principal in Kerberos.  Sets the error and
# returns undef on failure, and returns 1 on either success or if the
# principal already exists.  Note, this creates a keytab that is never
# used because it is not returned to the user.
sub create {
    my ($self, $principal) = @_;
    unless ($self->valid_principal($principal)) {
        die "ERROR: invalid principal name $principal\n";
        return;
    }
    if ($self->exists($principal)) {
        if ($Wallet::Config::AD_DEBUG) {
            $self->ad_debug('debug', "$principal exists");
        }
        return 1;
    }
    my $file = $self->ad_create_update($principal, 'create');
    if (-e $file) {
        unlink $file or die "Problem deleting $file\n";
    }
    return 1;
}

# TODO: Return a keytab.  Need to create a local keytab cache when
# a keytab is marked unchanging and return that.
sub keytab {
    my ($self, $principal) = @_;
    unless ($self->valid_principal($principal)) {
        die "ERROR: invalid principal name $principal\n";
        return;
    }
    my $file = 'call to route to get the file name of local keytab file';
    if (!-e $file) {
        die "ERROR: keytab file $file does not exist.\n";
    }
    return $self->read_keytab($file);
}

# Update a keytab for a principal.  This action changes the AD
# password for the principal and increments the kvno.  The enctypes
# passed in are ignored.
sub keytab_rekey {
    my ($self, $principal, @enctypes) = @_;
    unless ($self->valid_principal($principal)) {
        die "ERROR: invalid principal name: $principal\n";
        return;
    }
    if (!$self->exists($principal)) {
        die "ERROR: $principal does not exist\n";
    }
    unless ($self->valid_principal($principal)) {
        die "ERROR: invalid principal name $principal\n";
        return;
    }
    my $file = $self->ad_create_update($principal, 'update');
    return $self->read_keytab($file);
}

# Delete a principal from Kerberos.  Return true if successful, false
# otherwise.  If the deletion fails, sets the error.  If the principal
# doesn't exist, return success; we're bringing reality in line with
# our expectations.  For AD this means just delete the object using
# LDAP.
sub destroy {
    my ($self, $principal) = @_;
    unless ($self->valid_principal($principal)) {
        $self->error("invalid principal name: $principal");
    }
    my $exists = $self->exists($principal);
    if (!defined $exists) {
        return;
    } elsif (not $exists) {
        return 1;
    }

    return $self->ad_delete($principal);
}

# Delete an entry from AD using LDAP.

sub ad_delete {
    my ($self, $principal) = @_;

    my $k_type;
    my $k_id;
    my $dn;
    if ($principal =~ m,^(host|service)/(\S+),xms) {
        $k_type = $1;
        $k_id   = $2;
        if ($k_type eq 'host') {
            my $host = $k_id;
            $host =~ s/[.].*//;
            $dn =
                "cn=${host},"
                . $Wallet::Config::AD_COMPUTER_RDN . ','
                . $Wallet::Config::AD_BASE_DN;
        } elsif ($k_type eq 'service') {
            $dn =
                "cn=srv-${k_id},"
                . $Wallet::Config::AD_USER_RDN . ','
                . $Wallet::Config::AD_BASE_DN;
        }
    }

    my $ldap  = $self->ldap_connect();
    my $msgid = $ldap->delete($dn);
    if ($msgid->code) {
        my $m;
        $m .= "ERROR: Problem deleting $dn\n";
        $m .= $msgid->error;
        die $m;
    }
    return 1;
}

# Create a new AD kadmin object.  Very empty for the moment, but later it
# will probably fill out if we go to using a module rather than calling
# kadmin directly.
sub new {
    my ($class) = @_;
    unless (defined($Wallet::Config::KEYTAB_TMP)) {
        die "KEYTAB_TMP configuration variable not set\n";
    }
    my $self = {};
    $self->{SYSLOG} = undef;
    bless($self, $class);
    return $self;
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=for stopwords
rekeying rekeys remctl backend keytabs keytab kadmin KDC API Allbery
unlinked MacAllister msktutil

=head1 NAME

Wallet::Kadmin::AD - Wallet Kerberos administration API for Active Directory

=head1 SYNOPSIS

    my $kadmin = Wallet::Kadmin::AD->new;
    $kadmin->create ('host/foo.example.com');
    my $data = $kadmin->keytab_rekey ('host/foo.example.com');
    $data = $kadmin->keytab ('host/foo.example.com');
    my $exists = $kadmin->exists ('host/oldshell.example.com');
    $kadmin->destroy ('host/oldshell.example.com') if $exists;

=head1 DESCRIPTION

Wallet::Kadmin::AD implements the Wallet::Kadmin API for Active
Directory Kerberos, providing an interface to create and delete
principals and create keytabs.  It provides the API documented in
L<Wallet::Kadmin> for an Active Directory Kerberos KDC.

AD Kerberos does not provide any method via msktutil to retrieve a
keytab for a principal without rekeying it, so the keytab() method (as
opposed to keytab_rekey(), which rekeys the principal) is implemented
using a local keytab cache.

To use this class, several configuration parameters must be set.  See
L<Wallet::Config/"KEYTAB OBJECT CONFIGURATION"> for details.

=head1 LIMITATIONS

Currently, this implementation calls an external B<msktutil> program rather
than using a native Perl module and therefore requires B<msktutil> be
installed and parses its output.

=head1 SEE ALSO

msktutil, Wallet::Config(3), Wallet::Kadmin(3),
Wallet::Object::Keytab(3), wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHORS

Bill MacAllister <bill@ca-zephyr.org>
and Russ Allbery <eagle@eyrie.org>
and Jon Robertson <jonrober@stanford.edu>.

=cut
