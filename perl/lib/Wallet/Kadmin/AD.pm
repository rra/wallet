# Wallet::Kadmin::AD -- Wallet Kerberos administration API for AD
#
# Written by Bill MacAllister <whm@dropbox.com>
# Copyright 2016 Russ Allbery <eagle@eyrie.org>
# Copyright 2015,2016 Dropbox, Inc.
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

my $LDAP;

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

# Return a string given an array whose elements are command line arguments
# passws to IPC::Run.  Quote any strings that have embedded spaces.  Replace
# null elements with the string #NULL#.

sub ad_cmd_string {
    my ($self, $cmd_ref) = @_;
    my $z  = '';
    my $ws = ' ';
    for my $e (@{ $cmd_ref }) {
        if (!$e) {
            $z .= $ws . '#NULL#';
        } elsif ($e =~ /\s/xms) {
            $z .= $ws . '"' . $e . '"';
        } else {
            $z .= $ws . $e;
        }
        $ws = ' ';
    }
    return $z;
}

# Make sure that principals are well-formed and don't contain
# characters that will cause us problems when talking to kadmin.
# Takes a principal and returns true if it's okay, false otherwise.
# Note that we do not permit realm information here.
sub valid_principal {
    my ($self, $principal) = @_;
    return scalar ($principal =~ m,^[\w-]+(/[\w_.-]+)?\z,);
}

# Connect to the Active Directory server using LDAP. The connection is
# used to retrieve information about existing keytabs since msktutil
# does not have this functionality.
sub ldap_connect {
    my ($self) = @_;

    if (!$LDAP) {
        eval {
            local $ENV{KRB5CCNAME} = $Wallet::Config::AD_CACHE;
            my $sasl = Authen::SASL->new(mechanism => 'GSSAPI');
            $LDAP = Net::LDAP->new($Wallet::Config::KEYTAB_HOST,
                                   onerror => 'die');
            my $mesg = eval { $LDAP->bind(undef, sasl => $sasl) };
        };
        if ($@) {
            my $error = $@;
            chomp $error;
            1 while ($error =~ s/ at \S+ line \d+\.?\z//);
            die "LDAP bind to AD failed: $error\n";
        }
    }
    return $LDAP;
}

# Construct a base filter for searching Active Directory.

sub ldap_base_filter {
    my ($self, $principal) = @_;

    my $base;
    my $filter;
    my $this_type;
    my $this_id;

    if ($principal =~ m,^(.*?)/(\S+),xms) {
        $this_type = $1;
        $this_id   = $2;
    } else {
        $this_id = $principal;
    }

    # Create a filter to find the objects we create
    if ($this_id =~ s/@(.*)//xms) {
        $filter = "(userPrincipalName=${principal})";
    } elsif ($Wallet::Config::KEYTAB_REALM) {
        $filter = '(userPrincipalName=' . $principal
        . '@' . $Wallet::Config::KEYTAB_REALM . ')';
    } else {
        $filter = "(userPrincipalName=${principal}\@*)";
    }

    # Set the base distinguished name
    if ($this_type && $this_type eq 'host') {
        $base = $Wallet::Config::AD_COMPUTER_RDN;
    } else {
        $base = $Wallet::Config::AD_USER_RDN;
    }
    $base .= ',' . $Wallet::Config::AD_BASE_DN;

    return ($base, $filter);
}

# Take in a base and a filter and return the assoicated DN or return
# null if there is no matching entry.
sub ldap_get_dn {
    my ($self, $base, $filter) = @_;
    my $dn;

    if ($Wallet::Config::AD_DEBUG) {
        $self->ad_debug('debug', "base:$base filter:$filter scope:subtree\n");
    }

    $self->ldap_connect();
    my @attrs = ('objectclass');
    my $result;
    eval {
        $result = $LDAP->search(
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
        msg("INFO base:$base filter:$filter scope:subtree\n");
        die $result->error;
    }
    if ($Wallet::Config::AD_DEBUG) {
        $self->ad_debug('debug', 'returned: ' . $result->count);
    }

    if ($result->count == 1) {
        for my $entry ($result->entries) {
            $dn = $entry->dn;
        }
    } elsif ($result->count > 1) {
        msg('ERROR: too many AD entries for this keytab');
        for my $entry ($result->entries) {
            msg('INFO: dn found ' . $entry->dn . "\n");
        }
        die("INFO: use show to examine the problem\n");
    }

    return $dn;
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
        $self->ad_debug('debug', $self->ad_cmd_string(\@cmd));
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

# The unique identifier that Active Directory used to store keytabs
# has a maximum length of 20 characters.  This routine takes a
# principal name an generates a unique ID based on the principal name.
sub get_service_id {
    my ($self, $this_princ) = @_;

    my $this_id;
    my ($this_base, $this_filter) = $self->ldap_base_filter($this_princ);
    my $real_dn = $self->ldap_get_dn($this_base, $this_filter);
    if ($real_dn) {
        $this_id = $real_dn;
        $this_id =~ s/,.*//xms;
        $this_id =~ s/.*?=//xms;
    } else {
        my $this_cn = $this_princ;
        $this_cn =~ s{.*?/}{}xms;
        if ($Wallet::Config::AD_SERVICE_PREFIX) {
            $this_cn = $Wallet::Config::AD_SERVICE_PREFIX . $this_cn;
        }
        my $loop_limit = $Wallet::Config::AD_SERVICE_LIMIT;
        if (length($this_cn)>20) {
            my $cnt = 0;
            my $this_dn;
            my $suffix_size = length("$loop_limit");
            my $this_prefix = substr($this_cn, 0, 20-$suffix_size);
            my $this_format = "%0${suffix_size}i";
            while ($cnt<$loop_limit) {
                my $this_cn = $this_prefix . sprintf($this_format, $cnt);
                $this_dn = ldap_get_dn($this_base, "cn=$this_cn");
                if (!$this_dn) {
                    $this_id = $this_cn;
                    last;
                }
                $cnt++;
            }
        } else {
            $this_id = $this_cn;
        }
    }
    return $this_id;
}

# Either create or update a keytab for the principal.  Return the
# name of the keytab file created.
sub ad_create_update {
    my ($self, $principal, $action) = @_;
    return unless $self->valid_principal($principal);
    my $keytab = $Wallet::Config::KEYTAB_TMP . "/keytab.$$";
    if (-e $keytab) {
        unlink $keytab or die "Problem deleting $keytab\n";
    }
    my @cmd = ('--' . $action);
    push @cmd, '--server',   $Wallet::Config::AD_SERVER;
    push @cmd, '--enctypes', '0x4';
    push @cmd, '--enctypes', '0x8';
    push @cmd, '--enctypes', '0x10';
    push @cmd, '--keytab',   $keytab;
    push @cmd, '--realm',    $Wallet::Config::KEYTAB_REALM;
    push @cmd, '--upn',      $principal;

    my $this_type;
    my $this_id;
    if ($principal =~ m,^(.*?)/(\S+),xms) {
        $this_type = $1;
        $this_id   = $2;
        if ($this_type eq 'host') {
            my $host = $this_id;
            $host =~ s/[.].*//xms;
            push @cmd, '--base',          $Wallet::Config::AD_COMPUTER_RDN;
            push @cmd, '--dont-expire-password';
            push @cmd, '--computer-name', $host;
            push @cmd, '--hostname',      $this_id;
        } else {
            my $service_id = $self->get_service_id($this_id);
            push @cmd, '--base',         $Wallet::Config::AD_USER_RDN;
            push @cmd, '--use-service-account';
            push @cmd, '--service',      $principal;
            push @cmd, '--account-name', $service_id;
            push @cmd, '--no-pac';
        }
        my $out = $self->msktutil(\@cmd);
        if ($out =~ /Error:\s+\S+\s+failed/xms
            || !$self->exists($principal))
        {
            $self->ad_delete($principal);
            my $m = "ERROR: problem creating keytab for $principal";
            $self->ad_debug('error', $m);
            $self->ad_debug('error',
                            'Problem command:' . ad_cmd_string(\@cmd));
            die "$m\n";
        }
    } else {
        die "ERROR: Invalid principal format ($principal)\n";
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

    my ($base, $filter) = $self->ldap_base_filter($principal);

    return $self->ldap_get_dn($base, $filter);
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
        return 1;
    } elsif (not $exists) {
        return 1;
    }

    return $self->ad_delete($principal);
}

# Delete an entry from AD using LDAP.

sub ad_delete {
    my ($self, $principal) = @_;

    my ($base, $filter) = $self->ldap_base_filter($principal);
    my $dn = $self->ldap_get_dn($base, $filter);

    $self->ldap_connect();
    my $msgid = $LDAP->delete($dn);
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

Bill MacAllister <whm@dropbox.com>
and Russ Allbery <eagle@eyrie.org>
and Jon Robertson <jonrober@stanford.edu>.

=cut
