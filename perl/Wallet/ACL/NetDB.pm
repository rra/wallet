# Wallet::ACL::NetDB -- Wallet NetDB role ACL verifier.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::ACL::NetDB;
require 5.006;

use strict;
use vars qw(@ISA $VERSION);

use Wallet::ACL::Base;
use Wallet::Config;

@ISA = qw(Wallet::ACL::Base);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.03';

##############################################################################
# Interface
##############################################################################

# Creates a new persistant verifier.  Load the Net::Remctl module and open a
# persistant remctl connection that we'll use for later calls.
sub new {
    my $type = shift;
    my $host = $Wallet::Config::NETDB_REMCTL_HOST;
    unless ($host and $Wallet::Config::NETDB_REMCTL_CACHE) {
        die "NetDB ACL support not configured\n";
    }
    eval { require Net::Remctl };
    if ($@) {
        my $error = $@;
        chomp $error;
        1 while ($error =~ s/ at \S+ line \d+\.?\z//);
        die "NetDB ACL support not available: $error\n";
    }
    local $ENV{KRB5CCNAME} = $Wallet::Config::NETDB_REMCTL_CACHE;
    my $remctl = Net::Remctl->new;

    # Net::Remctl 2.12 and later will support passing in an empty string for
    # the principal.  Until then, be careful not to pass principal unless it
    # was specified.
    my $port = $Wallet::Config::NETDB_REMCTL_PORT || 0;
    my $principal = $Wallet::Config::NETDB_REMCTL_PRINCIPAL;
    my $status;
    if (defined $principal) {
        $status = $remctl->open ($host, $port, $principal);
    } else {
        $status = $remctl->open ($host, $port);
    }
    unless ($status) {
        die "cannot connect to NetDB remctl interface: ", $remctl->error, "\n";
    }
    my $self = { remctl => $remctl };
    bless ($self, $type);
    return $self;
}

# Check whether the given principal has one of the user, administrator, or
# admin team roles in NetDB for the given host.  Returns 1 if it does, 0 if it
# doesn't, and undef, setting the error, if there's some failure in making the
# remctl call.
sub check {
    my ($self, $principal, $acl) = @_;
    unless ($principal) {
        $self->error ('no principal specified');
        return;
    }
    unless ($acl) {
        $self->error ('malformed netdb ACL');
        return;
    }
    my $remctl = $self->{remctl};
    if ($Wallet::Config::NETDB_REALM) {
        $principal =~ s/\@\Q$Wallet::Config::NETDB_REALM\E\z//;
    }
    unless ($remctl->command ('netdb', 'node-roles', $principal, $acl)) {
        $self->error ('cannot check NetDB ACL: ' . $remctl->error);
        return;
    }
    my ($roles, $output, $status, $error);
    do {
        $output = $remctl->output;
        if ($output->type eq 'output') {
            if ($output->stream == 1) {
                $roles .= $output->data;
            } else {
                $error .= $output->data;
            }
        } elsif ($output->type eq 'error') {
            $self->error ('cannot check NetDB ACL: ' . $output->data);
            return;
        } elsif ($output->type eq 'status') {
            $status = $output->status;
        } else {
            $self->error ('malformed NetDB remctl token: ' . $output->type);
            return;
        }
    } while ($output->type eq 'output');
    if ($status == 0) {
        $roles ||= '';
        my @roles = split (' ', $roles);
        for my $role (@roles) {
            return 1 if $role eq 'admin';
            return 1 if $role eq 'team';
            return 1 if $role eq 'user';
        }
        return 0;
    } else {
        if ($error) {
            chomp $error;
            $error =~ s/\n/ /g;
            $self->error ("error checking NetDB ACL: $error");
        } else {
            $self->error ("error checking NetDB ACL");
        }
        return;
    }
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=head1 NAME

Wallet::ACL::NetDB - Wallet ACL verifier for NetDB roles

=head1 SYNOPSIS

    my $verifier = Wallet::ACL::NetDB->new;
    my $status = $verifier->check ($principal, $node);
    if (not defined $status) {
        die "Something failed: ", $verifier->error, "\n";
    } elsif ($status) {
        print "Access granted\n";
    } else {
        print "Access denied\n";
    }

=head1 DESCRIPTION

Wallet::ACL::NetDB checks a principal against the NetDB roles for a given
host.  It is used to verify ACL lines of type netdb.  The value of such an
ACL is a node, and the ACL grants access to a given principal if and only
if that principal has one of the roles user, admin, or team for that node.

To use this object, several configuration parameters must be set.  See
Wallet::Config(3) for details on those configuration parameters and
information about how to set wallet configuration.

=head1 METHODS

=over 4

=item new()

Creates a new ACL verifier.  Opens the remctl connection to the NetDB
server and authenticates.

=item check(PRINCIPAL, ACL)

Returns true if PRINCIPAL is granted access according to ACL, false if
not, and undef on an error (see L<"DIAGNOSTICS"> below).  ACL is a node,
and PRINCIPAL will be granted access if it (with the realm stripped off if
configured) has the user, admin, or team role for that node.

=item error()

Returns the error if check() returned undef.

=back

=head1 DIAGNOSTICS

The new() method may fail with one of the following exceptions:

=over 4

=item NetDB ACL support not available: %s

The Net::Remctl Perl module, required for NetDB ACL support, could not be
loaded.

=item NetDB ACL support not configured

The required configuration parameters were not set.  See Wallet::Config(3)
for the required configuration parameters and how to set them.

=item cannot connect to NetDB remctl interface: %s

Connecting to the NetDB remctl interface failed with the given error
message.

=back

Verifying a NetDB ACL may fail with the following errors (returned by the
error() method):

=over 4

=item cannot check NetDB ACL: %s

Issuing the remctl command to get the roles for the given principal failed
or returned an error.

=item error checking NetDB ACL: %s

The NetDB remctl interface that returns the roles for a user returned an
error message or otherwise returned failure.

=item malformed netdb ACL

The ACL parameter to check() was malformed.  Currently, this error is only
given if ACL is undefined or the empty string.

=item malformed NetDBL remctl token: %s

The Net::Remctl Perl library returned a malformed token.  This should
never happen and indicates a bug in Net::Remctl.

=item no principal specified

The PRINCIPAL parameter to check() was undefined or the empty string.

=back

=head1 CAVEATS

The list of possible NetDB roles that should be considered sufficient to
grant access is not currently configurable.

=head1 SEE ALSO

Net::Remctl(3), Wallet::ACL(3), Wallet::ACL::Base(3), Wallet::Config(3),
wallet-backend(8)

NetDB is a free software system for managing DNS, DHCP, and related machine
information for large organizations.  For more information on NetDB, see
L<http://www.stanford.edu/group/networking/netdb/>.

This module is part of the wallet system.  The current version is available
from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <rra@stanford.edu>

=cut
