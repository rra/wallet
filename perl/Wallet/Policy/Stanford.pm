# Wallet::Policy::Stanford -- Stanford's wallet naming and ownership policy.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Policy::Stanford;

use 5.008;
use strict;
use warnings;

use base qw(Exporter);

# Declare variables that should be set in BEGIN for robustness.
our (@EXPORT_OK, $VERSION);

# Set $VERSION and everything export-related in a BEGIN block for robustness
# against circular module loading (not that we load any modules, but
# consistency is good).
BEGIN {
    $VERSION   = '1.00';
    @EXPORT_OK = qw(default_owner verify_name);
}

##############################################################################
# Implementation
##############################################################################

# Retrieve an existing ACL and check whether it contains a netdb-root member.
# This is used to check if a default ACL is already present with a netdb-root
# member so that we can return a default owner that matches.  We only ever
# increase the ACL from netdb to netdb-root, never degrade it, so this doesn't
# pose a security problem.
#
# On any failure, just return an empty ACL to use the default.
sub acl_has_netdb_root {
    my ($name) = @_;
    my $schema = eval { Wallet::Schema->connect };
    return unless ($schema and not $@);
    my $acl = eval { Wallet::ACL->new ($name, $schema) };
    return unless ($acl and not $@);
    for my $line ($acl->list) {
        return 1 if $line->[0] eq 'netdb-root';
    }
    return;
}

# Map a file object name to a hostname and return it.  Returns undef if this
# file object name doesn't map to a hostname.
sub _host_for_file {
    my ($name) = @_;
    my %allowed = map { $_ => 1 }
        qw(htpasswd ssh-rsa ssh-dsa ssl-key tivoli-key);
    my $allowed_regex = '(?:' . join ('|', sort keys %allowed) . ')';
    if ($name !~ /^[^-]+-(.*)-$allowed_regex(?:-.*)?$/) {
        return;
    }
    my $host = $1;
    if ($host !~ /\./) {
        $host .= '.stanford.edu';
    }
    return $host;
}

# Map a keytab object name to a hostname and return it.  Returns undef if this
# keytab principal name doesn't map to a hostname.
sub _host_for_keytab {
    my ($name) = @_;
    my %allowed = map { $_ => 1 }
        qw(HTTP afpserver cifs ftp host imap ipp ldap lpr nfs pop postgres
           sieve smtp webauth xmpp);
    return unless $name =~ m,/,;
    my ($service, $host) = split ('/', $name, 2);
    return unless $allowed{$service};
    if ($host !~ /\./) {
        $host .= '.stanford.edu';
    }
    return $host;
}

# The default owner of host-based objects should be the host keytab and the
# NetDB ACL for that host, with one twist.  If the creator of a new node is
# using a root instance, we want to require everyone managing that node be
# using root instances by default.
sub default_owner {
    my ($type, $name) = @_;
    my $realm = 'stanford.edu';
    my %host_for = (
        keytab => \&_host_for_keytab,
        file   => \&_host_for_file,
    );
    return unless defined $host_for{$type};
    my $host = $host_for{$type}->($name);
    return unless $host;
    my $acl_name = "host/$host";
    my @acl;
    if ($ENV{REMOTE_USER} =~ m,/root, or acl_has_netdb_root ($acl_name)) {
        @acl = ([ 'netdb-root', $host ],
                [ 'krb5', "host/$host\@$realm" ]);
    } else {
        @acl = ([ 'netdb', $host ],
                [ 'krb5', "host/$host\@$realm" ]);
    }
    return ($acl_name, @acl);
}

# Enforce a naming policy.  Host-based keytabs must have fully-qualified
# hostnames, limit the acceptable characters for service/* keytabs, and
# enforce our naming constraints on */cgi principals.
#
# Also use this function to require that IDG staff always do implicit object
# creation using a */root instance.
sub verify_name {
    my ($type, $name, $user) = @_;
    my %host = map { $_ => 1 }
        qw(HTTP afpserver cifs ftp http host ident imap ipp ldap lpr nfs pop
           postgres sieve smtp uniengd webauth xmpp);
    my %staff;
    if (open (STAFF, '<', '/etc/remctl/acl/its-idg')) {
        local $_;
        while (<STAFF>) {
            s/^\s+//;
            s/\s+$//;
            next if m,/root\@,;
            $staff{$_} = 1;
        }
        close STAFF;
    }

    # Check for a staff member not using their root instance.
    if (defined ($user) && $staff{$user}) {
        return 'use a */root instance for wallet object creation';
    }

    # Check keytab naming conventions.
    if ($type eq 'keytab') {
        if ($name !~ m,^[a-zA-Z0-9_-]+/[a-z0-9.-]+$,) {
            return "invalid principal name $name";
        }
        my ($principal, $instance)
            = ($name =~ m,^([a-zA-Z0-9_-]+)/([a-z0-9.-]+)$,);
        unless (defined ($principal) && defined ($instance)) {
            return "invalid principal name $name";
        }
        if ($host{$principal} and $principal ne 'http') {
            if ($instance !~ /^[a-z0-9-]+\.[a-z0-9.-]+$/) {
                return "host name $instance is not fully qualified";
            }
        } elsif ($principal eq 'service') {
            if ($instance !~ /^[a-z0-9-]+$/) {
                return "invalid service principal name $name";
            }
        } elsif ($instance eq 'cgi') {
            if ($principal !~ /^[a-z][a-z0-9]{1,7}$/
                and $principal !~ /^(class|dept|group)-[a-z0-9_-]+$/) {
                return "invalid CGI principal name $name";
            }
        } else {
            return "unknown principal type $principal";
        }
    }

    # Check file object naming conventions.
    if ($type eq 'file') {
        my %groups = map { $_ => 1 }
            qw(apps crcsg gsb idg sysadmin sulair vast);
        my %types  = map { $_ => 1 }
            qw(config db gpg-key htpasswd password properties ssh-rsa ssh-dsa
               ssl-key ssl-keystore ssl-pkcs12 tivoli-key);
        if ($name !~ m,^[a-zA-Z0-9_.-]+$,) {
            return "invalid file object $name";
        }
        my $group_regex = '(?:' . join ('|', sort keys %groups) . ')';
        my $type_regex  = '(?:' . join ('|', sort keys %types)  . ')';
        if ($name !~ /^$group_regex-/) {
            return "no recognized owning group in $name";
        } elsif ($name !~ /^$group_regex-.*-$type_regex(-.*)?$/) {
            return "invalid file object name $name";
        }
    }

    # Success.
    return;
}

1;

##############################################################################
# Documentation
##############################################################################

=head1 NAME

Wallet::Policy::Stanford - Stanford's wallet naming and ownership policy

=head1 SYNOPSIS

    use Wallet::Policy::Stanford;
    my ($type, $name, $user) = @_;

    my $error = valid_name($type, $name, $user);
    my ($name, @acl) = default_owner($type, $name);

=head1 DESCRIPTION

Wallet::Policy::Stanford implements Stanford's wallet naming and ownership
policy as described in F<docs/stanford-naming> in the wallet distribution.
It is primarily intended as an example for other sites, but it is used at
Stanford to implement that policy.

This module provides the default_owner() and verify_name() functions that
are part of the wallet configuration interface (as documented in
L<Wallet::Config>).  They can be imported directly into a wallet
configuration file from this module or wrapped to apply additional rules.

=head1 SEE ALSO

Wallet::Config(3)

The L<Stanford policy|http://www.eyrie.org/~eagle/software/wallet/naming.html>
implemented by this module.

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <rra@stanford.edu>

=cut
