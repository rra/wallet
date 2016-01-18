# Wallet::Policy::Stanford -- Stanford's wallet naming and ownership policy
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2016 Russ Allbery <eagle@eyrie.org>
# Copyright 2013, 2014, 2015
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
    $VERSION   = '1.03';
    @EXPORT_OK = qw(default_owner verify_name is_for_host);
}

##############################################################################
# Configuration
##############################################################################

# These variables are all declared as globals so that they can be overridden
# from wallet.conf if desirable.

# The domain to append to hostnames to fully-qualify them.
our $DOMAIN = 'stanford.edu';

# Groups for file object naming, each mapped to the ACL to use for
# non-host-based objects owned by that group.  This default is entirely
# Stanford-specific, even more so than the rest of this file.
our %ACL_FOR_GROUP = (
    'its-apps'    => 'group/its-app-support',
    'its-crc-sg'  => 'group/crcsg',
    'its-idg'     => 'group/its-idg',
    'its-rc'      => 'group/its-rc',
    'its-sa-core' => 'group/its-sa-core',
);

# Legacy group names for older file objects.
our @GROUPS_LEGACY = qw(apps crcsg gsb idg sysadmin sulair vast);

# File object types.  Each type can have one or more parameters: whether it is
# host-based (host), whether it takes a qualifier after the host or service
# (extra), and whether that qualifier is mandatory (need_extra).
our %FILE_TYPE = (
    config            => {            extra => 1, need_extra => 1 },
    db                => {            extra => 1, need_extra => 1 },
    'gpg-key'         => { },
    htpasswd          => { host => 1, extra => 1, need_extra => 1 },
    password          => {            extra => 1, need_extra => 1 },
    'password-ipmi'   => { host => 1 },
    'password-root'   => { host => 1 },
    'password-tivoli' => { host => 1 },
    properties        => {            extra => 1 },
    'ssh-dsa'         => { host => 1, extra => 1 },
    'ssh-rsa'         => { host => 1, extra => 1 },
    'ssl-chain'       => { host => 1, extra => 1 },
    'ssl-key'         => { host => 1, extra => 1 },
    'ssl-keypair'     => { host => 1, extra => 1 },
    'ssl-keystore'    => {            extra => 1 },
    'ssl-pkcs12'      => {            extra => 1 },
    'tivoli-key'      => { host => 1 },
);

# Password object types.  Most of these mimic file object types (which should
# be gradually phased out).
our %PASSWORD_TYPE = (
    'ipmi'            => { host => 1 },
    'root'            => { host => 1 },
    'tivoli'          => { host => 1 },
    'system'          => { host => 1, extra => 1, need_extra => 1 },
    'app'             => { host => 1, extra => 1, need_extra => 1 },
    'service'         => {            extra => 1, need_extra => 1 },
);

# Mappings that let us determine the host for a host-based object, if any.
our %HOST_FOR = (
    'keytab'     => \&_host_for_keytab,
    'file'       => \&_host_for_file,
    'password'   => \&_host_for_password,
    'duo'        => \&_host_for_duo,
    'duo-pam'    => \&_host_for_duo,
    'duo-radius' => \&_host_for_duo,
    'duo-ldap'   => \&_host_for_duo,
    'duo-rdp'    => \&_host_for_duo,
);

# Host-based file object types for the legacy file object naming scheme.
our @FILE_HOST_LEGACY = qw(htpasswd ssh-rsa ssh-dsa ssl-key tivoli-key);

# File object types for the legacy file object naming scheme.
our @FILE_TYPES_LEGACY = qw(config db gpg-key htpasswd password properties
  ssh-rsa ssh-dsa ssl-key ssl-keystore ssl-pkcs12 tivoli-key);

# Host-based Kerberos principal prefixes.
our @KEYTAB_HOST = qw(HTTP afpserver cifs ftp host imap ipp ldap lpr nfs pop
  postgres sieve smtp webauth xmpp);

# The Kerberos realm, used when forming principals for krb5 ACLs.
our $REALM = 'stanford.edu';

# A file listing principal names that should be required to use a root
# instance to autocreate any objects.
our $ROOT_REQUIRED = '/etc/remctl/acl/its-idg';

##############################################################################
# Implementation
##############################################################################

# Retrieve an existing ACL and return its members as a list.
#
# $name - Name of the ACL to retrieve
#
# Returns: Members of the ACL as a list of pairs
#          The empty list on any failure to retrieve the ACL
sub _acl_members {
    my ($name) = @_;
    my $schema = eval { Wallet::Schema->connect };
    return if (!$schema || $@);
    my $acl = eval { Wallet::ACL->new ($name, $schema) };
    return if (!$acl || $@);
    return $acl->list;
}

# Retrieve an existing ACL and check whether it contains a netdb-root member.
# This is used to check if a default ACL is already present with a netdb-root
# member so that we can return a default owner that matches.  We only ever
# increase the ACL from netdb to netdb-root, never degrade it, so this doesn't
# pose a security problem.
#
# On any failure, just return an empty ACL to use the default.
sub _acl_has_netdb_root {
    my ($name) = @_;
    for my $line (_acl_members($name)) {
        return 1 if $line->[0] eq 'netdb-root';
    }
    return;
}

# Map a file object name to a hostname for the legacy file object naming
# scheme and return it.  Returns undef if this file object name doesn't map to
# a hostname.
sub _host_for_file_legacy {
    my ($name) = @_;
    my %allowed = map { $_ => 1 } @FILE_HOST_LEGACY;
    my $allowed_regex = '(?:' . join ('|', sort keys %allowed) . ')';
    if ($name !~ /^[^-]+-(.*)-$allowed_regex(?:-.*)?$/) {
        return;
    }
    my $host = $1;
    if ($host !~ /\./) {
        $host .= q{.} . $DOMAIN;
    }
    return $host;
}

# Map a password object name to a hostname.  Returns undef if this password
# object name doesn't map to a hostname.
sub _host_for_password {
    my ($name) = @_;

    # Parse the name and check whether this is a host-based object.
    my ($type, $host) = split('/', $name);
    return if !$PASSWORD_TYPE{$type}{host};
    return $host;
}

# Map a file object name to a hostname.  Returns undef if this file object
# name doesn't map to a hostname.
sub _host_for_file {
    my ($name) = @_;

    # If $name doesn't contain /, defer to the legacy naming scheme.
    if ($name !~ m{ / }xms) {
        return _host_for_file_legacy($name);
    }

    # Parse the name and check whether this is a host-based object.
    my ($type, $host) = split('/', $name);
    return if !$FILE_TYPE{$type}{host};
    return $host;
}

# Map a keytab object name to a hostname and return it.  Returns undef if this
# keytab principal name doesn't map to a hostname.
sub _host_for_keytab {
    my ($name) = @_;
    my %allowed = map { $_ => 1 } @KEYTAB_HOST;
    return unless $name =~ m,/,;
    my ($service, $host) = split ('/', $name, 2);
    return unless $allowed{$service};
    if ($host !~ /\./) {
        $host .= q{.} . $DOMAIN;
    }
    return $host;
}

# Map a duo-type object name to a hostname.  Currently all Duo objects are
# named just for the hostname, so this is easy.
sub _host_for_duo {
    my ($name) = @_;
    return $name;
}

# Take a object type and name, along with a host name, and use these to
# decide if the given object is host-based and matches the given host.
sub is_for_host {
    my ($type, $name, $host) = @_;

    # If we have a possible host mapping, get the host and see if it matches.
    if (defined($HOST_FOR{$type})) {
        my $object_host = $HOST_FOR{$type}->($name);
        return 0 unless $object_host;
        if ($host eq $object_host) {
            return 1;
        }
    }

    return 0;
}

# The default owner of host-based objects should be the host keytab and the
# NetDB ACL for that host, with one twist.  If the creator of a new node is
# using a root instance, we want to require everyone managing that node be
# using root instances by default.
sub default_owner {
    my ($type, $name) = @_;

    # If we have a possible host mapping, see if we can use that.
    if (defined($HOST_FOR{$type})) {
        my $host = $HOST_FOR{$type}->($name);
        if ($host) {
            my $acl_name = "host/$host";
            my @acl;
            if ($ENV{REMOTE_USER} =~ m,/root,
                || _acl_has_netdb_root ($acl_name)) {
                @acl = ([ 'netdb-root', $host ],
                        [ 'krb5', "host/$host\@$REALM" ]);
            } else {
                @acl = ([ 'netdb', $host ],
                        [ 'krb5', "host/$host\@$REALM" ]);
            }
            return ($acl_name, @acl);
        }
    }

    # We have no open if this is not a file object.
    return if $type ne 'file';

    # Parse the name of the file object only far enough to get type and group
    # (if there is a group).
    my ($file_type, $group) = split('/', $name);

    # Host-based file objects should be caught by the above.  We certainly
    # can't do anything about them here.
    return if $FILE_TYPE{$file_type}{host};

    # If we have a mapping for this group, retrieve the ACL contents.  We
    # would like to just return the ACL name, but wallet currently requires we
    # return the whole ACL.
    my $acl = $ACL_FOR_GROUP{$group};
    return if !defined($acl);
    my @members = _acl_members($acl);
    return if @members == 0;
    return ($acl, @members);
}

# Enforce a naming policy.  Host-based keytabs must have fully-qualified
# hostnames, limit the acceptable characters for service/* keytabs, and
# enforce our naming constraints on */cgi principals.
#
# Also use this function to require that ACS staff always do implicit object
# creation using a */root instance.
sub verify_name {
    my ($type, $name, $user) = @_;
    my %staff;
    if (open (STAFF, '<', $ROOT_REQUIRED)) {
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
        my %host = map { $_ => 1 } @KEYTAB_HOST;
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
        } elsif ($principal eq 'afs') {
            if ($instance !~ /^[a-z0-9-]+\.[a-z0-9.-]+$/) {
                return "AFS cell name $instance is not fully qualified";
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
        } elsif ($instance eq 'cron') {
            if ($principal !~ /^[a-z][a-z0-9]{1,7}$/
                and $principal !~ /^(class|dept|group)-[a-z0-9_-]+$/) {
                return "invalid cron principal name $name";
            }
        } else {
            return "unknown principal type $principal";
        }
    }

    # Check file object naming conventions.
    if ($type eq 'file') {
        if ($name =~ m{ / }xms) {
            my @name = split('/', $name);

            # Names have between two and four components and all must be
            # non-empty.
            if (@name > 4) {
                return "too many components in $name";
            }
            if (@name < 2) {
                return "too few components in $name";
            }
            if (grep { $_ eq q{} } @name) {
                return "empty component in $name";
            }

            # All objects start with the type.  First check if this is a
            # host-based type.
            my $type = shift @name;
            if ($FILE_TYPE{$type} && $FILE_TYPE{$type}{host}) {
                my ($host, $extra) = @name;
                if ($host !~ m{ [.] }xms) {
                    return "host name $host is not fully qualified";
                }
                if (defined($extra) && !$FILE_TYPE{$type}{extra}) {
                    return "extraneous component at end of $name";
                }
                if (!defined($extra) && $FILE_TYPE{$type}{need_extra}) {
                    return "missing component in $name";
                }
                return;
            }

            # Otherwise, the name is group-based.  There be at least two
            # remaining components.
            if (@name < 2) {
                return "too few components in $name";
            }
            my ($group, $service, $extra) = @name;

            # Check the group.
            if (!$ACL_FOR_GROUP{$group}) {
                return "unknown group $group";
            }

            # Check the type.  Be sure it's not host-based.
            if (!$FILE_TYPE{$type}) {
                return "unknown type $type";
            }
            if ($FILE_TYPE{$type}{host}) {
                return "bad name for host-based file type $type";
            }

            # Check the extra data.
            if (defined($extra) && !$FILE_TYPE{$type}{extra}) {
                return "extraneous component at end of $name";
            }
            if (!defined($extra) && $FILE_TYPE{$type}{need_extra}) {
                return "missing component in $name";
            }
            return;


        } else {
            # Legacy naming scheme.
            my %groups = map { $_ => 1 } @GROUPS_LEGACY;
            my %types  = map { $_ => 1 } @FILE_TYPES_LEGACY;
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
    }

    # Check password object naming conventions.
    if ($type eq 'password') {
        if ($name =~ m{ / }xms) {
            my @name = split('/', $name);

            # Names have between two and four components and all must be
            # non-empty.
            if (@name > 4) {
                return "too many components in $name";
            }
            if (@name < 2) {
                return "too few components in $name";
            }
            if (grep { $_ eq q{} } @name) {
                return "empty component in $name";
            }

            # All objects start with the type.  First check if this is a
            # host-based type.
            my $type = shift @name;
            if ($PASSWORD_TYPE{$type} && $PASSWORD_TYPE{$type}{host}) {
                my ($host, $extra) = @name;
                if ($host !~ m{ [.] }xms) {
                    return "host name $host is not fully qualified";
                }
                if (defined($extra) && !$PASSWORD_TYPE{$type}{extra}) {
                    return "extraneous component at end of $name";
                }
                if (!defined($extra) && $PASSWORD_TYPE{$type}{need_extra}) {
                    return "missing component in $name";
                }
                return;
            }

            # Otherwise, the name is group-based.  There be at least two
            # remaining components.
            if (@name < 2) {
                return "too few components in $name";
            }
            my ($group, $service, $extra) = @name;

            # Check the group.
            if (!$ACL_FOR_GROUP{$group}) {
                return "unknown group $group";
            }

            # Check the type.  Be sure it's not host-based.
            if (!$PASSWORD_TYPE{$type}) {
                return "unknown type $type";
            }
            if ($PASSWORD_TYPE{$type}{host}) {
                return "bad name for host-based file type $type";
            }

            # Check the extra data.
            if (defined($extra) && !$PASSWORD_TYPE{$type}{extra}) {
                return "extraneous component at end of $name";
            }
            if (!defined($extra) && $PASSWORD_TYPE{$type}{need_extra}) {
                return "missing component in $name";
            }
            return;
        }
    }

    # Check the naming conventions for all Duo object types.  The object
    # should simply be the host name for now.
    if ($type =~ m{^duo(-\w+)?$}) {
        if ($name !~ m{ [.] }xms) {
            return "host name $name is not fully qualified";
        }
    }

    # Success.
    return;
}

1;

##############################################################################
# Documentation
##############################################################################

=for stopwords
Allbery

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

Russ Allbery <eagle@eyrie.org>

=cut
