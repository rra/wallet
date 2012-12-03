# Wallet::Config -- Configuration handling for the wallet server.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007, 2008, 2010 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

package Wallet::Config;
require 5.006;

use strict;
use vars qw($PATH $VERSION);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.05';

# Path to the config file to load.
$PATH = $ENV{WALLET_CONFIG} || '/etc/wallet/wallet.conf';

=head1 NAME

Wallet::Config - Configuration handling for the wallet server

=for stopwords
DBI DSN SQLite subdirectories KEYTAB keytab kadmind KDC add-ons kadmin DNS
SRV kadmin keytabs remctl backend lowercased NETDB ACL NetDB unscoped
usernames rekey hostnames Allbery wallet-backend keytab-backend Heimdal
rekeys WebAuth WEBAUTH keyring LDAP DN GSS-API

=head1 SYNOPSIS

    use Wallet::Config;
    my $driver = $Wallet::Config::DB_DRIVER;
    my $info;
    if (defined $Wallet::Config::DB_INFO) {
        $info = $Wallet::Config::DB_INFO;
    } else {
        $info = "database=$Wallet::Config::DB_NAME";
        $info .= ";host=$Wallet::Config::DB_HOST"
            if $Wallet::Config::DB_HOST;
        $info .= ";port=$Wallet::Config::DB_PORT"
            if $Wallet::Config::DB_PORT;
    }
    my $dsn = "dbi:$driver:$info";
    my $user = $Wallet::Config::DB_USER;
    my $password = $Wallet::Config::DB_PASSWORD;
    my $dbh = DBI->connect ($dsn, $user, $password);

=head1 DESCRIPTION

Wallet::Config encapsulates all of the site-specific configuration for the
wallet server.  It is implemented as a Perl class that declares and sets
the defaults for various configuration variables and then, if it exists,
loads the file specified by the WALLET_CONFIG environment variable or
F</etc/wallet/wallet.conf> if that environment variable isn't set.  That
file should contain any site-specific overrides to the defaults, and at
least some parameters must be set.

This file must be valid Perl.  To set a variable, use the syntax:

    $VARIABLE = <value>;

where VARIABLE is the variable name (always in all-capital letters) and
<value> is the value.  If setting a variable to a string and not a number,
you should normally enclose <value> in C<''>.  For example, to set the
variable DB_DRIVER to C<MySQL>, use:

    $DB_DRIVER = 'MySQL';

Always remember the initial dollar sign (C<$>) and ending semicolon
(C<;>).  Those familiar with Perl syntax can of course use the full range
of Perl expressions.

This configuration file should end with the line:

    1;

This ensures that Perl doesn't think there is an error when loading the
file.

=head1 DATABASE CONFIGURATION

=over 4

=item DB_DRIVER

Sets the Perl database driver to use for the wallet database.  Common
values would be C<SQLite> or C<MySQL>.  Less common values would be
C<Oracle>, C<Sybase>, or C<ODBC>.  The appropriate DBD::* Perl module for
the chosen driver must be installed and will be dynamically loaded by the
wallet.  For more information, see L<DBI>.

This variable must be set.

=cut

our $DB_DRIVER;

=item DB_INFO

Sets the remaining contents for the DBI DSN (everything after the driver).
Using this variable provides full control over the connect string passed
to DBI.  When using SQLite, set this variable to the path to the SQLite
database.  If this variable is set, DB_NAME, DB_HOST, and DB_PORT are
ignored.  For more information, see L<DBI> and the documentation for the
database driver you're using.

Either DB_INFO or DB_NAME must be set.  If you don't need to pass any
additional information to DBI, set DB_INFO to the empty string (C<''>).

=cut

our $DB_INFO;

=item DB_NAME

If DB_INFO is not set, specifies the database name.  The third part of the
DBI connect string will be set to C<database=DB_NAME>, possibly with a
host and port appended if DB_HOST and DB_PORT are set.  For more
information, see L<DBI> and the documentation for the database driver
you're using.

Either DB_INFO or DB_NAME must be set.

=cut

our $DB_NAME;

=item DB_HOST

If DB_INFO is not set, specifies the database host.  C<;host=DB_HOST> will
be appended to the DBI connect string.  For more information, see L<DBI>
and the documentation for the database driver you're using.

=cut

our $DB_HOST;

=item DB_PORT

If DB_PORT is not set, specifies the database port.  C<;port=DB_PORT> will
be appended to the DBI connect string.  If this variable is set, DB_HOST
should also be set.  For more information, see L<DBI> and the
documentation for the database driver you're using.

=cut

our $DB_PORT;

=item DB_USER

Specifies the user for database authentication.  Some database backends,
particularly SQLite, do not need this.

=cut

our $DB_USER;

=item DB_PASSWORD

Specifies the password for database authentication.  Some database
backends, particularly SQLite, do not need this.

=cut

our $DB_PASSWORD;

=item DB_DDL_DIRECTORY

Specifies the directory used to dump the database schema in formats for
each possible database server.  This also includes diffs between schema
versions, for upgrades.

=cut

our $DB_DDL_DIRECTORY;

=back

=head1 FILE OBJECT CONFIGURATION

These configuration variables only need to be set if you intend to use the
C<file> object type (the Wallet::Object::File class).

=over 4

=item FILE_BUCKET

The directory into which to store file objects.  File objects will be
stored in subdirectories of this directory.  See L<Wallet::Object::File>
for the full details of the naming scheme.  This directory must be
writable by the wallet server and the wallet server must be able to create
subdirectories of it.

FILE_BUCKET must be set to use file objects.

=cut

our $FILE_BUCKET;

=item FILE_MAX_SIZE

The maximum size of data that can be stored in a file object in bytes.  If
this configuration variable is set, an attempt to store data larger than
this limit will be rejected.

=cut

our $FILE_MAX_SIZE;

=back

=head1 KEYTAB OBJECT CONFIGURATION

These configuration variables only need to be set if you intend to use the
C<keytab> object type (the Wallet::Object::Keytab class).

=over 4

=item KEYTAB_FILE

Specifies the keytab to use to authenticate to B<kadmind>.  The principal
whose key is stored in this keytab must have the ability to create,
modify, inspect, and delete any principals that should be managed by the
wallet.  (In MIT Kerberos F<kadm5.acl> parlance, this is C<admci>
privileges.)

KEYTAB_FILE must be set to use keytab objects.

=cut

our $KEYTAB_FILE;

=item KEYTAB_FLAGS

These flags, if any, are passed to the C<addprinc> command when creating a
new principal in the Kerberos KDC.  To not pass any flags, set
KEYTAB_FLAGS to the empty string.  The default value is C<-clearpolicy>,
which clears any password strength policy from principals created by the
wallet.  (Since the wallet randomizes the keys, password strength checking
is generally pointless and may interact poorly with the way C<addprinc
-randkey> works when third-party add-ons for password strength checking
are used.)

=cut

our $KEYTAB_FLAGS = '-clearpolicy';

=item KEYTAB_HOST

Specifies the host on which the kadmin service is running.  This setting
overrides the C<admin_server> setting in the [realms] section of
F<krb5.conf> and any DNS SRV records and allows the wallet to run on a
system that doesn't have a Kerberos configuration for the wallet's realm.

=cut

our $KEYTAB_HOST;

=item KEYTAB_KADMIN

The path to the B<kadmin> command-line client.  The default value is
C<kadmin>, which will cause the wallet to search for B<kadmin> on its
default PATH.

=cut

our $KEYTAB_KADMIN = 'kadmin';

=item KEYTAB_KRBTYPE

The Kerberos KDC implementation type, either C<Heimdal> or C<MIT>
(case-insensitive).  KEYTAB_KRBTYPE must be set to use keytab objects.

=cut

our $KEYTAB_KRBTYPE;

=item KEYTAB_PRINCIPAL

The principal whose key is stored in KEYTAB_FILE.  The wallet will
authenticate as this principal to the kadmin service.

KEYTAB_PRINCIPAL must be set to use keytab objects, at least until
B<kadmin> is smart enough to use the first principal found in the keytab
it's using for authentication.

=cut

our $KEYTAB_PRINCIPAL;

=item KEYTAB_REALM

Specifies the realm in which to create Kerberos principals.  The keytab
object implementation can only work in a single realm for a given wallet
installation and the keytab object names are stored without realm.
KEYTAB_REALM is added when talking to the KDC via B<kadmin>.

KEYTAB_REALM must be set to use keytab objects.  C<ktadd> doesn't always
default to the local realm.

=cut

our $KEYTAB_REALM;

=item KEYTAB_TMP

A directory into which the wallet can write keytabs temporarily while
processing C<get> commands from clients.  The keytabs are written into
this directory with predictable names, so this should not be a system
temporary directory such as F</tmp> or F</var/tmp>.  It's best to create a
directory solely for this purpose that's owned by the user the wallet
server will run as.

KEYTAB_TMP must be set to use keytab objects.

=cut

our $KEYTAB_TMP;

=back

=head2 Retrieving Existing Keytabs

Heimdal provides the choice, over the network protocol, of either
downloading the existing keys for a principal or generating new random
keys.  MIT Kerberos does not; downloading a keytab over the kadmin
protocol always rekeys the principal.

For MIT Kerberos, the keytab object backend therefore optionally supports
retrieving existing keys, and hence keytabs, for Kerberos principals by
contacting the KDC via remctl and talking to B<keytab-backend>.  This is
enabled by setting the C<unchanging> flag on keytab objects.  To configure
that support, set the following variables.

This is not required for Heimdal; for Heimdal, setting the C<unchanging>
flag is all that's needed.

=over 4

=item KEYTAB_REMCTL_CACHE

Specifies the ticket cache to use when retrieving existing keytabs from
the KDC.  This is only used to implement support for the C<unchanging>
flag.  The ticket cache must be for a principal with access to run
C<keytab retrieve> via remctl on KEYTAB_REMCTL_HOST.

=cut

our $KEYTAB_REMCTL_CACHE;

=item KEYTAB_REMCTL_HOST

The host to which to connect with remctl to retrieve existing keytabs.
This is only used to implement support for the C<unchanging> flag.  This
host must provide the C<keytab retrieve> command and KEYTAB_REMCTL_CACHE
must also be set to a ticket cache for a principal with access to run that
command.

=cut

our $KEYTAB_REMCTL_HOST;

=item KEYTAB_REMCTL_PRINCIPAL

The service principal to which to authenticate when retrieving existing
keytabs.  This is only used to implement support for the C<unchanging>
flag.  If this variable is not set, the default is formed by prepending
C<host/> to KEYTAB_REMCTL_HOST.  (Note that KEYTAB_REMCTL_HOST is not
lowercased first.)

=cut

our $KEYTAB_REMCTL_PRINCIPAL;

=item KEYTAB_REMCTL_PORT

The port on KEYTAB_REMCTL_HOST to which to connect with remctl to retrieve
existing keytabs.  This is only used to implement support for the
C<unchanging> flag.  If this variable is not set, the default remctl port
will be used.

=cut

our $KEYTAB_REMCTL_PORT;

=back

=head1 WEBAUTH KEYRING OBJECT CONFIGURATION

These configuration variables only need to be set if you intend to use the
C<wakeyring> object type (the Wallet::Object::WAKeyring class).

=over 4

=item WAKEYRING_BUCKET

The directory into which to store WebAuth keyring objects.  WebAuth
keyring objects will be stored in subdirectories of this directory.  See
L<Wallet::Object::WAKeyring> for the full details of the naming scheme.
This directory must be writable by the wallet server and the wallet server
must be able to create subdirectories of it.

WAKEYRING_BUCKET must be set to use WebAuth keyring objects.

=cut

our $WAKEYRING_BUCKET;

=item WAKEYRING_REKEY_INTERVAL

The interval, in seconds, at which new keys are generated in a keyring.
The object implementation will try to arrange for there to be keys added
to the keyring separated by this interval.

It's useful to provide some interval to install the keyring everywhere
that it's used before the key becomes inactive.  Every keyring will
therefore normally have at least three keys: one that's currently active,
one that becomes valid in the future but less than
WAKEYRING_REKEY_INTERVAL from now, and one that becomes valid between one
and two of those intervals into the future.  This means that one has twice
this interval to distribute the keyring everywhere it is used.

Internally, this is implemented by adding a new key that becomes valid in
twice this interval from the current time if the newest key becomes valid
at or less than this interval in the future.

The default value is 60 * 60 * 24 (one day).

=cut

our $WAKEYRING_REKEY_INTERVAL = 60 * 60 * 24;

=item WAKEYRING_PURGE_INTERVAL

The interval, in seconds, from the key creation date after which keys are
removed from the keyring.  This is used to clean up old keys and finish
key rotation.  Keys won't be removed unless there are more than three keys
in the keyring to try to keep a misconfiguration from removing all valid
keys.

The default value is 60 * 60 * 24 * 90 (90 days).

=cut

our $WAKEYRING_PURGE_INTERVAL = 60 * 60 * 24 * 90;

=back

=head1 LDAP ACL CONFIGURATION

These configuration variables are only needed if you intend to use the
C<ldap-attr> ACL type (the Wallet::ACL::LDAP::Attribute class).  They
specify the LDAP server and additional connection and data model
information required for the wallet to check for the existence of
attributes.

=over 4

=item LDAP_HOST

The LDAP server name to use to verify LDAP ACLs.  This variable must be
set to use LDAP ACLs.

=cut

our $LDAP_HOST;

=item LDAP_BASE

The base DN under which to search for the entry corresponding to a
principal.  Currently, the wallet always does a full subtree search under
this base DN.  This variable must be set to use LDAP ACLs.

=cut

our $LDAP_BASE;

=item LDAP_FILTER_ATTR

The attribute used to find the entry corresponding to a principal.  The
LDAP entry containing this attribute with a value equal to the principal
will be found and checked for the required attribute and value.  If this
variable is not set, the default is C<krb5PrincipalName>.

=cut

our $LDAP_FILTER_ATTR;

=item LDAP_CACHE

Specifies the Kerberos ticket cache to use when connecting to the LDAP
server.  GSS-API authentication is always used; there is currently no
support for any other type of bind.  The ticket cache must be for a
principal with access to verify the values of attributes that will be used
with this ACL type.  This variable must be set to use LDAP ACLs.

=cut

our $LDAP_CACHE;

=back

Finally, depending on the structure of the LDAP directory being queried,
there may not be any attribute in the directory whose value exactly
matches the Kerberos principal.  The attribute designated by
LDAP_FILTER_ATTR may instead hold a transformation of the principal name
(such as the principal with the local realm stripped off, or rewritten
into an LDAP DN form).  If this is the case, define a Perl function named
ldap_map_attribute.  This function will be called whenever an LDAP
attribute ACL is being verified.  It will take one argument, the
principal, and is expected to return the value to search for in the LDAP
directory server.

For example, if the principal name without the local realm is stored in
the C<uid> attribute in the directory, set LDAP_FILTER_ATTR to C<uid> and
then define ldap_map_attribute as follows:

    sub ldap_map_attribute {
        my ($principal) = @_;
        $principal =~ s/\@EXAMPLE\.COM$//;
        return $principal;
    }

Note that this example only removes the local realm (here, EXAMPLE.COM).
Any principal from some other realm will be left fully qualified, and then
presumably will not be found in the directory.

=head1 NETDB ACL CONFIGURATION

These configuration variables are only needed if you intend to use the
C<netdb> ACL type (the Wallet::ACL::NetDB class).  They specify the remctl
connection information for retrieving user roles from NetDB and the local
realm to remove from principals (since NetDB normally expects unscoped
local usernames).

=over 4

=item NETDB_REALM

The wallet uses fully-qualified principal names (including the realm), but
NetDB normally expects local usernames without the realm.  If this
variable is set, the given realm will be stripped from any principal names
before passing them to NetDB.  Principals in other realms will be passed
to NetDB without modification.

=cut

our $NETDB_REALM;

=item NETDB_REMCTL_CACHE

Specifies the ticket cache to use when querying the NetDB remctl interface
for user roles.  The ticket cache must be for a principal with access to
run C<netdb node-roles> via remctl on KEYTAB_REMCTL_HOST.  This variable
must be set to use NetDB ACLs.

=cut

our $NETDB_REMCTL_CACHE;

=item NETDB_REMCTL_HOST

The host to which to connect with remctl to query NetDB for user roles.
This host must provide the C<netdb node-roles> command and
NETDB_REMCTL_CACHE must also be set to a ticket cache for a principal with
access to run that command.  This variable must be set to use NetDB ACLs.

=cut

our $NETDB_REMCTL_HOST;

=item NETDB_REMCTL_PRINCIPAL

The service principal to which to authenticate when querying NetDB for
user roles.  If this variable is not set, the default is formed by
prepending C<host/> to NETDB_REMCTL_HOST.  (Note that NETDB_REMCTL_HOST is
not lowercased first.)

=cut

our $NETDB_REMCTL_PRINCIPAL;

=item NETDB_REMCTL_PORT

The port on NETDB_REMCTL_HOST to which to connect with remctl to query
NetDB for user roles.  If this variable is not set, the default remctl
port will be used.

=cut

our $NETDB_REMCTL_PORT;

=back

=head1 DEFAULT OWNERS

By default, only users in the ADMIN ACL can create new objects in the
wallet.  To allow other users to create new objects, define a Perl
function named default_owner.  This function will be called whenever a
non-ADMIN user tries to create a new object and will be passed the type
and name of the object.  It should return undef if there is no default
owner for that object.  If there is, it should return a list containing
the name to use for the ACL and then zero or more anonymous arrays of two
elements each giving the type and identifier for each ACL entry.

For example, the following simple function says to use a default owner
named C<default> with one entry of type C<krb5> and identifier
C<rra@example.com> for the object with type C<keytab> and name
C<host/example.com>:

    sub default_owner {
        my ($type, $name) = @_;
        if ($type eq 'keytab' and $name eq 'host/example.com') {
            return ('default', [ 'krb5', 'rra@example.com' ]);
        } else {
            return;
        }
    }

Of course, normally this function is used for more complex mappings.  Here
is a more complete example.  For objects of type keytab corresponding to
various types of per-machine principals, return a default owner that sets
as owner anyone with a NetDB role for that system and the system's host
principal.  This permits authorization management using NetDB while also
allowing the system to bootstrap itself once the host principal has been
downloaded and rekey itself using the old host principal.

    sub default_owner {
        my ($type, $name) = @_;
        my %allowed = map { $_ => 1 }
            qw(HTTP cifs host imap ldap nfs pop sieve smtp webauth);
        my $realm = 'example.com';
        return unless $type eq 'keytab';
        return unless $name =~ m%/%;
        my ($service, $instance) = split ('/', $name, 2);
        return unless $allowed{$service};
        my $acl_name = "host/$instance";
        my @acl = ([ 'netdb', $instance ],
                   [ 'krb5', "host/$instance\@$realm" ]);
        return ($acl_name, @acl);
    }

The auto-created ACL used for the owner of the new object will, in the
above example, be named C<host/I<system>> where I<system> is the
fully-qualified name of the system as derived from the keytab being
requested.

If the name of the ACL returned by the default_owner function matches an
ACL that already exists in the wallet database, the existing ACL will be
compared to the default ACL returned by the default_owner function.  If
the existing ACL has the same entries as the one returned by
default_owner, creation continues if the user is authorized by that ACL.
If they don't match, creation of the object is rejected, since the
presence of an existing ACL may indicate that something different is being
done with this object.

=head1 NAMING ENFORCEMENT

By default, wallet permits administrators to create objects of any name
(unless the object backend rejects the name).  However, naming standards
for objects can be enforced, even for administrators, by defining a Perl
function in the configuration file named verify_name.  If such a function
exists, it will be called for any object creation and will be passed the
type of object, the object name, and the identity of the person doing the
creation.  If it returns undef or the empty string, object creation will
be allowed.  If it returns anything else, object creation is rejected and
the return value is used as the error message.

This function is also called for naming audits done via Wallet::Report
to find any existing objects that violate a (possibly updated) naming
policy.  In this case, the third argument (the identity of the person
creating the object) will be undef.  As a general rule, if the third
argument is undef, the function should apply the most liberal accepted
naming policy so that the audit returns only objects that violate all
naming policies, but some sites may wish different results for their audit
reports.

Please note that this return status is backwards from what one would
normally expect.  A false value is success; a true value is failure with
an error message.

For example, the following verify_name function would ensure that any
keytab objects for particular principals have fully-qualified hostnames:

    sub verify_name {
        my ($type, $name, $user) = @_;
        my %host_based = map { $_ => 1 }
            qw(HTTP cifs host imap ldap nfs pop sieve smtp webauth);
        return unless $type eq 'keytab';
        return unless $name =~ m%/%;
        my ($service, $instance) = split ('/', $name, 2);
        return unless $host_based{$service};
        return "host name $instance must be fully qualified"
            unless $instance =~ /\./;
        return;
    }

Objects that aren't of type C<keytab> or which aren't for a host-based key
have no naming requirements enforced by this example.

=head1 ACL NAMING ENFORCEMENT

Similar to object names, by default wallet permits administrators to
create ACLs with any name.  However, naming standards for ACLs can be
enforced by defining a Perl function in the configuration file named
verify_acl_name.  If such a function exists, it will be called for any ACL
creation or rename and will be passed given the new ACL name and the
identity of the person doing the creation.  If it returns undef or the
empty string, object creation will be allowed.  If it returns anything
else, object creation is rejected and the return value is used as the
error message.

This function is also called for naming audits done via Wallet::Report to
find any existing objects that violate a (possibly updated) naming policy.
In this case, the second argument (the identity of the person creating the
ACL) will be undef.  As a general rule, if the second argument is undef,
the function should apply the most liberal accepted naming policy so that
the audit returns only ACLs that violate all naming policies, but some
sites may wish different results for their audit reports.

Please note that this return status is backwards from what one would
normally expect.  A false value is success; a true value is failure with
an error message.

For example, the following verify_acl_name function would ensure that any
ACLs created contain a slash and the part before the slash be one of
C<host>, C<group>, C<user>, or C<service>.

    sub verify_acl_name {
        my ($name, $user) = @_;
        return 'ACL names must contain a slash' unless $name =~ m,/,;
        my ($first, $rest) = split ('/', $name, 2);
        my %types = map { $_ => 1 } qw(host group user service);
        unless ($types{$first}) {
            return "unknown ACL type $first";
        }
        return;
    }

Obvious improvements could be made, such as checking that the part after
the slash for a C<host/> ACL looked like a host name and the part after a
slash for a C<user/> ACL look like a user name.

=head1 ENVIRONMENT

=over 4

=item WALLET_CONFIG

If this environment variable is set, it is taken to be the path to the
wallet configuration file to load instead of F</etc/wallet/wallet.conf>.

=back

=cut

# Now, load the configuration file so that it can override the defaults.
if (-r $PATH) {
    do $PATH or die (($@ || $!) . "\n");
}

1;
__END__

=head1 SEE ALSO

DBI(3), Wallet::Object::Keytab(3), Wallet::Server(3), wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <rra@stanford.edu>

=cut
