# Wallet::Config -- Configuration handling for the wallet server.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007 Board of Trustees, Leland Stanford Jr. University
#
# See README for licensing terms.

package Wallet::Config;
require 5.006;

use strict;
use vars qw($PATH $VERSION);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.01';

# Path to the config file to load.
$PATH = '/etc/wallet.conf';

=head1 NAME

Wallet::Config - Configuration handling for the wallet server

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
wallet server.  It is implemented as a Perl class that declares and sets the
defaults for various configuration variables and then, if it exists, loads
the file F</etc/wallet.conf>.  That file should contain any site-specific
overrides to the defaults, and at least some parameters must be set.

This file must be valid Perl.  To set a variable, use the syntax:

    $VARIABLE = <value>;

where VARIABLE is the variable name (always in all-capital letters) and
<value> is the value.  If setting a variable to a string and not a number,
you should normally enclose <value> in C<''>.  For example, to set the
variable DB_DRIVER to C<MySQL>, use:

    $DB_DRIVER = 'MySQL';

Always remember the initial dollar sign (C<$>) and ending semicolon (C<;>).
Those familiar with Perl syntax can of course use the full range of Perl
expressions.

This configuration file should end with the line:

    1;

This ensures that Perl doesn't think there is an error when loading the
file.

=head1 DATABASE CONFIGURATION

=over 4

=item DB_DRIVER

Sets the Perl database driver to use for the wallet database.  Common values
would be C<SQLite> or C<MySQL>.  Less common values would be C<Oracle>,
C<Sybase>, or C<ODBC>.  The appropriate DBD::* Perl module for the chosen
driver must be installed and will be dynamically loaded by the wallet.  For
more information, see DBI(3).

This variable must be set.

=cut

our $DB_DRIVER;

=item DB_INFO

Sets the remaining contents for the DBI DSN (everything after the driver).
Using this variable provides full control over the connect string passed to
DBI.  When using SQLite, set this variable to the path to the SQLite
database.  If this variable is set, DB_NAME, DB_HOST, and DB_PORT are
ignored.  For more information, see DBI(3) and the documentation for the
database driver you're using.

Either DB_INFO or DB_NAME must be set.  If you don't need to pass any
additional information to DBI, set DB_INFO to the empty string (C<''>).

=cut

our $DB_INFO;

=item DB_NAME

If DB_INFO is not set, specifies the database name.  The third part of the
DBI connect string will be set to C<database=DB_NAME>, possibly with a host
and port appended if DB_HOST and DB_PORT are set.  For more information, see
DBI(3) and the documentation for the database driver you're using.

Either DB_INFO or DB_NAME must be set.

=cut

our $DB_NAME;

=item DB_HOST

If DB_INFO is not set, specifies the database host.  C<;host=DB_HOST> will
be appended to the DBI connect string.  For more information, see DBI(3) and
the documentation for the database driver you're using.

=cut

our $DB_HOST;

=item DB_PORT

If DB_PORT is not set, specifies the database port.  C<;port=DB_PORT> will
be appended to the DBI connect string.  If this variable is set, DB_HOST
should also be set.  For more information, see DBI(3) and the documentation
for the database driver you're using.

=cut

our $DB_PORT;

=item DB_USER

Specifies the user for database authentication.  Some database backends,
particularly SQLite, do not need this.

=cut

our $DB_USER;

=item DB_PASSWORD

Specifies the password for database authentication.  Some database backends,
particularly SQLite, do not need this.

=cut

our $DB_PASSWORD;

=back

=head1 KEYTAB OBJECT CONFIGURATION

These configuration variables only need to be set if you intend to use the
C<keytab> object type (the Wallet::Object::Keytab class).  They point the
keytab object implementation at the right Kerberos server and B<kadmin>
client.

=over 4

=item KEYTAB_FILE

Specifies the keytab to use to authenticate to B<kadmind>.  The principal
whose key is stored in this keytab must have the ability to create, modify,
inspect, and delete any principals that should be managed by the wallet.
(In MIT Kerberos F<kadm5.acl> parlance, this is C<admci> privileges.)

KEYTAB_FILE must be set to use keytab objects.

=cut

our $KEYTAB_FILE;

=item KEYTAB_FLAGS

These flags, if any, are passed to the C<addprinc> command when creating a
new principal in the Kerberos KDC.  To not pass any flags, set KEYTAB_FLAGS
to the empty string.  The default value is C<-clearpolicy>, which clears any
password strength policy from principals created by the wallet.  (Since the
wallet randomizes the keys, password strength checking is generally
pointless and may interact poorly with the way C<addprinc -randkey> works
when third-party add-ons for password strength checking are used.)

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

=item KEYTAB_PRINCIPAL

The principal whose key is stored in KEYTAB_FILE.  The wallet will
authenticate as this principal to the kadmin service.

KEYTAB_PRINCIPAL must be set to use keytab objects, at least until B<kadmin>
is smart enough to use the first principal found in the keytab it's using
for authentication.

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
processing C<get> commands from clients.  The keytabs are written into this
directory with predictable names, so this should not be a system temporary
directory such as F</tmp> or F</var/tmp>.  It's best to create a directory
solely for this purpose that's owned by the user the wallet server will run
as.

KEYTAB_TMP must be set to use keytab objects.

=cut

our $KEYTAB_TMP;

=back

=head2 Retrieving Existing Keytabs

The keytab object backend optionally supports retrieving existing keys, and
hence keytabs, for Kerberos principals by contacting the KDC via remctl and
talking to B<keytab-backend>.  This is enabled by setting the C<unchanging>
flag on keytab objects.  To configure that support, set the following
variables.

=over 4

=item KEYTAB_REMCTL_CACHE

Specifies the ticket cache to use when retrieving existing keytabs from the
KDC.  This is only used to implement support for the C<unchanging> flag.
The ticket cache must be for a principal with access to run C<keytab
retrieve> via remctl on KEYTAB_REMCTL_HOST.

=cut

our $KEYTAB_CACHE;

=item KEYTAB_REMCTL_HOST

The host to which to connect with remctl to retrieve existing keytabs.  This
is only used to implement support for the C<unchanging> flag.  This host
must provide the C<keytab retrieve> command and KEYTAB_CACHE must also be
set to a ticket cache for a principal with access to run that command.

=cut

our $KEYTAB_REMCTL_HOST;

=item KEYTAB_REMCTL_PRINCIPAL

The service principal to which to authenticate when retrieving existing
keytabs.  This is only used to implement support for the C<unchanging> flag.
If this variable is not set, the default is formed by prepending C<host/> to
KEYTAB_REMCTL_HOST.  (Note that KEYTAB_REMCTL_HOST is not lowercased first.)

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

=head2 Synchronization with AFS kaserver

The keytab backend optionally supports synchronizing keys between the
Kerberos v5 realm and a Kerberos v4 realm using kaserver.  This
synchronization is done using B<kasetkey> and is controlled by the C<sync>
attribute on keytab objects.  To configure that support, set the following
variables.

=over 4

=item KEYTAB_AFS_ADMIN

The Kerberos v4 principal to use for authentication to the AFS kaserver.  If
this principal is not in the default local Kerberos v4 realm, it must be
fully qualified.  A srvtab for this principal must be stored in the path set
in $KEYTAB_AFS_SRVTAB.  This principal must have the ADMIN flag set in the
AFS kaserver so that it can create and remove principals.  This variable
must be set to use the kaserver synchronization support.

=cut

our $KEYTAB_AFS_ADMIN;

=item KEYTAB_AFS_DESTROY

If this variable, which is false by default, is set to a true value, each
time a keytab object that is not configured to be synchronized with the AFS
kaserver, the corresponding Kerberos v4 principal will be deleted from the
AFS kaserver.  Use this with caution; it will cause the AFS kaserver realm
to be slowly stripped of principals.  This is intended for use with
migration from Kerberos v4 to Kerberos v5, where the old principals should
be deleted out of Kerberos v4 whenever not requested from the wallet to aid
in tracking down and removing any systems with lingering Kerberos v4
dependencies.

Be aware that multiple Kerberos v5 principals map to the same Kerberos v4
principal since in Kerberos v4 the domain name is stripped from the
principal for machine principals.  If you create a keytab named
host/foo.example.com and mark it synchronized, and then create another
keytab named host/foo.example.net and don't mark it synchronized,
downloading the second will destroy the Kerberos v4 principal of the first
if this variable is set.

=cut

our $KEYTAB_AFS_DESTROY;

=item KEYTAB_AFS_KASETKEY

The path to the B<kasetkey> command-line client.  The default value is
C<kasetkey>, which will cause the wallet to search for B<kasetkey> on its
default PATH.

=cut

our $KEYTAB_AFS_KASETKEY = 'kasetkey';

=item KEYTAB_AFS_REALM

The name of the Kerberos v4 realm with which to synchronize keys.  This is a
realm, not a cell, so it should be in all uppercase.  If this variable is
not set, the default is the realm determined from the local cell name.

=cut

our $KEYTAB_AFS_REALM;

=item KEYTAB_AFS_SRVTAB

The path to a srvtab used to authenticate to the AFS kaserver.  This srvtab
should be for the principal set in $KEYTAB_AFS_ADMIN.  This variable must be
set to use the kaserver synchronization support.

=cut

our $KEYTAB_AFS_SRVTAB;

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

This module is part of the wallet system.  The current version is available
from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <rra@stanford.edu>

=cut
