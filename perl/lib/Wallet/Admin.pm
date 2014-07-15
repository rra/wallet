# Wallet::Admin -- Wallet system administrative interface.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2008, 2009, 2010, 2011, 2012, 2013, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Admin;
require 5.006;

use strict;
use warnings;
use vars qw($VERSION);

use Wallet::ACL;
use Wallet::Schema;

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.07';

# The last non-DBIx::Class version of Wallet::Schema.  If a database has no
# DBIx::Class versioning, we artificially install this version number before
# starting the upgrade process so that the automated DBIx::Class upgrade will
# work properly.
our $BASE_VERSION = '0.07';

##############################################################################
# Constructor, destructor, and accessors
##############################################################################

# Create a new wallet administrator object.  Opens a connection to the
# database that will be used for all of the wallet configuration information.
# Throw an exception if anything goes wrong.
sub new {
    my ($class) = @_;
    my $schema = Wallet::Schema->connect;
    my $self = { schema => $schema };
    bless ($self, $class);
    return $self;
}

# Returns the database handle (used mostly for testing).
sub dbh {
    my ($self) = @_;
    return $self->{schema}->storage->dbh;
}

# Returns the DBIx::Class-based database schema object.
sub schema {
    my ($self) = @_;
    return $self->{schema};
}

# Set or return the error stashed in the object.
sub error {
    my ($self, @error) = @_;
    if (@error) {
        my $error = join ('', @error);
        chomp $error;
        1 while ($error =~ s/ at \S+ line \d+\.?\z//);
        $self->{error} = $error;
    }
    return $self->{error};
}

# Disconnect the database handle on object destruction to avoid warnings.
sub DESTROY {
    my ($self) = @_;
    $self->{schema}->storage->dbh->disconnect;
}

##############################################################################
# Database initialization
##############################################################################

# Initializes the database by populating it with our schema and then creates
# and returns a new wallet server object.  This is used only for initial
# database creation.  Takes the Kerberos principal who will be the default
# administrator so that we can create an initial administrator ACL.  Returns
# true on success and false on failure, setting the object error.
sub initialize {
    my ($self, $user) = @_;

    # Deploy the database schema from DDL files, if they exist.  If not then
    # we automatically get the database from the Schema modules.
    $self->{schema}->deploy ({}, $Wallet::Config::DB_DDL_DIRECTORY);
    if ($@) {
        $self->error ($@);
        return;
    }
    $self->default_data;

    # Create a default admin ACL.
    my $acl = Wallet::ACL->create ('ADMIN', $self->{schema}, $user,
                                   'localhost');
    unless ($acl->add ('krb5', $user, $user, 'localhost')) {
        $self->error ($acl->error);
        return;
    }

    return 1;
}

# Load default data into various tables.  We'd like to do this more directly
# in the schema definitions, but not yet seeing a good way to do that.
sub default_data {
    my ($self) = @_;

    # acl_schemes default rows.
    my ($r1) = $self->{schema}->resultset('AclScheme')->populate ([
                       [ qw/as_name as_class/ ],
                       [ 'krb5',       'Wallet::ACL::Krb5'            ],
                       [ 'krb5-regex', 'Wallet::ACL::Krb5::Regex'     ],
                       [ 'ldap-attr',  'Wallet::ACL::LDAP::Attribute' ],
                       [ 'netdb',      'Wallet::ACL::NetDB'           ],
                       [ 'netdb-root', 'Wallet::ACL::NetDB::Root'     ],
                                                     ]);
    warn "default AclScheme not installed" unless defined $r1;

    # types default rows.
    my @record = ([ qw/ty_name ty_class/ ],
               [ 'file',       'Wallet::Object::File' ],
               [ 'keytab',     'Wallet::Object::Keytab' ],
               [ 'wa-keyring', 'Wallet::Object::WAKeyring' ]);
    ($r1) = $self->{schema}->resultset('Type')->populate (\@record);
    warn "default Type not installed" unless defined $r1;

    # enctypes default rows.
    @record = ([ qw/en_name/ ],
                  [ 'aes128-cts-hmac-sha1-96' ],
                  [ 'aes256-cts-hmac-sha1-96' ],
                  [ 'arcfour-hmac-md5' ],
                  [ 'des-cbc-crc' ],
                  [ 'des3-cbc-sha1' ]);
    ($r1) = $self->{schema}->resultset('Enctype')->populate (\@record);
    warn "default Enctype not installed" unless defined $r1;

    return 1;
}

# The same as initialize, but also drops any existing tables first before
# creating the schema.  Takes the same arguments.  Returns true on success and
# false on failure.
sub reinitialize {
    my ($self, $user) = @_;
    return unless $self->destroy;
    return $self->initialize ($user);
}

# Drop the database, including all of its data.  Returns true on success and
# false on failure.
sub destroy {
    my ($self) = @_;

    # Get an actual DBI handle and use it to delete all tables.
    my $dbh = $self->dbh;
    my @tables = qw/acls acl_entries acl_history acl_schemes duo enctypes
        flags keytab_enctypes keytab_sync objects object_history
        sync_targets types dbix_class_schema_versions/;
    for my $table (@tables) {
        my $sql = "DROP TABLE IF EXISTS $table";
        $dbh->do ($sql);
    }

    return 1;
}

# Save a DDL of the database in every supported database server.  Returns
# true on success and false on failure.
sub backup {
    my ($self, $oldversion) = @_;

    my @dbs = qw/MySQL SQLite PostgreSQL/;
    my $version = $Wallet::Schema::VERSION;
    $self->{schema}->create_ddl_dir (\@dbs, $version,
                                     $Wallet::Config::DB_DDL_DIRECTORY,
                                     $oldversion);

    return 1;
}

# Upgrade the database to the latest schema version.  Returns true on success
# and false on failure.
sub upgrade {
    my ($self) = @_;

    # Check to see if the database is versioned.  If not, install the
    # versioning table and default version.
    if (!$self->{schema}->get_db_version) {
        $self->{schema}->install ($BASE_VERSION);
    }

    # Suppress warnings that actually are just informational messages.
    local $SIG{__WARN__} = sub {
        my ($warn) = @_;
        return if $warn =~ m{Upgrade not necessary};
        return if $warn =~ m{Attempting upgrade};
        warn $warn;
    };

    # Perform the actual upgrade.
    if ($self->{schema}->get_db_version) {
        $self->{schema}->upgrade_directory ($Wallet::Config::DB_DDL_DIRECTORY);
        eval { $self->{schema}->upgrade; };
    }
    if ($@) {
        $self->error ($@);
        return;
    }

    return 1;
}

##############################################################################
# Object registration
##############################################################################

# Given an object type and class name, add a new class mapping to that
# database for the given object type.  This is used to register new object
# types.  Returns true on success, false on failure, and sets the internal
# error on failure.
sub register_object {
    my ($self, $type, $class) = @_;
    eval {
        my $guard = $self->{schema}->txn_scope_guard;
        my %record = (ty_name  => $type,
                      ty_class => $class);
        $self->{schema}->resultset('Type')->create (\%record);
        $guard->commit;
    };
    if ($@) {
        $self->error ("cannot register $class for $type: $@");
        return;
    }
    return 1;
}

# Given an ACL verifier scheme and class name, add a new class mapping to that
# database for the given ACL verifier scheme.  This is used to register new
# ACL schemes.  Returns true on success, false on failure, and sets the
# internal error on failure.
sub register_verifier {
    my ($self, $scheme, $class) = @_;
    eval {
        my $guard = $self->{schema}->txn_scope_guard;
        my %record = (as_name  => $scheme,
                      as_class => $class);
        $self->{schema}->resultset('AclScheme')->create (\%record);
        $guard->commit;
    };
    if ($@) {
        $self->error ("cannot register $class for $scheme: $@");
        return;
    }
    return 1;
}

1;
__DATA__

##############################################################################
# Documentation
##############################################################################

=head1 NAME

Wallet::Admin - Wallet system administrative interface

=for stopwords
ACL hostname Allbery verifier

=head1 SYNOPSIS

    use Wallet::Admin;
    my $admin = Wallet::Admin->new;
    unless ($admin->initialize ('user/admin@EXAMPLE.COM')) {
        die $admin->error;
    }

=head1 DESCRIPTION

Wallet::Admin implements the administrative interface to the wallet server
and database.  It is normally instantiated and used by B<wallet-admin>, a
thin wrapper around this object that provides a command-line interface to
its actions.

To use this object, several configuration variables must be set (at least
the database configuration).  For information on those variables and how
to set them, see L<Wallet::Config>.  For more information on the normal
user interface to the wallet server, see L<Wallet::Server>.

=head1 CLASS METHODS

=over 4

=item new()

Creates a new wallet administrative object and connects to the database.
On any error, this method throws an exception.

=back

=head1 INSTANCE METHODS

For all methods that can fail, the caller should call error() after a
failure to get the error message.

=over 4

=item destroy ()

Destroys the database, deleting all of its data and all of the tables used
by the wallet server.  Returns true on success and false on failure.

=item error ()

Returns the error of the last failing operation or undef if no operations
have failed.  Callers should call this function to get the error message
after an undef return from any other instance method.

=item initialize(PRINCIPAL)

Initializes the database as configured in Wallet::Config and loads the
wallet database schema.  Then, creates an ACL with the name ADMIN and adds
an ACL entry of scheme C<krb5> and instance PRINCIPAL to that ACL.  This
bootstraps the authorization system and lets that Kerberos identity make
further changes to the ADMIN ACL and the rest of the wallet database.
Returns true on success and false on failure.

initialize() uses C<localhost> as the hostname and PRINCIPAL as the user
when logging the history of the ADMIN ACL creation and for any subsequent
actions on the object it returns.

=item register_object (TYPE, CLASS)

Register in the database a mapping from the object type TYPE to the class
CLASS.  Returns true on success and false on failure (including when the
verifier is already registered).

=item register_verifier (SCHEME, CLASS)

Register in the database a mapping from the ACL scheme SCHEME to the class
CLASS.  Returns true on success and false on failure (including when the
verifier is already registered).

=item reinitialize (PRINCIPAL)

Performs the same actions as initialize(), but first drops any existing
wallet database tables from the database, allowing this function to be
called on a prior wallet database.  All data stored in the database will
be deleted and a fresh set of wallet database tables will be created.
This method is equivalent to calling destroy() followed by initialize().
Returns true on success and false on failure.

=item upgrade ()

Upgrades the database to the latest schema version, preserving data as
much as possible.  Returns true on success and false on failure.

=back

=head1 SEE ALSO

wallet-admin(8)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=cut
