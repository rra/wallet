# Wallet::Schema -- Database schema and connector for the wallet system
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2016 Russ Allbery <eagle@eyrie.org>
# Copyright 2012-2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# SPDX-License-Identifier: MIT

package Wallet::Schema;

use 5.008;
use strict;
use warnings;

use Wallet::Config;

use base 'DBIx::Class::Schema';

# Unlike all of the other wallet modules, this module's version is tied to the
# version of the schema in the database.  It should only be changed on schema
# changes, at least until better handling of upgrades is available.
our $VERSION = '0.10';

__PACKAGE__->load_namespaces;
__PACKAGE__->load_components (qw/Schema::Versioned/);

##############################################################################
# Core overrides
##############################################################################

# Override DBI::connect to supply our own connect string, username, and
# password and to set some standard options.  Takes no arguments other than
# the implicit class argument.
sub connect {
    my ($class) = @_;
    unless ($Wallet::Config::DB_DRIVER
            and (defined ($Wallet::Config::DB_INFO)
                 or defined ($Wallet::Config::DB_NAME))) {
        die "database connection information not configured\n";
    }
    my $dsn = "DBI:$Wallet::Config::DB_DRIVER:";
    if (defined $Wallet::Config::DB_INFO) {
        $dsn .= $Wallet::Config::DB_INFO;
    } else {
        $dsn .= "database=$Wallet::Config::DB_NAME";
        $dsn .= ";host=$Wallet::Config::DB_HOST" if $Wallet::Config::DB_HOST;
        $dsn .= ";port=$Wallet::Config::DB_PORT" if $Wallet::Config::DB_PORT;
    }
    my $user = $Wallet::Config::DB_USER;
    my $pass = $Wallet::Config::DB_PASSWORD;
    my %attrs = (PrintError => 0, RaiseError => 1);
    my $schema = eval { $class->SUPER::connect ($dsn, $user, $pass, \%attrs) };
    if ($@) {
        die "cannot connect to database: $@\n";
    }
    return $schema;
}

1;

__END__

##############################################################################
# Documentation
##############################################################################

=for stopwords
RaiseError PrintError AutoCommit ACL verifier API APIs enums keytab backend
enctypes DBI Allbery

=head1 NAME

Wallet::Schema - Database schema and connector for the wallet system

=head1 SYNOPSIS

    use Wallet::Schema;
    my $schema = Wallet::Schema->connect;

=head1 DESCRIPTION

This class encapsulates the database schema for the wallet system.  The
documentation you're reading explains and comments the schema.  The
class runs using the DBIx::Class module.

connect() will obtain the database connection information from the wallet
configuration; see L<Wallet::Config> for more details.  It will also
automatically set the RaiseError attribute to true and the PrintError and
AutoCommit attributes to false, matching the assumptions made by the
wallet database code.

=head1 SCHEMA

=head2 Normalization Tables

Holds the supported object types and their corresponding Perl classes:

  create table types
     (ty_name             varchar(16) primary key,
      ty_class            varchar(64));
  insert into types (ty_name, ty_class)
      values ('file', 'Wallet::Object::File');
  insert into types (ty_name, ty_class)
      values ('keytab', 'Wallet::Object::Keytab');

Holds the supported ACL schemes and their corresponding Perl classes:

  create table acl_schemes
     (as_name             varchar(32) primary key,
      as_class            varchar(64));
  insert into acl_schemes (as_name, as_class)
      values ('krb5', 'Wallet::ACL::Krb5');
  insert into acl_schemes (as_name, as_class)
      values ('krb5-regex', 'Wallet::ACL::Krb5::Regex');
  insert into acl_schemes (as_name, as_class)
      values ('ldap-attr', 'Wallet::ACL::LDAP::Attribute');
  insert into acl_schemes (as_name, as_class)
      values ('ldap-attr-root', 'Wallet::ACL::LDAP::Attribute::Root');
  insert into acl_schemes (as_name, as_class)
      values ('nested', 'Wallet::ACL::Nested');
  insert into acl_schemes (as_name, as_class)
      values ('netdb', 'Wallet::ACL::NetDB');
  insert into acl_schemes (as_name, as_class)
      values ('netdb-root', 'Wallet::ACL::NetDB::Root');

If you have extended the wallet to support additional object types or
additional ACL schemes, you will want to add additional rows to these
tables mapping those types or schemes to Perl classes that implement the
object or ACL verifier APIs.

=head2 ACL Tables

A wallet ACL consists of zero or more ACL entries, each of which is a
scheme and an identifier.  The scheme identifies the check that should be
performed and the identifier is additional scheme-specific information.
Each ACL references entries in the following table:

  create table acls
     (ac_id               integer auto_increment primary key,
      ac_name             varchar(255) not null,
      unique (ac_name));

This just keeps track of unique ACL identifiers.  The data is then stored
in:

  create table acl_entries
     (ae_id               integer not null references acls(ac_id),
      ae_scheme           varchar(32)
          not null references acl_schemes(as_name),
      ae_identifier       varchar(255) not null,
      primary key (ae_id, ae_scheme, ae_identifier));
  create index ae_id on acl_entries (ae_id);

ACLs may be referred to in the API via either the numeric ID or the
human-readable name, but internally ACLs are always referenced by numeric
ID so that they can be renamed without requiring complex data
modifications.

Currently, the ACL named C<ADMIN> (case-sensitive) is special-cased in the
Wallet::Server code and granted global access.

Every change made to any ACL in the database will be recorded in this
table.

  create table acl_history
     (ah_id               integer auto_increment primary key,
      ah_acl              integer not null,
      ah_name             varchar(255) default null,
      ah_action           varchar(16) not null,
      ah_scheme           varchar(32) default null,
      ah_identifier       varchar(255) default null,
      ah_by               varchar(255) not null,
      ah_from             varchar(255) not null,
      ah_on               datetime not null);
  create index ah_acl on acl_history (ah_acl);

ah_action must be one of C<create>, C<destroy>, C<add>, C<remove>, or
C<rename> (enums aren't used for compatibility with databases other than
MySQL).  For a change of type create, destroy, or rename, only the action,
the ACL name (in the case of rename, the old ACL name prior to the
rename), and the trace records (by, from, and on) are stored.  For a
change to the lines of an ACL, the scheme and identifier of the line that
was added or removed are included.

ah_by stores the authenticated identity that made the change, ah_from
stores the host from which they made the change, and ah_on stores the time
the change was made.

=head2 Object Tables

Each object stored in the wallet is represented by an entry in the objects
table:

  create table objects
     (ob_type             varchar(16)
          not null references types(ty_name),
      ob_name             varchar(255) not null,
      ob_owner            integer default null references acls(ac_id),
      ob_acl_get          integer default null references acls(ac_id),
      ob_acl_store        integer default null references acls(ac_id),
      ob_acl_show         integer default null references acls(ac_id),
      ob_acl_destroy      integer default null references acls(ac_id),
      ob_acl_flags        integer default null references acls(ac_id),
      ob_expires          datetime default null,
      ob_created_by       varchar(255) not null,
      ob_created_from     varchar(255) not null,
      ob_created_on       datetime not null,
      ob_stored_by        varchar(255) default null,
      ob_stored_from      varchar(255) default null,
      ob_stored_on        datetime default null,
      ob_downloaded_by    varchar(255) default null,
      ob_downloaded_from  varchar(255) default null,
      ob_downloaded_on    datetime default null,
      ob_comment          varchar(255) default null,
      primary key (ob_name, ob_type));
  create index ob_owner on objects (ob_owner);
  create index ob_expires on objects (ob_expires);

Object names are not globally unique but only unique within their type, so
the table has a joint primary key.  Each object has an owner and then up
to five more specific ACLs.  The owner provides permission for get, store,
and show operations if no more specific ACL is set.  It does not provide
permission for destroy or flags.

The ob_acl_flags ACL controls who can set flags on this object.  Each
object may have zero or more flags associated with it:

  create table flags
     (fl_type             varchar(16)
          not null references objects(ob_type),
      fl_name             varchar(255)
          not null references objects(ob_name),
      fl_flag             enum('locked', 'unchanging')
          not null,
      primary key (fl_type, fl_name, fl_flag));
  create index fl_object on flags (fl_type, fl_name);

Every change made to any object in the wallet database will be recorded in
this table:

  create table object_history
     (oh_id               integer auto_increment primary key,
      oh_type             varchar(16)
          not null references objects(ob_type),
      oh_name             varchar(255)
          not null references objects(ob_name),
      oh_action           varchar(16) not null,
      oh_field            varchar(16) default null,
      oh_type_field       varchar(255) default null,
      oh_old              varchar(255) default null,
      oh_new              varchar(255) default null,
      oh_by               varchar(255) not null,
      oh_from             varchar(255) not null,
      oh_on               datetime not null);
  create index oh_object on object_history (oh_type, oh_name);

oh_action must be one of C<create>, C<destroy>, C<get>, C<store>, or
C<set>.  oh_field must be one of C<owner>, C<acl_get>, C<acl_store>,
C<acl_show>, C<acl_destroy>, C<acl_flags>, C<expires>, C<flags>, or
C<type_data>.  Enums aren't used for compatibility with databases other
than MySQL.

For a change of type create, get, store, or destroy, only the action and
the trace records (by, from, and on) are stored.  For changes to columns
or to the flags table, oh_field takes what attribute is changed, oh_from
takes the previous value converted to a string and oh_to takes the next
value similarly converted to a string.  The special field value
"type_data" is used when type-specific data is changed, and in that case
(and only that case) some type-specific name for the data being changed is
stored in oh_type_field.

When clearing a flag, oh_old will have the name of the flag and oh_new
will be null.  When setting a flag, oh_old will be null and oh_new will
have the name of the flag.

oh_by stores the authenticated identity that made the change, oh_from
stores the host from which they made the change, and oh_on stores the time
the change was made.

=head2 Duo Backend Data

Duo integration objects store some additional metadata about the
integration to aid in synchronization with Duo.

  create table duo
     (du_name             varchar(255)
          not null references objects(ob_name),
      du_key              varchar(255) not null);
  create index du_key on duo (du_key);

du_key holds the Duo integration key, which is the unique name of the
integration within Duo.  Additional data may be added later to represent
the other possible settings within Duo.

=head2 Keytab Backend Data

The keytab backend has stub support for synchronizing keys with an
external system, although no external systems are currently supported.
The permitted external systems are listed in a normalization table:

  create table sync_targets
     (st_name             varchar(255) primary key);

and then the synchronization targets for a given keytab are stored in this
table:

  create table keytab_sync
     (ks_name             varchar(255)
          not null references objects(ob_name),
      ks_target           varchar(255)
          not null references sync_targets(st_name),
      primary key (ks_name, ks_target));
  create index ks_name on keytab_sync (ks_name);

The keytab backend supports restricting the allowable enctypes for a given
keytab.  The permitted enctypes are listed in a normalization table:

  create table enctypes
     (en_name             varchar(255) primary key);

and then the restrictions for a given keytab are stored in this table:

  create table keytab_enctypes
     (ke_name             varchar(255)
          not null references objects(ob_name),
      ke_enctype          varchar(255)
          not null references enctypes(en_name),
      primary key (ke_name, ke_enctype));
  create index ke_name on keytab_enctypes (ke_name);

To use this functionality, you will need to populate the enctypes table
with the enctypes that a keytab may be restricted to.  Currently, there is
no automated mechanism to do this.

=head1 CLASS METHODS

=over 4

=item connect()

Opens a new database connection and returns the database object.  On any
failure, throws an exception.  Unlike the DBI method, connect() takes no
arguments; all database connection information is derived from the wallet
configuration.

=back

=head1 SEE ALSO

wallet-backend(8), Wallet::Config(3)

This module is part of the wallet system.  The current version is
available from L<https://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=cut
