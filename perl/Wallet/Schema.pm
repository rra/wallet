# Wallet::Schema -- Database schema for the wallet system.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Schema;
require 5.006;

use strict;
use vars qw(@TABLES $VERSION);

use DBI;

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.02';

##############################################################################
# Implementation
##############################################################################

# Create a new Wallet::Schema object, parse the SQL out of the documentation,
# and store it in the object.
sub new {
    my ($class) = @_;
    local $_;
    my ($found, @sql);
    my $command = '';
    while (<DATA>) {
        if (not $found and /^=head1 SCHEMA/) {
            $found = 1;
        } elsif ($found and /^=head1 /) {
            last;
        } elsif ($found and /^  /) {
            s/^  //;
            $command .= $_;
            if (/;$/) {
                push (@sql, $command);
                $command = '';
            }
        }
    }
    close DATA;
    my $self = { sql => [ @sql ] };
    bless ($self, $class);
    return $self;
}

# Returns the SQL as a list of commands.
sub sql {
    my ($self) = @_;
    return @{ $self->{sql} };
}

# Given a database handle, try to create our database by running the SQL.  Do
# this in a transaction regardless of the database settings and throw an
# exception if this fails.  We have to do a bit of fiddling to get syntax that
# works with both MySQL and SQLite.
sub create {
    my ($self, $dbh) = @_;
    my $driver = $dbh->{Driver}->{Name};
    eval {
        $dbh->begin_work if $dbh->{AutoCommit};
        for my $sql (@{ $self->{sql} }) {
            if ($driver eq 'SQLite') {
                $sql =~ s{auto_increment primary key}
                         {primary key autoincrement};
            }
            $dbh->do ($sql, { RaiseError => 1, PrintError => 0 });
        }
        $dbh->commit;
    };
    if ($@) {
        $dbh->rollback;
        die "$@\n";
    }
}

##############################################################################
# Schema
##############################################################################

# The following POD is also parsed by the code to extract SQL blocks.  Don't
# add any verbatim blocks to this documentation in the SCHEMA section that
# aren't intended to be SQL.

1;
__DATA__

=head1 NAME

Wallet::Schema - Database schema for the wallet system

=head1 SYNOPSIS

    use Wallet::Schema;
    my $schema = Wallet::Schema->new;
    my @sql = $schema->sql;
    $schema->create ($dbh);

=head1 DESCRIPTION

This class encapsulates the database schema for the wallet system.  The
documentation you're reading explains and comments the schema.  The Perl
object extracts the schema from the documentation and can either return it
as a list of SQL commands to run or run those commands given a connected
database handle.

This schema attempts to be portable SQL, but it is designed for use with
MySQL and may require some modifications for other databases.

=head1 METHODS

=over 4

=item new()

Instantiates a new Wallet::Schema object.  This parses the documentation and
extracts the schema, but otherwise doesn't do anything.

=item create(DBH)

Given a connected database handle, runs the SQL commands necessary to create
the wallet database in an otherwise empty database.  This method will not
drop any existing tables and will therefore fail if a wallet database has
already been created.  On any error, this method will throw a database
exception.

=item sql()

Returns the schema and the population of the normalization tables as a list
of SQL commands to run to create the wallet database in an otherwise empty
database.

=back

=head1 SCHEMA

=head2 Normalization Tables

The following are normalization tables used to constrain the values in other
tables.

Holds the supported flag names:

  create table flag_names
     (fn_name             varchar(32) primary key);
  insert into flag_names (fn_name) values ('locked');
  insert into flag_names (fn_name) values ('unchanging');

Holds the supported object types and their corresponding Perl classes:

  create table types
     (ty_name             varchar(16) primary key,
      ty_class            varchar(64));
  insert into types (ty_name, ty_class)
      values ('keytab', 'Wallet::Object::Keytab');

Holds the supported ACL schemes and their corresponding Perl classes:

  create table acl_schemes
     (as_name             varchar(32) primary key,
      as_class            varchar(64));
  insert into acl_schemes (as_name, as_class)
      values ('krb5', 'Wallet::ACL::Krb5');

If you have extended the wallet to support additional object types or
additional ACL schemes, you will want to add additional rows to these tables
mapping those types or schemes to Perl classes that implement the object or
ACL verifier APIs.

=head2 ACL Tables

A wallet ACL consists of zero or more ACL entries, each of which is a scheme
and an identifier.  The scheme identifies the check that should be performed
and the identifier is additional scheme-specific information.  Each ACL
references entries in the following table:

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
human-readable name, but internally ACLs are always referenced by numeric ID
so that they can be renamed without requiring complex data modifications.

Currently, the ACL named C<ADMIN> (case-sensitive) is special-cased in the
Wallet::Server code and granted global access.

Every change made to any ACL in the database will be recorded in this
table.

  create table acl_history
     (ah_id               integer auto_increment primary key,
      ah_acl              integer not null,
      ah_action           varchar(16) not null,
      ah_scheme           varchar(32) default null,
      ah_identifier       varchar(255) default null,
      ah_by               varchar(255) not null,
      ah_from             varchar(255) not null,
      ah_on               datetime not null);
  create index ah_acl on acl_history (ah_acl);

ah_action must be one of C<create>, C<destroy>, C<add>, or C<remove> (enums
aren't used for compatibility with databases other than MySQL).  For a
change of type create or destroy, only the action and the trace records (by,
from, and on) are stored.  For a change to the lines of an ACL, the scheme
and identifier of the line that was added or removed is included.  Note that
changes to the ACL name are not recorded; ACLs are always tracked by
system-generated ID, so name changes are purely cosmetic.

ah_by stores the authenticated identity that made the change, ah_from stores
the host from which they made the change, and ah_on stores the time the
change was made.

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
      primary key (ob_name, ob_type));
  create index ob_owner on objects (ob_owner);
  create index ob_expires on objects (ob_expires);

Object names are not globally unique but only unique within their type, so
the table has a joint primary key.  Each object has an owner and then up to
five more specific ACLs.  The owner provides permission for get, store, and
show operations if no more specific ACL is set.  It does not provide
permission for destroy or flags.

The ob_acl_flags ACL controls who can set flags on this object.  Each object
may have zero or more flags associated with it:

  create table flags
     (fl_type             varchar(16)
          not null references objects(ob_type),
      fl_name             varchar(255)
          not null references objects(ob_name),
      fl_flag             varchar(32)
          not null references flag_names(fn_name),
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

oh_action must be one of C<create>, C<destroy>, C<get>, C<store>, or C<set>.
oh_field must be one of C<owner>, C<acl_get>, C<acl_store>, C<acl_show>,
C<acl_destroy>, C<acl_flags>, C<expires>, C<flags>, or C<type_data>.  Enums
aren't used for compatibility with databases other than MySQL.

For a change of type create, get, store, or destroy, only the action and the
trace records (by, from, and on) are stored.  For changes to columns or to
the flags table, oh_field takes what attribute is changed, oh_from takes the
previous value converted to a string and oh_to takes the next value
similarly converted to a string.  The special field value "type_data" is
used when type-specific data is changed, and in that case (and only that
case) some type-specific name for the data being changed is stored in
oh_type_field.

When clearing a flag, oh_old will have the name of the flag and oh_new
will be null.  When setting a flag, oh_old will be null and oh_new will
have the name of the flag.

oh_by stores the authenticated identity that made the change, oh_from stores
the host from which they made the change, and oh_on stores the time the
change was made.

=head2 Keytab Backend Data

The keytab backend supports synchronizing keys with an external system.  The
permitted external systems are listed in a normalization table:

  create table sync_targets
     (st_name             varchar(255) primary key);
  insert into sync_targets (st_name) values ('kaserver');

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

To use this functionality, you will need to populate the enctypes table with
the enctypes that a keytab may be restricted to.  Currently, there is no
automated mechanism to do this.

=head1 SEE ALSO

wallet-backend(8)

This module is part of the wallet system.  The current version is available
from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <rra@stanford.edu>

=cut
