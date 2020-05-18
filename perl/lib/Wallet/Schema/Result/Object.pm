# Wallet schema for an object.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2012-2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# SPDX-License-Identifier: MIT

package Wallet::Schema::Result::Object;

use strict;
use warnings;

use base 'DBIx::Class::Core';

our $VERSION = '1.05';

__PACKAGE__->load_components("InflateColumn::DateTime");

=head1 NAME

Wallet::Schema::Result::Object - Wallet schema for an object

=head1 DESCRIPTION

=cut

__PACKAGE__->table("objects");

=head1 ACCESSORS

=head2 ob_type

  data_type: 'varchar'
  is_nullable: 0
  size: 16

=head2 ob_name

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=head2 ob_owner

  data_type: 'integer'
  is_nullable: 1

=head2 ob_acl_get

  data_type: 'integer'
  is_nullable: 1

=head2 ob_acl_store

  data_type: 'integer'
  is_nullable: 1

=head2 ob_acl_show

  data_type: 'integer'
  is_nullable: 1

=head2 ob_acl_destroy

  data_type: 'integer'
  is_nullable: 1

=head2 ob_acl_flags

  data_type: 'integer'
  is_nullable: 1

=head2 ob_expires

  data_type: 'datetime'
  datetime_undef_if_invalid: 1
  is_nullable: 1

=head2 ob_created_by

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=head2 ob_created_from

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=head2 ob_created_on

  data_type: 'datetime'
  datetime_undef_if_invalid: 1
  is_nullable: 0

=head2 ob_stored_by

  data_type: 'varchar'
  is_nullable: 1
  size: 255

=head2 ob_stored_from

  data_type: 'varchar'
  is_nullable: 1
  size: 255

=head2 ob_stored_on

  data_type: 'datetime'
  datetime_undef_if_invalid: 1
  is_nullable: 1

=head2 ob_downloaded_by

  data_type: 'varchar'
  is_nullable: 1
  size: 255

=head2 ob_downloaded_from

  data_type: 'varchar'
  is_nullable: 1
  size: 255

=head2 ob_downloaded_on

  data_type: 'datetime'
  datetime_undef_if_invalid: 1
  is_nullable: 1

=head2 ob_comment

  data_type: 'varchar'
  is_nullable: 1
  size: 255

=cut

__PACKAGE__->add_columns(
  "ob_type",
  { data_type => "varchar", is_nullable => 0, size => 16 },
  "ob_name",
  { data_type => "varchar", is_nullable => 0, size => 255 },
  "ob_owner",
  { data_type => "integer", is_nullable => 1 },
  "ob_acl_get",
  { data_type => "integer", is_nullable => 1 },
  "ob_acl_store",
  { data_type => "integer", is_nullable => 1 },
  "ob_acl_show",
  { data_type => "integer", is_nullable => 1 },
  "ob_acl_destroy",
  { data_type => "integer", is_nullable => 1 },
  "ob_acl_flags",
  { data_type => "integer", is_nullable => 1 },
  "ob_expires",
  {
    data_type => "datetime",
    datetime_undef_if_invalid => 1,
    is_nullable => 1,
  },
  "ob_created_by",
  { data_type => "varchar", is_nullable => 0, size => 255 },
  "ob_created_from",
  { data_type => "varchar", is_nullable => 0, size => 255 },
  "ob_created_on",
  {
    data_type => "datetime",
    datetime_undef_if_invalid => 1,
    is_nullable => 0,
  },
  "ob_stored_by",
  { data_type => "varchar", is_nullable => 1, size => 255 },
  "ob_stored_from",
  { data_type => "varchar", is_nullable => 1, size => 255 },
  "ob_stored_on",
  {
    data_type => "datetime",
    datetime_undef_if_invalid => 1,
    is_nullable => 1,
  },
  "ob_downloaded_by",
  { data_type => "varchar", is_nullable => 1, size => 255 },
  "ob_downloaded_from",
  { data_type => "varchar", is_nullable => 1, size => 255 },
  "ob_downloaded_on",
  {
    data_type => "datetime",
    datetime_undef_if_invalid => 1,
    is_nullable => 1,
  },
  "ob_comment",
  { data_type => "varchar", is_nullable => 1, size => 255 },
);
__PACKAGE__->set_primary_key("ob_name", "ob_type");

__PACKAGE__->has_one(
                     'types',
                     'Wallet::Schema::Result::Type',
                     { 'foreign.ty_name' => 'self.ob_type' },
                    );

__PACKAGE__->has_many(
                      'flags',
                      'Wallet::Schema::Result::Flag',
                      { 'foreign.fl_type' => 'self.ob_type',
                        'foreign.fl_name' => 'self.ob_name' },
                      { cascade_copy => 0, cascade_delete => 0 },
                     );

__PACKAGE__->has_many(
                      'object_history',
                      'Wallet::Schema::Result::ObjectHistory',
                      { 'foreign.oh_type' => 'self.ob_type',
                        'foreign.oh_name' => 'self.ob_name' },
                      { cascade_copy => 0, cascade_delete => 0 },
                     );

__PACKAGE__->has_many(
                      'keytab_enctypes',
                      'Wallet::Schema::Result::KeytabEnctype',
                      { 'foreign.ke_name' => 'self.ob_name' },
                      { cascade_copy => 0, cascade_delete => 0 },
                     );

__PACKAGE__->has_many(
                      'keytab_sync',
                      'Wallet::Schema::Result::KeytabSync',
                      { 'foreign.ks_name' => 'self.ob_name' },
                      { cascade_copy => 0, cascade_delete => 0 },
                     );

# References for all of the various potential ACLs.
__PACKAGE__->belongs_to(
                        'acls_owner',
                        'Wallet::Schema::Result::Acl',
                        { 'foreign.ac_id' => 'self.ob_owner' },
                       );
__PACKAGE__->belongs_to(
                        'acls_get',
                        'Wallet::Schema::Result::Acl',
                        { 'foreign.ac_id' => 'self.ob_acl_get' },
                       );
__PACKAGE__->belongs_to(
                        'acls_store',
                        'Wallet::Schema::Result::Acl',
                        { 'foreign.ac_id' => 'self.ob_acl_store' },
                       );
__PACKAGE__->belongs_to(
                        'acls_show',
                        'Wallet::Schema::Result::Acl',
                        { 'foreign.ac_id' => 'self.ob_acl_show' },
                       );
__PACKAGE__->belongs_to(
                        'acls_destroy',
                        'Wallet::Schema::Result::Acl',
                        { 'foreign.ac_id' => 'self.ob_acl_destroy' },
                       );
__PACKAGE__->belongs_to(
                        'acls_flags',
                        'Wallet::Schema::Result::Acl',
                        { 'foreign.ac_id' => 'self.ob_acl_flags' },
                       );

1;
