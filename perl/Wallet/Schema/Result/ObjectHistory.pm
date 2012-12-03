package Wallet::Schema::Result::ObjectHistory;

use strict;
use warnings;

use base 'DBIx::Class::Core';

__PACKAGE__->load_components("InflateColumn::DateTime");

=head1 NAME

Wallet::Schema::Result::ObjectHistory

=head1 DESCRIPTION

=cut

__PACKAGE__->table("object_history");

=head1 ACCESSORS

=head2 oh_id

  data_type: 'integer'
  is_auto_increment: 1
  is_nullable: 0

=head2 oh_type

  data_type: 'varchar'
  is_nullable: 0
  size: 16

=head2 oh_name

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=head2 oh_action

  data_type: 'varchar'
  is_nullable: 0
  size: 16

=head2 oh_field

  data_type: 'varchar'
  is_nullable: 1
  size: 16

=head2 oh_type_field

  data_type: 'varchar'
  is_nullable: 1
  size: 255

=head2 oh_old

  data_type: 'varchar'
  is_nullable: 1
  size: 255

=head2 oh_new

  data_type: 'varchar'
  is_nullable: 1
  size: 255

=head2 oh_by

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=head2 oh_from

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=head2 oh_on

  data_type: 'datetime'
  datetime_undef_if_invalid: 1
  is_nullable: 0

=cut

__PACKAGE__->add_columns(
  "oh_id",
  { data_type => "integer", is_auto_increment => 1, is_nullable => 0 },
  "oh_type",
  { data_type => "varchar", is_nullable => 0, size => 16 },
  "oh_name",
  { data_type => "varchar", is_nullable => 0, size => 255 },
  "oh_action",
  { data_type => "varchar", is_nullable => 0, size => 16 },
  "oh_field",
  { data_type => "varchar", is_nullable => 1, size => 16 },
  "oh_type_field",
  { data_type => "varchar", is_nullable => 1, size => 255 },
  "oh_old",
  { data_type => "varchar", is_nullable => 1, size => 255 },
  "oh_new",
  { data_type => "varchar", is_nullable => 1, size => 255 },
  "oh_by",
  { data_type => "varchar", is_nullable => 0, size => 255 },
  "oh_from",
  { data_type => "varchar", is_nullable => 0, size => 255 },
  "oh_on",
  {
    data_type => "datetime",
    datetime_undef_if_invalid => 1,
    is_nullable => 0,
  },
);
__PACKAGE__->set_primary_key("oh_id");

__PACKAGE__->might_have(
                        'objects',
                        'Wallet::Schema::Result::Object',
                        { 'foreign.ob_type' => 'self.oh_type',
                          'foreign.ob_name' => 'self.oh_name' },
                       );

1;
