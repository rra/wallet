package Wallet::Schema::Result::AclEntry;

use strict;
use warnings;

use base 'DBIx::Class::Core';

=head1 NAME

Wallet::Schema::Result::AclEntry

=head1 DESCRIPTION

=cut

__PACKAGE__->table("acl_entries");

=head1 ACCESSORS

=head2 ae_id

  data_type: 'integer'
  is_nullable: 0

=head2 ae_scheme

  data_type: 'varchar'
  is_nullable: 0
  size: 32

=head2 ae_identifier

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=cut

__PACKAGE__->add_columns(
  "ae_id",
  { data_type => "integer", is_nullable => 0 },
  "ae_scheme",
  { data_type => "varchar", is_nullable => 0, size => 32 },
  "ae_identifier",
  { data_type => "varchar", is_nullable => 0, size => 255 },
);
__PACKAGE__->set_primary_key("ae_id", "ae_scheme", "ae_identifier");

__PACKAGE__->belongs_to(
                      'acls',
                      'Wallet::Schema::Result::Acl',
                      { 'foreign.ac_id' => 'self.ae_id' },
                      { is_deferrable => 1, on_delete => 'CASCADE',
                        on_update => 'CASCADE' },
                     );

__PACKAGE__->has_one(
                     'acl_scheme',
                     'Wallet::Schema::Result::AclScheme',
                     { 'foreign.as_name' => 'self.ae_scheme' },
                     { cascade_delete => 0 },
                    );
1;
