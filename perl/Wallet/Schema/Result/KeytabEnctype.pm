package Wallet::Schema::Result::KeytabEnctype;

use strict;
use warnings;

use base 'DBIx::Class::Core';

=head1 NAME

Wallet::Schema::Result::KeytabEnctype

=head1 DESCRIPTION

=cut

__PACKAGE__->table("keytab_enctypes");

=head1 ACCESSORS

=head2 ke_name

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=head2 ke_enctype

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=cut

__PACKAGE__->add_columns(
  "ke_name",
  { data_type => "varchar", is_nullable => 0, size => 255 },
  "ke_enctype",
  { data_type => "varchar", is_nullable => 0, size => 255 },
);
__PACKAGE__->set_primary_key("ke_name", "ke_enctype");

1;
