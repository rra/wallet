package Wallet::Schema::Result::KeytabSync;

use strict;
use warnings;

use base 'DBIx::Class::Core';

=for stopwords
keytab

=head1 NAME

Wallet::Schema::Result::KeytabSync - Wallet schema for keytab synchronization

=head1 DESCRIPTION

=cut

__PACKAGE__->table("keytab_sync");

=head1 ACCESSORS

=head2 ks_name

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=head2 ks_target

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=cut

__PACKAGE__->add_columns(
  "ks_name",
  { data_type => "varchar", is_nullable => 0, size => 255 },
  "ks_target",
  { data_type => "varchar", is_nullable => 0, size => 255 },
);
__PACKAGE__->set_primary_key("ks_name", "ks_target");

1;
