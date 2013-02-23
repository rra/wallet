package Wallet::Schema::Result::Enctype;

use strict;
use warnings;

use base 'DBIx::Class::Core';

=for stopwords
Kerberos

=head1 NAME

Wallet::Schema::Result::Enctype - Wallet schema for Kerberos encryption type

=head1 DESCRIPTION

=cut

__PACKAGE__->table("enctypes");

=head1 ACCESSORS

=head2 en_name

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=cut

__PACKAGE__->add_columns(
  "en_name",
  { data_type => "varchar", is_nullable => 0, size => 255 },
);
__PACKAGE__->set_primary_key("en_name");

1;
