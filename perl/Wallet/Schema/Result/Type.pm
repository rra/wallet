package Wallet::Schema::Result::Type;

use strict;
use warnings;

use base 'DBIx::Class::Core';

=for stopwords
APIs

=head1 NAME

Wallet::Schema::Result::Type - Wallet schema for object types

=head1 DESCRIPTION

This is a normalization table used to constrain the values in other
tables.  It contains the types of wallet objects that are considered
valid, and the modules that govern each.

By default it contains the following entries:

  insert into types (ty_name, ty_class)
      values ('file', 'Wallet::Object::File');
  insert into types (ty_name, ty_class)
      values ('keytab', 'Wallet::Object::Keytab');

If you have extended the wallet to support additional object types ,
you will want to add additional rows to this table mapping those types
to Perl classes that implement the object APIs.

=cut

__PACKAGE__->table("types");

=head1 ACCESSORS

=head2 ty_name

  data_type: 'varchar'
  is_nullable: 0
  size: 16

=head2 ty_class

  data_type: 'varchar'
  is_nullable: 1
  size: 64

=cut

__PACKAGE__->add_columns(
  "ty_name",
  { data_type => "varchar", is_nullable => 0, size => 16 },
  "ty_class",
  { data_type => "varchar", is_nullable => 1, size => 64 },
);
__PACKAGE__->set_primary_key("ty_name");

#__PACKAGE__->has_many(
#                      'objects',
#                      'Wallet::Schema::Result::Object',
#                      { 'foreign.ob_type' => 'self.ty_name' },
#                      { cascade_copy => 0, cascade_delete => 0 },
#                     );

1;
