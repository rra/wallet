# Wallet schema for keytab enctype.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2012, 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package Wallet::Schema::Result::KeytabEnctype;

use strict;
use warnings;

use base 'DBIx::Class::Core';

=for stopwords
keytab enctype

=head1 NAME

Wallet::Schema::Result::KeytabEnctype - Wallet schema for keytab enctype

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
