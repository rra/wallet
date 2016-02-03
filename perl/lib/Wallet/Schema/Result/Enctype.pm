# Wallet schema for Kerberos encryption type.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2012, 2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package Wallet::Schema::Result::Enctype;

use strict;
use warnings;

use base 'DBIx::Class::Core';

our $VERSION = '1.03';

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
