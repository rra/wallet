# Wallet schema for Duo metadata.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

package Wallet::Schema::Result::Duo;

use strict;
use warnings;

use base 'DBIx::Class::Core';

our $VERSION = '1.04';

=for stopwords
keytab enctype

=head1 NAME

Wallet::Schema::Result::Duo - Wallet schema for Duo metadata

=head1 DESCRIPTION

=cut

__PACKAGE__->table("duo");

=head1 ACCESSORS

=head2 du_name

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=head2 du_key

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=cut

__PACKAGE__->add_columns(
  "du_name",
  { data_type => "varchar", is_nullable => 0, size => 255 },
  "du_type",
  { data_type => "varchar", is_nullable => 0, size => 16 },
  "du_key",
  { data_type => "varchar", is_nullable => 0, size => 255 },
);
__PACKAGE__->set_primary_key("du_name", "du_type");

__PACKAGE__->belongs_to(
                        'object',
                        'Wallet::Schema::Result::Object',
                        {
                            'foreign.ob_type' => 'self.du_type',
                            'foreign.ob_name' => 'self.du_name',
                        },
                       );
1;
