# Wallet schema for object flags.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2012-2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# SPDX-License-Identifier: MIT

package Wallet::Schema::Result::Flag;

use strict;
use warnings;

use base 'DBIx::Class::Core';

our $VERSION = '1.04';

=head1 NAME

Wallet::Schema::Result::Flag - Wallet schema for object flags

=head1 DESCRIPTION

=cut

__PACKAGE__->table("flags");

=head1 ACCESSORS

=head2 fl_type

  data_type: 'varchar'
  is_nullable: 0
  size: 16

=head2 fl_name

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=head2 fl_flag

  data_type: 'varchar'
  is_nullable: 0
  size: 32

=cut

__PACKAGE__->add_columns(
  "fl_type" =>
  { data_type => "varchar", is_nullable => 0, size => 16 },
  "fl_name" =>
  { data_type => "varchar", is_nullable => 0, size => 255 },
  "fl_flag" => {
      data_type => 'enum',
      is_enum   => 1,
      extra     => { list => [qw/locked unchanging/] },
  },
);
__PACKAGE__->set_primary_key("fl_type", "fl_name", "fl_flag");


1;
