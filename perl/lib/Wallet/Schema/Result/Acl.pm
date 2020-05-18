# Wallet schema for an ACL.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2012-2013
#     The Board of Trustees of the Leland Stanford Junior University
#
# SPDX-License-Identifier: MIT

package Wallet::Schema::Result::Acl;

use strict;
use warnings;

use base 'DBIx::Class::Core';

our $VERSION = '1.05';

=for stopwords
ACL

=head1 NAME

Wallet::Schema::Result::Acl - Wallet schema for an ACL

=head1 DESCRIPTION

=cut

__PACKAGE__->table("acls");

=head1 ACCESSORS

=head2 ac_id

  data_type: 'integer'
  is_auto_increment: 1
  is_nullable: 0

=head2 ac_name

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=cut

__PACKAGE__->add_columns(
  "ac_id",
  { data_type => "integer", is_auto_increment => 1, is_nullable => 0 },
  "ac_name",
  { data_type => "varchar", is_nullable => 0, size => 255 },
);
__PACKAGE__->set_primary_key("ac_id");
__PACKAGE__->add_unique_constraint("ac_name", ["ac_name"]);

__PACKAGE__->has_one(
                     'acl_entries',
                     'Wallet::Schema::Result::AclEntry',
                     { 'foreign.ae_id' => 'self.ac_id' },
                     { cascade_copy => 0, cascade_delete => 0 },
                    );
__PACKAGE__->has_many(
                      'acl_history',
                      'Wallet::Schema::Result::AclHistory',
                      { 'foreign.ah_id' => 'self.ac_id' },
                      { cascade_copy => 0, cascade_delete => 0 },
                     );

# References for all of the various potential ACLs in owners.
__PACKAGE__->has_many(
                        'acls_owner',
                        'Wallet::Schema::Result::Object',
                        { 'foreign.ob_owner' => 'self.ac_id' },
                       );
__PACKAGE__->has_many(
                        'acls_get',
                        'Wallet::Schema::Result::Object',
                        { 'foreign.ob_acl_get' => 'self.ac_id' },
                       );
__PACKAGE__->has_many(
                        'acls_store',
                        'Wallet::Schema::Result::Object',
                        { 'foreign.ob_acl_store' => 'self.ac_id' },
                       );
__PACKAGE__->has_many(
                        'acls_show',
                        'Wallet::Schema::Result::Object',
                        { 'foreign.ob_acl_show' => 'self.ac_id' },
                       );
__PACKAGE__->has_many(
                        'acls_destroy',
                        'Wallet::Schema::Result::Object',
                        { 'foreign.ob_acl_destroy' => 'self.ac_id' },
                       );
__PACKAGE__->has_many(
                        'acls_flags',
                        'Wallet::Schema::Result::Object',
                        { 'foreign.ob_acl_flags' => 'self.ac_id' },
                       );

# Override the insert method so that we can automatically create history
# items.
#sub insert {
#    my ($self, @args) = @_;
#    my $ret = $self->next::method (@args);
#    print "ID: ".$self->ac_id."\n";
#    use Data::Dumper; print Dumper (@args);

#    return $self;
#}

1;
