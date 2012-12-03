package Wallet::Schema::Result::SyncTarget;

use strict;
use warnings;

use base 'DBIx::Class::Core';

=head1 NAME

Wallet::Schema::Result::SyncTarget

=head1 DESCRIPTION

=cut

__PACKAGE__->table("sync_targets");

=head1 ACCESSORS

=head2 st_name

  data_type: 'varchar'
  is_nullable: 0
  size: 255

=cut

__PACKAGE__->add_columns(
  "st_name",
  { data_type => "varchar", is_nullable => 0, size => 255 },
);
__PACKAGE__->set_primary_key("st_name");

#__PACKAGE__->has_many(
#                      'keytab_sync',
#                      'Wallet::Schema::Result::KeytabSync',
#                      { 'foreign.ks_target' => 'self.st_name' },
#                      { cascade_copy => 0, cascade_delete => 0 },
#                     );
1;
