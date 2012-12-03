package Wallet::Schema::Result::AclScheme;

use strict;
use warnings;

use base 'DBIx::Class::Core';
__PACKAGE__->load_components (qw//);

=head1 NAME

Wallet::Schema::Result::AclScheme

=head1 DESCRIPTION

This is a normalization table used to constrain the values in other
tables.  It contains the types of ACL schemes that Wallet will
recognize, and the modules that govern each of those schemes.

By default it contains the following entries:

  insert into acl_schemes (as_name, as_class)
      values ('krb5', 'Wallet::ACL::Krb5');
  insert into acl_schemes (as_name, as_class)
      values ('krb5-regex', 'Wallet::ACL::Krb5::Regex');
  insert into acl_schemes (as_name, as_class)
      values ('ldap-attr', 'Wallet::ACL::LDAP::Attribute');
  insert into acl_schemes (as_name, as_class)
      values ('netdb', 'Wallet::ACL::NetDB');
  insert into acl_schemes (as_name, as_class)
      values ('netdb-root', 'Wallet::ACL::NetDB::Root');

If you have extended the wallet to support additional ACL schemes, you
will want to add additional rows to this table mapping those schemes
to Perl classes that implement the ACL verifier APIs.

=cut

__PACKAGE__->table("acl_schemes");

=head1 ACCESSORS

=head2 as_name

  data_type: 'varchar'
  is_nullable: 0
  size: 32

=head2 as_class

  data_type: 'varchar'
  is_nullable: 1
  size: 64

=cut

__PACKAGE__->add_columns(
  "as_name",
  { data_type => "varchar", is_nullable => 0, size => 32 },
  "as_class",
  { data_type => "varchar", is_nullable => 1, size => 64 },
);
__PACKAGE__->set_primary_key("as_name");

#__PACKAGE__->resultset->populate ([
#                       [ qw/as_name as_class/ ],
#                       [ 'krb5',       'Wallet::ACL::Krb5'            ],
#                       [ 'krb5-regex', 'Wallet::ACL::Krb5::Regex'     ],
#                       [ 'ldap-attr',  'Wallet::ACL::LDAP::Attribute' ],
#                       [ 'netdb',      'Wallet::ACL::NetDB'           ],
#                       [ 'netdb-root', 'Wallet::ACL::NetDB::Root'     ],
#                      ]);

1;
