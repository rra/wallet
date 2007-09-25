#!/usr/bin/perl -w
# $Id$
#
# t/schema.t -- Tests for the wallet schema class.

use Test::More tests => 5;

use DBI;
use Wallet::Schema;

my $schema = Wallet::Schema->new;
ok (defined $schema, 'Wallet::Schema creation');
ok ($schema->isa ('Wallet::Schema'), ' and class verification');
my @sql = $schema->sql;
ok (@sql > 0, 'sql() returns something');
is (scalar (@sql), 26, ' and returns the right number of statements');

# Create a SQLite database to use for create.
unlink 'wallet-db';
my $dbh = DBI->connect ("DBI:SQLite:wallet-db");
if (not defined $dbh) {
    die "cannot create database wallet-db: $DBI::errstr\n";
}
$dbh->{RaiseError} = 1;
$dbh->{PrintError} = 0;
eval { $schema->create ($dbh) };
is ($@, '', "create() doesn't die");

# Clean up.
unlink 'wallet-db';
