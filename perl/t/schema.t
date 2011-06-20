#!/usr/bin/perl -w
#
# Tests for the wallet schema class.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007, 2008, 2011
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use Test::More tests => 16;

use DBI ();
use POSIX qw(strftime);
use Wallet::Config ();
use Wallet::Schema ();

use lib 't/lib';
use Util;

my $schema = Wallet::Schema->new;
ok (defined $schema, 'Wallet::Schema creation');
ok ($schema->isa ('Wallet::Schema'), ' and class verification');
my @sql = $schema->sql;
ok (@sql > 0, 'sql() returns something');
is (scalar (@sql), 31, ' and returns the right number of statements');

# Connect to a database and test create.
db_setup;
my $connect = "DBI:${Wallet::Config::DB_DRIVER}:${Wallet::Config::DB_INFO}";
my $user = $Wallet::Config::DB_USER;
my $password = $Wallet::Config::DB_PASSWORD;
$dbh = DBI->connect ($connect, $user, $password);
if (not defined $dbh) {
    die "cannot connect to database $connect: $DBI::errstr\n";
}
$dbh->{RaiseError} = 1;
$dbh->{PrintError} = 0;
eval { $schema->create ($dbh) };
is ($@, '', "create() doesn't die");

# Check that the version number is correct.
my $sql = "select md_version from metadata";
my $version = $dbh->selectall_arrayref ($sql);
is (@$version, 1, 'metadata has correct number of rows');
is (@{ $version->[0] }, 1, ' and correct number of columns');
is ($version->[0][0], 1, ' and the schema version is correct');

# Test upgrading the database from version 0.  SQLite cannot drop table
# columns, so we have to kill the table and then recreate it.
$dbh->do ("drop table metadata");
if (lc ($Wallet::Config::DB_DRIVER) eq 'sqlite') {
    ($sql) = grep { /create table objects/ } $schema->sql;
    $sql =~ s/ob_comment .*,//;
    $dbh->do ("drop table objects")
        or die "cannot drop objects table: $DBI::errstr\n";
    $dbh->do ($sql)
        or die "cannot recreate objects table: $DBI::errstr\n";
} else {
    $dbh->do ("alter table objects drop column ob_comment")
        or die "cannot drop ob_comment column: $DBI::errstr\n";
}
eval { $schema->upgrade ($dbh) };
is ($@, '', "upgrade() doesn't die");
$sql = "select md_version from metadata";
$version = $dbh->selectall_arrayref ($sql);
is (@$version, 1, ' and metadata has correct number of rows');
is (@{ $version->[0] }, 1, ' and correct number of columns');
is ($version->[0][0], 1, ' and the schema version is correct');
$sql = "insert into objects (ob_type, ob_name, ob_created_by, ob_created_from,
    ob_created_on, ob_comment) values ('file', 'test', 'test',
    'test.example.org', ?, 'a test comment')";
$dbh->do ($sql, undef, strftime ('%Y-%m-%d %T', localtime time));
$sql = "select ob_comment from objects where ob_name = 'test'";
my ($comment) = $dbh->selectrow_array ($sql);
is ($comment, 'a test comment', ' and ob_comment was added to objects');

# Test dropping the database.
eval { $schema->drop ($dbh) };
is ($@, '', "drop() doesn't die");

# Make sure all the tables are gone.
SKIP: {
    if (lc ($Wallet::Config::DB_DRIVER) eq 'sqlite') {
        my $sql = "select name from sqlite_master where type = 'table'";
        my $sth = $dbh->prepare ($sql);
        $sth->execute;
        my ($table, @tables);
        while (defined ($table = $sth->fetchrow_array)) {
            push (@tables, $table) unless $table =~ /^sqlite_/;
        }
        is ("@tables", '', ' and there are no tables in the database');
    } elsif (lc ($Wallet::Config::DB_DRIVER) eq 'mysql') {
        my $sql = "show tables";
        my $sth = $dbh->prepare ($sql);
        $sth->execute;
        my ($table, @tables);
        while (defined ($table = $sth->fetchrow_array)) {
            push (@tables, $table);
        }
        is ("@tables", '', ' and there are no tables in the database');
    } else {
        skip 1;
    }
}
eval { $schema->create ($dbh) };
is ($@, '', ' and we can run create again');

# Clean up.
eval { $schema->drop ($dbh) };
unlink 'wallet-db';
