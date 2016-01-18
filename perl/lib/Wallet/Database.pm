# Wallet::Database -- Wallet system database connection management
#
# This module is a thin wrapper around DBIx::Class to handle determination
# of the database configuration settings automatically on connect.  The
# intention is that Wallet::Database objects can be treated in all respects
# like DBIx::Class objects in the rest of the code.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2016 Russ Allbery <eagle@eyrie.org>
# Copyright 2008, 2009, 2010, 2012, 2013, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Database;

use 5.008;
use strict;
use warnings;

use Wallet::Config;
use Wallet::Schema;

our @ISA     = qw(Wallet::Schema);
our $VERSION = '1.03';

##############################################################################
# Core overrides
##############################################################################

# Override DBI::connect to supply our own connect string, username, and
# password and to set some standard options.  Takes no arguments other than
# the implicit class argument.
sub connect {
    my ($class) = @_;
    unless ($Wallet::Config::DB_DRIVER
            and (defined ($Wallet::Config::DB_INFO)
                 or defined ($Wallet::Config::DB_NAME))) {
        die "database connection information not configured\n";
    }
    my $dsn = "DBI:$Wallet::Config::DB_DRIVER:";
    if (defined $Wallet::Config::DB_INFO) {
        $dsn .= $Wallet::Config::DB_INFO;
    } else {
        $dsn .= "database=$Wallet::Config::DB_NAME";
        $dsn .= ";host=$Wallet::Config::DB_HOST" if $Wallet::Config::DB_HOST;
        $dsn .= ";port=$Wallet::Config::DB_PORT" if $Wallet::Config::DB_PORT;
    }
    my $user = $Wallet::Config::DB_USER;
    my $pass = $Wallet::Config::DB_PASSWORD;
    my %attrs = (PrintError => 0, RaiseError => 1);
    my $dbh = eval { $class->SUPER::connect ($dsn, $user, $pass, \%attrs) };
    if ($@) {
        die "cannot connect to database: $@\n";
    }
    return $dbh;
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=head1 NAME

Wallet::Dabase - Wrapper module for wallet database connections

=for stopwords
DBI RaiseError PrintError AutoCommit Allbery

=head1 SYNOPSIS

    use Wallet::Database;
    my $dbh = Wallet::Database->connect;

=head1 DESCRIPTION

Wallet::Database is a thin wrapper module around DBI that takes care of
building a connect string and setting database options based on wallet
configuration.  The only overridden method is connect().  All other
methods should work the same as in DBI and Wallet::Database objects should
be usable exactly as if they were DBI objects.

connect() will obtain the database connection information from the wallet
configuration; see L<Wallet::Config> for more details.  It will also
automatically set the RaiseError attribute to true and the PrintError and
AutoCommit attributes to false, matching the assumptions made by the
wallet database code.

=head1 CLASS METHODS

=over 4

=item connect()

Opens a new database connection and returns the database object.  On any
failure, throws an exception.  Unlike the DBI method, connect() takes no
arguments; all database connection information is derived from the wallet
configuration.

=back

=head1 SEE ALSO

DBI(3), Wallet::Config(3)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=cut
