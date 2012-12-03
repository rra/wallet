# Wallet::Database -- Wallet system database connection management.
#
# This module is a thin wrapper around DBIx::Class to handle determination
# of the database configuration settings automatically on connect.  The
# intention is that Wallet::Database objects can be treated in all respects
# like DBIx::Class objects in the rest of the code.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2008-2012 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Database;
require 5.006;

use strict;
use vars qw(@ISA $VERSION);

use Wallet::Schema;
use Wallet::Config;

@ISA = qw(Wallet::Schema);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.04';

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

Russ Allbery <rra@stanford.edu>

=cut
