# Util -- Utility class for wallet tests.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

package Util;
require 5.006;

use strict;
use vars qw(@ISA @EXPORT $VERSION);

use Wallet::Config;

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.01';

use Exporter ();
@ISA    = qw(Exporter);
@EXPORT = qw(contents db_setup);

##############################################################################
# General utility functions
##############################################################################

# Returns the one-line contents of a file as a string, removing the newline.
sub contents {
    my ($file) = @_;
    open (FILE, '<', $file) or die "cannot open $file: $!\n";
    my $data = <FILE>;
    close FILE;
    chomp $data;
    return $data;
}

##############################################################################
# User test configuration
##############################################################################

# Set up the database configuration parameters.  Use a local SQLite database
# for testing by default, but support t/data/test.database as a configuration
# file to use another database backend.
sub db_setup {
    if (-f 't/data/test.database') {
        open (DB, '<', 't/data/test.database')
            or die "cannot open t/data/test.database: $!";
        my $driver = <DB>;
        my $info = <DB>;
        my $user = <DB>;
        my $password = <DB>;
        chomp ($driver, $info);
        chomp $user if $user;
        chomp $password if $password;
        $Wallet::Config::DB_DRIVER = $driver;
        $Wallet::Config::DB_INFO = $info;
        $Wallet::Config::DB_USER = $user if $user;
        $Wallet::Config::DB_PASSWORD = $password if $password;
    } else {
        $Wallet::Config::DB_DRIVER = 'SQLite';
        $Wallet::Config::DB_INFO = 'wallet-db';
        unlink 'wallet-db';
    }
}
