#!/usr/bin/perl -w
#
# Tests for the wallet server configuration.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2008, 2010
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

use Test::More tests => 6;

# Silence warnings since we're not using use.
package Wallet::Config;
our $DB_DRIVER;
our $KEYTAB_AFS_KASETKEY;
our $KEYTAB_FLAGS;
our $KEYTAB_KADMIN;
package main;

# Load with a nonexistent file.
$ENV{WALLET_CONFIG} = '/path/to/nonexistent/file';
eval { require Wallet::Config };
is ($@, '', 'Loading Wallet::Config with nonexistent config file works');
is ($Wallet::Config::KEYTAB_FLAGS, '-clearpolicy',
    ' and KEYTAB_FLAGS is correct');
is ($Wallet::Config::KEYTAB_KADMIN, 'kadmin',
    ' and KEYTAB_KADMIN is correct');
is ($Wallet::Config::DB_DRIVER, undef, ' and DB_DRIVER is unset');

# Create a configuration file with a single setting.
open (CONFIG, '>', 'test-wallet.conf')
    or die "$0: cannot create test-wallet.conf: $!\n";
print CONFIG '$DB_DRIVER = "mysql";', "\n";
print CONFIG "1;\n";
close CONFIG;
$ENV{WALLET_CONFIG} = './test-wallet.conf';

# Reload the module and be sure it picks up that configuration file.
delete $INC{'Wallet/Config.pm'};
eval { require Wallet::Config };
is ($@, '', 'Loading Wallet::Config with new config file works');
is ($Wallet::Config::DB_DRIVER, 'mysql', ' and now DB_DRIVER is set');
unlink 'test-wallet.conf';
