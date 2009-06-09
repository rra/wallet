# Util -- Utility class for wallet tests.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007, 2008 Board of Trustees, Leland Stanford Jr. University
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
$VERSION = '0.02';

use Exporter ();
@ISA    = qw(Exporter);
@EXPORT = qw(contents db_setup getcreds remctld_spawn remctld_stop);

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

##############################################################################
# Local ticket cache
##############################################################################

# Given a keytab file and a principal, try authenticating with kinit.
sub getcreds {
    my ($file, $principal) = @_;
    my @commands = (
        "kinit -k -t $file $principal >/dev/null 2>&1 </dev/null",
        "kinit -t $file $principal >/dev/null 2>&1 </dev/null",
        "kinit -T /bin/true -k -K $file $principal >/dev/null 2>&1 </dev/null",
    );
    for my $command (@commands) {
        if (system ($command) == 0) {
            return 1;
        }
    }
    return 0;
}

##############################################################################
# remctld handling
##############################################################################

# Start remctld with the appropriate options to run our fake keytab backend.
# Takes the path to remctld, the principal it uses as its server principal,
# the keytab it uses for authentication, and the configuration file it should
# load.
sub remctld_spawn {
    my ($path, $principal, $keytab, $config) = @_;
    unlink 'test-pid';
    my @command = ($path, '-m', '-p', 14373, '-s', $principal, '-P',
                   'test-pid', '-f', $config, '-S', '-F', '-k', $keytab);
    print "Starting remctld: @command\n";
    my $pid = fork;
    if (not defined $pid) {
        die "cannot fork: $!\n";
    } elsif ($pid == 0) {
        open (STDERR, '>&STDOUT') or die "cannot redirect stderr: $!\n";
        exec (@command) or die "cannot exec $path: $!\n";
    } else {
        my $tries = 0;
        while ($tries < 10 && ! -f 'test-pid') {
            select (undef, undef, undef, 0.25);
        }
    }
}

# Stop the running remctld process.
sub remctld_stop {
    open (PID, '<', 'test-pid') or return;
    my $pid = <PID>;
    close PID;
    chomp $pid;
    kill 15, $pid;
}
