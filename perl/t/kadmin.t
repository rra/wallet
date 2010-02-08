#!/usr/bin/perl -w
#
# t/kadmin.t -- Tests for the kadmin object implementation.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2009 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

use POSIX qw(strftime);
use Test::More tests => 17;

use Wallet::Admin;
use Wallet::Config;
use Wallet::Kadmin;
use Wallet::Kadmin::MIT;

# Only load Wallet::Kadmin::Heimdal if a required module is found.
my $heimdal_kadm5 = 0;
eval 'use Heimdal::Kadm5';
if (!$@) {
    print "No error...\n";
    $heimdal_kadm5 = 1;
    require Wallet::Kadmin::Heimdal;
}

use lib 't/lib';
use Util;

# We test a Wallet::Kadmin::* module's actual workings in the keytab.t tests.
# The only things we want to test here are that each module is found, that
# Wallet::Kadmin itself delegates to them, and that the private MIT principal
# validation works as it should.
for my $bad (qw{service\* = host/foo+bar host/foo/bar /bar bar/
                rcmd.foo}) {
    ok (! Wallet::Kadmin::MIT->valid_principal ($bad),
        "Invalid principal name $bad");
}
for my $good (qw{service service/foo bar foo/bar host/example.org
                 aservice/foo}) {
    ok (Wallet::Kadmin::MIT->valid_principal ($good),
        "Valid principal name $good");
}

# Test creating an MIT object and seeing if the callback works.
$Wallet::Config::KEYTAB_KRBTYPE = 'MIT';
my $kadmin = Wallet::Kadmin->new;
ok (defined ($kadmin), 'MIT kadmin object created');
my $callback = sub { return 1 };
$kadmin->fork_callback ($callback);
is ($kadmin->{fork_callback} (), 1, ' and callback works.');
$callback = sub { return 2 };
$kadmin->fork_callback ($callback);
is ($kadmin->{fork_callback} (), 2, ' and changing it works.');

# Test creating a Heimdal object.  For us to test a working Heimdal object,
# we need a properly configured Heimdal KDC.  So instead, we deliberately
# connect without configuration to get the error.  That at least tests that
# we can find the Heimdal module and it dies how it should.
SKIP: {
    skip 'Heimdal::Kadm5 not installed', 1 unless $heimdal_kadm5;
    undef $Wallet::Config::KEYTAB_PRINCIPAL;
    undef $Wallet::Config::KEYTAB_FILE;
    undef $Wallet::Config::KEYTAB_REALM;
    undef $kadmin;
    $Wallet::Config::KEYTAB_KRBTYPE = 'Heimdal';
    $kadmin = eval { Wallet::Kadmin->new };
    is ($kadmin, undef, 'Heimdal fails properly.');
}
