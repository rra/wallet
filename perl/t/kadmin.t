#!/usr/bin/perl -w
#
# t/kadmin.t -- Tests for the kadmin object implementation.
#
# Written by Jon Robertson <jonrober@stanford.edu>
# Copyright 2009, 2010 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

use POSIX qw(strftime);
use Test::More tests => 32;

BEGIN { $Wallet::Config::KEYTAB_TMP = '.' }

use Wallet::Admin;
use Wallet::Config;
use Wallet::Kadmin;
use Wallet::Kadmin::MIT;

# Only load Wallet::Kadmin::Heimdal if a required module is found.
my $heimdal_kadm5 = 0;
eval 'use Heimdal::Kadm5';
if (!$@) {
    $heimdal_kadm5 = 1;
    require Wallet::Kadmin::Heimdal;
}

use lib 't/lib';
use Util;

# Test creating an MIT object and seeing if the callback works.
$Wallet::Config::KEYTAB_KRBTYPE = 'MIT';
my $kadmin = Wallet::Kadmin->new;
ok (defined ($kadmin), 'MIT kadmin object created');
my $callback = sub { return 1 };
$kadmin->fork_callback ($callback);
is ($kadmin->{fork_callback} (), 1, ' and callback works');
$callback = sub { return 2 };
$kadmin->fork_callback ($callback);
is ($kadmin->{fork_callback} (), 2, ' and changing it works');

# Check principal validation in the Wallet::Kadmin::MIT module.  This is
# specific to that module, since Heimdal doesn't require passing the principal
# through the kadmin client.
for my $bad (qw{service\* = host/foo+bar host/foo/bar /bar bar/ rcmd.foo}) {
    ok (! Wallet::Kadmin::MIT->valid_principal ($bad),
        "Invalid principal name $bad");
}
for my $good (qw{service service/foo bar foo/bar host/example.org
                 aservice/foo}) {
    ok (Wallet::Kadmin::MIT->valid_principal ($good),
        "Valid principal name $good");
}

# Test creating a Heimdal object.  We deliberately connect without
# configuration to get the error.  That tests that we can find the Heimdal
# module and it dies how it should.
SKIP: {
    skip 'Heimdal::Kadm5 not installed', 3 unless $heimdal_kadm5;
    undef $Wallet::Config::KEYTAB_PRINCIPAL;
    undef $Wallet::Config::KEYTAB_FILE;
    undef $Wallet::Config::KEYTAB_REALM;
    undef $kadmin;
    $Wallet::Config::KEYTAB_KRBTYPE = 'Heimdal';
    $kadmin = eval { Wallet::Kadmin->new };
    is ($kadmin, undef, 'Heimdal fails properly');
    is ($@, "keytab object implementation not configured\n",
        ' with the right error');
}

# Now, check the generic API.  We can run this test no matter which
# implementation is configured.  This retests some things that are also tested
# by the keytab test, but specifically through the Wallet::Kadmin API.
SKIP: {
    skip 'no keytab configuration', 14 unless -f 't/data/test.keytab';

    # Set up our configuration.
    $Wallet::Config::KEYTAB_FILE      = 't/data/test.keytab';
    $Wallet::Config::KEYTAB_PRINCIPAL = contents ('t/data/test.principal');
    $Wallet::Config::KEYTAB_REALM     = contents ('t/data/test.realm');
    $Wallet::Config::KEYTAB_KRBTYPE   = contents ('t/data/test.krbtype');
    $Wallet::Config::KEYTAB_TMP       = '.';

    # Create the object and clean up the principal we're going to use.
    $kadmin = eval { Wallet::Kadmin->new };
    ok (defined $kadmin, 'Creating Wallet::Kadmin object succeeds');
    is ($@, '', ' and there is no error');
    is ($kadmin->destroy ('wallet/one'), 1, 'Deleting wallet/one works');
    is ($kadmin->exists ('wallet/one'), 0, ' and it does not exist');

    # Create the principal and check that keytab returns something.  We'll
    # check the details of the return in the keytab check.
    is ($kadmin->create ('wallet/one'), 1, 'Creating wallet/one works');
    is ($kadmin->exists ('wallet/one'), 1, ' and it now exists');
    my $data = $kadmin->keytab_rekey ('wallet/one');
    ok (defined ($data), ' and retrieving a keytab works');
    is (keytab_valid ($data, 'wallet/one'), 1,
        ' and works for authentication');

    # Delete the principal and confirm behavior.
    is ($kadmin->destroy ('wallet/one'), 1, 'Deleting principal works');
    is ($kadmin->exists ('wallet/one'), 0, ' and now it does not exist');
    is ($kadmin->keytab_rekey ('wallet/one', './tmp.keytab'), undef,
        ' and retrieving the keytab does not work');
    ok (! -f './tmp.keytab', ' and no file was created');
    like ($kadmin->error, qr%^error creating keytab for wallet/one%,
          ' and the right error message is set');
    is ($kadmin->destroy ('wallet/one'), 1, ' and deleting it again works');
}
