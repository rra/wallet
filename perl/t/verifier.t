#!/usr/bin/perl -w
# $Id$
#
# t/verifier.t -- Tests for the basic wallet ACL verifiers.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

use Test::More tests => 37;

use Wallet::ACL::Base;
use Wallet::ACL::Krb5;
use Wallet::ACL::NetDB;
use Wallet::Config;

use lib 't/lib';
use Util;

# Given a keytab file, try authenticating with kinit.
sub getcreds {
    my ($file, $principal) = @_;
    my @commands = (
        "kinit -k -t $file $principal >/dev/null </dev/null",
        "kinit -t $file $principal >/dev/null </dev/null",
        "kinit -k -K $file $principal >/dev/null </dev/null",
    );
    for my $command (@commands) {
        if (system ($command) == 0) {
            return 1;
        }
    }
    return 0;
}

# Start remctld with the appropriate options to run our fake keytab backend.
sub spawn_remctld {
    my ($path, $principal, $keytab) = @_;
    unlink 'test-pid';
    my $pid = fork;
    if (not defined $pid) {
        die "cannot fork: $!\n";
    } elsif ($pid == 0) {
        open (STDERR, '>&STDOUT') or die "cannot redirect stderr: $!\n";
        exec ($path, '-m', '-p', 14373, '-s', $principal, '-P', 'test-pid',
              '-f', 't/data/netdb.conf', '-S', '-F', '-k', $keytab) == 0
            or die "cannot exec $path: $!\n";
    } else {
        my $tries = 0;
        while ($tries < 10 && ! -f 'test-pid') {
            select (undef, undef, undef, 0.25);
        }
    }
}

# Stop the running remctld process.
sub stop_remctld {
    open (PID, '<', 'test-pid') or return;
    my $pid = <PID>;
    close PID;
    chomp $pid;
    kill 15, $pid;
}

my $verifier = Wallet::ACL::Base->new;
ok (defined $verifier, 'Wallet::ACL::Base creation');
ok ($verifier->isa ('Wallet::ACL::Base'), ' and class verification');
is ($verifier->check ('rra@stanford.edu', 'rra@stanford.edu'), 0,
    'Default check declines');
is ($verifier->error, undef, 'No error set');

$verifier = Wallet::ACL::Krb5->new;
ok (defined $verifier, 'Wallet::ACL::Krb5 creation');
ok ($verifier->isa ('Wallet::ACL::Krb5'), ' and class verification');
is ($verifier->check ('rra@stanford.edu', 'rra@stanford.edu'), 1,
    'Simple check');
is ($verifier->check ('rra@stanford.edu', 'thoron@stanford.edu'), 0,
    'Simple failure');
is ($verifier->error, undef, 'No error set');
is ($verifier->check (undef, 'rra@stanford.edu'), undef,
    'Undefined principal');
is ($verifier->error, 'no principal specified', ' and right error');
is ($verifier->check ('rra@stanford.edu', ''), undef, 'Empty ACL');
is ($verifier->error, 'malformed krb5 ACL', ' and right error');

# Tests for unchanging support.  Skip these if we don't have a keytab or if we
# can't find remctld.
SKIP: {
    skip 'no keytab configuration', 24 unless -f 't/data/test.keytab';
    my @path = (split (':', $ENV{PATH}), '/usr/local/sbin', '/usr/sbin');
    my ($remctld) = grep { -x $_ } map { "$_/remctld" } @path;
    skip 'remctld not found', 24 unless $remctld;
    eval { require Net::Remctl };
    skip 'Net::Remctl not available', 24 if $@;

    # Set up our configuration.
    $Wallet::Config::NETDB_REALM = 'EXAMPLE.COM';
    my $principal = contents ('t/data/test.principal');

    # Now spawn our remctld server and get a ticket cache.
    unlink ('krb5cc_test', 'test-acl', 'test-pid');
    spawn_remctld ($remctld, $principal, 't/data/test.keytab');
    $ENV{KRB5CCNAME} = 'krb5cc_test';
    getcreds ('t/data/test.keytab', $principal);

    # Finally, we can test.
    my $verifier = eval { Wallet::ACL::NetDB->new };
    is ($verifier, undef, 'Constructor fails without configuration');
    is ($@, "NetDB ACL support not configured\n", ' with the right exception');
    $Wallet::Config::NETDB_REMCTL_CACHE = 'krb5cc_test';
    $verifier = eval { Wallet::ACL::NetDB->new };
    is ($verifier, undef, ' and still fails without host');
    is ($@, "NetDB ACL support not configured\n", ' with the right exception');
    $Wallet::Config::NETDB_REMCTL_HOST = 'localhost';
    $Wallet::Config::NETDB_REMCTL_PRINCIPAL = $principal;
    $Wallet::Config::NETDB_REMCTL_PORT = 14373;
    $verifier = eval { Wallet::ACL::NetDB->new };
    ok (defined $verifier, ' and now creation succeeds');
    ok ($verifier->isa ('Wallet::ACL::NetDB'), ' and returns the right class');
    is ($verifier->check ('test-user', 'all'), undef,
        ' but verification fails without an ACL');
    is ($verifier->error, 'cannot check NetDB ACL: Access denied',
        ' with the right error');

    # Create an ACL so that tests will start working.
    open (ACL, '>', 'test-acl') or die "cannot create test-acl: $!\n";
    print ACL "$principal\n";
    close ACL;
    is ($verifier->check ('test-user', 'all'), 1,
        ' and now verification works');

    # Test the successful verifications.
    for my $node (qw/admin team user/) {
        is ($verifier->check ('test-user', $node), 1,
            "Verification succeeds for $node");
    }

    # Test various failures.
    is ($verifier->check ('test-user', 'unknown'), 0,
        'Verification fails for unknown');
    is ($verifier->check ('test-user', 'none'), 0, ' and for none');
    is ($verifier->check (undef, 'all'), undef,
        'Undefined principal');
    is ($verifier->error, 'no principal specified', ' and right error');
    is ($verifier->check ('test-user', ''), undef, 'Empty ACL');
    is ($verifier->error, 'malformed netdb ACL', ' and right error');
    is ($verifier->check ('error', 'normal'), undef, 'Regular error');
    is ($verifier->error, 'error checking NetDB ACL: some error',
        ' and correct error return');
    is ($verifier->check ('error', 'status'), undef, 'Status-only error');
    is ($verifier->error, 'error checking NetDB ACL', ' and correct error');
    is ($verifier->check ('unknown', 'unknown'), undef, 'Unknown node');
    is ($verifier->error,
        'error checking NetDB ACL: Unknown principal unknown',
        ' and correct error');
    stop_remctld;

    unlink ('krb5cc_test', 'test-acl', 'test-pid');
}
