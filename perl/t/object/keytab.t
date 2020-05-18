#!/usr/bin/perl
#
# Tests for the keytab object implementation.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2020 Russ Allbery <eagle@eyrie.org>
# Copyright 2007-2010, 2013-2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# SPDX-License-Identifier: MIT

use strict;
use warnings;

use POSIX qw(strftime);
use Test::More tests => 142;

BEGIN { $Wallet::Config::KEYTAB_TMP = '.' }

use DBI;
use Wallet::Admin;
use Wallet::Config;
use Wallet::Kadmin;
use Wallet::Object::Keytab;

use lib 't/lib';
use Util;

# Mapping of klist -ke output from old MIT Kerberos implementations to to the
# strings that Kerberos uses internally.  It's very annoying to have to
# maintain this, and it probably breaks with Heimdal.
#
# Newer versions of MIT Kerberos just print out the canonical enctype names
# and don't need this logic, but the current test requires that they still
# have entries.  That's why the second set where the key and value are the
# same.
my %enctype =
    ('triple des cbc mode with hmac/sha1'      => 'des3-cbc-sha1',
     'des cbc mode with crc-32'                => 'des-cbc-crc',
     'des cbc mode with rsa-md5'               => 'des-cbc-md5',
     'aes-128 cts mode with 96-bit sha-1 hmac' => 'aes128-cts-hmac-sha1-96',
     'aes-256 cts mode with 96-bit sha-1 hmac' => 'aes256-cts-hmac-sha1-96',
     'arcfour with hmac/md5'                   => 'rc4-hmac',

     'des3-cbc-sha1'                           => 'des3-cbc-sha1',
     'des-cbc-crc'                             => 'des-cbc-crc',
     'des-cbc-md5'                             => 'des-cbc-md5',
     'aes128-cts-hmac-sha1-96'                 => 'aes128-cts-hmac-sha1-96',
     'aes256-cts-hmac-sha1-96'                 => 'aes256-cts-hmac-sha1-96',
     'rc4-hmac'                                => 'rc4-hmac');

# Some global defaults to use.
my $user = 'admin@EXAMPLE.COM';
my $host = 'localhost';
my @trace = ($user, $host, time);

# Flush all output immediately.
$| = 1;

# Run a command and throw away the output, returning the exit status.
sub system_quiet {
    my ($command, @args) = @_;
    my $pid = fork;
    if (not defined $pid) {
        die "cannot fork: $!\n";
    } elsif ($pid == 0) {
        open (STDIN, '<', '/dev/null') or die "cannot reopen stdin: $!\n";
        open (STDOUT, '>', '/dev/null') or die "cannot reopen stdout: $!\n";
        open (STDERR, '>', '/dev/null') or die "cannot reopen stderr: $!\n";
        exec ($command, @args) or die "cannot exec $command: $!\n";
    } else {
        waitpid ($pid, 0);
        return $?;
    }
}

# Create a principal out of Kerberos.  Only usable once the configuration has
# been set up.
sub create {
    my ($principal) = @_;
    my $kadmin = Wallet::Kadmin->new;
    return $kadmin->create ($principal);
}

# Destroy a principal out of Kerberos.  Only usable once the configuration has
# been set up.
sub destroy {
    my ($principal) = @_;
    my $kadmin = Wallet::Kadmin->new;
    return $kadmin->destroy ($principal);
}

# Check whether a principal exists.  MIT uses kvno and Heimdal uses kgetcred.
# Note that the Kerberos type may be different than our local userspace, so
# don't use the Kerberos type to decide here.  Instead, check for which
# program is available on the path.
sub created {
    my ($principal) = @_;
    $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    local $ENV{KRB5CCNAME} = 'krb5cc_temp';
    getcreds ('t/data/test.keytab', $Wallet::Config::KEYTAB_PRINCIPAL);
    if (grep { -x "$_/kvno" } split (':', $ENV{PATH})) {
        return (system_quiet ('kvno', $principal) == 0);
    } elsif (grep { -x "$_/kgetcred" } split (':', $ENV{PATH})) {
        return (system_quiet ('kgetcred', $principal) == 0);
    } else {
        warn "# No kvno or kgetcred found\n";
        return;
    }
}

# Given keytab data, write it to a file and try to determine the enctypes of
# the keys present in that file.  Returns the enctypes as a list, with UNKNOWN
# for encryption types that weren't recognized.  This is an ugly way of doing
# this for MIT.  Heimdal is much more straightforward, but MIT ktutil doesn't
# have the needed abilities.
sub enctypes {
    my ($keytab) = @_;
    open (KEYTAB, '>', 'keytab') or die "cannot create keytab: $!\n";
    print KEYTAB $keytab;
    close KEYTAB;

    my @enctypes;
    my $pid = open (KLIST, '-|');
    if (not defined $pid) {
        die "cannot fork: $!\n";
    } elsif ($pid == 0) {
        open (STDERR, '>', '/dev/null') or die "cannot reopen stderr: $!\n";
        exec ('klist', '-ke', 'keytab')
            or die "cannot run klist: $!\n";
    }
    local $_;
    while (<KLIST>) {
        next unless /^ *\d+ /;
        my ($string) = /\((.*)\)\s*$/;
        next unless $string;
        my $enctype = $enctype{lc $string} || 'UNKNOWN';
        push (@enctypes, $enctype);
    }
    close KLIST;

    # If that failed, we may have a Heimdal user space instead, so try ktutil.
    # If we try this directly, it will just hang with MIT ktutil.
    if ($? != 0 || !@enctypes) {
        @enctypes = ();
        open (KTUTIL, '-|', 'ktutil', '-k', 'keytab', 'list')
            or die "cannot run ktutil: $!\n";
        local $_;
        while (<KTUTIL>) {
            next unless /^ *\d+ /;
            my ($string) = /^\s*\d+\s+(\S+)/;
            next unless $string;
            push (@enctypes, $string);
        }
        close KTUTIL;
    }
    unlink 'keytab';
    return sort @enctypes;
}

# Use Wallet::Admin to set up the database.
unlink ('krb5cc_temp', 'krb5cc_test', 'test-acl', 'test-pid');
db_setup;
my $admin = eval { Wallet::Admin->new };
is ($@, '', 'Database connection succeeded');
is ($admin->reinitialize ($user), 1, 'Database initialization succeeded');
my $schema = $admin->schema;
my $dbh = $admin->dbh;

# Use this to accumulate the history traces so that we can check history.
my $history = '';
my $date = strftime ('%Y-%m-%d %H:%M:%S', localtime $trace[2]);

# Basic keytab creation and manipulation tests.
SKIP: {
    skip 'no keytab configuration', 53 unless -f 't/data/test.keytab';

    # Set up our configuration.
    $Wallet::Config::KEYTAB_FILE      = 't/data/test.keytab';
    $Wallet::Config::KEYTAB_PRINCIPAL = contents ('t/data/test.principal');
    $Wallet::Config::KEYTAB_REALM     = contents ('t/data/test.realm');
    $Wallet::Config::KEYTAB_KRBTYPE   = contents ('t/data/test.krbtype');
    my $realm = $Wallet::Config::KEYTAB_REALM;

    # Clean up the principals we're going to use.
    destroy ('wallet/one');
    destroy ('wallet/two');

    # Don't destroy the user's Kerberos ticket cache.
    $ENV{KRB5CCNAME} = 'krb5cc_test';

    # Test that object creation without KEYTAB_TMP fails.
    undef $Wallet::Config::KEYTAB_TMP;
    my $object = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $schema,
                                        @trace)
      };
    is ($object, undef, 'Creating keytab without KEYTAB_TMP fails');
    is ($@, "KEYTAB_TMP configuration variable not set\n",
        ' with the right error');
    $Wallet::Config::KEYTAB_TMP = '.';

    # Okay, now we can test.  First, create.
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', "wallet\nf", $schema,
                                        @trace)
      };
    is ($object, undef, 'Creating malformed principal fails');
    if ($Wallet::Config::KEYTAB_KRBTYPE eq 'MIT') {
        is ($@, "invalid principal name wallet\nf\n", ' with the right error');
    } elsif ($Wallet::Config::KEYTAB_KRBTYPE eq 'Heimdal') {
        like ($@, qr/^error adding principal wallet\nf/,
              ' with the right error');
    }
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', '', $schema, @trace)
      };
    is ($object, undef, 'Creating empty principal fails');
    if ($Wallet::Config::KEYTAB_KRBTYPE eq 'MIT') {
        is ($@, "invalid principal name \n", ' with the right error');
    } elsif ($Wallet::Config::KEYTAB_KRBTYPE eq 'Heimdal') {
        like ($@, qr/^error adding principal \@/, ' with the right error');
    }
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $schema,
                                        @trace)
      };
    if (defined ($object)) {
        ok (defined ($object), 'Creating good principal succeeds');
    } else {
        is ($@, '', 'Creating good principal succeeds');
    }
    ok ($object->isa ('Wallet::Object::Keytab'), ' and is the right class');
    ok (created ('wallet/one'), ' and the principal was created');
    create ('wallet/two');
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/two', $schema,
                                        @trace)
      };
    if (defined ($object)) {
        ok (defined ($object), 'Creating an existing principal succeeds');
    } else {
        is ($@, '', 'Creating an existing principal succeeds');
    }
    ok ($object->isa ('Wallet::Object::Keytab'), ' and is the right class');
    is ($object->destroy (@trace), 1, ' and destroying it succeeds');
    is ($object->error, undef, ' with no error message');
    ok (! created ('wallet/two'), ' and now it does not exist');
    my @name = qw(keytab wallet-test/one);
    $object = eval { Wallet::Object::Keytab->create (@name, $schema, @trace) };
    is ($object, undef, 'Creation without permissions fails');
    like ($@, qr{^error adding principal wallet-test/one\@\Q$realm: },
          ' with the right error');

    # Now, try retrieving the keytab.
    $object = Wallet::Object::Keytab->new ('keytab', 'wallet/one', $schema);
    ok (defined ($object), 'Retrieving the object works');
    ok ($object->isa ('Wallet::Object::Keytab'), ' and is the right type');
    is ($object->flag_set ('locked', @trace), 1, ' and setting locked works');
    is ($object->get (@trace), undef, ' and get fails');
    is ($object->error, "cannot get keytab:wallet/one: object is locked",
        ' because it is locked');
    is ($object->flag_clear ('locked', @trace), 1,
        ' and clearing locked works');
    my $data = $object->get (@trace);
    if (defined ($data)) {
        ok (defined ($data), ' and getting the keytab works');
    } else {
        is ($object->error, '', ' and getting the keytab works');
    }
    ok (! -f "./keytab.$$", ' and the temporary file was cleaned up');
    ok (keytab_valid ($data, 'wallet/one'), ' and the keytab is valid');

    # For right now, this is the only backend type that we have for which we
    # can do a get, so test display of the last download information.
    my $expected = <<"EOO";
           Type: keytab
           Name: wallet/one
     Created by: $user
   Created from: $host
     Created on: $date
  Downloaded by: $user
Downloaded from: $host
  Downloaded on: $date
EOO
    is ($object->show, $expected, 'Show output is correct');

    # Test error handling on keytab retrieval.
  SKIP: {
        skip 'no kadmin program test for Heimdal', 2
            if $Wallet::Config::KEYTAB_KRBTYPE eq 'Heimdal';
        $Wallet::Config::KEYTAB_KADMIN = '/some/nonexistent/file';
        $data = $object->get (@trace);
        is ($data, undef, 'Cope with a failure to run kadmin');
        like ($object->error, qr{^cannot run /some/nonexistent/file: },
              ' with the right error');
        $Wallet::Config::KEYTAB_KADMIN = 'kadmin';
    }
    destroy ('wallet/one');
    $data = $object->get (@trace);
    is ($data, undef, 'Getting a keytab for a nonexistent principal fails');
    like ($object->error,
          qr{^error creating keytab for wallet/one\@\Q$realm\E: },
          ' with the right error');
    is ($object->destroy (@trace), 1, ' but we can still destroy it');

    # Test principal deletion on object destruction.
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $schema,
                                        @trace)
      };
    ok (defined ($object), 'Creating good principal succeeds');
    is ($@, '', ' with no error');
    ok (created ('wallet/one'), ' and the principal was created');
  SKIP: {
        skip 'no kadmin program test for Heimdal', 2
            if $Wallet::Config::KEYTAB_KRBTYPE eq 'Heimdal';
        $Wallet::Config::KEYTAB_KADMIN = '/some/nonexistent/file';
        is ($object->destroy (@trace), undef,
            ' and destroying it with bad kadmin fails');
        like ($object->error, qr{^cannot run /some/nonexistent/file: },
              ' with the right error');
        $Wallet::Config::KEYTAB_KADMIN = 'kadmin';
    }
    is ($object->flag_set ('locked', @trace), 1, ' and setting locked works');
    is ($object->destroy (@trace), undef, ' and destroying it fails');
    is ($object->error, "cannot destroy keytab:wallet/one: object is locked",
        ' because it is locked');
    is ($object->flag_clear ('locked', @trace), 1,
        ' and clearing locked works');
    is ($object->destroy (@trace), 1, ' and destroying it succeeds');
    ok (! created ('wallet/one'), ' and now it does not exist');

    # Test history (which should still work after the object is deleted).
    $history .= <<"EOO";
$date  create
    by $user from $host
$date  set flag locked
    by $user from $host
$date  clear flag locked
    by $user from $host
$date  get
    by $user from $host
$date  destroy
    by $user from $host
$date  create
    by $user from $host
$date  set flag locked
    by $user from $host
$date  clear flag locked
    by $user from $host
$date  destroy
    by $user from $host
EOO
    is ($object->history, $history, 'History is correct to this point');

    # Test configuration errors.
    undef $Wallet::Config::KEYTAB_FILE;
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $schema,
                                        @trace)
      };
    is ($object, undef, 'Creating with bad configuration fails');
    is ($@, "keytab object implementation not configured\n",
        ' with the right error');
    $Wallet::Config::KEYTAB_FILE = 't/data/test.keytab';
    undef $Wallet::Config::KEYTAB_PRINCIPAL;
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $schema,
                                        @trace)
      };
    is ($object, undef, ' likewise with another missing variable');
    is ($@, "keytab object implementation not configured\n",
        ' with the right error');
    $Wallet::Config::KEYTAB_PRINCIPAL = contents ('t/data/test.principal');
    undef $Wallet::Config::KEYTAB_REALM;
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $schema,
                                        @trace)
      };
    is ($object, undef, ' and another');
    is ($@, "keytab object implementation not configured\n",
        ' with the right error');
    $Wallet::Config::KEYTAB_REALM = contents ('t/data/test.realm');
    undef $Wallet::Config::KEYTAB_KRBTYPE;
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $schema,
                                        @trace)
      };
    is ($object, undef, ' and another');
    is ($@, "keytab object implementation not configured\n",
        ' with the right error');
    $Wallet::Config::KEYTAB_KRBTYPE = 'Active Directory';
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $schema,
                                        @trace)
      };
    is ($object, undef, ' and one set to an invalid value');
    is ($@, "unknown KEYTAB_KRBTYPE setting: Active Directory\n",
        ' with the right error');
    $Wallet::Config::KEYTAB_KRBTYPE = contents ('t/data/test.krbtype');
}

# Tests for unchanging support.  Skip these if we don't have a keytab or if we
# can't find remctld.
SKIP: {
    skip 'no keytab configuration', 32 unless -f 't/data/test.keytab';

    # Set up our configuration.
    $Wallet::Config::KEYTAB_FILE      = 't/data/test.keytab';
    $Wallet::Config::KEYTAB_PRINCIPAL = contents ('t/data/test.principal');
    $Wallet::Config::KEYTAB_REALM     = contents ('t/data/test.realm');
    $Wallet::Config::KEYTAB_KRBTYPE   = contents ('t/data/test.krbtype');
    $Wallet::Config::KEYTAB_TMP       = '.';
    my $realm = $Wallet::Config::KEYTAB_REALM;
    my $principal = $Wallet::Config::KEYTAB_PRINCIPAL;

    # Create the objects for testing and set the unchanging flag.
    my $one = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $schema,
                                        @trace)
      };
    ok (defined ($one), 'Creating wallet/one succeeds');
    is ($one->flag_set ('unchanging', @trace), 1, ' and setting unchanging');
    my $two = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/two', $schema,
                                        @trace);
      };
    ok (defined ($two), 'Creating wallet/two succeeds');
    is ($two->flag_set ('unchanging', @trace), 1, ' and setting unchanging');

    # Finally we can test.  First the MIT Kerberos tests.
  SKIP: {
        skip 'skipping MIT unchanging tests for Heimdal', 16
            if (lc ($Wallet::Config::KEYTAB_KRBTYPE) eq 'heimdal');

        # We need remctld and Net::Remctl.
        my @path = (split (':', $ENV{PATH}), '/usr/local/sbin', '/usr/sbin');
        my ($remctld) = grep { -x $_ } map { "$_/remctld" } @path;
        skip 'remctld not found', 16 unless $remctld;
        eval { require Net::Remctl };
        skip 'Net::Remctl not available', 16 if $@;

        # Now spawn our remctld server and get a ticket cache.
        remctld_spawn ($remctld, $principal, 't/data/test.keytab',
                       't/data/keytab.conf', 1);
        $ENV{KRB5CCNAME} = 'krb5cc_test';
        getcreds ('t/data/test.keytab', $principal);
        $ENV{KRB5CCNAME} = 'krb5cc_good';

        # Do the unchanging tests for MIT Kerberos.
        is ($one->get (@trace), undef, 'Get without configuration fails');
        is ($one->error, 'keytab unchanging support not configured',
            ' with the right error');
        $Wallet::Config::KEYTAB_REMCTL_CACHE = 'krb5cc_test';
        is ($one->get (@trace), undef, ' and still fails without host');
        is ($one->error, 'keytab unchanging support not configured',
            ' with the right error');
        $Wallet::Config::KEYTAB_REMCTL_HOST = 'localhost';
        $Wallet::Config::KEYTAB_REMCTL_PRINCIPAL = $principal;
        $Wallet::Config::KEYTAB_REMCTL_PORT = 14373;
        is ($one->get (@trace), undef, ' and still fails without ACL');
        is ($one->error,
            "cannot retrieve keytab for wallet/one\@$realm: Access denied",
            ' with the right error');
        open (ACL, '>', 'test-acl') or die "cannot create test-acl: $!\n";
        print ACL "$principal\n";
        close ACL;
        is ($one->get (@trace), 'Keytab for wallet/one', 'Now get works');
        is ($ENV{KRB5CCNAME}, 'krb5cc_good',
            ' and we did not nuke the cache name');
        is ($one->get (@trace), 'Keytab for wallet/one',
            ' and we get the same thing the second time');
        is ($one->flag_clear ('unchanging', @trace), 1,
            'Clearing the unchanging flag works');
        my $data = $one->get (@trace);
        ok (defined ($data), ' and getting the keytab works');
        ok (keytab_valid ($data, 'wallet/one'), ' and the keytab is valid');
        is ($two->get (@trace), undef, 'Get for wallet/two does not work');
        is ($two->error,
            "cannot retrieve keytab for wallet/two\@$realm: bite me",
            ' with the right error');
        is ($one->destroy (@trace), 1, 'Destroying wallet/one works');
        is ($two->destroy (@trace), 1, ' as does destroying wallet/two');
        remctld_stop;
        unlink 'krb5cc_good';
    }

    # Now Heimdal.  Since the keytab contains timestamps, before testing for
    # equality we have to substitute out the timestamps.
  SKIP: {
        skip 'skipping Heimdal unchanging tests for MIT', 11
            if (lc ($Wallet::Config::KEYTAB_KRBTYPE) eq 'mit');
        my $data = $one->get (@trace);
        ok (defined $data, 'Get of unchanging keytab works');
        ok (keytab_valid ($data, 'wallet/one'), ' and the keytab is valid');
        my $second = $one->get (@trace);
        ok (defined $second, ' and second retrieval also works');
        $data =~ s/one.{8}/one\000\000\000\000\000\000\000\000/g;
        $second =~ s/one.{8}/one\000\000\000\000\000\000\000\000/g;
        ok (keytab_valid ($second, 'wallet/one'), ' and the keytab is valid');
        ok (keytab_valid ($data, 'wallet/one'), ' as is the first keytab');
        is ($one->flag_clear ('unchanging', @trace), 1,
            'Clearing the unchanging flag works');
        $data = $one->get (@trace);
        ok (defined ($data), ' and getting the keytab works');
        ok (keytab_valid ($data, 'wallet/one'), ' and the keytab is valid');
        $data =~ s/one.{8}/one\000\000\000\000\000\000\000\000/g;
        ok ($data ne $second, ' and the new keytab is different');
        is ($one->destroy (@trace), 1, 'Destroying wallet/one works');
        is ($two->destroy (@trace), 1, ' as does destroying wallet/two');
    }

    # Check that history has been updated correctly.
    $history .= <<"EOO";
$date  create
    by $user from $host
$date  set flag unchanging
    by $user from $host
$date  get
    by $user from $host
$date  get
    by $user from $host
$date  clear flag unchanging
    by $user from $host
$date  get
    by $user from $host
$date  destroy
    by $user from $host
EOO
    is ($one->history, $history, 'History is correct to this point');
}

# Tests for synchronization support.  This code is deactivated at present
# since no synchronization targets are supported, but we want to still test
# the basic stub code.
SKIP: {
    skip 'no keytab configuration', 18 unless -f 't/data/test.keytab';

    # Test setting synchronization attributes, which can also be done without
    # configuration.
    my $one = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $schema,
                                        @trace)
      };
    ok (defined ($one), 'Creating wallet/one succeeds');
    my $expected = <<"EOO";
           Type: keytab
           Name: wallet/one
     Created by: $user
   Created from: $host
     Created on: $date
EOO
    is ($one->show, $expected, 'Show output displays no attributes');
    is ($one->attr ('foo', [ 'bar' ], @trace), undef,
        'Setting unknown attribute fails');
    is ($one->error, 'unknown attribute foo', ' with the right error');
    my @targets = $one->attr ('foo');
    is (scalar (@targets), 0, ' and getting an unknown attribute fails');
    is ($one->error, 'unknown attribute foo', ' with the right error');
    is ($one->attr ('sync', [ 'kaserver' ], @trace), undef,
        ' and setting an unknown sync target fails');
    is ($one->error, 'unsupported synchronization target kaserver',
        ' with the right error');
    is ($one->attr ('sync', [ 'kaserver', 'bar' ], @trace), undef,
        ' and setting two targets fails');
    is ($one->error, 'only one synchronization target supported',
        ' with the right error');

    # Create a synchronization manually so that we can test the display and
    # removal code.
    my $sql = "insert into keytab_sync (ks_name, ks_target) values
        ('wallet/one', 'kaserver')";
    $dbh->do ($sql);
    @targets = $one->attr ('sync');
    is (scalar (@targets), 1, ' and now one target is set');
    is ($targets[0], 'kaserver', ' and it is correct');
    is ($one->error, undef, ' and there is no error');
    $expected = <<"EOO";
           Type: keytab
           Name: wallet/one
    Synced with: kaserver
     Created by: $user
   Created from: $host
     Created on: $date
EOO
    is ($one->show, $expected, ' and show now displays the attribute');
    $history .= <<"EOO";
$date  create
    by $user from $host
EOO
    is ($one->history, $history, ' and history is correct for attributes');
    is ($one->attr ('sync', [], @trace), 1,
        'Removing the kaserver sync attribute works');
    is ($one->destroy (@trace),1, ' and then destroying wallet/one works');
    $history .= <<"EOO";
$date  remove kaserver from attribute sync
    by $user from $host
$date  destroy
    by $user from $host
EOO
    is ($one->history, $history, ' and history is correct for removal');
}

# Tests for enctype restriction.
SKIP: {
    skip 'no keytab configuration', 37 unless -f 't/data/test.keytab';

    # Set up our configuration.
    $Wallet::Config::KEYTAB_FILE      = 't/data/test.keytab';
    $Wallet::Config::KEYTAB_PRINCIPAL = contents ('t/data/test.principal');
    $Wallet::Config::KEYTAB_REALM     = contents ('t/data/test.realm');
    $Wallet::Config::KEYTAB_KRBTYPE   = contents ('t/data/test.krbtype');
    $Wallet::Config::KEYTAB_TMP       = '.';
    my $realm = $Wallet::Config::KEYTAB_REALM;
    my $principal = $Wallet::Config::KEYTAB_PRINCIPAL;

    # Create an object for testing and determine the enctypes we have to work
    # with.
    my $one = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $schema,
                                        @trace)
      };
    if (defined ($one)) {
        ok (1, 'Creating wallet/one succeeds');
    } else {
        is ($@, '', 'Creating wallet/one succeeds');
    }
    my $keytab = $one->get (@trace);
    ok (defined ($keytab), ' and retrieving the keytab works');
    my @enctypes = grep { $_ ne 'UNKNOWN' } enctypes ($keytab);
    $history .= <<"EOO";
$date  create
    by $user from $host
$date  get
    by $user from $host
EOO
    is ($one->history, $history, ' and history is still correct');

    # No enctypes we recognize?
    skip 'no recognized enctypes', 34 unless @enctypes;

    # Set those encryption types and make sure we get back a limited keytab.
    is ($one->attr ('enctypes', [ @enctypes ], @trace), 1,
        'Setting enctypes works');
    is ($one->error, undef, ' with no error');
    for my $enctype (@enctypes) {
        $history .= "$date  add $enctype to attribute enctypes\n";
        $history .= "    by $user from $host\n";
    }
    my @values = $one->attr ('enctypes');
    is ("@values", "@enctypes", ' and we get back the right enctype list');
    my $eshow = join ("\n" . (' ' x 17), @enctypes);
    $eshow =~ s/\s+\z/\n/;
    my $expected = <<"EOO";
           Type: keytab
           Name: wallet/one
       Enctypes: $eshow
     Created by: $user
   Created from: $host
     Created on: $date
  Downloaded by: $user
Downloaded from: $host
  Downloaded on: $date
EOO
    is ($one->show, $expected, ' and show now displays the enctype list');
    $keytab = $one->get (@trace);
    ok (defined ($keytab), ' and retrieving the keytab still works');
    @values = enctypes ($keytab);
    is ("@values", "@enctypes", ' and the keytab has the right keys');
    is ($one->attr ('enctypes', [ 'foo-bar' ], @trace), undef,
        'Setting an unrecognized enctype fails');
    is ($one->error, 'unknown encryption type foo-bar',
        ' with the right error message');
    is ($one->show, $expected, ' and we did rollback properly');
    $history .= <<"EOO";
$date  get
    by $user from $host
EOO
    is ($one->history, $history, 'History is correct to this point');

    # Now, try testing limiting the enctypes to just one.
  SKIP: {
        skip 'insufficient recognized enctypes', 14 unless @enctypes > 1;

        is ($one->attr ('enctypes', [ $enctypes[0] ], @trace), 1,
            'Setting a single enctype works');
        for my $enctype (@enctypes) {
            next if $enctype eq $enctypes[0];
            $history .= "$date  remove $enctype from attribute enctypes\n";
            $history .= "    by $user from $host\n";
        }
        @values = $one->attr ('enctypes');
        is ("@values", $enctypes[0], ' and we get back the right value');
        $keytab = $one->get (@trace);
        ok (defined ($keytab), ' and retrieving the keytab still works');
        if (defined ($keytab)) {
            @values = enctypes ($keytab);
            is ("@values", $enctypes[0], ' and it has the right enctype');
        } else {
            ok (0, ' and it has the right keytab');
        }
        is ($one->attr ('enctypes', [ $enctypes[1] ], @trace), 1,
            'Setting a different single enctype works');
        @values = $one->attr ('enctypes');
        is ("@values", $enctypes[1], ' and we get back the right value');
        $keytab = $one->get (@trace);
        ok (defined ($keytab), ' and retrieving the keytab still works');
        @values = enctypes ($keytab);
        is ("@values", $enctypes[1], ' and it has the right enctype');
        is ($one->attr ('enctypes', [ @enctypes[0..1] ], @trace), 1,
            'Setting two enctypes works');
        @values = $one->attr ('enctypes');
        is ("@values", "@enctypes[0..1]", ' and we get back the right values');
        $keytab = $one->get (@trace);
        ok (defined ($keytab), ' and retrieving the keytab still works');
        @values = enctypes ($keytab);
        is ("@values", "@enctypes[0..1]", ' and it has the right enctypes');

        # Check the history trace.  Put back all the enctypes for consistent
        # status whether or not we skipped this section.
        $history .= <<"EOO";
$date  get
    by $user from $host
$date  remove $enctypes[0] from attribute enctypes
    by $user from $host
$date  add $enctypes[1] to attribute enctypes
    by $user from $host
$date  get
    by $user from $host
$date  add $enctypes[0] to attribute enctypes
    by $user from $host
$date  get
    by $user from $host
EOO
        is ($one->attr ('enctypes', [ @enctypes ], @trace), 1,
            'Restoring all enctypes works');
        for my $enctype (@enctypes) {
            next if $enctype eq $enctypes[0];
            next if $enctype eq $enctypes[1];
            $history .= "$date  add $enctype to attribute enctypes\n";
            $history .= "    by $user from $host\n";
        }
        is ($one->history, $history, 'History is correct to this point');
    }

    # Test clearing enctypes.
    is ($one->attr ('enctypes', [], @trace), 1, 'Clearing enctypes works');
    for my $enctype (@enctypes) {
        $history .= "$date  remove $enctype from attribute enctypes\n";
        $history .= "    by $user from $host\n";
    }
    @values = $one->attr ('enctypes');
    ok (@values == 0, ' and now there are no enctypes');
    is ($one->error, undef, ' and no error');

    # Test deleting enctypes on object destruction.
    is ($one->attr ('enctypes', [ $enctypes[0] ], @trace), 1,
        'Setting a single enctype works');
    is ($one->destroy (@trace), 1, ' and destroying the object works');
    $one = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $schema,
                                        @trace)
      };
    ok (defined ($one), ' as does recreating it');
    @values = $one->attr ('enctypes');
    ok (@values == 0, ' and now there are no enctypes');
    is ($one->error, undef, ' and no error');

    # All done.  Clean up and check history.
    is ($one->destroy (@trace), 1, 'Destroying wallet/one works');
    $history .= <<"EOO";
$date  add $enctypes[0] to attribute enctypes
    by $user from $host
$date  destroy
    by $user from $host
$date  create
    by $user from $host
$date  destroy
    by $user from $host
EOO
    is ($one->history, $history, 'History is correct to this point');
}

# Clean up.
$admin->destroy;
END {
    unlink ('wallet-db', 'krb5cc_temp', 'krb5cc_test', 'test-acl', 'test-pid');
}
