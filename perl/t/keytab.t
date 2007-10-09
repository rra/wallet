#!/usr/bin/perl -w
# $Id$
#
# t/keytab.t -- Tests for the keytab object implementation.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

use Test::More tests => 194;

use Wallet::Config;
use Wallet::Object::Keytab;
use Wallet::Server;

# Mapping of klist -ke encryption type names to the strings that Kerberos uses
# internally.  It's very annoying to have to maintain this, and it probably
# breaks with Heimdal.
my %enctype =
    ('triple des cbc mode with hmac/sha1'      => 'des3-cbc-sha1',
     'des cbc mode with crc-32'                => 'des-cbc-crc',
     'des cbc mode with rsa-md5'               => 'des-cbc-md5',
     'aes-256 cts mode with 96-bit sha-1 hmac' => 'aes256-cts',
     'arcfour with hmac/md5'                   => 'rc4-hmac');

# Use a local SQLite database for testing.
$Wallet::Config::DB_DRIVER = 'SQLite';
$Wallet::Config::DB_INFO = 'wallet-db';
unlink ('wallet-db', 'krb5cc_temp', 'krb5cc_test', 'test-acl', 'test-pid');

# Some global defaults to use.
my $user = 'admin@EXAMPLE.COM';
my $host = 'localhost';
my @trace = ($user, $host);

# Flush all output immediately.
$| = 1;

# Returns the one-line contents of a file as a string, removing the newline.
sub contents {
    my ($file) = @_;
    open (FILE, '<', $file) or die "cannot open $file: $!\n";
    my $data = <FILE>;
    close FILE;
    chomp $data;
    return $data;
}

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
    my @args = ('-p', $Wallet::Config::KEYTAB_PRINCIPAL, '-k',
                '-t', $Wallet::Config::KEYTAB_FILE,
                '-r', $Wallet::Config::KEYTAB_REALM,
                '-q', "addprinc -clearpolicy -randkey $principal");
    system_quiet ($Wallet::Config::KEYTAB_KADMIN, @args);
}

# Destroy a principal out of Kerberos.  Only usable once the configuration has
# been set up.
sub destroy {
    my ($principal) = @_;
    my @args = ('-p', $Wallet::Config::KEYTAB_PRINCIPAL, '-k',
                '-t', $Wallet::Config::KEYTAB_FILE,
                '-r', $Wallet::Config::KEYTAB_REALM,
                '-q', "delprinc -force $principal");
    system_quiet ($Wallet::Config::KEYTAB_KADMIN, @args);
}

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

# Check whether a principal exists.
sub created {
    my ($principal) = @_;
    $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    local $ENV{KRB5CCNAME} = 'krb5cc_temp';
    getcreds ('t/data/test.keytab', $Wallet::Config::KEYTAB_PRINCIPAL);
    return (system_quiet ('kvno', $principal) == 0);
}

# Given keytab data and the principal, write it to a file and try
# authenticating using kinit.
sub valid {
    my ($keytab, $principal) = @_;
    open (KEYTAB, '>', 'keytab') or die "cannot create keytab: $!\n";
    print KEYTAB $keytab;
    close KEYTAB;
    $principal .= '@' . $Wallet::Config::KEYTAB_REALM;
    my $result = getcreds ('keytab', $principal);
    if ($result) {
        unlink 'keytab';
    }
    return $result;
}

# Given keytab data, write it to a file and try to determine the enctypes of
# the keys present in that file.  Returns the enctypes as a list, with UNKNOWN
# for encryption types that weren't recognized.  This is an ugly way of doing
# this.
sub enctypes {
    my ($keytab) = @_;
    open (KEYTAB, '>', 'keytab') or die "cannot create keytab: $!\n";
    print KEYTAB $keytab;
    close KEYTAB;
    open (KLIST, '-|', 'klist', '-ke', 'keytab')
        or die "cannot run klist: $!\n";
    my @enctypes;
    local $_;
    while (<KLIST>) {
        next unless /^ *\d+ /;
        my ($string) = /\((.*)\)\s*$/;
        next unless $string;
        $enctype = $enctype{lc $string} || 'UNKNOWN';
        push (@enctypes, $enctype);
    }
    close KLIST;
    unlink 'keytab';
    return sort @enctypes;
}

# Given a Wallet::Object::Keytab object, the keytab data, the Kerberos v5
# principal, and the Kerberos v4 principal, write the keytab to a file,
# generate a srvtab, and try authenticating using k4start.
sub valid_srvtab {
    my ($object, $keytab, $k5, $k4) = @_;
    open (KEYTAB, '>', 'keytab') or die "cannot create keytab: $!\n";
    print KEYTAB $keytab;
    close KEYTAB;
    unless ($object->kaserver_srvtab ('keytab', $k5, 'srvtab', $k4)) {
        warn "cannot write srvtab: ", $object->error, "\n";
        return 0;
    }
    $ENV{KRBTKFILE} = 'krb4cc_temp';
    system ("k4start -f srvtab $k4 2>&1 >/dev/null </dev/null");
    unlink 'keytab', 'srvtab', 'krb4cc_temp';
    return ($? == 0) ? 1 : 0;
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
              '-f', 't/data/keytab.conf', '-S', '-F', '-k', $keytab) == 0
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

# Use Wallet::Server to set up the database.
my $server = eval { Wallet::Server->initialize ($user) };
is ($@, '', 'Database initialization did not die');
ok ($server->isa ('Wallet::Server'), ' and returned the right class');
my $dbh = $server->dbh;

# Basic keytab creation and manipulation tests.
SKIP: {
    skip 'no keytab configuration', 48 unless -f 't/data/test.keytab';

    # Set up our configuration.
    $Wallet::Config::KEYTAB_FILE      = 't/data/test.keytab';
    $Wallet::Config::KEYTAB_PRINCIPAL = contents ('t/data/test.principal');
    $Wallet::Config::KEYTAB_REALM     = contents ('t/data/test.realm');
    $Wallet::Config::KEYTAB_TMP       = '.';
    my $realm = $Wallet::Config::KEYTAB_REALM;

    # Clean up the principals we're going to use.
    destroy ('wallet/one');
    destroy ('wallet/two');

    # Don't destroy the user's Kerberos ticket cache.
    $ENV{KRB5CCNAME} = 'krb5cc_test';

    # Okay, now we can test.  First, create.
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', "wallet\nf", $dbh, @trace)
      };
    is ($object, undef, 'Creating malformed principal fails');
    is ($@, "invalid principal name wallet\nf\n", ' with the right error');
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', '', $dbh, @trace)
      };
    is ($object, undef, 'Creating empty principal fails');
    is ($@, "invalid principal name \n", ' with the right error');
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $dbh, @trace)
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
        Wallet::Object::Keytab->create ('keytab', 'wallet/two', $dbh, @trace)
      };
    ok (defined ($object), 'Creating an existing principal succeeds');
    ok ($object->isa ('Wallet::Object::Keytab'), ' and is the right class');
    is ($object->destroy (@trace), 1, ' and destroying it succeeds');
    ok (! created ('wallet/two'), ' and now it does not exist');
    my @name = qw(keytab wallet-test/one);
    $object = eval { Wallet::Object::Keytab->create (@name, $dbh, @trace) };
    is ($object, undef, 'Creation without permissions fails');
    like ($@, qr{^error adding principal wallet-test/one\@\Q$realm: },
          ' with the right error');

    # Now, try retrieving the keytab.
    $object = Wallet::Object::Keytab->new ('keytab', 'wallet/one', $dbh);
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
    ok (valid ($data, 'wallet/one'), ' and the keytab is valid');

    # For right now, this is the only backend type that we have for which we
    # can do a get, so test display of the last download information.
    my $show = $object->show;
    $show =~ s/^(\s*(?:Created|Downloaded) on:) \d+$/$1 0/mg;
    my $expected = <<"EOO";
           Type: keytab
           Name: wallet/one
     Created by: $user
   Created from: $host
     Created on: 0
  Downloaded by: $user
Downloaded from: $host
  Downloaded on: 0
EOO
    is ($show, $expected, 'Show output is correct');

    # Test error handling on keytab retrieval.
    undef $Wallet::Config::KEYTAB_TMP;
    $data = $object->get (@trace);
    is ($data, undef, 'Getting a keytab without a tmp directory fails');
    is ($object->error, 'KEYTAB_TMP configuration variable not set',
        ' with the right error');
    $Wallet::Config::KEYTAB_TMP = '.';
    $Wallet::Config::KEYTAB_KADMIN = '/some/nonexistent/file';
    $data = $object->get (@trace);
    is ($data, undef, 'Cope with a failure to run kadmin');
    like ($object->error, qr{^cannot run /some/nonexistent/file: },
          ' with the right error');
    $Wallet::Config::KEYTAB_KADMIN = 'kadmin';
    destroy ('wallet/one');
    $data = $object->get (@trace);
    is ($data, undef, 'Getting a keytab for a nonexistent principal fails');
    like ($object->error,
          qr{^error creating keytab for wallet/one\@\Q$realm\E: },
          ' with the right error');
    is ($object->destroy (@trace), 1, ' but we can still destroy it');

    # Test principal deletion on object destruction.
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $dbh, @trace)
      };
    ok (defined ($object), 'Creating good principal succeeds');
    ok (created ('wallet/one'), ' and the principal was created');
    $Wallet::Config::KEYTAB_KADMIN = '/some/nonexistent/file';
    is ($object->destroy (@trace), undef,
        ' and destroying it with bad kadmin fails');
    like ($object->error, qr{^cannot run /some/nonexistent/file: },
          ' with the right error');
    $Wallet::Config::KEYTAB_KADMIN = 'kadmin';
    is ($object->flag_set ('locked', @trace), 1, ' and setting locked works');
    is ($object->destroy (@trace), undef, ' and destroying it fails');
    is ($object->error, "cannot destroy keytab:wallet/one: object is locked",
        ' because it is locked');
    is ($object->flag_clear ('locked', @trace), 1,
        ' and clearing locked works');
    is ($object->destroy (@trace), 1, ' and destroying it succeeds');
    ok (! created ('wallet/one'), ' and now it does not exist');

    # Test configuration errors.
    undef $Wallet::Config::KEYTAB_FILE;
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $dbh, @trace)
      };
    is ($object, undef, 'Creating with bad configuration fails');
    is ($@, "keytab object implementation not configured\n",
        ' with the right error');
    $Wallet::Config::KEYTAB_FILE = 't/data/test.keytab';
    undef $Wallet::Config::KEYTAB_PRINCIPAL;
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $dbh, @trace)
      };
    is ($object, undef, ' likewise with another missing variable');
    is ($@, "keytab object implementation not configured\n",
        ' with the right error');
    $Wallet::Config::KEYTAB_PRINCIPAL = contents ('t/data/test.principal');
    undef $Wallet::Config::KEYTAB_REALM;
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $dbh, @trace)
      };
    is ($object, undef, ' and another');
    is ($@, "keytab object implementation not configured\n",
        ' with the right error');
    $Wallet::Config::KEYTAB_REALM = contents ('t/data/test.realm');
    $Wallet::Config::KEYTAB_KADMIN = '/some/nonexistent/file';
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $dbh, @trace)
      };
    is ($object, undef, 'Cope with a failure to run kadmin');
    like ($@, qr{^cannot run /some/nonexistent/file: },
          ' with the right error');
    $Wallet::Config::KEYTAB_KADMIN = 'kadmin';
}

# Tests for unchanging support.  Skip these if we don't have a keytab or if we
# can't find remctld.
SKIP: {
    skip 'no keytab configuration', 16 unless -f 't/data/test.keytab';
    my @path = (split (':', $ENV{PATH}), '/usr/local/sbin', '/usr/sbin');
    my ($remctld) = grep { -x $_ } map { "$_/remctld" } @path;
    skip 'remctld not found', 16 unless $remctld;
    eval { require Net::Remctl };
    skip 'Net::Remctl not available', 16 if $@;

    # Set up our configuration.
    $Wallet::Config::KEYTAB_FILE      = 't/data/test.keytab';
    $Wallet::Config::KEYTAB_PRINCIPAL = contents ('t/data/test.principal');
    $Wallet::Config::KEYTAB_REALM     = contents ('t/data/test.realm');
    $Wallet::Config::KEYTAB_TMP       = '.';
    my $realm = $Wallet::Config::KEYTAB_REALM;
    my $principal = $Wallet::Config::KEYTAB_PRINCIPAL;

    # Create the objects for testing and set the unchanging flag.
    my $one = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $dbh, @trace)
      };
    ok (defined ($one), 'Creating wallet/one succeeds');
    is ($one->flag_set ('unchanging', @trace), 1, ' and setting unchanging');
    my $two = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/two', $dbh, @trace);
      };
    ok (defined ($two), 'Creating wallet/two succeeds');
    is ($two->flag_set ('unchanging', @trace), 1, ' and setting unchanging');

    # Now spawn our remctld server and get a ticket cache.
    spawn_remctld ($remctld, $principal, 't/data/test.keytab');
    $ENV{KRB5CCNAME} = 'krb5cc_test';
    getcreds ('t/data/test.keytab', $principal);
    $ENV{KRB5CCNAME} = 'krb5cc_good';

    # Finally we can test.
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
    is ($two->get (@trace), undef, ' but get for wallet/two does not');
    is ($two->error,
        "cannot retrieve keytab for wallet/two\@$realm: bite me",
        ' with the right error');
    is ($one->destroy (@trace), 1, 'Destroying wallet/one works');
    is ($two->destroy (@trace), 1, ' as does destroying wallet/two');
    stop_remctld;
}

# Tests for kaserver synchronization support.
SKIP: {
    skip 'no keytab configuration', 98 unless -f 't/data/test.keytab';

    # Test the principal mapping.  We can do this without having a kaserver
    # configuration.  We only need a basic keytab object configuration.  Do
    # this as white-box testing since we don't want to fill the test realm
    # with a bunch of random principals.
    my $one = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $dbh, @trace)
      };
    ok (defined ($one), 'Creating wallet/one succeeds');
    my %princs =
        (foo                     => 'foo',
         host                    => 'host',
         rcmd                    => 'rcmd',
         'rcmd.foo'              => 'rcmd.foo',
         'host/foo.example.org'  => 'rcmd.foo',
         'ident/foo.example.org' => 'ident.foo',
         'imap/foo.example.org'  => 'imap.foo',
         'pop/foo.example.org'   => 'pop.foo',
         'smtp/foo.example.org'  => 'smtp.foo',
         'service/foo'           => 'service.foo',
         'foo/bar'               => 'foo.bar');
    for my $princ (sort keys %princs) {
        my $result = $princs{$princ};
        is ($one->kaserver_name ($princ), $result, "Name mapping: $princ");
        is ($one->kaserver_name ("$princ\@EXAMPLE.ORG"), $result,
            ' with K5 realm');
        $Wallet::Config::KEYTAB_AFS_REALM = 'AFS.EXAMPLE.ORG';
        is ($one->kaserver_name ($princ), "$result\@AFS.EXAMPLE.ORG",
            ' with K4 realm');
        is ($one->kaserver_name ("$princ\@EXAMPLE.ORG"),
            "$result\@AFS.EXAMPLE.ORG", ' with K5 and K4 realm');
        undef $Wallet::Config::KEYTAB_AFS_REALM;
    }
    for my $princ (qw{service/foo/bar foo/bar/baz}) {
        is ($one->kaserver_name ($princ), undef, "Name mapping: $princ");
        is ($one->kaserver_name ("$princ\@EXAMPLE.ORG"), undef,
            ' with K5 realm');
        $Wallet::Config::KEYTAB_AFS_REALM = 'AFS.EXAMPLE.ORG';
        is ($one->kaserver_name ($princ), undef, ' with K4 realm');
        is ($one->kaserver_name ("$princ\@EXAMPLE.ORG"), undef,
            ' with K5 and K4 realm');
        undef $Wallet::Config::KEYTAB_AFS_REALM;
    }

    # Test setting synchronization attributes, which can also be done without
    # configuration.
    my $show = $one->show;
    $show =~ s/^(\s*Created on:) \d+$/$1 0/mg;
    my $expected = <<"EOO";
           Type: keytab
           Name: wallet/one
     Created by: $user
   Created from: $host
     Created on: 0
EOO
    is ($show, $expected, 'Show output displays no attributes');
    is ($one->attr ('foo', [ 'bar' ], @trace), undef,
        'Setting unknown attribute fails');
    is ($one->error, 'unknown attribute foo', ' with the right error');
    my @targets = $one->attr ('foo');
    is (scalar (@targets), 0, ' and getting an unknown attribute fails');
    is ($one->error, 'unknown attribute foo', ' with the right error');
    is ($one->attr ('sync', [ 'foo' ], @trace), undef,
        ' and setting an unknown sync target fails');
    is ($one->error, 'unsupported synchronization target foo',
        ' with the right error');
    is ($one->attr ('sync', [ 'kaserver', 'bar' ], @trace), undef,
        ' and setting two targets fails');
    is ($one->error, 'only one synchronization target supported',
        ' with the right error');
    is ($one->attr ('sync', [ 'kaserver' ], @trace), 1,
        ' but setting only kaserver works');
    @targets = $one->attr ('sync');
    is (scalar (@targets), 1, ' and now one target is set');
    is ($targets[0], 'kaserver', ' and it is correct');
    is ($one->error, undef, ' and there is no error');
    $show = $one->show;
    $show =~ s/^(\s*Created on:) \d+$/$1 0/mg;
    $expected = <<"EOO";
           Type: keytab
           Name: wallet/one
    Synced with: kaserver
     Created by: $user
   Created from: $host
     Created on: 0
EOO
    is ($show, $expected, ' and show now displays the attribute');

    # Set up our configuration.
    skip 'no AFS kaserver configuration', 31 unless -f 't/data/test.srvtab';
    $Wallet::Config::KEYTAB_FILE         = 't/data/test.keytab';
    $Wallet::Config::KEYTAB_PRINCIPAL    = contents ('t/data/test.principal');
    $Wallet::Config::KEYTAB_REALM        = contents ('t/data/test.realm');
    $Wallet::Config::KEYTAB_TMP          = '.';
    $Wallet::Config::KEYTAB_AFS_KASETKEY = '../kasetkey/kasetkey';
    my $realm = $Wallet::Config::KEYTAB_REALM;
    my $k5 = "wallet/one\@$realm";

    # Finally, we can test.
    is ($one->get (@trace), undef, 'Get without configuration fails');
    is ($one->error, 'kaserver synchronization not configured',
        ' with the right error');
    $Wallet::Config::KEYTAB_AFS_ADMIN = contents ('t/data/test.admin');
    my $k4_realm = $Wallet::Config::KEYTAB_AFS_ADMIN;
    $k4_realm =~ s/^[^\@]+\@//;
    $Wallet::Config::KEYTAB_AFS_REALM = $k4_realm;
    my $k4 = "wallet.one\@$k4_realm";
    is ($one->get (@trace), undef, ' and still fails with just admin');
    is ($one->error, 'kaserver synchronization not configured',
        ' with the right error');
    $Wallet::Config::KEYTAB_AFS_SRVTAB = 't/data/test.srvtab';
    my $keytab = $one->get (@trace);
    if (defined ($keytab)) {
        ok (1, ' and now get works');
    } else {
        is ($one->error, '', ' and now get works');
    }
    ok (valid_srvtab ($one, $keytab, $k5, $k4), ' and the srvtab is valid');
    ok (! -f "./srvtab.$$", ' and the temporary file was cleaned up');

    # Now remove the sync attribute and make sure things aren't synced.
    is ($one->attr ('sync', [], @trace), 1, 'Clearing sync works');
    @targets = $one->attr ('sync');
    is (scalar (@targets), 0, ' and now there is no attribute');
    is ($one->error, undef, ' and no error');
    my $new_keytab = $one->get (@trace);
    ok (defined ($new_keytab), ' and get still works');
    ok (! valid_srvtab ($one, $new_keytab, $k5, $k4),
        ' but the srvtab does not');
    ok (valid_srvtab ($one, $keytab, $k5, $k4), ' and the old one does');
    is ($one->destroy (@trace), 1, ' and destroying wallet/one works');
    ok (valid_srvtab ($one, $keytab, $k5, $k4),
        ' and the principal is still there');

    # Test KEYTAB_AFS_DESTROY.
    $one = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $dbh, @trace)
      };
    ok (defined ($one), 'Creating wallet/one succeeds');
    $Wallet::Config::KEYTAB_AFS_DESTROY = 1;
    $new_keytab = $one->get (@trace);
    ok (defined ($new_keytab), ' and get works');
    ok (! valid_srvtab ($one, $new_keytab, $k5, $k4),
        ' but the srvtab does not');
    ok (! valid_srvtab ($one, $keytab, $k5, $k4),
        ' and now neither does the old one');
    $Wallet::Config::KEYTAB_AFS_DESTROY = 0;

    # Put it back and make sure it works again.
    is ($one->attr ('sync', [ 'kaserver' ], @trace), 1, 'Setting sync works');
    $keytab = $one->get (@trace);
    ok (defined ($keytab), ' and get works');
    ok (valid_srvtab ($one, $keytab, $k5, $k4), ' and the srvtab is valid');
    $Wallet::Config::KEYTAB_AFS_KASETKEY = '/path/to/nonexistent/file';
    $new_keytab = $one->get (@trace);
    ok (! defined ($new_keytab),
        ' but it fails if we mess up the kasetkey path');
    like ($one->error, qr{^cannot synchronize key with kaserver: },
          ' with the right error message');
    ok (! -f "keytab.$$", ' and the temporary file was cleaned up');
    $Wallet::Config::KEYTAB_AFS_KASETKEY = '../kasetkey/kasetkey';

    # Destroy the principal and recreate it and make sure we cleaned up.
    is ($one->destroy (@trace), 1, 'Destroying wallet/one works');
    ok (! valid_srvtab ($one, $keytab, $k5, $k4),
        ' and the principal is gone');
    $one = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $dbh, @trace)
      };
    ok (defined ($one), ' and recreating it succeeds');
    @targets = $one->attr ('sync');
    is (scalar (@targets), 0, ' and now there is no attribute');
    is ($one->error, undef, ' and no error');

    # Now destroy it for good.
    is ($one->destroy (@trace), 1, 'Destroying wallet/one works');
}

# Tests for enctype restriction.
SKIP: {
    skip 'no keytab configuration', 30 unless -f 't/data/test.keytab';

    # Set up our configuration.
    $Wallet::Config::KEYTAB_FILE      = 't/data/test.keytab';
    $Wallet::Config::KEYTAB_PRINCIPAL = contents ('t/data/test.principal');
    $Wallet::Config::KEYTAB_REALM     = contents ('t/data/test.realm');
    $Wallet::Config::KEYTAB_TMP       = '.';
    my $realm = $Wallet::Config::KEYTAB_REALM;
    my $principal = $Wallet::Config::KEYTAB_PRINCIPAL;

    # Create an object for testing and determine the enctypes we have to work
    # with.
    my $one = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $dbh, @trace)
      };
    ok (defined ($one), 'Creating wallet/one succeeds');
    my $keytab = $one->get (@trace);
    ok (defined ($keytab), ' and retrieving the keytab works');
    my @enctypes = grep { $_ ne 'UNKNOWN' } enctypes ($keytab);

    # No enctypes we recognize?
    skip 'no recognized enctypes', 28 unless @enctypes;

    # We can test.  Add the enctypes we recognized to the enctypes table so
    # that we'll be allowed to use them.
    for (@enctypes) {
        my $sql = 'insert into enctypes (en_name) values (?)';
        $dbh->do ($sql, undef, $_);
    }

    # Set those encryption types and make sure we get back a limited keytab.
    is ($one->attr ('enctypes', [ @enctypes ], @trace), 1,
        'Setting enctypes works');
    my @values = $one->attr ('enctypes');
    is ("@values", "@enctypes", ' and we get back the right enctype list');
    my $eshow = join ("\n" . (' ' x 17), @enctypes);
    $eshow =~ s/\s+\z/\n/;
    my $show = $one->show;
    $show =~ s/^(\s*(Created|Downloaded) on:) \d+$/$1 0/mg;
    $expected = <<"EOO";
           Type: keytab
           Name: wallet/one
       Enctypes: $eshow
     Created by: $user
   Created from: $host
     Created on: 0
  Downloaded by: $user
Downloaded from: $host
  Downloaded on: 0
EOO
    is ($show, $expected, ' and show now displays the enctype list');
    $keytab = $one->get (@trace);
    ok (defined ($keytab), ' and retrieving the keytab still works');
    @values = enctypes ($keytab);
    is ("@values", "@enctypes", ' and the keytab has the right keys');
    is ($one->attr ('enctypes', [ 'foo-bar' ], @trace), undef,
        'Setting an unrecognized enctype fails');
    is ($one->error, 'unknown encryption type foo-bar',
        ' with the right error message');

    # Now, try testing limiting the enctypes to just one.
  SKIP: {
        skip 'insufficient recognized enctypes', 12 unless @enctypes > 1;
        is ($one->attr ('enctypes', [ $enctypes[0] ], @trace), 1,
            'Setting a single enctype works');
        @values = $one->attr ('enctypes');
        is ("@values", $enctypes[0], ' and we get back the right value');
        $keytab = $one->get (@trace);
        ok (defined ($keytab), ' and retrieving the keytab still works');
        @values = enctypes ($keytab);
        is ("@values", $enctypes[0], ' and it has the right enctype');
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
    }

    # Test clearing enctypes.
    is ($one->attr ('enctypes', [], @trace), 1, 'Clearing enctypes works');
    @values = $one->attr ('enctypes');
    ok (@values == 0, ' and now there are no enctypes');
    is ($one->error, undef, ' and no error');

    # Test deleting enctypes on object destruction.
    is ($one->attr ('enctypes', [ $enctypes[0] ], @trace), 1,
        'Setting a single enctype works');
    is ($one->destroy (@trace), 1, ' and destroying the object works');
    $one = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $dbh, @trace)
      };
    ok (defined ($one), ' as does recreating it');
    @values = $one->attr ('enctypes');
    ok (@values == 0, ' and now there are no enctypes');
    is ($one->error, undef, ' and no error');

    # All done.  Clean up.
    is ($one->destroy (@trace), 1, 'Destroying wallet/one works');
}

# Clean up.
unlink ('wallet-db', 'krb5cc_temp', 'krb5cc_test', 'test-acl', 'test-pid');
