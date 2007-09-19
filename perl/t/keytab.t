#!/usr/bin/perl -w
# $Id$
#
# t/keytab.t -- Tests for the keytab object implementation.

use Test::More tests => 66;

use Wallet::Config;
use Wallet::Object::Keytab;
use Wallet::Server;

# Use a local SQLite database for testing.
$Wallet::Config::DB_DRIVER = 'SQLite';
$Wallet::Config::DB_INFO = 'wallet-db';
unlink 'wallet-db';

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

# Start remctld with the appropriate options to run our fake keytab backend.
sub spawn_remctld {
    my ($path, $principal, $keytab) = @_;
    unlink 'test-pid';
    my $pid = fork;
    if (not defined $pid) {
        die "cannot fork: $!\n";
    } elsif ($pid == 0) {
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
    $Wallet::Config::KEYTAB_CACHE = 'krb5cc_test';
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

# Clean up.
unlink ('wallet-db', 'krb5cc_temp', 'krb5cc_test', 'test-acl', 'test-pid');
