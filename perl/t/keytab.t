#!/usr/bin/perl -w
# $Id$
#
# t/keytab.t -- Tests for the keytab object implementation.

use Test::More tests => 23;

use DBD::SQLite;
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
            unlink ('keytab');
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
    return getcreds ('keytab', $principal);
}

SKIP: {
    skip 'no keytab configuration', 23 unless -f 't/data/test.keytab';

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

    # Use Wallet::Server to set up the database.
    my $server = eval { Wallet::Server->initialize ($user) };
    is ($@, '', 'Database initialization did not die');
    ok ($server->isa ('Wallet::Server'), ' and returned the right class');
    my $dbh = $server->dbh;

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
    ok (defined ($object), 'Creating good principal succeeds');
    ok ($object->isa ('Wallet::Object::Keytab'), ' and is the right class');
    ok (created ('wallet/one'), ' and the principal was created');
    create ('wallet/two');
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/two', $dbh, @trace)
      };
    is ($object, undef, 'Creating an existing principal fails');
    like ($@, qr{^error adding principal wallet/two\@\Q$realm\E: },
          ' with the right error message');
    destroy ('wallet/two');

    # Now, try retrieving the keytab.
    $object = Wallet::Object::Keytab->new ('keytab', 'wallet/one', $dbh);
    ok (defined ($object), 'Retrieving the object works');
    ok ($object->isa ('Wallet::Object::Keytab'), ' and is the right type');
    my $data = $object->get (@trace);
    if (defined ($data)) {
        ok (defined ($data), ' and getting the keytab works');
    } else {
        is ($object->error, '', ' and getting the keytab works');
    }
    ok (! -f "./keytab.$$", ' and the temporary file was cleaned up');
    ok (valid ($data, 'wallet/one'), ' and the keytab is valid');

    # Test error handling on keytab retrieval.
    destroy ('wallet/one');
    $data = $object->get (@trace);
    is ($data, undef, 'Getting a keytab for a nonexistent principal fails');
    like ($object->error,
          qr{^error creating keytab for wallet/one\@\Q$realm\E: },
          ' with the right error');
    is ($object->destroy (@trace), 1, ' but we can still destroy it');

    # Finally, test principal deletion on object destruction.
    $object = eval {
        Wallet::Object::Keytab->create ('keytab', 'wallet/one', $dbh, @trace)
      };
    ok (defined ($object), 'Creating good principal succeeds');
    ok (created ('wallet/one'), ' and the principal was created');
    is ($object->destroy (@trace), 1, ' and destroying it succeeds');
    ok (! created ('wallet/one'), ' and now it does not exist');

    # Clean up.
    unlink ('wallet-db', 'krb5cc_temp', 'krb5cc_test');
}
