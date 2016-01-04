# Wallet::ACL::External -- Wallet external ACL verifier
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2016 Russ Allbery <eagle@eyrie.org>
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::ACL::External;
require 5.008;

use strict;
use warnings;
use vars qw(@ISA $VERSION);

use Wallet::ACL::Base;
use Wallet::Config;

@ISA = qw(Wallet::ACL::Base);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.01';

##############################################################################
# Interface
##############################################################################

# Creates a new persistent verifier.  This just checks if the configuration
# is in place.
sub new {
    my $type = shift;
    unless ($Wallet::Config::EXTERNAL_COMMAND) {
        die "external ACL support not configured\n";
    }
    my $self = {};
    bless ($self, $type);
    return $self;
}

# The most trivial ACL verifier.  Returns true if the provided principal
# matches the ACL.
sub check {
    my ($self, $principal, $acl) = @_;
    unless ($principal) {
        $self->error ('no principal specified');
        return;
    }
    my @args = split (' ', $acl);
    unshift @args, $principal;
    my $pid = open (EXTERNAL, '-|');
    if (not defined $pid) {
        $self->error ("cannot fork: $!");
        return;
    } elsif ($pid == 0) {
        unless (open (STDERR, '>&STDOUT')) {
            warn "wallet: cannot dup stdout: $!\n";
            exit 1;
        }
        unless (exec ($Wallet::Config::EXTERNAL_COMMAND, @args)) {
            warn "wallet: cannot run $Wallet::Config::EXTERNAL_COMMAND: $!\n";
            exit 1;
        }
    }
    local $_;
    my @output = <EXTERNAL>;
    close EXTERNAL;
    if ($? == 0) {
        return 1;
    } else {
        if (@output) {
            $self->error ($output[0]);
            return;
        } else {
            return 0;
        }
    }
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=for stopwords
ACL Allbery verifier

=head1 NAME

Wallet::ACL::External - Wallet ACL verifier using an external command

=head1 SYNOPSIS

    my $verifier = Wallet::ACL::External->new;
    my $status = $verifier->check ($principal, $acl);
    if (not defined $status) {
        die "Something failed: ", $verifier->error, "\n";
    } elsif ($status) {
        print "Access granted\n";
    } else {
        print "Access denied\n";
    }

=head1 DESCRIPTION

Wallet::ACL::External runs an external command to determine whether access is
granted.  The command configured via $EXTERNAL_COMMAND in L<Wallet::Config>
will be run.  The first argument to the command will be the principal
requesting access.  The identifier of the ACL will be split on whitespace and
passed in as the remaining arguments to this command.

No other arguments are passed to the command, but the command will have access
to all of the remctl environment variables seen by the wallet server (such as
REMOTE_USER).  For a full list of environment variables, see
L<remctld(8)/ENVIRONMENT>.

The external command should exit with a non-zero status but no output to
indicate a normal failure to satisfy the ACL.  Any output will be treated as
an error.

=head1 METHODS

=over 4

=item new()

Creates a new ACL verifier.  For this verifier, this just confirms that
the wallet configuration sets an external command.

=item check(PRINCIPAL, ACL)

Returns true if the external command returns success when run with that
PRINCIPAL and ACL.  ACL will be split on whitespace and passed as multiple
arguments.  So, for example, the ACL C<external mdbset shell> will, when
triggered by a request from rra@EXAMPLE.COM, result in the command:

    $Wallet::Config::EXTERNAL_COMMAND rra@EXAMPLE.COM mdbset shell

=item error()

Returns the error if check() returned undef.

=back

=head1 DIAGNOSTICS

The new() method may fail with one of the following exceptions:

=over 4

=item external ACL support not configured

The required configuration parameters were not set.  See L<Wallet::Config>
for the required configuration parameters and how to set them.

=back

Verifying an external ACL may fail with the following errors (returned by
the error() method):

=over 4

=item cannot fork: %s

The attempt to fork in order to execute the external ACL verifier
command failed, probably due to a lack of system resources.

=item no principal specified

The PRINCIPAL parameter to check() was undefined or the empty string.

=back

In addition, if the external command fails and produces some output,
that will be considered a failure and the first line of its output will
be returned as the error message.  The external command should exit
with a non-zero status but no error to indicate a normal failure.

=head1 SEE ALSO

remctld(8), Wallet::ACL(3), Wallet::ACL::Base(3), Wallet::Config(3),
wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=cut
