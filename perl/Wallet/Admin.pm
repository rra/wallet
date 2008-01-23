# Wallet::Admin -- Wallet system administrative interface.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2008 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Admin;
require 5.006;

use strict;
use vars qw($VERSION);

use Wallet::ACL;
use Wallet::Database;
use Wallet::Schema;

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.01';

##############################################################################
# Constructor, destructor, and accessors
##############################################################################

# Create a new wallet administrator object.  Opens a connection to the
# database that will be used for all of the wallet configuration information.
# Throw an exception if anything goes wrong.
sub new {
    my ($class) = @_;
    my $dbh = Wallet::Database->connect;
    my $self = { dbh => $dbh };
    bless ($self, $class);
    return $self;
}

# Returns the database handle (used mostly for testing).
sub dbh {
    my ($self) = @_;
    return $self->{dbh};
}

# Set or return the error stashed in the object.
sub error {
    my ($self, @error) = @_;
    if (@error) {
        my $error = join ('', @error);
        chomp $error;
        1 while ($error =~ s/ at \S+ line \d+\.?\z//);
        $self->{error} = $error;
    }
    return $self->{error};
}

# Disconnect the database handle on object destruction to avoid warnings.
sub DESTROY {
    my ($self) = @_;
    $self->{dbh}->disconnect unless $self->{dbh}->{InactiveDestroy};
}

##############################################################################
# Database initialization
##############################################################################

# Initializes the database by populating it with our schema and then creates
# and returns a new wallet server object.  This is used only for initial
# database creation.  Takes the Kerberos principal who will be the default
# administrator so that we can create an initial administrator ACL.  Returns
# true on success and false on failure, setting the object error.
sub initialize {
    my ($self, $user) = @_;
    my $schema = Wallet::Schema->new;
    eval { $schema->create ($self->{dbh}) };
    if ($@) {
        $self->error ($@);
        return;
    }
    my $acl = Wallet::ACL->create ('ADMIN', $self->{dbh}, $user, 'localhost');
    unless ($acl->add ('krb5', $user, $user, 'localhost')) {
        $self->error ($acl->error);
        return;
    }
    return 1;
}

# The same as initialize, but also drops any existing tables first before
# creating the schema.  Takes the same arguments and throws an exception on
# failure.
sub reinitialize {
    my ($self, $user) = @_;
    my $schema = Wallet::Schema->new;
    eval { $schema->drop ($self->{dbh}) };
    if ($@) {
        $self->error ($@);
        return;
    }
    return $self->initialize ($user);
}

1;
__DATA__

##############################################################################
# Documentation
##############################################################################

=head1 NAME

Wallet::Admin - Wallet system administrative interface

=head1 SYNOPSIS

    use Wallet::Admin;
    my $admin = Wallet::Admin->new;
    unless ($admin->initialize ('user/admin@EXAMPLE.COM')) {
        die $admin->error;
    }

=head1 DESCRIPTION

Wallet::Admin implements the administrative interface to the wallet server
and database.  It is normally instantiated and used by B<wallet-admin>, a
thin wrapper around this object that provides a command-line interface to
its actions.

To use this object, several configuration variables must be set (at least
the database configuration).  For information on those variables and how to
set them, see Wallet::Config(3).  For more information on the normal user
interface to the wallet server, see Wallet::Server(3).

=head1 CLASS METHODS

=over 4

=item new()

Creates a new wallet administrative object and connects to the database.
On any error, this method throws an exception.

=back

=head1 INSTANCE METHODS

For all methods that can fail, the caller should call error() after a
failure to get the error message.

=over 4

=item initialize(PRINCIPAL)

Initializes the database as configured in Wallet::Config and loads the
wallet database schema.  Then, creates an ACL with the name ADMIN and adds
an ACL entry of scheme C<krb5> and instance PRINCIPAL to that ACL.  This
bootstraps the authorization system and lets that Kerberos identity make
further changes to the ADMIN ACL and the rest of the wallet database.

initialize() uses C<localhost> as the hostname and PRINCIPAL as the user
when logging the history of the ADMIN ACL creation and for any subsequent
actions on the object it returns.

=item error()

Returns the error of the last failing operation or undef if no operations
have failed.  Callers should call this function to get the error message
after an undef return from any other instance method.

=item reinitialize(PRINCIPAL)

Performs the same actions as initialize(), but first drops any existing
wallet database tables from the database, allowing this function to be
called on a prior wallet database.  All data stored in the database will
be deleted and a fresh set of wallet database tables will be created.

=back

=head1 SEE ALSO

wallet-admin(8)

This module is part of the wallet system.  The current version is available
from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <rra@stanford.edu>

=cut
