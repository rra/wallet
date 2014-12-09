# Wallet::Object::Duo::RDP -- Duo RDP int. object implementation for wallet
#
# Written by Russ Allbery <eagle@eyrie.org>
#            Jon Robertson <jonrober@stanford.edu>
# Copyright 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Object::Duo::RDP;
require 5.006;

use strict;
use warnings;
use vars qw(@ISA $VERSION);

use JSON;
use Net::Duo::Admin;
use Net::Duo::Admin::Integration;
use Perl6::Slurp qw(slurp);
use Wallet::Config ();
use Wallet::Object::Duo;

@ISA = qw(Wallet::Object::Duo);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.01';

##############################################################################
# Core methods
##############################################################################

# Override create to provide the specific Duo integration type that will be
# used in the remote Duo record.
sub create {
    my ($class, $type, $name, $schema, $creator, $host, $time) = @_;

    $time ||= time;
    my $self = $class->SUPER::create ($type, $name, $schema, $creator, $host,
                                      $time, 'rdp');
    return $self;
}

# Override get to output the data in a specific format used by Duo's RDP
# module.
sub get {
    my ($self, $user, $host, $time) = @_;
    $time ||= time;

    # Check that the object isn't locked.
    my $id = $self->{type} . ':' . $self->{name};
    if ($self->flag_check ('locked')) {
        $self->error ("cannot get $id: object is locked");
        return;
    }

    # Retrieve the integration from Duo.
    my $key;
    eval {
        my %search = (du_name => $self->{name});
        my $row = $self->{schema}->resultset ('Duo')->find (\%search);
        $key = $row->get_column ('du_key');
    };
    if ($@) {
        $self->error ($@);
        return;
    }
    my $integration = Net::Duo::Admin::Integration->new ($self->{duo}, $key);

    # We also need the admin server name, which we can get from the Duo object
    # configuration with a bit of JSON decoding.
    my $json = JSON->new->utf8 (1)->relaxed (1);
    my $config = $json->decode (scalar slurp $Wallet::Config::DUO_KEY_FILE);

    # Construct the returned file.
    my $output;
    $output .= "Integration key: $key\n";
    $output .= 'Secret key:      ' . $integration->secret_key . "\n";
    $output .= "Host:            $config->{api_hostname}\n";

    # Log the action and return.
    $self->log_action ('get', $user, $host, $time);
    return $output;
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=for stopwords
Allbery Duo integration DBH keytab

=head1 NAME

Wallet::Object::Duo::RDP -- Duo RDP int. object implementation for wallet

=head1 SYNOPSIS

    my @name = qw(duo-rdp host.example.com);
    my @trace = ($user, $host, time);
    my $object = Wallet::Object::Duo::RDP->create (@name, $schema, @trace);
    my $config = $object->get (@trace);
    $object->destroy (@trace);

=head1 DESCRIPTION

Wallet::Object::Duo::RDP is a representation of Duo integrations with
the wallet, specifically to output Duo integrations to set up an RDP
integration.  This can be used to set up remote logins, or all Windows
logins period if so selected in Duo's software.  It implements the
wallet object API and provides the necessary glue to create a Duo
integration, return a configuration file containing the key and API
information for that integration, and delete the integration from Duo
when the wallet object is destroyed.

Because the Duo RDP software is configured by a GUI, the information
returned for a get operation is a simple set that's readable but not
useful for directly plugging into a config file.  The values would need
to be cut and pasted into the GUI.

This object can be retrieved repeatedly without changing the secret key,
matching Duo's native behavior with integrations.  To change the keys of
the integration, delete it and recreate it.

To use this object, at least one configuration parameter must be set.  See
L<Wallet::Config> for details on supported configuration parameters and
information about how to set wallet configuration.

=head1 METHODS

This object mostly inherits from Wallet::Object::Duo.  See the
documentation for that class for all generic methods.  Below are only
those methods that are overridden or behave specially for this
implementation.

=over 4

=item create(TYPE, NAME, DBH, PRINCIPAL, HOSTNAME [, DATETIME])

This will override the Wallet::Object::Duo class with the information
needed to create a specific integration type in Duo.  It creates a new
object with the given TYPE and NAME (TYPE is normally C<duo-pam> and must
be for the rest of the wallet system to use the right class, but this
module doesn't check for ease of subclassing), using DBH as the handle
to the wallet metadata database.  PRINCIPAL, HOSTNAME, and DATETIME are
stored as history information.  PRINCIPAL should be the user who is
creating the object.  If DATETIME isn't given, the current time is
used.

When a new Duo integration object is created, a new integration will be
created in the configured Duo account and the integration key will be
stored in the wallet object.  If the integration already exists, create()
will fail.

If create() fails, it throws an exception.

=item get(PRINCIPAL, HOSTNAME [, DATETIME])

Retrieves the configuration information for the Duo integration and
returns that information in the format expected by the configuration file
for the Duo UNIX integration.  Returns undef on failure.  The caller
should call error() to get the error message if get() returns undef.

The returned configuration look look like:

    Integration key: <integration-key>
    Secret key:      <secret-key>
    Host:            <api-hostname>

The C<host> parameter will be taken from the configuration file pointed
to by the DUO_KEY_FILE configuration variable.

PRINCIPAL, HOSTNAME, and DATETIME are stored as history information.
PRINCIPAL should be the user who is downloading the keytab.  If DATETIME
isn't given, the current time is used.

=back

=head1 LIMITATIONS

Only one Duo account is supported for a given wallet implementation.

=head1 SEE ALSO

Net::Duo(3), Wallet::Config(3), Wallet::Object::Duo(3), wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHORS

Russ Allbery <eagle@eyrie.org>
Jon Robertson <eagle@eyrie.org>

=cut
