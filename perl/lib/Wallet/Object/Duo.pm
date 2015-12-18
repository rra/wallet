# Wallet::Object::Duo -- Base Duo object implementation for the wallet
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Object::Duo;
require 5.006;

use strict;
use warnings;
use vars qw(@ISA $VERSION);

use JSON;
use Net::Duo::Admin;
use Net::Duo::Admin::Integration;
use Perl6::Slurp qw(slurp);
use Wallet::Config ();
use Wallet::Object::Base;

@ISA = qw(Wallet::Object::Base);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.03';

# Mappings from our types into what Duo calls the integration types.
our %DUO_TYPES = (
                  'duo'        => {
                      integration => 'unix',
                      output      => \&_output_generic,
                  },
                  'duo-ldap'   => {
                      integration => 'ldapproxy',
                      output      => \&_output_ldap,
                  },
                  'duo-pam'    => {
                      integration => 'unix',
                      output      => \&_output_pam,
                  },
                  'duo-radius' => {
                      integration => 'radius',
                      output      => \&_output_radius,
                  },
                 );

# Extra types to add.  These are all just named as the Duo integration name
# with duo- before it and go to the generic output.  Put them here to prevent
# pages of settings.  These are also not all actually set as types in the
# types table to prevent overpopulation.  You should manually create the
# entries in that table for any Duo integrations you want to add.
our @EXTRA_TYPES = ('accountsapi', 'adfs', 'adminapi', 'array', 'barracuda',
                    'cisco', 'citrixcag', 'citrixns', 'confluence', 'drupal',
                    'f5bigip', 'f5firepass', 'fortinet', 'jira', 'juniper',
                    'juniperuac', 'lastpass', 'okta', 'onelogin', 'openvpn',
                    'openvpnas', 'owa', 'paloalto', 'rdgateway', 'rdp',
                    'rdweb', 'rest', 'rras', 'shibboleth', 'sonicwallsra',
                    'splunk', 'tmg', 'uag', 'verify', 'vmwareview', 'websdk',
                    'wordpress');
for my $type (@EXTRA_TYPES) {
    my $wallet_type = 'duo-'.$type;
    $DUO_TYPES{$wallet_type}{integration} = $type;
    $DUO_TYPES{$wallet_type}{output}      = \&_output_generic;
};

##############################################################################
# Get output methods
##############################################################################

# Output for any miscellaneous Duo integration, usually those that use a GUI
# to set information and so don't need a custom configuration file.
sub _output_generic {
    my ($key, $secret, $hostname) = @_;

    my $output;
    $output .= "Integration key: $key\n";
    $output .= "Secret key:      $secret\n";
    $output .= "Host:            $hostname\n";

    return $output;
}

# Output for the Duo unix integration, which hooks into the PAM stack.
sub _output_pam {
    my ($key, $secret, $hostname) = @_;

    my $output = "[duo]\n";
    $output .= "ikey = $key\n";
    $output .= "skey = $secret\n";
    $output .= "host = $hostname\n";

    return $output;
}

# Output for the radius proxy, which can be plugged into the proxy config.
sub _output_radius {
    my ($key, $secret, $hostname) = @_;

    my $output = "[radius_server_challenge]\n";
    $output .= "ikey     = $key\n";
    $output .= "skey     = $secret\n";
    $output .= "api_host = $hostname\n";
    $output .= "client   = radius_client\n";

    return $output;
}

# Output for the LDAP proxy, which can be plugged into the proxy config.
sub _output_ldap {
    my ($key, $secret, $hostname) = @_;

    my $output = "[ldap_server_challenge]\n";
    $output .= "ikey     = $key\n";
    $output .= "skey     = $secret\n";
    $output .= "api_host = $hostname\n";

    return $output;
}

##############################################################################
# Core methods
##############################################################################

# Override attr_show to display the Duo integration key attribute.
sub attr_show {
    my ($self) = @_;
    my $output = '';
    my $key;
    eval {
        my %search = (du_name => $self->{name},
                      du_type => $self->{type},
                     );
        my $row = $self->{schema}->resultset ('Duo')->find (\%search);
        $key = $row->get_column ('du_key');
    };
    if ($@) {
        $self->error ($@);
        return;
    }
    return sprintf ("%15s: %s\n", 'Duo key', $key);
}

# Override new to start by creating a Net::Duo::Admin object for subsequent
# calls.
sub new {
    my ($class, $type, $name, $schema) = @_;

    # We have to have a Duo integration key file set.
    if (not $Wallet::Config::DUO_KEY_FILE) {
        die "duo object implementation not configured\n";
    }
    my $key_file = $Wallet::Config::DUO_KEY_FILE;
    my $agent    = $Wallet::Config::DUO_AGENT;

    # Construct the Net::Duo::Admin object.
    require Net::Duo::Admin;
    my $duo = Net::Duo::Admin->new (
        {
            key_file   => $key_file,
            user_agent => $agent,
        }
    );

    # Construct the object.
    my $self = $class->SUPER::new ($type, $name, $schema);
    $self->{duo} = $duo;
    return $self;
}

# Override create to start by creating a new integration in Duo, and only
# create the entry in the database if that succeeds.  Error handling isn't
# great here since we don't have a way to communicate the error back to the
# caller.
sub create {
    my ($class, $type, $name, $schema, $creator, $host, $time) = @_;

    # We have to have a Duo integration key file set.
    if (not $Wallet::Config::DUO_KEY_FILE) {
        die "duo object implementation not configured\n";
    }
    my $key_file = $Wallet::Config::DUO_KEY_FILE;
    my $agent    = $Wallet::Config::DUO_AGENT;

    # Make sure this is actually a type we know about, since this handler
    # can handle many types.
    if (!exists $DUO_TYPES{$type}) {
        die "$type is not a valid duo integration\n";
    }

    # Construct the Net::Duo::Admin object.
    require Net::Duo::Admin;
    my $duo = Net::Duo::Admin->new (
        {
            key_file   => $key_file,
            user_agent => $agent,
        }
    );

    # Create the object in Duo.
    require Net::Duo::Admin::Integration;
    my $duo_type = $DUO_TYPES{$type}{integration};
    my %data = (
        name  => "$name ($duo_type)",
        notes => 'Managed by wallet',
        type  => $duo_type,
    );
    my $integration = Net::Duo::Admin::Integration->create ($duo, \%data);

    # Create the object in wallet.
    my @trace = ($creator, $host, $time);
    my $self = $class->SUPER::create ($type, $name, $schema, @trace);
    $self->{duo} = $duo;

    # Add the integration key to the object metadata.
    my $guard = $self->{schema}->txn_scope_guard;
    eval {
        my %record = (
            du_name => $name,
            du_type => $type,
            du_key  => $integration->integration_key,
        );
        $self->{schema}->resultset ('Duo')->create (\%record);
        $guard->commit;
    };
    if ($@) {
        my $id = $self->{type} . ':' . $self->{name};
        $self->error ("cannot set Duo key for $id: $@");
        return;
    }

    # Done.  Return the object.
    return $self;
}

# Override destroy to delete the integration out of Duo as well.
sub destroy {
    my ($self, $user, $host, $time) = @_;
    my $id = $self->{type} . ':' . $self->{name};
    if ($self->flag_check ('locked')) {
        $self->error ("cannot destroy $id: object is locked");
        return;
    }
    my $schema = $self->{schema};
    my $guard = $schema->txn_scope_guard;
    eval {
        my %search = (du_name => $self->{name},
                      du_type => $self->{type},
                     );
        my $row = $schema->resultset ('Duo')->find (\%search);
        my $key = $row->get_column ('du_key');
        my $int = Net::Duo::Admin::Integration->new ($self->{duo}, $key);
        $int->delete;
        $row->delete;
        $guard->commit;
    };
    if ($@) {
        $self->error ($@);
        return;
    }
    return $self->SUPER::destroy ($user, $host, $time);
}

# Our get implementation.  Retrieve the integration information from Duo and
# construct the configuration file expected by the Duo PAM module.
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
        my %search = (du_name => $self->{name},
                      du_type => $self->{type},
                     );
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

    # Construct the returned file.  Assume the generic handler in case there
    # is no valid handler, though that shouldn't happen.
    my $output_sub;
    my $type = $self->{type};
    if (exists $DUO_TYPES{$type}{output}) {
        $output_sub = $DUO_TYPES{$type}{output};
    } else {
        $output_sub = \&_output_generic;
    }
    my $output = $output_sub->($key, $integration->secret_key,
                               $config->{api_hostname});

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

Wallet::Object::Duo - Duo integration object implementation for wallet

=head1 SYNOPSIS

    my @name = qw(duo host.example.com);
    my @trace = ($user, $host, time);
    my $object = Wallet::Object::Duo->create (@name, $schema, @trace);
    my $config = $object->get (@trace);
    $object->destroy (@trace);

=head1 DESCRIPTION

Wallet::Object::Duo is a representation of Duo integrations the wallet.
It implements the wallet object API and provides the necessary glue to
create a Duo integration, return a configuration file containing the key
and API information for that integration, and delete the integration from
Duo when the wallet object is destroyed.

Usually you will want to use one of the subclasses of this module, which
override the output to give you a configuration fragment suited for a
specific application type.  However, you can always use this module for
generic integrations where you don't mind massaging the output into the
configuration for the application using Duo.

This object can be retrieved repeatedly without changing the secret key,
matching Duo's native behavior with integrations.  To change the keys of
the integration, delete it and recreate it.

To use this object, at least one configuration parameter must be set.  See
L<Wallet::Config> for details on supported configuration parameters and
information about how to set wallet configuration.

=head1 METHODS

This object mostly inherits from Wallet::Object::Base.  See the
documentation for that class for all generic methods.  Below are only
those methods that are overridden or behave specially for this
implementation.

=over 4

=item create(TYPE, NAME, DBH, PRINCIPAL, HOSTNAME [, DATETIME, INTEGRATION_TYPE])

This is a class method and should be called on the Wallet::Object::Duo
class.  It creates a new object with the given TYPE and NAME (TYPE is
normally C<duo> and must be for the rest of the wallet system to use the
right class, but this module doesn't check for ease of subclassing), using
DBH as the handle to the wallet metadata database.  PRINCIPAL, HOSTNAME,
and DATETIME are stored as history information.  PRINCIPAL should be the
user who is creating the object.  If DATETIME isn't given, the current
time is used.

When a new Duo integration object is created, a new integration will be
created in the configured Duo account and the integration key will be
stored in the wallet object.  If the integration already exists, create()
will fail.  If an integration type isn't given, the new integration's type
is controlled by the DUO_TYPE configuration variable, which defaults to
C<unix>.  See L<Wallet::Config> for more information.

If create() fails, it throws an exception.

=item destroy(PRINCIPAL, HOSTNAME [, DATETIME])

Destroys a Duo integration object by removing it from the database and
deleting the integration from Duo.  If deleting the Duo integration fails,
destroy() fails.  Returns true on success and false on failure.  The
caller should call error() to get the error message after a failure.
PRINCIPAL, HOSTNAME, and DATETIME are stored as history information.
PRINCIPAL should be the user who is destroying the object.  If DATETIME
isn't given, the current time is used.

=item get(PRINCIPAL, HOSTNAME [, DATETIME])

Retrieves the configuration information for the Duo integration and
returns that information in the format expected by the configuration file
for the Duo UNIX integration.  Returns undef on failure.  The caller
should call error() to get the error message if get() returns undef.

The returned configuration look look like:

    [duo]
    ikey = <integration-key>
    skey = <secret-key>
    host = <api-hostname>

The C<host> parameter will be taken from the configuration file pointed
to by the DUO_KEY_FILE configuration variable.

PRINCIPAL, HOSTNAME, and DATETIME are stored as history information.
PRINCIPAL should be the user who is downloading the keytab.  If DATETIME
isn't given, the current time is used.

=back

=head1 LIMITATIONS

Only one Duo account is supported for a given wallet implementation.

=head1 SEE ALSO

Net::Duo(3), Wallet::Config(3), Wallet::Object::Base(3), wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=cut
