# Wallet::Object::Base -- Parent class for any object stored in the wallet
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2016 Russ Allbery <eagle@eyrie.org>
# Copyright 2007-2008, 2010-2011, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# SPDX-License-Identifier: MIT

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Object::Base;

use 5.008;
use strict;
use warnings;

use DateTime;
use Date::Parse qw(str2time);
use Text::Wrap qw(wrap);
use Wallet::ACL;

our $VERSION = '1.05';

##############################################################################
# Constructors
##############################################################################

# Initialize an object from the database.  Verifies that the object already
# exists with the given type, and if it does, returns a new blessed object of
# the specified class.  Stores the database handle to use, the name, and the
# type in the object.  If the object doesn't exist, returns undef.  This will
# probably be usable as-is by most object types.
sub new {
    my ($class, $type, $name, $schema) = @_;
    my %search = (ob_type => $type,
                  ob_name => $name);
    my $object = $schema->resultset('Object')->find (\%search);
    die "cannot find ${type}:${name}\n"
        unless ($object and $object->ob_name eq $name);
    my $self = {
        schema => $schema,
        name   => $name,
        type   => $type,
    };
    bless ($self, $class);
    return $self;
}

# Create a new object in the database of the specified name and type, setting
# the ob_created_* fields accordingly, and returns a new blessed object of the
# specified class.  Stores the database handle to use, the name, and the type
# in the object.  Subclasses may need to override this to do additional setup.
sub create {
    my ($class, $type, $name, $schema, $user, $host, $time) = @_;
    $time ||= time;
    die "invalid object type\n" unless $type;
    die "invalid object name\n" unless $name;
    my $guard = $schema->txn_scope_guard;
    eval {
        my $date = DateTime->from_epoch (epoch => $time);
        my %record = (ob_type         => $type,
                      ob_name         => $name,
                      ob_created_by   => $user,
                      ob_created_from => $host,
                      ob_created_on   => $date);
        $schema->resultset('Object')->create (\%record);
        %record = (oh_type   => $type,
                   oh_name   => $name,
                   oh_action => 'create',
                   oh_by     => $user,
                   oh_from   => $host,
                   oh_on     => $date);
        $schema->resultset('ObjectHistory')->create (\%record);
        $guard->commit;
    };
    if ($@) {
        die "cannot create object ${type}:${name}: $@\n";
    }
    my $self = {
        schema => $schema,
        name   => $name,
        type   => $type,
    };
    bless ($self, $class);
    return $self;
}

##############################################################################
# Utility functions
##############################################################################

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

# Returns the type of the object.
sub type {
    my ($self) = @_;
    return $self->{type};
}

# Returns the name of the object.
sub name {
    my ($self) = @_;
    return $self->{name};
}

# Record a global object action for this object.  Takes the action (which must
# be one of get or store), and the trace information: user, host, and time.
# Returns true on success and false on failure, setting error appropriately.
#
# This function commits its transaction when complete and should not be called
# inside another transaction.
sub log_action {
    my ($self, $action, $user, $host, $time) = @_;
    unless ($action =~ /^(get|store)\z/) {
        $self->error ("invalid history action $action");
        return;
    }

    # We have two traces to record, one in the object_history table and one in
    # the object record itself.  Commit both changes as a transaction.  We
    # assume that AutoCommit is turned off.
    my $guard = $self->{schema}->txn_scope_guard;
    eval {
        my $date = DateTime->from_epoch (epoch => $time);
        my %record = (oh_type   => $self->{type},
                      oh_name   => $self->{name},
                      oh_action => $action,
                      oh_by     => $user,
                      oh_from   => $host,
                      oh_on     => $date);
        $self->{schema}->resultset('ObjectHistory')->create (\%record);

        # Add in more timestamps based on the action type.
        my %search = (ob_type   => $self->{type},
                      ob_name   => $self->{name});
        my $object = $self->{schema}->resultset('Object')->find (\%search);
        if ($action eq 'get') {
            $object->ob_downloaded_by   ($user);
            $object->ob_downloaded_from ($host);
            $object->ob_downloaded_on   ($date);
        } elsif ($action eq 'store') {
            $object->ob_stored_by   ($user);
            $object->ob_stored_from ($host);
            $object->ob_stored_on   ($date);
        }
        $object->update;
        $guard->commit;
    };
    if ($@) {
        my $id = $self->{type} . ':' . $self->{name};
        $self->error ("cannot update history for $id: $@");
        return;
    }
    return 1;
}

# Record a setting change for this object.  Takes the field, the old value,
# the new value, and the trace information (user, host, and time).  The field
# may have the special value "type_data <field>" in which case the value after
# the whitespace is used as the type_field value.
#
# This function does not commit and does not catch exceptions.  It should
# normally be called as part of a larger transaction that implements the
# setting change and should be committed with that change.
sub log_set {
    my ($self, $field, $old, $new, $user, $host, $time) = @_;
    my $type_field;
    if ($field =~ /^type_data\s+/) {
        ($field, $type_field) = split (' ', $field, 2);
    }
    my %fields = map { $_ => 1 }
        qw(owner acl_get acl_store acl_show acl_destroy acl_flags expires
           comment flags type_data name);
    unless ($fields{$field}) {
        die "invalid history field $field";
    }

    my $date = DateTime->from_epoch (epoch => $time);
    my %record = (oh_type       => $self->{type},
                  oh_name       => $self->{name},
                  oh_action     => 'set',
                  oh_field      => $field,
                  oh_type_field => $type_field,
                  oh_old        => $old,
                  oh_new        => $new,
                  oh_by         => $user,
                  oh_from       => $host,
                  oh_on         => $date);
    $self->{schema}->resultset('ObjectHistory')->create (\%record);
}

##############################################################################
# Get/set values
##############################################################################

# Set a particular attribute.  Takes the attribute to set and its new value.
# Returns undef on failure and true on success.
sub _set_internal {
    my ($self, $attr, $value, $user, $host, $time) = @_;
    if ($attr !~ /^[a-z_]+\z/) {
        $self->error ("invalid attribute $attr");
        return;
    }
    $time ||= time;
    my $name = $self->{name};
    my $type = $self->{type};
    if ($self->flag_check ('locked')) {
        $self->error ("cannot modify ${type}:${name}: object is locked");
        return;
    }

    my $guard = $self->{schema}->txn_scope_guard;
    eval {
        my %search = (ob_type => $type,
                      ob_name => $name);
        my $object = $self->{schema}->resultset('Object')->find (\%search);
        my $column = "ob_$attr";
        my $old = $object->$column;
        my $new = $value;
        $object->update ({ $column => $value });

        if (ref ($old) && $old->isa ('DateTime')) {
            $old->set_time_zone ('local');
            $old = $old->ymd . q{ } . $old->hms;
        }
        if (ref ($new) && $new->isa ('DateTime')) {
            $new->set_time_zone ('local');
            $new = $new->ymd . q{ } . $new->hms;
        }
        $self->log_set ($attr, $old, $new, $user, $host, $time);
        $guard->commit;
    };
    if ($@) {
        my $id = $self->{type} . ':' . $self->{name};
        $self->error ("cannot set $attr on $id: $@");
        return;
    }
    return 1;
}

# Get a particular attribute.  Returns the attribute value or undef if the
# value isn't set or on a database error.  The two cases can be distinguished
# by whether $self->{error} is set.
sub _get_internal {
    my ($self, $attr) = @_;
    undef $self->{error};
    if ($attr !~ /^[a-z_]+\z/) {
        $self->error ("invalid attribute $attr");
        return;
    }
    $attr = 'ob_' . $attr;
    my $name = $self->{name};
    my $type = $self->{type};
    my $value;
    eval {
        my %search = (ob_type => $type,
                      ob_name => $name);
        my $object = $self->{schema}->resultset('Object')->find (\%search);
        $value = $object->$attr;
    };
    if ($@) {
        $self->error ($@);
        return;
    }
    return $value;
}

# Get or set an ACL on an object.  Takes the type of ACL and, if setting, the
# new ACL identifier.  If setting it, trace information must also be provided.
sub acl {
    my ($self, $type, $id, $user, $host, $time) = @_;
    if ($type !~ /^(get|store|show|destroy|flags)\z/) {
        $self->error ("invalid ACL type $type");
        return;
    }
    my $attr = "acl_$type";
    if ($id) {
        my $acl;
        eval { $acl = Wallet::ACL->new ($id, $self->{schema}) };
        if ($@) {
            $self->error ($@);
            return;
        }
        return $self->_set_internal ($attr, $acl->id, $user, $host, $time);
    } elsif (defined $id) {
        return $self->_set_internal ($attr, undef, $user, $host, $time);
    } else {
        my $id = $self->_get_internal ($attr);
        return unless defined $id;
        my $acl = eval { Wallet::ACL->new ($id, $self->{schema}) };
        if ($@) {
            $self->error ($@);
            return;
        }
        return $acl->name;
    }
}

# Get or set an attribute on an object.  Takes the name of the attribute and,
# if setting, the values and trace information.  The values must be provided
# as a reference to an array, even if there is only one value.
#
# Attributes are used by backends for backend-specific information (such as
# enctypes for a keytab).  The default implementation rejects all attribute
# names as unknown.
sub attr {
    my ($self, $attr, $values, $user, $host, $time) = @_;
    $self->error ("unknown attribute $attr");
    return;
}

# Format the object attributes for inclusion in show().  The default
# implementation just returns the empty string.
sub attr_show {
    my ($self) = @_;
    return '';
}

# Get or set the comment value of an object.  If setting it, trace information
# must also be provided.
sub comment {
    my ($self, $comment, $user, $host, $time) = @_;
    if ($comment) {
        return $self->_set_internal ('comment', $comment, $user, $host, $time);
    } elsif (defined $comment) {
        return $self->_set_internal ('comment', undef, $user, $host, $time);
    } else {
        return $self->_get_internal ('comment');
    }
}

# Get or set the expires value of an object.  Expects an expiration time in
# seconds since epoch.  If setting the expiration, trace information must also
# be provided.
sub expires {
    my ($self, $expires, $user, $host, $time) = @_;
    if ($expires) {
        my $seconds = str2time ($expires);
        unless (defined $seconds) {
            $self->error ("malformed expiration time $expires");
            return;
        }
        my $date = DateTime->from_epoch (epoch => $seconds);
        return $self->_set_internal ('expires', $date, $user, $host, $time);
    } elsif (defined $expires) {
        return $self->_set_internal ('expires', undef, $user, $host, $time);
    } else {
        my $date = $self->_get_internal ('expires');
        if (defined $date) {
            $date->set_time_zone ('local');
            return $date->ymd . q{ } . $date->hms;
        } else {
            return;
        }
    }
}

# Get or set the owner of an object.  If setting it, trace information must
# also be provided.
sub owner {
    my ($self, $owner, $user, $host, $time) = @_;
    if ($owner) {
        my $acl;
        eval { $acl = Wallet::ACL->new ($owner, $self->{schema}) };
        if ($@) {
            $self->error ($@);
            return;
        }
        return $self->_set_internal ('owner', $acl->id, $user, $host, $time);
    } elsif (defined $owner) {
        return $self->_set_internal ('owner', undef, $user, $host, $time);
    } else {
        my $id = $self->_get_internal ('owner');
        return unless defined $id;
        my $acl = eval { Wallet::ACL->new ($id, $self->{schema}) };
        if ($@) {
            $self->error ($@);
            return;
        }
        return $acl->name;
    }
}

##############################################################################
# Flags
##############################################################################

# Check whether a flag is set on the object.  Returns true if set, 0 if not
# set, and undef on error.
sub flag_check {
    my ($self, $flag) = @_;
    my $name = $self->{name};
    my $type = $self->{type};
    my $schema = $self->{schema};
    my $value;
    eval {
        my %search = (fl_type => $type,
                      fl_name => $name,
                      fl_flag => $flag);
        my $flag = $schema->resultset('Flag')->find (\%search);
        if (not defined $flag) {
            $value = 0;
        } else {
            $value = $flag->fl_flag;
        }
    };
    if ($@) {
        $self->error ("cannot check flag $flag for ${type}:${name}: $@");
        return;
    } else {
        return ($value) ? 1 : 0;
    }
}

# Clear a flag on an object.  Takes the flag and trace information.  Returns
# true on success and undef on failure.
sub flag_clear {
    my ($self, $flag, $user, $host, $time) = @_;
    $time ||= time;
    my $name = $self->{name};
    my $type = $self->{type};
    my $schema = $self->{schema};
    my $guard = $schema->txn_scope_guard;
    eval {
        my %search = (fl_type => $type,
                      fl_name => $name,
                      fl_flag => $flag);
        my $flag = $schema->resultset('Flag')->find (\%search);
        unless (defined $flag) {
            die "flag not set\n";
        }
        $flag->delete;
        $self->log_set ('flags', $flag->fl_flag, undef, $user, $host, $time);
        $guard->commit;
    };
    if ($@) {
        $self->error ("cannot clear flag $flag on ${type}:${name}: $@");
        return;
    }
    return 1;
}

# List the flags on an object.  Returns a list of flag names, which may be
# empty.  On error, returns the empty list.  The caller should call error() in
# this case to determine if an error occurred.
sub flag_list {
    my ($self) = @_;
    undef $self->{error};
    my @flags;
    eval {
        my %search = (fl_type => $self->{type},
                      fl_name => $self->{name});
        my %attrs  = (order_by => 'fl_flag');
        my @flags_rs = $self->{schema}->resultset('Flag')->search (\%search,
                                                                   \%attrs);
        for my $flag (@flags_rs) {
            push (@flags, $flag->fl_flag);
        }
    };
    if ($@) {
        my $id = $self->{type} . ':' . $self->{name};
        $self->error ("cannot retrieve flags for $id: $@");
        return;
    } else {
        return @flags;
    }
}

# Set a flag on an object.  Takes the flag and trace information.  Returns
# true on success and undef on failure.
sub flag_set {
    my ($self, $flag, $user, $host, $time) = @_;
    $time ||= time;
    my $name = $self->{name};
    my $type = $self->{type};
    my $schema = $self->{schema};
    my $guard = $schema->txn_scope_guard;
    eval {
        my %search = (fl_type => $type,
                      fl_name => $name,
                      fl_flag => $flag);
        my $flag = $schema->resultset('Flag')->find (\%search);
        if (defined $flag) {
            die "flag already set\n";
        }
        $flag = $schema->resultset('Flag')->create (\%search);
        $self->log_set ('flags', undef, $flag->fl_flag, $user, $host, $time);
        $guard->commit;
    };
    if ($@) {
        $self->error ("cannot set flag $flag on ${type}:${name}: $@");
        return;
    }
    return 1;
}

##############################################################################
# History
##############################################################################

# Expand a given ACL id to add its name, for readability.  Returns the
# original id alone if there was a problem finding the name.
sub format_acl_id {
    my ($self, $id) = @_;
    my $name = $id;

    my %search = (ac_id => $id);
    my $acl_rs = $self->{schema}->resultset('Acl')->find (\%search);
    if (defined $acl_rs) {
        $name = $acl_rs->ac_name . " ($id)";
    }

    return $name;
}

# Return the formatted history for a given object or undef on error.
# Currently always returns the complete history, but eventually will need to
# provide some way of showing only recent entries.
sub history {
    my ($self) = @_;
    my $output = '';
    eval {
        my %search = (oh_type => $self->{type},
                      oh_name => $self->{name});
        my %attrs = (order_by => 'oh_id');
        my @history = $self->{schema}->resultset('ObjectHistory')
            ->search (\%search, \%attrs);

        for my $history_rs (@history) {
            my $date = $history_rs->oh_on;
            $date->set_time_zone ('local');
            $output .= sprintf ("%s %s  ", $date->ymd, $date->hms);

            my $old    = $history_rs->oh_old;
            my $new    = $history_rs->oh_new;
            my $action = $history_rs->oh_action;
            my $field  = $history_rs->oh_field;

            if ($action eq 'set' and $field eq 'flags') {
                if (defined ($new)) {
                    $output .= "set flag $new";
                } elsif (defined ($old)) {
                    $output .= "clear flag $old";
                }
            } elsif ($action eq 'set' and $field eq 'type_data') {
                my $attr = $history_rs->oh_type_field;
                if (defined ($old) and defined ($new)) {
                    $output .= "set attribute $attr to $new (was $old)";
                } elsif (defined ($old)) {
                    $output .= "remove $old from attribute $attr";
                } elsif (defined ($new)) {
                    $output .= "add $new to attribute $attr";
                }
            } elsif ($action eq 'set'
                     and ($field eq 'owner' or $field =~ /^acl_/)) {
                $old = $self->format_acl_id ($old) if defined ($old);
                $new = $self->format_acl_id ($new) if defined ($new);
                if (defined ($old) and defined ($new)) {
                    $output .= "set $field to $new (was $old)";
                } elsif (defined ($new)) {
                    $output .= "set $field to $new";
                } elsif (defined ($old)) {
                    $output .= "unset $field (was $old)";
                }
            } elsif ($action eq 'set') {
                if (defined ($old) and defined ($new)) {
                    $output .= "set $field to $new (was $old)";
                } elsif (defined ($new)) {
                    $output .= "set $field to $new";
                } elsif (defined ($old)) {
                    $output .= "unset $field (was $old)";
                }
            } else {
                $output .= $action;
            }
            $output .= sprintf ("\n    by %s from %s\n", $history_rs->oh_by,
                               $history_rs->oh_from);
        }
    };
    if ($@) {
        my $id = $self->{type} . ':' . $self->{name};
        $self->error ("cannot read history for $id: $@");
        return;
    }
    return $output;
}

##############################################################################
# Object manipulation
##############################################################################

# The get methods must always be overridden by the subclass.
sub get { die "Do not instantiate Wallet::Object::Base directly\n"; }

# The update method should only work if a subclass supports it as something
# different from get.  That makes it explicit about whether the subclass has
# a meaningful update.
sub update {
    my ($self) = @_;
    $self->error ("update is not supported for this type, use get instead");
    return;
}

# Provide a default store implementation that returns an immutable object
# error so that auto-generated types don't have to provide their own.
sub store {
    my ($self, $data, $user, $host, $time) = @_;
    my $id = $self->{type} . ':' . $self->{name};
    if ($self->flag_check ('locked')) {
        $self->error ("cannot store $id: object is locked");
        return;
    }
    $self->error ("cannot store $id: object type is immutable");
    return;
}

# The default show function.  This may be adequate for many types; types that
# have additional data should call this method, grab the results, and then add
# their data on to the end.
sub show {
    my ($self) = @_;
    my $name = $self->{name};
    my $type = $self->{type};
    my @attrs = ([ ob_type            => 'Type'            ],
                 [ ob_name            => 'Name'            ],
                 [ ob_owner           => 'Owner'           ],
                 [ ob_acl_get         => 'Get ACL'         ],
                 [ ob_acl_store       => 'Store ACL'       ],
                 [ ob_acl_show        => 'Show ACL'        ],
                 [ ob_acl_destroy     => 'Destroy ACL'     ],
                 [ ob_acl_flags       => 'Flags ACL'       ],
                 [ ob_expires         => 'Expires'         ],
                 [ ob_comment         => 'Comment'         ],
                 [ ob_created_by      => 'Created by'      ],
                 [ ob_created_from    => 'Created from'    ],
                 [ ob_created_on      => 'Created on'      ],
                 [ ob_stored_by       => 'Stored by'       ],
                 [ ob_stored_from     => 'Stored from'     ],
                 [ ob_stored_on       => 'Stored on'       ],
                 [ ob_downloaded_by   => 'Downloaded by'   ],
                 [ ob_downloaded_from => 'Downloaded from' ],
                 [ ob_downloaded_on   => 'Downloaded on'   ]);
    my $fields = join (', ', map { $_->[0] } @attrs);
    my @data;
    my $object_rs;
    eval {
        my %search = (ob_type => $type,
                      ob_name => $name);
        $object_rs = $self->{schema}->resultset('Object')->find (\%search);
    };
    if ($@) {
        $self->error ("cannot retrieve data for ${type}:${name}: $@");
        return;
    }
    my $output = '';
    my @acls;

    # Format the results.  We use a hack to insert the flags before the first
    # trace field since they're not a field in the object in their own right.
    # The comment should be word-wrapped at 80 columns.
    for my $i (0 .. $#attrs) {
        my $field = $attrs[$i][0];
        my $fieldtext = $attrs[$i][1];
        my $value = $object_rs->$field;
        next unless defined($value);

        if ($field eq 'ob_comment' && length ($value) > 79 - 17) {
            local $Text::Wrap::columns = 80;
            local $Text::Wrap::unexpand = 0;
            $value = wrap (' ' x 17, ' ' x 17, $value);
            $value =~ s/^ {17}//;
        } elsif ($field eq 'ob_created_by') {
            my @flags = $self->flag_list;
            if (not @flags and $self->error) {
                return;
            }
            if (@flags) {
                $output .= sprintf ("%15s: %s\n", 'Flags', "@flags");
            }
            my $attr_output = $self->attr_show;
            if (not defined $attr_output) {
                return;
            }
            $output .= $attr_output;
        } elsif (ref ($value) && $value->isa ('DateTime')) {
            $value->set_time_zone ('local');
            $value = sprintf ("%s %s", $value->ymd, $value->hms);
        } elsif ($field =~ /^ob_(owner|acl_)/) {
            my $acl = eval { Wallet::ACL->new ($value, $self->{schema}) };
            if ($acl and not $@) {
                $value = $acl->name || $value;
                push (@acls, [ $acl, $value ]);
            }
        }
        $output .= sprintf ("%15s: %s\n", $fieldtext, $value);
    }
    if (@acls) {
        my %seen;
        @acls = grep { !$seen{$_->[1]}++ } @acls;
        for my $acl (@acls) {
            $output .= "\n" . $acl->[0]->show;
        }
    }
    return $output;
}

# The default destroy function only destroys the database metadata.  Generally
# subclasses need to override this to destroy whatever additional information
# is stored about this object.
sub destroy {
    my ($self, $user, $host, $time) = @_;
    $time ||= time;
    my $name = $self->{name};
    my $type = $self->{type};
    if ($self->flag_check ('locked')) {
        $self->error ("cannot destroy ${type}:${name}: object is locked");
        return;
    }
    my $guard = $self->{schema}->txn_scope_guard;
    eval {

        # Remove any flags that may exist for the record.
        my %search = (fl_type => $type,
                      fl_name => $name);
        $self->{schema}->resultset('Flag')->search (\%search)->delete;

        # Remove any object records
        %search = (ob_type => $type,
                   ob_name => $name);
        $self->{schema}->resultset('Object')->search (\%search)->delete;

        # And create a new history object for the destroy action.
        my $date = DateTime->from_epoch (epoch => $time);
        my %record = (oh_type => $type,
                      oh_name => $name,
                      oh_action => 'destroy',
                      oh_by     => $user,
                      oh_from   => $host,
                      oh_on     => $date);
        $self->{schema}->resultset('ObjectHistory')->create (\%record);
        $guard->commit;
    };
    if ($@) {
        $self->error ("cannot destroy ${type}:${name}: $@");
        return;
    }
    return 1;
}

1;
__END__

##############################################################################
# Documentation
##############################################################################

=head1 NAME

Wallet::Object::Base - Generic parent class for wallet objects

=for stopwords
DBH HOSTNAME DATETIME ACL backend metadata timestamp Allbery wallet-backend
backend-specific subclasses

=head1 SYNOPSIS

    package Wallet::Object::Simple;
    @ISA = qw(Wallet::Object::Base);
    sub get {
        my ($self, $user, $host, $time) = @_;
        $self->log_action ('get', $user, $host, $time) or return;
        return "Some secure data";
    }

=head1 DESCRIPTION

Wallet::Object::Base is the generic parent class for wallet objects (data
types that can be stored in the wallet system).  It provides default
functions and behavior, including handling generic object settings.  All
handlers for objects stored in the wallet should inherit from it.  It is
not used directly.

=head1 PUBLIC CLASS METHODS

The following methods are called by the rest of the wallet system and
should be implemented by all objects stored in the wallet.  They should be
called with the desired wallet object class as the first argument
(generally using the Wallet::Object::Type->new syntax).

=over 4

=item new(TYPE, NAME, DBH)

Creates a new object with the given object type and name, based on data
already in the database.  This method will only succeed if an object of
the given TYPE and NAME is already present in the wallet database.  If no
such object exits, throws an exception.  Otherwise, returns an object
blessed into the class used for the new() call (so subclasses can leave
this method alone and not override it).

Takes a Wallet::Schema object, which is stored in the object and used
for any further operations.

=item create(TYPE, NAME, DBH, PRINCIPAL, HOSTNAME [, DATETIME])

Similar to new() but instead creates a new entry in the database.  This
method will throw an exception if an entry for that type and name already
exists in the database or if creating the database record fails.
Otherwise, a new database entry will be created with that type and name,
no owner, no ACLs, no expiration, no flags, and with created by, from, and
on set to the PRINCIPAL, HOSTNAME, and DATETIME parameters.  If DATETIME
isn't given, the current time is used.  The database handle is treated as
with new().

=back

=head1 PUBLIC INSTANCE METHODS

The following methods may be called on instantiated wallet objects.
Normally, the only methods that a subclass will need to override are
get(), store(), show(), and destroy().

If the locked flag is set on an object, no actions may be performed on
that object except for the flag methods and show().  All other actions
will be rejected with an error saying the object is locked.

=over 4

=item acl(TYPE [, ACL, PRINCIPAL, HOSTNAME [, DATETIME]])

Sets or retrieves a given object ACL as a numeric ACL ID.  TYPE must be
one of C<get>, C<store>, C<show>, C<destroy>, or C<flags>, corresponding
to the ACLs kept on an object.  If no other arguments are given, returns
the current ACL setting as an ACL ID or undef if that ACL isn't set.  If
other arguments are given, change that ACL to ACL and return true on
success and false on failure.  Pass in the empty string for ACL to clear
the ACL.  The other arguments are used for logging and history and should
indicate the user and host from which the change is made and the time of
the change.

=item attr(ATTRIBUTE [, VALUES, PRINCIPAL, HOSTNAME [, DATETIME]])

Sets or retrieves a given object attribute.  Attributes are used to store
backend-specific information for a particular object type and ATTRIBUTE
must be an attribute type known to the underlying object implementation.
The default implementation of this method rejects all attributes as
unknown.

If no other arguments besides ATTRIBUTE are given, returns the values of
that attribute, if any, as a list.  On error, returns the empty list.  To
distinguish between an error and an empty return, call error() afterward.
It is guaranteed to return undef unless there was an error.

If other arguments are given, sets the given ATTRIBUTE values to VALUES,
which must be a reference to an array (even if only one value is being
set).  Pass a reference to an empty array to clear the attribute values.
The other arguments are used for logging and history and should indicate
the user and host from which the change is made and the time of the
change.  Returns true on success and false on failure.

=item attr_show()

Returns a formatted text description of the type-specific attributes of
the object, or undef on error.  The default implementation of this method
always returns the empty string.  If there are any type-specific
attributes set, this method should return that metadata, formatted as key:
value pairs with the keys right-aligned in the first 15 characters,
followed by a space, a colon, and the value.

=item comment([COMMENT, PRINCIPAL, HOSTNAME [, DATETIME]])

Sets or retrieves the comment associated with an object.  If no arguments
are given, returns the current comment or undef if no comment is set.  If
arguments are given, change the comment to COMMENT and return true on
success and false on failure.  Pass in the empty string for COMMENT to
clear the comment.

The other arguments are used for logging and history and should indicate
the user and host from which the change is made and the time of the
change.

=item destroy(PRINCIPAL, HOSTNAME [, DATETIME])

Destroys the object by removing all record of it from the database.  The
Wallet::Object::Base implementation handles the generic database work, but
any subclass should override this method to do any deletion of files or
entries in external databases and any other database entries and then call
the parent method to handle the generic database cleanup.  Returns true on
success and false on failure.  The arguments are used for logging and
history and should indicate the user and host from which the change is
made and the time of the change.

=item error([ERROR ...])

Returns the error of the last failing operation or undef if no operations
have failed.  Callers should call this function to get the error message
after an undef return from any other instance method.

For the convenience of child classes, this method can also be called with
one or more error strings.  If so, those strings are concatenated
together, trailing newlines are removed, any text of the form S<C< at \S+
line \d+\.?>> at the end of the message is stripped off, and the result is
stored as the error.  Only child classes should call this method with an
error string.

=item expires([EXPIRES, PRINCIPAL, HOSTNAME [, DATETIME]])

Sets or retrieves the expiration date of an object.  If no arguments are
given, returns the current expiration or undef if no expiration is set.
If arguments are given, change the expiration to EXPIRES and return true
on success and false on failure.  EXPIRES must be in the format
C<YYYY-MM-DD HH:MM:SS>, although the time portion may be omitted.  Pass in
the empty string for EXPIRES to clear the expiration date.

The other arguments are used for logging and history and should indicate
the user and host from which the change is made and the time of the
change.

=item flag_check(FLAG)

Check whether the given flag is set on an object.  Returns true if set,
C<0> if not set, and undef on error.

=item flag_clear(FLAG, PRINCIPAL, HOSTNAME [, DATETIME])

Clears FLAG on an object.  Returns true on success and false on failure.
The other arguments are used for logging and history and should indicate
the user and host from which the change is made and the time of the
change.

=item flag_list()

List the flags set on an object.  If no flags are set, returns the empty
list.  On failure, returns an empty list.  To distinguish between the
empty response and an error, the caller should call error() after an empty
return.  It is guaranteed to return undef if there was no error.

=item flag_set(FLAG, PRINCIPAL, HOSTNAME [, DATETIME])

Sets FLAG on an object.  Returns true on success and false on failure.
The other arguments are used for logging and history and should indicate
the user and host from which the change is made and the time of the
change.

=item get(PRINCIPAL, HOSTNAME [, DATETIME])

An object implementation must override this method with one that returns
either the data of the object or undef on some error, using the provided
arguments to update history information.  The Wallet::Object::Base
implementation just throws an exception.

=item history()

Returns the formatted history for the object.  There will be two lines for
each action on the object.  The first line has the timestamp of the action
and the action, and the second line gives the user who performed the
action and the host from which they performed it (based on the trace
information passed into the other object methods).

=item name()

Returns the object's name.

=item owner([OWNER, PRINCIPAL, HOSTNAME [, DATETIME]])

Sets or retrieves the owner of an object as a numeric ACL ID.  If no
arguments are given, returns the current owner ACL ID or undef if none is
set.  If arguments are given, change the owner to OWNER and return true on
success and false on failure.  Pass in the empty string for OWNER to clear
the owner.  The other arguments are used for logging and history and
should indicate the user and host from which the change is made and the
time of the change.

=item show()

Returns a formatted text description of the object suitable for human
display, or undef on error.  All of the base metadata about the object,
formatted as key: value pairs with the keys aligned in the first 15
characters followed by a space, a colon, and the value.  The attr_show()
method of the object is also called and any formatted output it returns
will be included.  If any ACLs or an owner are set, after this data there
is a blank line and then the information for each unique ACL, separated by
blank lines.

=item store(DATA, PRINCIPAL, HOSTNAME [, DATETIME])

Store user-supplied data into the given object.  This may not be supported
by all backends (for instance, backends that automatically generate the
data will not support this).  The default implementation rejects all
store() calls with an error message saying that the object is immutable.

=item type()

Returns the object's type.

=back

=head1 UTILITY METHODS

The following instance methods should not be called externally but are
provided for subclasses to call to implement some generic actions.

=over 4

=item log_action (ACTION, PRINCIPAL, HOSTNAME, DATETIME)

Updates the history tables and trace information appropriately for ACTION,
which should be either C<get> or C<store>.  No other changes are made to
the database, just updates of the history table and trace fields with the
provided data about who performed the action and when.

This function commits its transaction when complete and therefore should
not be called inside another transaction.  Normally it's called as a
separate transaction after the data is successfully stored or retrieved.

=item log_set (FIELD, OLD, NEW, PRINCIPAL, HOSTNAME, DATETIME)

Updates the history tables for the change in a setting value for an
object.  FIELD should be one of C<owner>, C<acl_get>, C<acl_store>,
C<acl_show>, C<acl_destroy>, C<acl_flags>, C<expires>, C<flags>, or a
value starting with C<type_data> followed by a space and a type-specific
field name.  The last form is the most common form used by a subclass.
OLD is the previous value of the field or undef if the field was unset,
and NEW is the new value of the field or undef if the field should be
unset.

This function does not commit and does not catch database exceptions.  It
should normally be called as part of a larger transaction that implements
the change in the setting.

=back

=head1 SEE ALSO

wallet-backend(8)

This module is part of the wallet system.  The current version is
available from L<https://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <eagle@eyrie.org>

=cut
