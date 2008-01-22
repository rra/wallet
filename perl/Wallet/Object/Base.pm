# Wallet::Object::Base -- Parent class for any object stored in the wallet.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007, 2008 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Object::Base;
require 5.006;

use strict;
use vars qw($VERSION);

use DBI;
use POSIX qw(strftime);
use Wallet::ACL;

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.04';

##############################################################################
# Constructors
##############################################################################

# Initialize an object from the database.  Verifies that the object already
# exists with the given type, and if it does, returns a new blessed object of
# the specified class.  Stores the database handle to use, the name, and the
# type in the object.  If the object doesn't exist, returns undef.  This will
# probably be usable as-is by most object types.
sub new {
    my ($class, $type, $name, $dbh) = @_;
    my $sql = 'select ob_name from objects where ob_type = ? and ob_name = ?';
    my $data = $dbh->selectrow_array ($sql, undef, $type, $name);
    $dbh->commit;
    die "cannot find ${type}:${name}\n" unless ($data and $data eq $name);
    my $self = {
        dbh  => $dbh,
        name => $name,
        type => $type,
    };
    bless ($self, $class);
    return $self;
}

# Create a new object in the database of the specified name and type, setting
# the ob_created_* fields accordingly, and returns a new blessed object of the
# specified class.  Stores the database handle to use, the name, and the type
# in the object.  Subclasses may need to override this to do additional setup.
sub create {
    my ($class, $type, $name, $dbh, $user, $host, $time) = @_;
    $time ||= time;
    die "invalid object type\n" unless $type;
    die "invalid object name\n" unless $name;
    eval {
        my $date = strftime ('%Y-%m-%d %T', localtime $time);
        my $sql = 'insert into objects (ob_type, ob_name, ob_created_by,
            ob_created_from, ob_created_on) values (?, ?, ?, ?, ?)';
        $dbh->do ($sql, undef, $type, $name, $user, $host, $date);
        $sql = "insert into object_history (oh_type, oh_name, oh_action,
            oh_by, oh_from, oh_on) values (?, ?, 'create', ?, ?, ?)";
        $dbh->do ($sql, undef, $type, $name, $user, $host, $date);
        $dbh->commit;
    };
    if ($@) {
        $dbh->rollback;
        die "cannot create object ${type}:${name}: $@\n";
    }
    my $self = {
        dbh  => $dbh,
        name => $name,
        type => $type,
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
    eval {
        my $date = strftime ('%Y-%m-%d %T', localtime $time);
        my $sql = 'insert into object_history (oh_type, oh_name, oh_action,
            oh_by, oh_from, oh_on) values (?, ?, ?, ?, ?, ?)';
        $self->{dbh}->do ($sql, undef, $self->{type}, $self->{name}, $action,
                          $user, $host, $date);
        if ($action eq 'get') {
            $sql = 'update objects set ob_downloaded_by = ?,
                ob_downloaded_from = ?, ob_downloaded_on = ? where
                ob_type = ? and ob_name = ?';
            $self->{dbh}->do ($sql, undef, $user, $host, $date, $self->{type},
                              $self->{name});
        } elsif ($action eq 'store') {
            $sql = 'update objects set ob_stored_by = ?, ob_stored_from = ?,
                ob_stored_on = ? where ob_type = ? and ob_name = ?';
            $self->{dbh}->do ($sql, undef, $user, $host, $date, $self->{type},
                              $self->{name});
        }
        $self->{dbh}->commit;
    };
    if ($@) {
        my $id = $self->{type} . ':' . $self->{name};
        $self->error ("cannot update history for $id: $@");
        $self->{dbh}->rollback;
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
           flags type_data);
    unless ($fields{$field}) {
        die "invalid history field $field";
    }
    my $date = strftime ('%Y-%m-%d %T', localtime $time);
    my $sql = "insert into object_history (oh_type, oh_name, oh_action,
        oh_field, oh_type_field, oh_old, oh_new, oh_by, oh_from, oh_on)
        values (?, ?, 'set', ?, ?, ?, ?, ?, ?, ?)";
    $self->{dbh}->do ($sql, undef, $self->{type}, $self->{name}, $field,
                      $type_field, $old, $new, $user, $host, $date);
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
    eval {
        my $sql = "select ob_$attr from objects where ob_type = ? and
            ob_name = ?";
        my $old = $self->{dbh}->selectrow_array ($sql, undef, $type, $name);
        $sql = "update objects set ob_$attr = ? where ob_type = ? and
            ob_name = ?";
        $self->{dbh}->do ($sql, undef, $value, $type, $name);
        $self->log_set ($attr, $old, $value, $user, $host, $time);
        $self->{dbh}->commit;
    };
    if ($@) {
        my $id = $self->{type} . ':' . $self->{name};
        $self->error ("cannot set $attr on $id: $@");
        $self->{dbh}->rollback;
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
        my $sql = "select $attr from objects where ob_type = ? and
            ob_name = ?";
        $value = $self->{dbh}->selectrow_array ($sql, undef, $type, $name);
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ($@);
        $self->{dbh}->rollback;
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
        eval { $acl = Wallet::ACL->new ($id, $self->{dbh}) };
        if ($@) {
            $self->error ($@);
            return;
        }
        return $self->_set_internal ($attr, $acl->id, $user, $host, $time);
    } elsif (defined $id) {
        return $self->_set_internal ($attr, undef, $user, $host, $time);
    } else {
        return $self->_get_internal ($attr);
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

# Get or set the expires value of an object.  Expects an expiration time in
# seconds since epoch.  If setting the expiration, trace information must also
# be provided.
sub expires {
    my ($self, $expires, $user, $host, $time) = @_;
    if ($expires) {
        if ($expires !~ /^\d{4}-\d\d-\d\d( \d\d:\d\d:\d\d)?\z/) {
            $self->error ("malformed expiration time $expires");
            return;
        }
        return $self->_set_internal ('expires', $expires, $user, $host, $time);
    } elsif (defined $expires) {
        return $self->_set_internal ('expires', undef, $user, $host, $time);
    } else {
        return $self->_get_internal ('expires');
    }
}

# Get or set the owner of an object.  If setting it, trace information must
# also be provided.
sub owner {
    my ($self, $owner, $user, $host, $time) = @_;
    if ($owner) {
        my $acl;
        eval { $acl = Wallet::ACL->new ($owner, $self->{dbh}) };
        if ($@) {
            $self->error ($@);
            return;
        }
        return $self->_set_internal ('owner', $acl->id, $user, $host, $time);
    } elsif (defined $owner) {
        return $self->_set_internal ('owner', undef, $user, $host, $time);
    } else {
        return $self->_get_internal ('owner');
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
    my $dbh = $self->{dbh};
    my $value;
    eval {
        my $sql = 'select fl_flag from flags where fl_type = ? and fl_name = ?
            and fl_flag = ?';
        $value = $dbh->selectrow_array ($sql, undef, $type, $name, $flag);
        $dbh->commit;
    };
    if ($@) {
        $self->error ("cannot check flag $flag for ${type}:${name}: $@");
        $dbh->rollback;
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
    my $dbh = $self->{dbh};
    eval {
        my $sql = 'select * from flags where fl_type = ? and fl_name = ? and
            fl_flag = ?';
        my ($data) = $dbh->selectrow_array ($sql, undef, $type, $name, $flag);
        unless (defined $data) {
            die "flag not set\n";
        }
        $sql = 'delete from flags where fl_type = ? and fl_name = ? and
            fl_flag = ?';
        $dbh->do ($sql, undef, $type, $name, $flag);
        $self->log_set ('flags', $flag, undef, $user, $host, $time);
        $dbh->commit;
    };
    if ($@) {
        $self->error ("cannot clear flag $flag on ${type}:${name}: $@");
        $dbh->rollback;
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
        my $sql = 'select fl_flag from flags where fl_type = ? and
            fl_name = ? order by fl_flag';
        my $sth = $self->{dbh}->prepare ($sql);
        $sth->execute ($self->{type}, $self->{name});
        my $flag;
        while (defined ($flag = $sth->fetchrow_array)) {
            push (@flags, $flag);
        }
        $self->{dbh}->commit;
    };
    if ($@) {
        my $id = $self->{type} . ':' . $self->{name};
        $self->error ("cannot retrieve flags for $id: $@");
        $self->{dbh}->rollback;
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
    my $dbh = $self->{dbh};
    eval {
        my $sql = 'select * from flags where fl_type = ? and fl_name = ? and
            fl_flag = ?';
        my ($data) = $dbh->selectrow_array ($sql, undef, $type, $name, $flag);
        if (defined $data) {
            die "flag already set\n";
        }
        $sql = 'insert into flags (fl_type, fl_name, fl_flag)
            values (?, ?, ?)';
        $dbh->do ($sql, undef, $type, $name, $flag);
        $self->log_set ('flags', undef, $flag, $user, $host, $time);
        $dbh->commit;
    };
    if ($@) {
        $self->error ("cannot set flag $flag on ${type}:${name}: $@");
        $dbh->rollback;
        return;
    }
    return 1;
}

##############################################################################
# History
##############################################################################

# Return the formatted history for a given object or undef on error.
# Currently always returns the complete history, but eventually will need to
# provide some way of showing only recent entries.
sub history {
    my ($self) = @_;
    my $output = '';
    eval {
        my $sql = 'select oh_action, oh_field, oh_type_field, oh_old, oh_new,
            oh_by, oh_from, oh_on from object_history where oh_type = ? and
            oh_name = ? order by oh_on';
        my $sth = $self->{dbh}->prepare ($sql);
        $sth->execute ($self->{type}, $self->{name});
        my @data;
        while (@data = $sth->fetchrow_array) {
            $output .= "$data[7]  ";
            my ($old, $new) = @data[3..4];
            if ($data[0] eq 'set' and $data[1] eq 'flags') {
                if (defined ($data[4])) {
                    $output .= "set flag $data[4]";
                } elsif (defined ($data[3])) {
                    $output .= "clear flag $data[3]";
                }
            } elsif ($data[0] eq 'set' and $data[1] eq 'type_data') {
                my $attr = $data[2];
                if (defined ($old) and defined ($new)) {
                    $output .= "set attribute $attr to $new (was $old)";
                } elsif (defined ($old)) {
                    $output .= "remove $old from attribute $attr";
                } elsif (defined ($new)) {
                    $output .= "add $new to attribute $attr";
                }
            } elsif ($data[0] eq 'set') {
                my $field = $data[1];
                if (defined ($old) and defined ($new)) {
                    $output .= "set $field to $new (was $old)";
                } elsif (defined ($new)) {
                    $output .= "set $field to $new";
                } elsif (defined ($old)) {
                    $output .= "unset $field (was $old)";
                }
            } else {
                $output .= $data[0];
            }
            $output .= "\n    by $data[5] from $data[6]\n";
        }
        $self->{dbh}->commit;
    };
    if ($@) {
        my $id = $self->{type} . ':' . $self->{name};
        $self->error ("cannot read history for $id: $@");
        $self->{dbh}->rollback;
        return;
    }
    return $output;
}

##############################################################################
# Object manipulation
##############################################################################

# The get methods must always be overridden by the subclass.
sub get { die "Do not instantiate Wallet::Object::Base directly\n"; }

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
    eval {
        my $sql = "select $fields from objects where ob_type = ? and
            ob_name = ?";
        @data = $self->{dbh}->selectrow_array ($sql, undef, $type, $name);
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ("cannot retrieve data for ${type}:${name}: $@");
        $self->{dbh}->rollback;
        return;
    }
    my $output = '';
    my @acls;

    # Format the results.  We use a hack to insert the flags before the first
    # trace field since they're not a field in the object in their own right.
    for my $i (0 .. $#data) {
        if ($attrs[$i][0] eq 'ob_created_by') {
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
        }
        next unless defined $data[$i];
        if ($attrs[$i][0] =~ /^ob_(owner|acl_)/) {
            my $acl = eval { Wallet::ACL->new ($data[$i], $self->{dbh}) };
            if ($acl and not $@) {
                $data[$i] = $acl->name || $data[$i];
                push (@acls, [ $acl, $data[$i] ]);
            }
        }
        $output .= sprintf ("%15s: %s\n", $attrs[$i][1], $data[$i]);
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
    eval {
        my $date = strftime ('%Y-%m-%d %T', localtime $time);
        my $sql = 'delete from flags where fl_type = ? and fl_name = ?';
        $self->{dbh}->do ($sql, undef, $type, $name);
        $sql = 'delete from objects where ob_type = ? and ob_name = ?';
        $self->{dbh}->do ($sql, undef, $type, $name);
        $sql = "insert into object_history (oh_type, oh_name, oh_action,
            oh_by, oh_from, oh_on) values (?, ?, 'destroy', ?, ?, ?)";
        $self->{dbh}->do ($sql, undef, $type, $name, $user, $host, $date);
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ("cannot destroy ${type}:${name}: $@");
        $self->{dbh}->rollback;
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
types that can be stored in the wallet system).  It provides defualt
functions and behavior, including handling generic object settings.  All
handlers for objects stored in the wallet should inherit from it.  It is
not used directly.

=head1 PUBLIC CLASS METHODS

The following methods are called by the rest of the wallet system and should
be implemented by all objects stored in the wallet.  They should be called
with the desired wallet object class as the first argument (generally using
the Wallet::Object::Type->new syntax).

=over 4

=item new(TYPE, NAME, DBH)

Creates a new object with the given object type and name, based on data
already in the database.  This method will only succeed if an object of the
given TYPE and NAME is already present in the wallet database.  If no such
object exits, throws an exception.  Otherwise, returns an object blessed
into the class used for the new() call (so subclasses can leave this method
alone and not override it).

Takes a Wallet::Database object, which is stored in the object and used for
any further operations.

=item create(TYPE, NAME, DBH, PRINCIPAL, HOSTNAME [, DATETIME])

Similar to new() but instead creates a new entry in the database.  This
method will throw an exception if an entry for that type and name already
exists in the database or if creating the database record fails.  Otherwise,
a new database entry will be created with that type and name, no owner, no
ACLs, no expiration, no flags, and with created by, from, and on set to the
PRINCIPAL, HOSTNAME, and DATETIME parameters.  If DATETIME isn't given, the
current time is used.  The database handle is treated as with new().

=back

=head1 PUBLIC INSTANCE METHODS

The following methods may be called on instantiated wallet objects.
Normally, the only methods that a subclass will need to override are get(),
store(), show(), and destroy().

If the locked flag is set on an object, no actions may be performed on that
object except for the flag methods and show().  All other actions will be
rejected with an error saying the object is locked.

=over 4

=item acl(TYPE [, ACL, PRINCIPAL, HOSTNAME [, DATETIME]])

Sets or retrieves a given object ACL as a numeric ACL ID.  TYPE must be one
of C<get>, C<store>, C<show>, C<destroy>, or C<flags>, corresponding to the
ACLs kept on an object.  If no other arguments are given, returns the
current ACL setting as an ACL ID or undef if that ACL isn't set.  If other
arguments are given, change that ACL to ACL and return true on success and
false on failure.  Pass in the empty string for ACL to clear the ACL.  The
other arguments are used for logging and history and should indicate the
user and host from which the change is made and the time of the change.

=item attr(ATTRIBUTE [, VALUES, PRINCIPAL, HOSTNAME [, DATETIME]])

Sets or retrieves a given object attribute.  Attributes are used to store
backend-specific information for a particular object type and ATTRIBUTE must
be an attribute type known to the underlying object implementation.  The
default implementation of this method rejects all attributes as unknown.

If no other arguments besides ATTRIBUTE are given, returns the values of
that attribute, if any, as a list.  On error, returns the empty list.  To
distinguish between an error and an empty return, call error() afterwards.
It is guaranteed to return undef unless there was an error.

If other arguments are given, sets the given ATTRIBUTE values to VALUES,
which must be a reference to an array (even if only one value is being set).
Pass a reference to an empty array to clear the attribute values.  The other
arguments are used for logging and history and should indicate the user and
host from which the change is made and the time of the change.  Returns true
on success and false on failure.

=item attr_show()

Returns a formatted text description of the type-specific attributes of the
object, or undef on error.  The default implementation of this method always
returns the empty string.  If there are any type-specific attributes set,
this method should return that metadata, formatted as key: value pairs with
the keys right-aligned in the first 15 characters, followed by a space, a
colon, and the value.

=item destroy(PRINCIPAL, HOSTNAME [, DATETIME])

Destroys the object by removing all record of it from the database.  The
Wallet::Object::Base implementation handles the generic database work,
but any subclass should override this method to do any deletion of files
or entries in external databases and any other database entries and then
call the parent method to handle the generic database cleanup.  Returns
true on success and false on failure.  The arguments are used for logging
and history and should indicate the user and host from which the change is
made and the time of the change.

=item error([ERROR ...])

Returns the error of the last failing operation or undef if no operations
have failed.  Callers should call this function to get the error message
after an undef return from any other instance method.

For the convenience of child classes, this method can also be called with
one or more error strings.  If so, those strings are concatenated together,
trailing newlines are removed, any text of the form S<C< at \S+ line
\d+\.?>> at the end of the message is stripped off, and the result is stored
as the error.  Only child classes should call this method with an error
string.

=item expires([EXPIRES, PRINCIPAL, HOSTNAME [, DATETIME]])

Sets or retrieves the expiration date of an object.  If no arguments are
given, returns the current expiration or undef if no expiration is set.  If
arguments are given, change the expiration to EXPIRES and return true on
success and false on failure.  EXPIRES must be in the format C<YYYY-MM-DD
HH:MM:SS>, although the time portion may be omitted.  Pass in the empty
string for EXPIRES to clear the expiration date.

The other arguments are used for logging and history and should indicate the
user and host from which the change is made and the time of the change.

=item flag_check(FLAG)

Check whether the given flag is set on an object.  Returns true if set, C<0>
if not set, and undef on error.

=item flag_clear(FLAG, PRINCIPAL, HOSTNAME [, DATETIME])

Clears FLAG on an object.  Returns true on success and false on failure.
The other arguments are used for logging and history and should indicate the
user and host from which the change is made and the time of the change.

=item flag_list()

List the flags set on an object.  If no flags are set, returns the empty
list.  On failure, returns an empty list.  To distinguish between the empty
response and an error, the caller should call error() after an empty return.
It is guaranteed to return undef if there was no error.

=item flag_set(FLAG, PRINCIPAL, HOSTNAME [, DATETIME])

Sets FLAG on an object.  Returns true on success and false on failure.
The other arguments are used for logging and history and should indicate the
user and host from which the change is made and the time of the change.

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
the owner.  The other arguments are used for logging and history and should
indicate the user and host from which the change is made and the time of the
change.

=item show()

Returns a formatted text description of the object suitable for human
display, or undef on error.  All of the base metadata about the object,
formatted as key: value pairs with the keys aligned in the first 15
characters followed by a space, a colon, and the value.  The attr_show()
method of the object is also called and any formatted output it returns will
be included.  If any ACLs or an owner are set, after this data there is a
blank line and then the information for each unique ACL, separated by blank
lines.

=item store(DATA, PRINCIPAL, HOSTNAME [, DATETIME])

Store user-supplied data into the given object.  This may not be supported
by all backends (for instance, backends that automatically generate the data
will not support this).  The default implementation rejects all store()
calls with an error message saying that the object is immutable.

=item type()

Returns the object's type.

=back

=head1 UTILITY METHODS

The following instance methods should not be called externally but are
provided for subclasses to call to implement some generic actions.

=over 4

=item log_action (ACTION, PRINCIPAL, HOSTNAME, DATETIME)

Updates the history tables and trace information appropriately for ACTION,
which should be either C<get> or C<store>.  No other changes are made to the
database, just updates of the history table and trace fields with the
provided data about who performed the action and when.

This function commits its transaction when complete and therefore should not
be called inside another transaction.  Normally it's called as a separate
transaction after the data is successfully stored or retrieved.

=item log_set (FIELD, OLD, NEW, PRINCIPAL, HOSTNAME, DATETIME)

Updates the history tables for the change in a setting value for an object.
FIELD should be one of C<owner>, C<acl_get>, C<acl_store>, C<acl_show>,
C<acl_destroy>, C<acl_flags>, C<expires>, C<flags>, or a value starting with
C<type_data> followed by a space and a type-specific field name.  The last
form is the most common form used by a subclass.  OLD is the previous value
of the field or undef if the field was unset, and NEW is the new value of
the field or undef if the field should be unset.

This function does not commit and does not catch database exceptions.  It
should normally be called as part of a larger transaction that implements
the change in the setting.

=back

=head1 SEE ALSO

wallet-backend(8)

This module is part of the wallet system.  The current version is available
from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <rra@stanford.edu>

=cut
