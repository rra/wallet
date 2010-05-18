# Wallet::Report -- Wallet system reporting interface.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2008, 2009, 2010 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Report;
require 5.006;

use strict;
use vars qw($VERSION);

use Wallet::ACL;
use Wallet::Database;

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.03';

##############################################################################
# Constructor, destructor, and accessors
##############################################################################

# Create a new wallet report object.  Opens a connection to the database that
# will be used for all of the wallet configuration information.  Throw an
# exception if anything goes wrong.
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
# Object reports
##############################################################################

# Return the SQL statement to find every object in the database.
sub objects_all {
    my ($self) = @_;
    my $sql = 'select ob_type, ob_name from objects order by ob_type,
        ob_name';
    return $sql;
}

# Return the SQL statement and the search field required to find all objects
# matching a specific type.
sub objects_type {
    my ($self, $type) = @_;
    my $sql = 'select ob_type, ob_name from objects where ob_type=? order
        by ob_type, ob_name';
    return ($sql, $type);
}

# Return the SQL statement and search field required to find all objects owned
# by a given ACL.  If the requested owner is null, we ignore this and do a
# different search for IS NULL.  If the requested owner does not actually
# match any ACLs, set an error and return undef.
sub objects_owner {
    my ($self, $owner) = @_;
    my ($sth);
    if (lc ($owner) eq 'null') {
        my $sql = 'select ob_type, ob_name from objects where ob_owner is null
            order by objects.ob_type, objects.ob_name';
        return ($sql);
    } else {
        my $acl = eval { Wallet::ACL->new ($owner, $self->{dbh}) };
        return unless $acl;
        my $sql = 'select ob_type, ob_name from objects where ob_owner = ?
            order by objects.ob_type, objects.ob_name';
        return ($sql, $acl->id);
    }
}

# Return the SQL statement and search field required to find all objects that
# have a specific flag set.
sub objects_flag {
    my ($self, $flag) = @_;
    my $sql = 'select ob_type, ob_name from objects left join flags on
        (objects.ob_type = flags.fl_type and objects.ob_name = flags.fl_name)
        where flags.fl_flag = ? order by objects.ob_type, objects.ob_name';
    return ($sql, $flag);
}

# Return the SQL statement and search field required to find all objects that
# a given ACL has any permissions on.  This expands from objects_owner in that
# it will also match any records that have the ACL set for get, store, show,
# destroy, or flags.  If the requested owner does not actually match any ACLs,
# set an error and return the empty string.
sub objects_acl {
    my ($self, $search) = @_;
    my $acl = eval { Wallet::ACL->new ($search, $self->{dbh}) };
    return unless $acl;
    my $sql = 'select ob_type, ob_name from objects where ob_owner = ? or
        ob_acl_get = ? or ob_acl_store = ? or ob_acl_show = ? or
        ob_acl_destroy = ? or ob_acl_flags = ? order by objects.ob_type,
        objects.ob_name';
    return ($sql, ($acl->id) x 6);
}

# Return the SQL statement to find all objects that have been created but
# have never been retrieved (via get).
sub objects_unused {
    my ($self) = @_;
    my $sql = 'select ob_type, ob_name from objects where ob_downloaded_on
        is null order by objects.ob_type, objects.ob_name';
    return ($sql);
}

# Returns a list of all objects stored in the wallet database in the form of
# type and name pairs.  On error and for an empty database, the empty list
# will be returned.  To distinguish between an empty list and an error, call
# error(), which will return undef if there was no error.  Farms out specific
# statement to another subroutine for specific search types, but each case
# should return ob_type and ob_name in that order.
sub objects {
    my ($self, $type, @args) = @_;
    undef $self->{error};

    # Find the SQL statement and the arguments to use.
    my $sql = '';
    my @search = ();
    if (!defined $type || $type eq '') {
        ($sql) = $self->objects_all;
    } else {
        if ($type ne 'unused' && @args != 1) {
            $self->error ("object searches require one argument to search");
        } elsif ($type eq 'type') {
            ($sql, @search) = $self->objects_type (@args);
        } elsif ($type eq 'owner') {
            ($sql, @search) = $self->objects_owner (@args);
        } elsif ($type eq 'flag') {
            ($sql, @search) = $self->objects_flag (@args);
        } elsif ($type eq 'acl') {
            ($sql, @search) = $self->objects_acl (@args);
        } elsif ($type eq 'unused') {
            ($sql) = $self->objects_unused (@args);
        } else {
            $self->error ("do not know search type: $type");
        }
        return unless $sql;
    }

    # Do the search.
    my @objects;
    eval {
        my $sth = $self->{dbh}->prepare ($sql);
        $sth->execute (@search);
        my $object;
        while (defined ($object = $sth->fetchrow_arrayref)) {
            push (@objects, [ @$object ]);
        }
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ("cannot list objects: $@");
        $self->{dbh}->rollback;
        return;
    }
    return @objects;
}

##############################################################################
# ACL reports
##############################################################################

# Returns the SQL statement required to find and return all ACLs in the
# database.
sub acls_all {
    my ($self) = @_;
    my $sql = 'select ac_id, ac_name from acls order by ac_id';
    return ($sql);
}

# Returns the SQL statement required to find all empty ACLs in the database.
sub acls_empty {
    my ($self) = @_;
    my $sql = 'select ac_id, ac_name from acls left join acl_entries
        on (acls.ac_id = acl_entries.ae_id) where ae_id is null order by
        ac_id';
    return ($sql);
}

# Returns the SQL statement and the field required to find ACLs containing the
# specified entry.  The identifier is automatically surrounded by wildcards to
# do a substring search.
sub acls_entry {
    my ($self, $type, $identifier) = @_;
    my $sql = 'select distinct ac_id, ac_name from acl_entries left join acls
        on (ae_id = ac_id) where ae_scheme = ? and ae_identifier like ? order
        by ac_id';
    return ($sql, $type, '%' . $identifier . '%');
}

# Returns the SQL statement required to find unused ACLs.
sub acls_unused {
    my ($self) = @_;
    my $sql = 'select ac_id, ac_name from acls where not ac_id in (select
        ob_owner from objects where ob_owner = ac_id)';
    for my $acl (qw/get store show destroy flags/) {
        $sql .= " and not ac_id in (select ob_acl_$acl from objects where
            ob_acl_$acl = ac_id)";
    }
    return ($sql);
}

# Obtain a textual representation of the membership of an ACL, returning undef
# on error and setting the internal error.
sub acl_membership {
    my ($self, $id) = @_;
    my $acl = eval { Wallet::ACL->new ($id, $self->{dbh}) };
    if ($@) {
        $self->error ($@);
        return;
    }
    my @members = map { "$_->[0] $_->[1]" } $acl->list;
    if (!@members && $acl->error) {
        $self->error ($acl->error);
        return;
    }
    return join ("\n", @members);
}

# Duplicate ACL detection unfortunately needs to do something more complex
# than just return a SQL statement, so it's handled differently than other
# reports.  All the work is done here and the results returned as a list of
# sets of duplicates.
sub acls_duplicate {
    my ($self) = @_;
    my @acls = sort map { $_->[1] } $self->acls;
    return if (!@acls && $self->{error});
    return if @acls < 2;
    my %result;
    for my $i (0 .. ($#acls - 1)) {
        my $members = $self->acl_membership ($acls[$i]);
        return unless defined $members;
        for my $j (($i + 1) .. $#acls) {
            my $check = $self->acl_membership ($acls[$j]);
            return unless defined $check;
            if ($check eq $members) {
                $result{$acls[$i]} ||= [];
                push (@{ $result{$acls[$i]} }, $acls[$j]);
            }
        }
    }
    my @result;
    for my $acl (sort keys %result) {
        push (@result, [ $acl, sort @{ $result{$acl} } ]);
    }
    return @result;
}

# Returns a list of all ACLs stored in the wallet database as a list of pairs
# of ACL IDs and ACL names, possibly limited by some criteria.  On error and
# for an empty database, the empty list will be returned.  To distinguish
# between an empty list and an error, call error(), which will return undef if
# there was no error.
sub acls {
    my ($self, $type, @args) = @_;
    undef $self->{error};

    # Find the SQL statement and the arguments to use.
    my $sql;
    my @search = ();
    if (!defined $type || $type eq '') {
        ($sql) = $self->acls_all;
    } else {
        if ($type eq 'duplicate') {
            return $self->acls_duplicate;
        } elsif ($type eq 'entry') {
            if (@args == 0) {
                $self->error ('ACL searches require an argument to search');
                return;
            } else {
                ($sql, @search) = $self->acls_entry (@args);
            }
        } elsif ($type eq 'empty') {
            ($sql) = $self->acls_empty;
        } elsif ($type eq 'unused') {
            ($sql) = $self->acls_unused;
        } else {
            $self->error ("unknown search type: $type");
            return;
        }
    }

    # Do the search.
    my @acls;
    eval {
        my $sth = $self->{dbh}->prepare ($sql);
        $sth->execute (@search);
        my $object;
        while (defined ($object = $sth->fetchrow_arrayref)) {
            push (@acls, [ @$object ]);
        }
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ("cannot list ACLs: $@");
        $self->{dbh}->rollback;
        return;
    }
    return @acls;
}

# Returns all ACL entries contained in owner ACLs for matching objects.
# Objects are specified by type and name, which may be SQL wildcard
# expressions.  Each list member will be a pair of ACL scheme and ACL
# identifier, with duplicates removed.  On error and for no matching entries,
# the empty list will be returned.  To distinguish between an empty return and
# an error, call error(), which will return undef if there was no error.
sub owners {
    my ($self, $type, $name) = @_;
    undef $self->{error};
    my @lines;
    eval {
        my $sql = 'select distinct ae_scheme, ae_identifier from acl_entries,
            acls, objects where ae_id = ac_id and ac_id = ob_owner and
            ob_type like ? and ob_name like ? order by ae_scheme,
            ae_identifier';
        my $sth = $self->{dbh}->prepare ($sql);
        $sth->execute ($type, $name);
        my $object;
        while (defined ($object = $sth->fetchrow_arrayref)) {
            push (@lines, [ @$object ]);
        }
        $self->{dbh}->commit;
    };
    if ($@) {
        $self->error ("cannot report on owners: $@");
        $self->{dbh}->rollback;
        return;
    }
    return @lines;
}

##############################################################################
# Auditing
##############################################################################

# Audit the database for violations of local policy.  Returns a list of
# objects (as type and name pairs) or a list of ACLs (as ID and name pairs).
# On error and for no matching entries, the empty list will be returned.  To
# distinguish between an empty return and an error, call error(), which will
# return undef if there was no error.
sub audit {
    my ($self, $type, $audit) = @_;
    undef $self->{error};
    unless (defined ($type) and defined ($audit)) {
        $self->error ("type and audit not specified");
        return;
    }
    if ($type eq 'objects') {
        if ($audit eq 'name') {
            return unless defined &Wallet::Config::verify_name;
            my @objects = $self->objects;
            my @results;
            for my $object (@objects) {
                my ($type, $name) = @$object;
                my $error = Wallet::Config::verify_name ($type, $name);
                push (@results, $object) if $error;
            }
            return @results;
        } else {
            $self->error ("unknown object audit: $audit");
            return;
        }
    } elsif ($type eq 'acls') {
        if ($audit eq 'name') {
            return unless defined &Wallet::Config::verify_acl_name;
            my @acls = $self->acls;
            my @results;
            for my $acl (@acls) {
                my $error = Wallet::Config::verify_acl_name ($acl->[1]);
                push (@results, $acl) if $error;
            }
            return @results;
        } else {
            $self->error ("unknown acl audit: $audit");
            return;
        }
    } else {
        $self->error ("unknown audit type: $type");
        return;
    }
}

1;
__DATA__

##############################################################################
# Documentation
##############################################################################

=head1 NAME

Wallet::Report - Wallet system reporting interface

=for stopwords
ACL ACLs wildcard Allbery SQL tuples

=head1 SYNOPSIS

    use Wallet::Report;
    my $report = Wallet::Report->new;
    my @objects = $report->objects ('type', 'keytab');
    for my $object (@objects) {
        print "@$object\n";
    }
    @objects = $report->audit ('objects', 'name');

=head1 DESCRIPTION

Wallet::Report provides a mechanism to generate lists and reports on the
contents of the wallet database.  The format of the results returned
depend on the type of search, but will generally be returned as a list of
tuples identifying objects, ACLs, or ACL entries.

To use this object, several configuration variables must be set (at least
the database configuration).  For information on those variables and how
to set them, see L<Wallet::Config>.  For more information on the normal
user interface to the wallet server, see L<Wallet::Server>.

=head1 CLASS METHODS

=over 4

=item new()

Creates a new wallet report object and connects to the database.  On any
error, this method throws an exception.

=back

=head1 INSTANCE METHODS

For all methods that can fail, the caller should call error() after a
failure to get the error message.  For all methods that return lists, if
they return an empty list, the caller should call error() to distinguish
between an empty report and an error.

=over 4

=item acls([ TYPE [, SEARCH ... ]])

Returns a list of all ACLs matching a search type and string in the
database, or all ACLs if no search information is given.  There are
currently four search types.  C<duplicate> returns sets of duplicate ACLs
(ones with exactly the same entries).  C<empty> takes no arguments and
will return only those ACLs that have no entries within them.  C<entry>
takes two arguments, an entry scheme and a (possibly partial) entry
identifier, and will return any ACLs containing an entry with that scheme
and with an identifier containing that value.  C<unused> returns all ACLs
that are not referenced by any object.

The return value for everything except C<duplicate> is a list of
references to pairs of ACL ID and name.  For example, if there are two
ACLs in the database, one with name C<ADMIN> and ID 1 and one with name
C<group/admins> and ID 3, acls() with no arguments would return:

    ([ 1, 'ADMIN' ], [ 3, 'group/admins' ])

The return value for the C<duplicate> search is sets of ACL names that are
duplicates (have the same entries).  For example, if C<d1>, C<d2>, and
C<d3> are all duplicates, and C<o1> and C<o2> are also duplicates, the
result would be:

    ([ 'd1', 'd2', 'd3' ], [ 'o1', 'o2' ])

Returns the empty list on failure.  An error can be distinguished from
empty search results by calling error().  error() is guaranteed to return
the error message if there was an error and undef if there was no error.

=item audit(TYPE, AUDIT)

Audits the wallet database for violations of local policy.  TYPE is the
general class of thing to audit, and AUDIT is the specific audit to
perform.  TYPE may be either C<objects> or C<acls>.  Currently, the only
implemented audit is C<name>.  This returns a list of all objects, as
references to pairs of type and name, or ACLs, as references to pairs of
ID and name, that are not accepted by the verify_name() or
verify_acl_name() function defined in the wallet configuration.  See
L<Wallet::Config> for more information.

Returns the empty list on failure.  An error can be distinguished from
empty search results by calling error().  error() is guaranteed to return
the error message if there was an error and undef if there was no error.

=item error()

Returns the error of the last failing operation or undef if no operations
have failed.  Callers should call this function to get the error message
after an undef return from any other instance method.

=item objects([ TYPE [, SEARCH ... ]])

Returns a list of all objects matching a search type and string in the
database, or all objects in the database if no search information is
given.

There are five types of searches currently.  C<type>, with a given type,
will return only those entries where the type matches the given type.
C<owner>, with a given owner, will only return those objects owned by the
given ACL name or ID.  C<flag>, with a given flag name, will only return
those items with a flag set to the given value.  C<acl> operates like
C<owner>, but will return only those objects that have the given ACL name
or ID on any of the possible ACL settings, not just owner.  C<unused> will
return all entries for which a get command has never been issued.

The return value is a list of references to pairs of type and name.  For
example, if two objects existed in the database, both of type C<keytab>
and with values C<host/example.com> and C<foo>, objects() with no
arguments would return:

    ([ 'keytab', 'host/example.com' ], [ 'keytab', 'foo' ])

Returns the empty list on failure.  To distinguish between this and an
empty search result, the caller should call error().  error() is
guaranteed to return the error message if there was an error and undef if
there was no error.

=item owners(TYPE, NAME)

Returns a list of all ACL lines contained in owner ACLs for objects
matching TYPE and NAME, which are interpreted as SQL patterns using C<%>
as a wildcard.  The return value is a list of references to pairs of
schema and identifier, with duplicates removed.

Returns the empty list on failure.  To distinguish between this and no
matches, the caller should call error().  error() is guaranteed to return
the error message if there was an error and undef if there was no error.

=back

=head1 SEE ALSO

Wallet::Config(3), Wallet::Server(3)

This module is part of the wallet system.  The current version is
available from L<http://www.eyrie.org/~eagle/software/wallet/>.

=head1 AUTHOR

Russ Allbery <rra@stanford.edu> and Jon Robertson <jonrober@stanford.edu>.

=cut
