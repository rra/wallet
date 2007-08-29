# Wallet::Config -- Configuration handling for the wallet server.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007 Board of Trustees, Leland Stanford Jr. University
#
# See README for licensing terms.

##############################################################################
# Modules and declarations
##############################################################################

package Wallet::Config;
require 5.006;

use strict;
use vars qw($PATH $VERSION);

# This version should be increased on any code change to this module.  Always
# use two digits for the minor version with a leading zero if necessary so
# that it will sort properly.
$VERSION = '0.01';

# Path to the config file to load.
$PATH = '/etc/wallet.conf';

##############################################################################
# Variables
##############################################################################

# Database configuration.
our $DB_DRIVER;
our $DB_NAME;
our $DB_HOST;
our $DB_PORT;
our $DB_USER;
our $DB_PASSWORD;

# Configuration for the keytab object type.
our $KEYTAB_FILE;
our $KEYTAB_FLAGS     = '-clearpolicy';
our $KEYTAB_HOST;
our $KEYTAB_KADMIN    = 'kadmin';
our $KEYTAB_PRINCIPAL;
our $KEYTAB_REALM;
our $KEYTAB_TMP;

1;
__END__
