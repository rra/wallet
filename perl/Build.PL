#!/usr/bin/perl
#
# Build script for the wallet distribution.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2016 Russ Allbery <eagle@eyrie.org>
# Copyright 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# SPDX-License-Identifier: MIT

use 5.006;
use strict;
use warnings;

use Module::Build;

# Basic package configuration.
my $build = Module::Build->new(
    dist_abstract        => 'Secure credential management system',
    dist_author          => 'Russ Allbery <eagle@eyrie.org>',
    dist_name            => 'Wallet',
    dist_version_from    => 'lib/Wallet/Server.pm',
    license              => 'mit',
    module_name          => 'Wallet::Server',
    recursive_test_files => 1,

    # Other package relationships.
    configure_requires => { 'Module::Build' => 0.28 },
    requires           => {
        'Date::Parse'     => 0,
        DateTime          => 0,
        'DBIx::Class'     => 0,
        DBI               => 0,
        'Digest::MD5'     => 0,
        'SQL::Translator' => 0,
        perl              => '5.008',
    },
    recommends => {
        'Authen::SASL'             => 0,
        'Crypt::GeneratePassword'  => 0,
        'DateTime::Format::SQLite' => 0,
        'DBD::SQLite'              => 0,
        'Heimdal::Kadm5'           => 0,
        'IPC::Run'                 => 0,
        'Net::Duo'                 => 0,
        'Net::LDAP'                => 0,
        'Net::Remctl'              => 0,
        WebAuth                    => 0,
    },
    test_requires => {
        'Crypt::GeneratePassword'  => 0,
        'DateTime::Format::SQLite' => 0,
    },
);

# Generate the build script.
$build->create_build_script;
