#!/usr/bin/perl -w
# $Id$
#
# t/verifier.t -- Tests for the basic wallet ACL verifiers.

use Test::More tests => 13;

use Wallet::ACL::Base;
use Wallet::ACL::Krb5;

my $verifier = Wallet::ACL::Base->new;
ok (defined $verifier, 'Wallet::ACL::Base creation');
ok ($verifier->isa ('Wallet::ACL::Base'), ' and class verification');
is ($verifier->check ('rra@stanford.edu', 'rra@stanford.edu'), 0,
    'Default check declines');
is ($verifier->error, undef, 'No error set');

$verifier = Wallet::ACL::Krb5->new;
ok (defined $verifier, 'Wallet::ACL::Krb5 creation');
ok ($verifier->isa ('Wallet::ACL::Krb5'), ' and class verification');
is ($verifier->check ('rra@stanford.edu', 'rra@stanford.edu'), 1,
    'Simple check');
is ($verifier->check ('rra@stanford.edu', 'thoron@stanford.edu'), 0,
    'Simple failure');
is ($verifier->error, undef, 'No error set');
is ($verifier->check (undef, 'rra@stanford.edu'), undef,
    'Undefined principal');
is ($verifier->error, 'no principal specified', ' and right error');
is ($verifier->check ('rra@stanford.edu', ''), undef, 'Empty ACL');
is ($verifier->error, 'malformed krb5 ACL', ' and right error');
