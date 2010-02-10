/*
 * Test suite for Kerberos error handling routines.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <tests/tap/basic.h>
#include <tests/tap/process.h>
#include <util/messages-krb5.h>
#include <util/messages.h>
#include <util/xmalloc.h>


/*
 * Test functions.
 */
static void
test_warn(void)
{
    krb5_context ctx;
    krb5_error_code code;
    krb5_principal princ;

    code = krb5_init_context(&ctx);
    if (code < 0)
        die_krb5(ctx, code, "cannot create context");
    code = krb5_parse_name(ctx, "foo@bar@EXAMPLE.COM", &princ);
    if (code < 0)
        warn_krb5(ctx, code, "principal parse failed");
    else
        die("unexpected success parsing principal");
    exit(0);
}

static void
test_die(void)
{
    krb5_context ctx;
    krb5_error_code code;
    krb5_principal princ;

    code = krb5_init_context(&ctx);
    if (code < 0)
        die_krb5(ctx, code, "cannot create context");
    code = krb5_parse_name(ctx, "foo@bar@EXAMPLE.COM", &princ);
    if (code < 0)
        die_krb5(ctx, code, "principal parse failed");
    else
        die("unexpected success parsing principal");
    exit(0);
}


/*
 * Run the tests.
 */
int
main(void)
{
    krb5_context ctx;
    krb5_error_code code;
    krb5_principal princ;
    const char *message;
    char *wanted;

    plan(6 * 3);

    /* First, we have to get what the correct error message is. */
    code = krb5_init_context(&ctx);
    if (code < 0)
        bail("cannot create context");
    code = krb5_parse_name(ctx, "foo@bar@EXAMPLE.COM", &princ);
    message = krb5_get_error_message(ctx, code);

    xasprintf(&wanted, "principal parse failed: %s\n", message);
    is_function_output(test_warn, 0, wanted, "warn_krb5");
    is_function_output(test_die, 1, wanted, "die_krb5");
    free(wanted);

    message_program_name = "msg-test";
    xasprintf(&wanted, "msg-test: principal parse failed: %s\n", message);
    is_function_output(test_warn, 0, wanted, "warn_krb5 with name");
    is_function_output(test_die, 1, wanted, "die_krb5 with name");
    free(wanted);

    message_handlers_warn(0);
    is_function_output(test_warn, 0, "", "warn_krb5 with no handlers");
    message_handlers_die(0);
    is_function_output(test_die, 1, "", "warn_krb5 with no handlers");

    return 0;
}
