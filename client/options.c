/*
 * Set default options for wallet clients.
 *
 * This file provides the functions to set default options from the krb5.conf
 * file for both wallet and wallet-rekey.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2018 Russ Allbery <eagle@eyrie.org>
 * Copyright 2006-2008, 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <client/internal.h>


/*
 * Load a string option from Kerberos appdefaults.  This requires an annoying
 * workaround because one cannot specify a default value of NULL.
 */
static void
default_string(krb5_context ctx, const char *opt, const char *defval,
               char **result)
{
    if (defval == NULL)
        defval = "";
    krb5_appdefault_string(ctx, "wallet", NULL, opt, defval, result);
    if (*result != NULL && (*result)[0] == '\0') {
        free(*result);
        *result = NULL;
    }
}


/*
 * Load a number option from Kerberos appdefaults.  The native interface
 * doesn't support numbers, so we actually read a string and then convert.
 */
static void
default_number(krb5_context ctx, const char *opt, int defval, int *result)
{
    char *tmp = NULL;

    krb5_appdefault_string(ctx, "wallet", NULL, opt, "", &tmp);
    if (tmp != NULL && tmp[0] != '\0')
        *result = atoi(tmp);
    else
        *result = defval;
    if (tmp != NULL)
        free(tmp);
}


/*
 * Set option defaults and then get krb5.conf configuration, if any, and
 * override the defaults.  Later, command-line options will override those
 * defaults.
 */
void
default_options(krb5_context ctx, struct options *options)
{
    int port;

    default_string(ctx, "wallet_type", "wallet", &options->type);
    default_string(ctx, "wallet_server", WALLET_SERVER, &options->server);
    default_string(ctx, "wallet_principal", NULL, &options->principal);
    default_number(ctx, "wallet_port", WALLET_PORT, &port);
    if (port <= 0 || port > 65535)
        options->port = WALLET_PORT;
    else
        options->port = (unsigned short) port;
    options->user = NULL;
}
