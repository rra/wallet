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

#include <errno.h>

#include <client/internal.h>
#include <util/messages.h>


/*
 * Load a number option from Kerberos appdefaults.  Takes the Kerberos
 * context, the realm, the option, and the result location.  The native
 * interface doesn't support numbers, so we actually read a string and then
 * convert.
 */
static void
default_number(krb5_context ctx, const char *realm, const char *opt,
               long defval, long *result)
{
    char *tmp = NULL;
    char *end;
    long value;
#ifdef HAVE_KRB5_REALM
    krb5_const_realm rdata = realm;
#else
    krb5_data realm_struct;
    const krb5_data *rdata;

    if (realm == NULL)
        rdata = NULL;
    else {
        rdata = &realm_struct;
        realm_struct.magic = KV5M_DATA;
        realm_struct.data = (void *) realm;
        realm_struct.length = (unsigned int) strlen(realm);
    }
#endif

    *result = defval;
    krb5_appdefault_string(ctx, "wallet", rdata, opt, "", &tmp);
    if (tmp != NULL && tmp[0] != '\0') {
        errno = 0;
        value = strtol(tmp, &end, 10);
        if (errno != 0 || *end != '\0')
            warn("invalid number in krb5.conf setting for %s: %s", opt, tmp);
        else
            *result = value;
    }
    free(tmp);
}


/*
 * Load a string option from Kerberos appdefaults.  Takes the Kerberos
 * context, the realm, the option, and the result location.
 *
 * This requires an annoying workaround because one cannot specify a default
 * value of NULL with MIT Kerberos, since MIT Kerberos unconditionally calls
 * strdup on the default value.  There's also no way to determine if memory
 * allocation failed while parsing or while setting the default value, so we
 * don't return an error code.
 */
static void
default_string(krb5_context ctx, const char *realm, const char *opt,
               const char *defval, char **result)
{
    char *value = NULL;
#ifdef HAVE_KRB5_REALM
    krb5_const_realm rdata = realm;
#else
    krb5_data realm_struct;
    const krb5_data *rdata;

    if (realm == NULL)
        rdata = NULL;
    else {
        rdata = &realm_struct;
        realm_struct.magic = KV5M_DATA;
        realm_struct.data = (void *) realm;
        realm_struct.length = (unsigned int) strlen(realm);
    }
#endif

    if (defval == NULL)
        defval = "";
    krb5_appdefault_string(ctx, "wallet", rdata, opt, defval, &value);
    if (value != NULL) {
        if (value[0] == '\0')
            free(value);
        else {
            if (*result != NULL)
                free(*result);
            *result = value;
        }
    }
}


/*
 * Set option defaults and then get krb5.conf configuration, if any, and
 * override the defaults.  Later, command-line options will override those
 * defaults.
 */
void
default_options(krb5_context ctx, struct options *options)
{
    long port;
    char *realm = NULL;

    /* Having no local realm may be intentional, so don't report an error. */
    krb5_get_default_realm(ctx, &realm);
        
    /* Load the options. */
    default_string(ctx, realm, "wallet_type", "wallet", &options->type);
    default_string(ctx, realm, "wallet_server", WALLET_SERVER,
                   &options->server);
    default_string(ctx, realm, "wallet_principal", NULL, &options->principal);
    default_number(ctx, realm, "wallet_port", WALLET_PORT, &port);

    /* Additional checks on the option values. */
    if (port != WALLET_PORT && (port <= 0 || port > 65535)) {
        warn("invalid number in krb5.conf setting for wallet_port: %ld", port);
        options->port = WALLET_PORT;
    } else {
        options->port = (unsigned short) port;
    }

    /* Clean up. */
    if (realm != NULL)
        krb5_free_default_realm(ctx, realm);
}
