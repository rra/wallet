/*  $Id$
**
**  Kerberos support functions for the wallet client.
**
**  Currently, the only function here is one to obtain a ticket cache for a
**  given principal and store it in memory for use by the rest of the wallet
**  client.
**
**  Written by Russ Allbery <rra@stanford.edu>
**  Copyright 2007, 2008 Board of Trustees, Leland Stanford Jr. University
*/

#include <config.h>
#include <system.h>

#include <krb5.h>

#include <client/internal.h>
#include <util/util.h>

/* The memory cache used for wallet authentication. */
#define CACHE_NAME "MEMORY:wallet"


/*
**  Given a Kerberos context and a principal name, authenticate as that user
**  and store the TGT in a memory ticket cache for later use by remctl.  Dies
**  on failure.
*/
void
kinit(krb5_context ctx, const char *principal)
{
    krb5_principal princ;
    krb5_ccache ccache;
    krb5_creds creds;
    krb5_get_init_creds_opt opts;
    krb5_error_code status;

    /* Obtain a TGT. */
    status = krb5_parse_name(ctx, principal, &princ);
    if (status != 0)
        die_krb5(ctx, status, "invalid Kerberos principal %s", principal);
    krb5_get_init_creds_opt_init(&opts);
    memset(&creds, 0, sizeof(creds));
    status = krb5_get_init_creds_password(ctx, &creds, princ, NULL,
                 krb5_prompter_posix, NULL, 0, NULL, &opts);
    if (status != 0)
        die_krb5(ctx, status, "authentication failed");

    /* Put the new credentials into a memory cache. */
    status = krb5_cc_resolve(ctx, CACHE_NAME, &ccache);
    if (status != 0)
        die_krb5(ctx, status, "cannot create cache %s", CACHE_NAME);
    status = krb5_cc_initialize(ctx, ccache, princ);
    if (status != 0)
        die_krb5(ctx, status, "cannot initialize cache %s", CACHE_NAME);
    krb5_free_principal(ctx, princ);
    status = krb5_cc_store_cred(ctx, ccache, &creds);
    if (status != 0)
        die_krb5(ctx, status, "cannot store credentials");
    krb5_cc_close(ctx, ccache);
    if (putenv((char *) "KRB5CCNAME=" CACHE_NAME) != 0)
        sysdie("cannot set KRB5CCNAME");
}
