/*  $Id$
**
**  Implementation of srvtab handling for the wallet client.
**
**  Written by Russ Allbery <rra@stanford.edu>
**  Copyright 2007 Board of Trustees, Leland Stanford Jr. University
**
**  See README for licensing terms.
*/

#include <config.h>
#include <system.h>

#include <krb5.h>

#include <client/internal.h>
#include <util/util.h>

#ifndef KRB5_KRB4_COMPAT
# define ANAME_SZ 40
# define INST_SZ  40
# define REALM_SZ 40
#endif

#ifdef HAVE_KRB5_GET_ERROR_MESSAGE
static const char *
strerror_krb5(krb5_context ctx, krb5_error_code code)
{
    const char *msg;

    msg = krb5_get_error_message(ctx, code);
    if (msg == NULL)
        return "unknown error";
    else
        return msg;
}
#elif HAVE_KRB5_GET_ERR_TEXT
static const char *
strerror_krb5(krb5_context ctx, krb5_error_code code)
{
    return krb5_get_err_text(ctx, code);
}
#else /* !HAVE_KRB5_GET_ERROR_MESSAGE */
static const char *
strerror_krb5(krb5_context ctx UNUSED, krb5_error_code code)
{
    return error_message(code);
}
#endif

#ifdef HAVE_KRB5_FREE_ERROR_MESSAGE
static void
strerror_krb5_free(krb5_context ctx, const char *msg)
{
    krb5_free_error_message(ctx, msg);
}
#else /* !HAVE_KRB5_FREE_ERROR_MESSAGE */
static void
strerror_krb5_free(krb5_context ctx UNUSED, const char *msg UNUSED)
{
    return;
}
#endif /* !HAVE_KRB5_FREE_ERROR_MESSAGE */


/*
**  Report a Kerberos error and exit.
*/
static void
die_krb5(krb5_context ctx, const char *message, krb5_error_code code)
{
    const char *k5_msg = NULL;

    k5_msg = strerror_krb5(ctx, code);
    warn("%s: %s\n", message, k5_msg);
    strerror_krb5_free(ctx, k5_msg);
    exit(1);
}


/*
**  Given the srvtab file name, a Kerberos principal (as a string), and a
**  keytab file name, extract the des-cbc-crc key from that keytab and write
**  it to the newly created srvtab file as a srvtab.  Convert the principal
**  from Kerberos v5 form to Kerberos v4 form.
**
**  We always force the kvno to 0 for the srvtab.  This works with how the
**  wallet synchronizes keys, even though it's not particularly correct.
**
**  On any failure, print an error message to standard error and then exit.
*/
void
write_srvtab(const char *srvtab, const char *principal, const char *keytab)
{
    krb5_context ctx = NULL;
    krb5_keytab kt;
    krb5_principal princ;
    krb5_keytab_entry entry;
    krb5_error_code ret;
    size_t length;
    char aname[ANAME_SZ + 1] = "";
    char inst[INST_SZ + 1]   = "";
    char realm[REALM_SZ + 1] = "";
    char data[ANAME_SZ + 1 + INST_SZ + 1 + REALM_SZ + 1 + 1 + 8];

    /* Open the keytab and get the DES key. */
    ret = krb5_init_context(&ctx);
    if (ret != 0)
        die_krb5(ctx, "error creating Kerberos context", ret);
    ret = krb5_parse_name(ctx, principal, &princ);
    if (ret != 0)
        die_krb5(ctx, "error parsing Kerberos principal", ret);
    ret = krb5_kt_resolve(ctx, keytab, &kt);
    if (ret != 0)
        die_krb5(ctx, "error opening keytab", ret);
    ret = krb5_kt_get_entry(ctx, kt, princ, 0, ENCTYPE_DES_CBC_CRC, &entry);
    if (ret != 0)
        die_krb5(ctx, "error reading DES key from keytab", ret);
    if (entry.key.length != 8) {
        fprintf(stderr, "invalid DES key length in keytab\n");
        exit(1);
    }
    krb5_kt_close(ctx, kt);

    /* Convert the principal to a Kerberos v4 principal. */
    ret = krb5_524_conv_principal(ctx, princ, aname, inst, realm);
    if (ret != 0)
        die_krb5(ctx, "error converting principal to Kerberos v4", ret);

    /* Assemble the srvtab data. */
    length = 0;
    strcpy(data + length, aname);
    length += strlen(aname);
    data[length++] = '\0';
    strcpy(data + length, inst);
    length += strlen(inst);
    data[length++] = '\0';
    strcpy(data + length, realm);
    length += strlen(realm);
    data[length++] = '\0';
    data[length++] = '\0';
    memcpy(data + length, entry.key.contents, 8);
    length += 8;
    krb5_free_keytab_entry_contents(ctx, &entry);

    /* Write out the srvtab file. */
    write_file(srvtab, data, length);
}
