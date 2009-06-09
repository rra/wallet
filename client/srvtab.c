/*
 * Implementation of srvtab handling for the wallet client.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2007, 2008 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <krb5.h>

#include <client/internal.h>
#include <util/util.h>

#ifndef KRB5_KRB4_COMPAT
# define ANAME_SZ 40
# define INST_SZ  40
# define REALM_SZ 40
#endif


/*
 * Given the Kerberos context, srvtab file name, a Kerberos principal (as a
 * string), and a keytab file name, extract the des-cbc-crc key from that
 * keytab and write it to the newly created srvtab file as a srvtab.  Convert
 * the principal from Kerberos v5 form to Kerberos v4 form.
 *
 * We always force the kvno to 0 for the srvtab.  This works with how the
 * wallet synchronizes keys with kasetkey, even though it's not particularly
 * correct.
 *
 * On any failure, print an error message to standard error and then exit.
 */
void
write_srvtab(krb5_context ctx, const char *srvtab, const char *principal,
             const char *keytab)
{
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
    ret = krb5_parse_name(ctx, principal, &princ);
    if (ret != 0)
        die_krb5(ctx, ret, "error parsing Kerberos principal %s", principal);
    ret = krb5_kt_resolve(ctx, keytab, &kt);
    if (ret != 0)
        die_krb5(ctx, ret, "error opening keytab %s", keytab);
    ret = krb5_kt_get_entry(ctx, kt, princ, 0, ENCTYPE_DES_CBC_CRC, &entry);
    if (ret != 0)
        die_krb5(ctx, ret, "error reading DES key from keytab %s", keytab);
    if (entry.key.length != 8)
        die("invalid DES key length in keytab");
    krb5_kt_close(ctx, kt);

    /* Convert the principal to a Kerberos v4 principal. */
    ret = krb5_524_conv_principal(ctx, princ, aname, inst, realm);
    if (ret != 0)
        die_krb5(ctx, ret, "error converting principal %s to Kerberos v4",
                 principal);

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
