# Shell function library to initialize Kerberos credentials
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2009, 2010 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

# Set up Kerberos, including the ticket cache environment variable.  Bail out
# if not successful, return 0 if successful, and return 1 if Kerberos is not
# configured.  Sets the global principal variable to the principal to use.
kerberos_setup () {
    local keytab
    keytab=`test_file_path data/test.keytab`
    principal=`test_file_path data/test.principal`
    principal=`cat "$principal" 2>/dev/null`
    if [ -z "$keytab" ] || [ -z "$principal" ] ; then
        return 1
    fi
    KRB5CCNAME="$BUILD/data/test.cache"; export KRB5CCNAME
    kinit -k -t "$keytab" "$principal" >/dev/null </dev/null
    status=$?
    if [ $status != 0 ] ; then
        kinit -t "$keytab" "$principal" >/dev/null </dev/null
        status=$?
    fi
    if [ $status != 0 ] ; then
        kinit -k -K "$keytab" "$principal" >/dev/null </dev/null
        status=$?
    fi
    if [ $status != 0 ] ; then
        bail "Can't get Kerberos tickets"
    fi
    return 0
}

# Clean up at the end of a test.  Currently only removes the ticket cache.
kerberos_cleanup () {
    rm -f "$BUILD/data/test.cache"
}

# List the contents of a keytab with enctypes and keys.  This adjusts for the
# difference between MIT Kerberos (which uses klist) and Heimdal (which uses
# ktutil).  Be careful to try klist first, since the ktutil on MIT Kerberos
# may just hang.  Takes the keytab to list and the file into which to save the
# output, and strips off the header containing the file name.
ktutil_list () {
    if klist -keK "$1" > ktutil-tmp 2>/dev/null ; then
        :
    else
        ktutil -k "$1" list --keys > ktutil-tmp < /dev/null 2>/dev/null
    fi
    sed -e '/Keytab name:/d' -e "/^[^ ]*:/d" ktutil-tmp > "$2"
    rm -f ktutil-tmp
}
