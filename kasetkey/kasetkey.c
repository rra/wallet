/*  $Id$
**
**  Create or change a principal and/or generate a srvtab.
**
**  Written by Roland Schemers <schemers@stanford.edu>
**  Updated by Russ Allbery <rra@stanford.edu>
**  Updated again by AAU, Anton Ushakov  <antonu@stanford.edu>
**  Copyright 1994, 1998-2000, 2006
**      Board of Trustees, Leland Stanford Jr. University
**
**  Sets the key of a principal in the AFS kaserver given a srvtab.  This
**  program is now used for synchronization of K5 and K4 and nothing else.
**  It will no longer be used once K4 is retired.
*/

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <strerror.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <afs/stds.h>
#include <afs/kautils.h>
#include <afs/cellconfig.h>

void crash_and_burn(char *message);
void errno_crash_and_burn(char *message);
void usage(void);
void do_init_key_file(void);
void do_service(void);

#ifndef SNAME_SZ
# define SNAME_SZ       40
# define INST_SZ        40
# define REALM_SZ       40
#endif

#define VERSION "2.0"

char *prog;         /* duh */
char *local_cell;   /* duh^2 */
int o_debug=0;    /* turn on debugging  */
int o_init=0;     /* intialize keyfile  */
int o_random=0;   /* use random DES key */

char *o_keyfile = NULL;     /* name of DES key file to use */
char *o_admin = NULL;       /* name of ADMIN user to use */
char *o_pass = NULL;        /* password to use (else random or prompted) */
char *o_srvtab = NULL;      /* srvtab file to generate */
char *o_service = NULL;     /* service to create */
char *o_k5srvtab = NULL;   /* converted keytab from K5*/

int
main(int argc, char *argv[])
{
  long code;
  int c;
 
  /* initialize, get our local cell, etc */
  prog = argv[0];
  code = ka_Init(0);
  local_cell = ka_LocalCell();
  if (o_debug) fprintf(stdout,"cell: %s\n", local_cell);

  if (!local_cell || code) crash_and_burn("can't initialize");

  /* for production, remove the -d debugging option*/
  while ((c = getopt(argc, argv, "a:hk:is:p:f:rdvc:")) != EOF) {
           switch(c) {
           case 'k': o_keyfile = optarg; break;
           case 'i': o_init = 1;         break;
           case 'a': o_admin = optarg;   break;
           case 'r': o_random = 1;       break;
           case 'p': o_pass = optarg;    break;
           case 'f': o_srvtab = optarg;  break;
           case 's': o_service = optarg; break;
           case 'd': o_debug = 1;        break;
           case 'c': o_k5srvtab = optarg;   break;
           case 'v': fprintf(stderr,"%s: version %s\n",prog,VERSION); exit(0);
           case 'h': 
           default:  usage(); /* usage doesn't return */
           }
  }

  if (o_random && o_k5srvtab)
    usage();

  if (o_init) do_init_key_file();
  else if (o_service) do_service();
  else usage();

  return 0;
}

void
do_init_key_file(void)
{
  struct ktc_encryptionKey key;
  char name[MAXKTCNAMELEN];
  char inst[MAXKTCNAMELEN];
  char cell[MAXKTCNAMELEN];
  long code;
  int kfd;

  if (!o_keyfile) usage();

  if (!o_admin) o_admin = (char*)getlogin();

  code = ka_ParseLoginName(o_admin, name, inst, cell);
  if (o_debug) printf("ka_ParseLoginName %ld\n",code);
  if (code) crash_and_burn("can't parse admin name");
  if (cell[0]=='\0') strcpy(cell, local_cell);
 
  if (o_pass) {
    ka_StringToKey(o_pass, cell, &key);
    memset(o_pass, 0, strlen(o_pass));
  } else {
    char buffer[MAXKTCNAMELEN*3+40];
    sprintf(buffer,"password for %s: ",o_admin);
    code = ka_ReadPassword(buffer, 1, cell, &key);
    if (code) crash_and_burn("can't read password");
  }

  unlink(o_keyfile); /* remove it if it exists */
  kfd = open(o_keyfile, O_WRONLY | O_CREAT, 0600);
  if (kfd == -1) errno_crash_and_burn("can't open keyfile");

  if (write(kfd, &key, sizeof(key)) != sizeof(key)) {
     errno_crash_and_burn("write keyfile");
  }
  if (close(kfd)!=0) errno_crash_and_burn("close keyfile");

  exit(0);
}

void
do_service(void)
{
  struct ktc_encryptionKey key;
  struct ktc_token token;
  struct ubik_client *conn;
  long code;
  char name[MAXKTCNAMELEN];
  char inst[MAXKTCNAMELEN];
  char cell[MAXKTCNAMELEN];

  /*AAU:*/
  char sbuf[SNAME_SZ * 4];  /* to read in the whole converted srvtab */
  char* sbuf_ptr = sbuf;          /* "reading" pointer for parsing the srvtab*/
  char sname[SNAME_SZ];       /* name of service from converted srvtab*/
  char sinst[INST_SZ];        /* instance of service  from converted srvtab*/
  char srealm[REALM_SZ];      /* realm of service  from converted srvtab*/
  unsigned char kvno;         /* key version number  from converted srvtab*/

  if (!o_admin) o_admin = (char*)getlogin();

  code = ka_ParseLoginName(o_admin, name, inst, cell);
  if (o_debug) printf("ka_ParseLoginName %ld\n",code);
  if (code) crash_and_burn("can't parse admin name");
  if (cell[0]=='\0') strcpy(cell, local_cell);

  if (o_keyfile) {
    int kfd;
    kfd = open(o_keyfile, O_RDONLY, 0);
    if (kfd == -1) errno_crash_and_burn("can't open keyfile");
    if (read(kfd, &key, sizeof(key)) != sizeof(key)) {
        errno_crash_and_burn("can't read keyfile");
    }
    close(kfd);
  } else {
    char buffer[MAXKTCNAMELEN*3+40];
    sprintf(buffer,"password for %s: ",o_admin);
    code = ka_ReadPassword(buffer, 0, cell, &key);
    if (code) crash_and_burn("can't read password");
  }
  
  code = ka_GetAdminToken(name, inst, cell, &key, 300, &token, 1);
  memset((char*)&key, 0, sizeof(key));
  if (o_debug) printf("ka_GetAdminToken %ld\n",code);
  if (code) crash_and_burn("can't get admin token");
 
  /* make connection to AuthServer */
  code = ka_AuthServerConn(cell, KA_MAINTENANCE_SERVICE, &token, &conn);
  if (o_debug) printf("ka_AuthServerConn %ld\n",code);
  if (code) crash_and_burn("can't make connection to auth server");

  /* do a similar dance on the service principal and key */

  code = ka_ParseLoginName(o_service, name, inst, cell);
  if (o_debug) printf("ka_ParseLoginName %ld\n",code);
  if (code) crash_and_burn("can't parse service name");
  if (cell[0]=='\0') strcpy(cell, local_cell);

  /*read service principal key from a srvtab, converted from a K5 keytab. AAU*/
  if (o_k5srvtab) { 
    FILE* ksfd;
    ksfd = fopen(o_k5srvtab, "r");
    if (!ksfd) errno_crash_and_burn("can't open converted srvtab");

    /*must read whole string first: srvtab fields are separated by NULLs, all in one line*/
    if (!(fgets(sbuf, sizeof(sbuf), ksfd)))
        errno_crash_and_burn("can't read converted srvtab");
    strncpy(sname, sbuf_ptr, SNAME_SZ -1);
    sbuf_ptr = &sbuf_ptr[strlen(sbuf_ptr)+1];
    strncpy(sinst, sbuf_ptr, INST_SZ -1);
    sbuf_ptr = &sbuf_ptr[strlen(sbuf_ptr)+1];
    strncpy(srealm, sbuf_ptr, REALM_SZ -1);
    sbuf_ptr = &sbuf_ptr[strlen(sbuf_ptr)+1];
    strncpy(&kvno, sbuf_ptr, sizeof(unsigned char));
    strncpy(key.data, sbuf_ptr+sizeof(unsigned char), sizeof(key));

    fclose(ksfd);
  } else if (o_random) {  /* get random key */
     code = ubik_Call (KAM_GetRandomKey, conn, 0, &key);
     if (o_debug) printf("ka_AuthServerConn %ld\n",code);
     if (code) crash_and_burn("can't get random key");
  } else {
    code = ka_ReadPassword("service password: ", 1, cell, &key);
    if (code) crash_and_burn("can't read password");
  }
 
  /* try to create principal */
  code = ubik_Call (KAM_CreateUser, conn, 0, name, inst, key);
  if (o_debug) printf("ubik_Call KAM_CreateUser %ld\n",code);

  if (code == KAEXIST) { /* need to delete first */
    code = ubik_Call (KAM_DeleteUser, conn, 0, name, inst);
    if (o_debug) printf("ubik_Call KAM_DeleteUser %ld\n",code);
    if (code) crash_and_burn("can't delete existing instance");
    code = ubik_Call (KAM_CreateUser, conn, 0, name, inst, key);
    if (o_debug) printf("ubik_Call KAM_CreateUser %ld\n",code);
    if (code) crash_and_burn("can't create user");
  } else if (code) {
    crash_and_burn("can't create user");
  }

  code = ubik_ClientDestroy (conn);

  /* create srvtab file */
  if (o_srvtab && !o_k5srvtab) {
      char realm[MAXKTCREALMLEN];
      int local;
      unsigned char kvno=0;
      int sfd;
      int nlen, ilen, rlen;

      if (ka_CellToRealm(cell, realm, &local) == KANOCELL) {
        crash_and_burn("unable to determine realm");
      }
      if (access(o_srvtab,F_OK)==0) {
          char backup[MAXPATHLEN];
          sprintf(backup,"%s.bak", o_srvtab);
          if (rename(o_srvtab, backup)!=0) {
             errno_crash_and_burn("can't create backup srvtab");
          }
      }

      sfd = open(o_srvtab, O_WRONLY | O_CREAT, 0600);
      if (sfd == -1) errno_crash_and_burn("can't open srvtab");

      nlen = strlen(name)+1;
      ilen = strlen(inst)+1;
      rlen = strlen(realm)+1;
      
      if (write(sfd, name, nlen) != nlen) {
         errno_crash_and_burn("write srvtab name");
      }
      if (write(sfd, inst, ilen) != ilen) {
         errno_crash_and_burn("write srvtab instance");
      }
      if (write(sfd, realm, rlen) != rlen) {
         errno_crash_and_burn("write srvtab realm");
      }
      if (write(sfd, &kvno, sizeof(kvno)) != sizeof(kvno)) {
         errno_crash_and_burn("write srvtab kvno");
      }
      if (write(sfd, &key, sizeof(key)) != sizeof(key)) {
         errno_crash_and_burn("write srvtab key");
      }
      if (close(sfd)!=0) errno_crash_and_burn("close srvtab");
  }
  memset((char*)&key, 0, sizeof(key));
  memset((char*)&sbuf, 0, sizeof(sbuf));
  exit(0);
}

void 
crash_and_burn(char *message)
{
  fprintf(stderr,"%s: %s\n", prog, message);
  exit(1);
}


void 
errno_crash_and_burn(char *message)
{
  fprintf(stderr,"%s: %s: %s\n", prog, message, strerror(errno));
  exit(1);
}

void 
usage()
{
  fprintf(stderr,"usage: %s [options]\n",prog);
  fprintf(stderr,"  -k keyfile       file containing admin's DES key\n");
  fprintf(stderr,"  -i               initialize DES key file\n");
  fprintf(stderr,"  -a adminuser     admin user\n");
  fprintf(stderr,"  -r               use random key\n");
  fprintf(stderr,"  -p password      use given password to create key\n");
  fprintf(stderr,"  -c input_srvtab  use the key from the given srvtab (for sync w/ K5)\n");
  fprintf(stderr,"  -f srvtabfile    name of srvtab file to create\n");
  fprintf(stderr,"  -s service       name of service to create\n");
  fprintf(stderr,"  -h               this help\n");
  fprintf(stderr,"  -d               turn on debugging\n");
  fprintf(stderr,"  -v               version\n");
  fprintf(stderr,"\n");
  fprintf(stderr,"   To create a srvtab for rcmd.slapshot and be prompted \n");
  fprintf(stderr,"   for the admin (i.e, your) password:\n");
  fprintf(stderr,"\n");
  fprintf(stderr,"   %s -f srvtab.rcmd.slapshot -s rcmd.slapshot -r\n",prog);
  fprintf(stderr,"\n");
  fprintf(stderr,"   To create a srvtab from within a script you must stash the DES key\n");
  fprintf(stderr,"   someplace then do something like:\n");
  fprintf(stderr,"\n");
  fprintf(stderr,"   %s -k /.adminkey -a admin -r -f srvtab -s rcmd.slapshot\n",prog);
  fprintf(stderr,"\n");
  exit(1);
}

