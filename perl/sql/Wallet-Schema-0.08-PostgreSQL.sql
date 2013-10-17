--
-- Created by SQL::Translator::Producer::PostgreSQL
-- Created on Fri Jan 25 14:12:02 2013
--
-- Copyright 2012, 2013
--     The Board of Trustees of the Leland Stanford Junior University
--
-- Permission is hereby granted, free of charge, to any person obtaining a
-- copy of this software and associated documentation files (the
-- "Software"), to deal in the Software without restriction, including
-- without limitation the rights to use, copy, modify, merge, publish,
-- distribute, sublicense, and/or sell copies of the Software, and to
-- permit persons to whom the Software is furnished to do so, subject to
-- the following conditions:
--
-- The above copyright notice and this permission notice shall be included
-- in all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
-- OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
-- MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
-- IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
-- CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
-- TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
-- SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
--
--
-- Table: acl_history
--
DROP TABLE "acl_history" CASCADE;
CREATE TABLE "acl_history" (
  "ah_id" serial NOT NULL,
  "ah_acl" integer NOT NULL,
  "ah_action" character varying(16) NOT NULL,
  "ah_scheme" character varying(32),
  "ah_identifier" character varying(255),
  "ah_by" character varying(255) NOT NULL,
  "ah_from" character varying(255) NOT NULL,
  "ah_on" timestamp NOT NULL,
  PRIMARY KEY ("ah_id")
);

--
-- Table: acl_schemes
--
DROP TABLE "acl_schemes" CASCADE;
CREATE TABLE "acl_schemes" (
  "as_name" character varying(32) NOT NULL,
  "as_class" character varying(64),
  PRIMARY KEY ("as_name")
);

--
-- Table: acls
--
DROP TABLE "acls" CASCADE;
CREATE TABLE "acls" (
  "ac_id" serial NOT NULL,
  "ac_name" character varying(255) NOT NULL,
  PRIMARY KEY ("ac_id"),
  CONSTRAINT "ac_name" UNIQUE ("ac_name")
);

--
-- Table: enctypes
--
DROP TABLE "enctypes" CASCADE;
CREATE TABLE "enctypes" (
  "en_name" character varying(255) NOT NULL,
  PRIMARY KEY ("en_name")
);

--
-- Table: flags
--
DROP TABLE "flags" CASCADE;
CREATE TABLE "flags" (
  "fl_type" character varying(16) NOT NULL,
  "fl_name" character varying(255) NOT NULL,
  "fl_flag" character varying NOT NULL,
  PRIMARY KEY ("fl_type", "fl_name", "fl_flag")
);

--
-- Table: keytab_enctypes
--
DROP TABLE "keytab_enctypes" CASCADE;
CREATE TABLE "keytab_enctypes" (
  "ke_name" character varying(255) NOT NULL,
  "ke_enctype" character varying(255) NOT NULL,
  PRIMARY KEY ("ke_name", "ke_enctype")
);

--
-- Table: keytab_sync
--
DROP TABLE "keytab_sync" CASCADE;
CREATE TABLE "keytab_sync" (
  "ks_name" character varying(255) NOT NULL,
  "ks_target" character varying(255) NOT NULL,
  PRIMARY KEY ("ks_name", "ks_target")
);

--
-- Table: sync_targets
--
DROP TABLE "sync_targets" CASCADE;
CREATE TABLE "sync_targets" (
  "st_name" character varying(255) NOT NULL,
  PRIMARY KEY ("st_name")
);

--
-- Table: types
--
DROP TABLE "types" CASCADE;
CREATE TABLE "types" (
  "ty_name" character varying(16) NOT NULL,
  "ty_class" character varying(64),
  PRIMARY KEY ("ty_name")
);

--
-- Table: acl_entries
--
DROP TABLE "acl_entries" CASCADE;
CREATE TABLE "acl_entries" (
  "ae_id" integer NOT NULL,
  "ae_scheme" character varying(32) NOT NULL,
  "ae_identifier" character varying(255) NOT NULL,
  PRIMARY KEY ("ae_id", "ae_scheme", "ae_identifier")
);
CREATE INDEX "acl_entries_idx_ae_scheme" on "acl_entries" ("ae_scheme");
CREATE INDEX "acl_entries_idx_ae_id" on "acl_entries" ("ae_id");

--
-- Table: objects
--
DROP TABLE "objects" CASCADE;
CREATE TABLE "objects" (
  "ob_type" character varying(16) NOT NULL,
  "ob_name" character varying(255) NOT NULL,
  "ob_owner" integer,
  "ob_acl_get" integer,
  "ob_acl_store" integer,
  "ob_acl_show" integer,
  "ob_acl_destroy" integer,
  "ob_acl_flags" integer,
  "ob_expires" timestamp,
  "ob_created_by" character varying(255) NOT NULL,
  "ob_created_from" character varying(255) NOT NULL,
  "ob_created_on" timestamp NOT NULL,
  "ob_stored_by" character varying(255),
  "ob_stored_from" character varying(255),
  "ob_stored_on" timestamp,
  "ob_downloaded_by" character varying(255),
  "ob_downloaded_from" character varying(255),
  "ob_downloaded_on" timestamp,
  "ob_comment" character varying(255),
  PRIMARY KEY ("ob_name", "ob_type")
);
CREATE INDEX "objects_idx_ob_acl_destroy" on "objects" ("ob_acl_destroy");
CREATE INDEX "objects_idx_ob_acl_flags" on "objects" ("ob_acl_flags");
CREATE INDEX "objects_idx_ob_acl_get" on "objects" ("ob_acl_get");
CREATE INDEX "objects_idx_ob_owner" on "objects" ("ob_owner");
CREATE INDEX "objects_idx_ob_acl_show" on "objects" ("ob_acl_show");
CREATE INDEX "objects_idx_ob_acl_store" on "objects" ("ob_acl_store");
CREATE INDEX "objects_idx_ob_type" on "objects" ("ob_type");

--
-- Table: object_history
--
DROP TABLE "object_history" CASCADE;
CREATE TABLE "object_history" (
  "oh_id" serial NOT NULL,
  "oh_type" character varying(16) NOT NULL,
  "oh_name" character varying(255) NOT NULL,
  "oh_action" character varying(16) NOT NULL,
  "oh_field" character varying(16),
  "oh_type_field" character varying(255),
  "oh_old" character varying(255),
  "oh_new" character varying(255),
  "oh_by" character varying(255) NOT NULL,
  "oh_from" character varying(255) NOT NULL,
  "oh_on" timestamp NOT NULL,
  PRIMARY KEY ("oh_id")
);
CREATE INDEX "object_history_idx_oh_type_oh_name" on "object_history" ("oh_type", "oh_name");

--
-- Foreign Key Definitions
--

ALTER TABLE "acl_entries" ADD FOREIGN KEY ("ae_scheme")
  REFERENCES "acl_schemes" ("as_name") DEFERRABLE;

ALTER TABLE "acl_entries" ADD FOREIGN KEY ("ae_id")
  REFERENCES "acls" ("ac_id") ON DELETE CASCADE ON UPDATE CASCADE DEFERRABLE;

ALTER TABLE "objects" ADD FOREIGN KEY ("ob_acl_destroy")
  REFERENCES "acls" ("ac_id") ON DELETE CASCADE ON UPDATE CASCADE DEFERRABLE;

ALTER TABLE "objects" ADD FOREIGN KEY ("ob_acl_flags")
  REFERENCES "acls" ("ac_id") ON DELETE CASCADE ON UPDATE CASCADE DEFERRABLE;

ALTER TABLE "objects" ADD FOREIGN KEY ("ob_acl_get")
  REFERENCES "acls" ("ac_id") ON DELETE CASCADE ON UPDATE CASCADE DEFERRABLE;

ALTER TABLE "objects" ADD FOREIGN KEY ("ob_owner")
  REFERENCES "acls" ("ac_id") ON DELETE CASCADE ON UPDATE CASCADE DEFERRABLE;

ALTER TABLE "objects" ADD FOREIGN KEY ("ob_acl_show")
  REFERENCES "acls" ("ac_id") ON DELETE CASCADE ON UPDATE CASCADE DEFERRABLE;

ALTER TABLE "objects" ADD FOREIGN KEY ("ob_acl_store")
  REFERENCES "acls" ("ac_id") ON DELETE CASCADE ON UPDATE CASCADE DEFERRABLE;

ALTER TABLE "objects" ADD FOREIGN KEY ("ob_type")
  REFERENCES "types" ("ty_name") DEFERRABLE;

--ALTER TABLE "object_history" ADD FOREIGN KEY ("oh_type", "oh_name")
--  REFERENCES "objects" ("ob_type", "ob_name") DEFERRABLE;

