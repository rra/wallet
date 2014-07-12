-- 
-- Created by SQL::Translator::Producer::SQLite
-- Created on Fri Jul 11 16:33:48 2014
-- 

BEGIN TRANSACTION;

--
-- Table: duo
--
DROP TABLE IF EXISTS duo;

CREATE TABLE duo (
  du_name varchar(255) NOT NULL,
  du_key varchar(255) NOT NULL,
  PRIMARY KEY (du_name)
);

--
-- Table: acl_history
--
DROP TABLE IF EXISTS acl_history;

CREATE TABLE acl_history (
  ah_id INTEGER PRIMARY KEY NOT NULL,
  ah_acl integer NOT NULL,
  ah_action varchar(16) NOT NULL,
  ah_scheme varchar(32),
  ah_identifier varchar(255),
  ah_by varchar(255) NOT NULL,
  ah_from varchar(255) NOT NULL,
  ah_on datetime NOT NULL
);

--
-- Table: acl_schemes
--
DROP TABLE IF EXISTS acl_schemes;

CREATE TABLE acl_schemes (
  as_name varchar(32) NOT NULL,
  as_class varchar(64),
  PRIMARY KEY (as_name)
);

--
-- Table: acls
--
DROP TABLE IF EXISTS acls;

CREATE TABLE acls (
  ac_id INTEGER PRIMARY KEY NOT NULL,
  ac_name varchar(255) NOT NULL
);

CREATE UNIQUE INDEX ac_name ON acls (ac_name);

--
-- Table: enctypes
--
DROP TABLE IF EXISTS enctypes;

CREATE TABLE enctypes (
  en_name varchar(255) NOT NULL,
  PRIMARY KEY (en_name)
);

--
-- Table: flags
--
DROP TABLE IF EXISTS flags;

CREATE TABLE flags (
  fl_type varchar(16) NOT NULL,
  fl_name varchar(255) NOT NULL,
  fl_flag enum NOT NULL,
  PRIMARY KEY (fl_type, fl_name, fl_flag)
);

--
-- Table: keytab_enctypes
--
DROP TABLE IF EXISTS keytab_enctypes;

CREATE TABLE keytab_enctypes (
  ke_name varchar(255) NOT NULL,
  ke_enctype varchar(255) NOT NULL,
  PRIMARY KEY (ke_name, ke_enctype)
);

--
-- Table: keytab_sync
--
DROP TABLE IF EXISTS keytab_sync;

CREATE TABLE keytab_sync (
  ks_name varchar(255) NOT NULL,
  ks_target varchar(255) NOT NULL,
  PRIMARY KEY (ks_name, ks_target)
);

--
-- Table: sync_targets
--
DROP TABLE IF EXISTS sync_targets;

CREATE TABLE sync_targets (
  st_name varchar(255) NOT NULL,
  PRIMARY KEY (st_name)
);

--
-- Table: types
--
DROP TABLE IF EXISTS types;

CREATE TABLE types (
  ty_name varchar(16) NOT NULL,
  ty_class varchar(64),
  PRIMARY KEY (ty_name)
);

--
-- Table: acl_entries
--
DROP TABLE IF EXISTS acl_entries;

CREATE TABLE acl_entries (
  ae_id integer NOT NULL,
  ae_scheme varchar(32) NOT NULL,
  ae_identifier varchar(255) NOT NULL,
  PRIMARY KEY (ae_id, ae_scheme, ae_identifier),
  FOREIGN KEY (ae_scheme) REFERENCES acl_schemes(as_name),
  FOREIGN KEY (ae_id) REFERENCES acls(ac_id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX acl_entries_idx_ae_scheme ON acl_entries (ae_scheme);

CREATE INDEX acl_entries_idx_ae_id ON acl_entries (ae_id);

--
-- Table: objects
--
DROP TABLE IF EXISTS objects;

CREATE TABLE objects (
  ob_type varchar(16) NOT NULL,
  ob_name varchar(255) NOT NULL,
  ob_owner integer,
  ob_acl_get integer,
  ob_acl_store integer,
  ob_acl_show integer,
  ob_acl_destroy integer,
  ob_acl_flags integer,
  ob_expires datetime,
  ob_created_by varchar(255) NOT NULL,
  ob_created_from varchar(255) NOT NULL,
  ob_created_on datetime NOT NULL,
  ob_stored_by varchar(255),
  ob_stored_from varchar(255),
  ob_stored_on datetime,
  ob_downloaded_by varchar(255),
  ob_downloaded_from varchar(255),
  ob_downloaded_on datetime,
  ob_comment varchar(255),
  PRIMARY KEY (ob_name, ob_type),
  FOREIGN KEY (ob_acl_destroy) REFERENCES acls(ac_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (ob_acl_flags) REFERENCES acls(ac_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (ob_acl_get) REFERENCES acls(ac_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (ob_owner) REFERENCES acls(ac_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (ob_acl_show) REFERENCES acls(ac_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (ob_acl_store) REFERENCES acls(ac_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (ob_type) REFERENCES types(ty_name)
);

CREATE INDEX objects_idx_ob_acl_destroy ON objects (ob_acl_destroy);

CREATE INDEX objects_idx_ob_acl_flags ON objects (ob_acl_flags);

CREATE INDEX objects_idx_ob_acl_get ON objects (ob_acl_get);

CREATE INDEX objects_idx_ob_owner ON objects (ob_owner);

CREATE INDEX objects_idx_ob_acl_show ON objects (ob_acl_show);

CREATE INDEX objects_idx_ob_acl_store ON objects (ob_acl_store);

CREATE INDEX objects_idx_ob_type ON objects (ob_type);

--
-- Table: object_history
--
DROP TABLE IF EXISTS object_history;

CREATE TABLE object_history (
  oh_id INTEGER PRIMARY KEY NOT NULL,
  oh_type varchar(16) NOT NULL,
  oh_name varchar(255) NOT NULL,
  oh_action varchar(16) NOT NULL,
  oh_field varchar(16),
  oh_type_field varchar(255),
  oh_old varchar(255),
  oh_new varchar(255),
  oh_by varchar(255) NOT NULL,
  oh_from varchar(255) NOT NULL,
  oh_on datetime NOT NULL,
  FOREIGN KEY (oh_type, oh_name) REFERENCES objects(ob_type, ob_name)
);

CREATE INDEX object_history_idx_oh_type_oh_name ON object_history (oh_type, oh_name);

COMMIT;
