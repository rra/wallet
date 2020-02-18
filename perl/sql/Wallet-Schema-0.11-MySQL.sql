-- 
-- Created by SQL::Translator::Producer::MySQL
-- Created on Thu Oct  9 20:54:55 2014
-- 
-- Copyright 2014
--     The Board of Trustees of the Leland Stanford Junior University
--
-- SPDX-License-Identifier: MIT
--

SET foreign_key_checks=0;

DROP TABLE IF EXISTS `acl_history`;

--
-- Table: `acl_history`
--
CREATE TABLE `acl_history` (
  `ah_id` integer NOT NULL auto_increment,
  `ah_acl` integer NOT NULL,
  `ah_name` varchar(255) NULL,
  `ah_action` varchar(16) NOT NULL,
  `ah_scheme` varchar(32) NULL,
  `ah_identifier` varchar(255) NULL,
  `ah_by` varchar(255) NOT NULL,
  `ah_from` varchar(255) NOT NULL,
  `ah_on` datetime NOT NULL,
  INDEX `acl_history_idx_ah_acl` (`ah_acl`),
  INDEX `acl_history_idx_ah_name` (`ah_name`),
  PRIMARY KEY (`ah_id`)
) CHARACTER SET latin1 COLLATE latin1_swedish_ci;

DROP TABLE IF EXISTS `acl_schemes`;

--
-- Table: `acl_schemes`
--
CREATE TABLE `acl_schemes` (
  `as_name` varchar(32) NOT NULL,
  `as_class` varchar(64) NULL,
  PRIMARY KEY (`as_name`)
) CHARACTER SET latin1 COLLATE latin1_swedish_ci ENGINE=InnoDB;

DROP TABLE IF EXISTS `acls`;

--
-- Table: `acls`
--
CREATE TABLE `acls` (
  `ac_id` integer NOT NULL auto_increment,
  `ac_name` varchar(255) NOT NULL,
  `ac_comment` varchar(255) NULL,
  PRIMARY KEY (`ac_id`),
  UNIQUE `ac_name` (`ac_name`)
) CHARACTER SET latin1 COLLATE latin1_swedish_ci ENGINE=InnoDB;

DROP TABLE IF EXISTS `enctypes`;

--
-- Table: `enctypes`
--
CREATE TABLE `enctypes` (
  `en_name` varchar(255) NOT NULL,
  PRIMARY KEY (`en_name`)
) CHARACTER SET latin1 COLLATE latin1_swedish_ci;

DROP TABLE IF EXISTS `flags`;

--
-- Table: `flags`
--
CREATE TABLE `flags` (
  `fl_type` varchar(16) NOT NULL,
  `fl_name` varchar(255) NOT NULL,
  `fl_flag` enum('locked', 'unchanging') NOT NULL,
  PRIMARY KEY (`fl_type`, `fl_name`, `fl_flag`)
) CHARACTER SET latin1 COLLATE latin1_swedish_ci;

DROP TABLE IF EXISTS `keytab_enctypes`;

--
-- Table: `keytab_enctypes`
--
CREATE TABLE `keytab_enctypes` (
  `ke_name` varchar(255) NOT NULL,
  `ke_enctype` varchar(255) NOT NULL,
  PRIMARY KEY (`ke_name`, `ke_enctype`)
) CHARACTER SET latin1 COLLATE latin1_swedish_ci;

DROP TABLE IF EXISTS `keytab_sync`;

--
-- Table: `keytab_sync`
--
CREATE TABLE `keytab_sync` (
  `ks_name` varchar(255) NOT NULL,
  `ks_target` varchar(255) NOT NULL,
  PRIMARY KEY (`ks_name`, `ks_target`)
) CHARACTER SET latin1 COLLATE latin1_swedish_ci;

DROP TABLE IF EXISTS `object_history`;

--
-- Table: `object_history`
--
CREATE TABLE `object_history` (
  `oh_id` integer NOT NULL auto_increment,
  `oh_type` varchar(16) NOT NULL,
  `oh_name` varchar(255) NOT NULL,
  `oh_action` varchar(16) NOT NULL,
  `oh_field` varchar(16) NULL,
  `oh_type_field` varchar(255) NULL,
  `oh_old` varchar(255) NULL,
  `oh_new` varchar(255) NULL,
  `oh_by` varchar(255) NOT NULL,
  `oh_from` varchar(255) NOT NULL,
  `oh_on` datetime NOT NULL,
  INDEX `object_history_idx_oh_type_oh_name` (`oh_type`, `oh_name`),
  PRIMARY KEY (`oh_id`)
) CHARACTER SET latin1 COLLATE latin1_swedish_ci;

DROP TABLE IF EXISTS `sync_targets`;

--
-- Table: `sync_targets`
--
CREATE TABLE `sync_targets` (
  `st_name` varchar(255) NOT NULL,
  PRIMARY KEY (`st_name`)
) CHARACTER SET latin1 COLLATE latin1_swedish_ci;

DROP TABLE IF EXISTS `types`;

--
-- Table: `types`
--
CREATE TABLE `types` (
  `ty_name` varchar(16) NOT NULL,
  `ty_class` varchar(64) NULL,
  PRIMARY KEY (`ty_name`)
) CHARACTER SET latin1 COLLATE latin1_swedish_ci ENGINE=InnoDB;

DROP TABLE IF EXISTS `acl_entries`;

--
-- Table: `acl_entries`
--
CREATE TABLE `acl_entries` (
  `ae_id` integer NOT NULL,
  `ae_scheme` varchar(32) NOT NULL,
  `ae_identifier` varchar(255) NOT NULL,
  INDEX `acl_entries_idx_ae_scheme` (`ae_scheme`),
  INDEX `acl_entries_idx_ae_id` (`ae_id`),
  PRIMARY KEY (`ae_id`, `ae_scheme`, `ae_identifier`),
  CONSTRAINT `acl_entries_fk_ae_scheme` FOREIGN KEY (`ae_scheme`) REFERENCES `acl_schemes` (`as_name`),
  CONSTRAINT `acl_entries_fk_ae_id` FOREIGN KEY (`ae_id`) REFERENCES `acls` (`ac_id`) ON DELETE CASCADE ON UPDATE CASCADE
) CHARACTER SET latin1 COLLATE latin1_swedish_ci ENGINE=InnoDB;

DROP TABLE IF EXISTS `objects`;

--
-- Table: `objects`
--
CREATE TABLE `objects` (
  `ob_type` varchar(16) NOT NULL,
  `ob_name` varchar(255) NOT NULL,
  `ob_owner` integer NULL,
  `ob_acl_get` integer NULL,
  `ob_acl_store` integer NULL,
  `ob_acl_show` integer NULL,
  `ob_acl_destroy` integer NULL,
  `ob_acl_flags` integer NULL,
  `ob_expires` datetime NULL,
  `ob_created_by` varchar(255) NOT NULL,
  `ob_created_from` varchar(255) NOT NULL,
  `ob_created_on` datetime NOT NULL,
  `ob_stored_by` varchar(255) NULL,
  `ob_stored_from` varchar(255) NULL,
  `ob_stored_on` datetime NULL,
  `ob_downloaded_by` varchar(255) NULL,
  `ob_downloaded_from` varchar(255) NULL,
  `ob_downloaded_on` datetime NULL,
  `ob_comment` varchar(255) NULL,
  INDEX `objects_idx_ob_acl_destroy` (`ob_acl_destroy`),
  INDEX `objects_idx_ob_acl_flags` (`ob_acl_flags`),
  INDEX `objects_idx_ob_acl_get` (`ob_acl_get`),
  INDEX `objects_idx_ob_owner` (`ob_owner`),
  INDEX `objects_idx_ob_acl_show` (`ob_acl_show`),
  INDEX `objects_idx_ob_acl_store` (`ob_acl_store`),
  INDEX `objects_idx_ob_type` (`ob_type`),
  PRIMARY KEY (`ob_name`, `ob_type`),
  CONSTRAINT `objects_fk_ob_acl_destroy` FOREIGN KEY (`ob_acl_destroy`) REFERENCES `acls` (`ac_id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `objects_fk_ob_acl_flags` FOREIGN KEY (`ob_acl_flags`) REFERENCES `acls` (`ac_id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `objects_fk_ob_acl_get` FOREIGN KEY (`ob_acl_get`) REFERENCES `acls` (`ac_id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `objects_fk_ob_owner` FOREIGN KEY (`ob_owner`) REFERENCES `acls` (`ac_id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `objects_fk_ob_acl_show` FOREIGN KEY (`ob_acl_show`) REFERENCES `acls` (`ac_id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `objects_fk_ob_acl_store` FOREIGN KEY (`ob_acl_store`) REFERENCES `acls` (`ac_id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `objects_fk_ob_type` FOREIGN KEY (`ob_type`) REFERENCES `types` (`ty_name`)
) CHARACTER SET latin1 COLLATE latin1_swedish_ci ENGINE=InnoDB;

DROP TABLE IF EXISTS `duo`;

--
-- Table: `duo`
--
CREATE TABLE `duo` (
  `du_name` varchar(255) NOT NULL,
  `du_type` varchar(16) NOT NULL,
  `du_key` varchar(255) NOT NULL,
  INDEX `duo_idx_du_type_du_name` (`du_type`, `du_name`),
  PRIMARY KEY (`du_name`, `du_type`),
  CONSTRAINT `duo_fk_du_type_du_name` FOREIGN KEY (`du_type`, `du_name`) REFERENCES `objects` (`ob_type`, `ob_name`)
) CHARACTER SET latin1 COLLATE latin1_swedish_ci ENGINE=InnoDB;

SET foreign_key_checks=1;

