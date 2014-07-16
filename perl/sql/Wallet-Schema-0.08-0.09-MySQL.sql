-- Convert schema 'sql/Wallet-Schema-0.08-MySQL.sql' to 'Wallet::Schema v0.09':;

BEGIN;

SET foreign_key_checks=0;

CREATE TABLE duo (
  du_name varchar(255) NOT NULL,
  du_key varchar(255) NOT NULL,
  PRIMARY KEY (du_name)
);

SET foreign_key_checks=1;

ALTER TABLE acl_history ADD COLUMN ah_name varchar(255) NULL,
                        ADD INDEX acl_history_idx_ah_acl (ah_acl),
                        ADD INDEX acl_history_idx_ah_name (ah_name);

ALTER TABLE object_history DROP FOREIGN KEY object_history_fk_oh_type_oh_name,
                           ALTER TABLE object_history;


COMMIT;

