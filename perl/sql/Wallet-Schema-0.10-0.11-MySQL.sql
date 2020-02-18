-- Convert schema 'sql/Wallet-Schema-0.10-MySQL.sql' to 'Wallet::Schema v0.11':;

BEGIN;

ALTER TABLE acls ADD COLUMN ac_comment varchar(255);

COMMIT;


