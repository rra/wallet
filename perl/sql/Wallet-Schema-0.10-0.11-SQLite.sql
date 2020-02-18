-- Convert schema 'sql/Wallet-Schema-0.10-SQLite.sql' to 'sql/Wallet-Schema-0.11-SQLite.sql':;

BEGIN;

ALTER TABLE acls ADD ac_comment varchar(255) default null;

COMMIT;
