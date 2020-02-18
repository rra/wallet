-- Convert schema 'sql/Wallet-Schema-0.10-PostgreSQL.sql' to 'sql/Wallet-Schema-0.11-PostgreSQL.sql':;

BEGIN;

ALTER TABLE acls ADD COLUMN ac_comment character varying(255) NULL;

COMMIT;

