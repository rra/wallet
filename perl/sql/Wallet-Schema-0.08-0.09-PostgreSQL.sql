-- Convert schema 'sql/Wallet-Schema-0.08-PostgreSQL.sql' to 'sql/Wallet-Schema-0.09-PostgreSQL.sql':;

BEGIN;

CREATE TABLE "duo" (
  "du_name" character varying(255) NOT NULL,
  "du_key" character varying(255) NOT NULL,
  PRIMARY KEY ("du_name")
);

COMMIT;

