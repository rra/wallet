-- Convert schema 'sql/Wallet-Schema-0.09-PostgreSQL.sql' to 'sql/Wallet-Schema-0.10-PostgreSQL.sql':;

BEGIN;

ALTER TABLE duo DROP CONSTRAINT duo_pkey;

ALTER TABLE duo ADD COLUMN du_type character varying(16) NOT NULL;

CREATE INDEX duo_idx_du_type_du_name on duo (du_type, du_name);

ALTER TABLE duo ADD PRIMARY KEY (du_name, du_type);

ALTER TABLE duo ADD CONSTRAINT duo_fk_du_type_du_name FOREIGN KEY (du_type, du_name)
  REFERENCES objects (ob_type, ob_name) DEFERRABLE;


COMMIT;

