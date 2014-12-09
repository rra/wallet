-- Convert schema 'sql/Wallet-Schema-0.09-SQLite.sql' to 'sql/Wallet-Schema-0.10-SQLite.sql':;

BEGIN;

-- Back up Duo data to a temp table.  SQLite has limited ALTER TABLE support,
-- so we need to do this to alter the keys on the table.
CREATE TEMPORARY TABLE duo_backup (
  du_name varchar(255) NOT NULL,
  du_key varchar(255) NOT NULL,
  PRIMARY KEY (du_name)
);
INSERT INTO duo_backup SELECT du_name,du_key FROM duo;
DROP TABLE duo;

-- Create the new Duo table and move the old data into it.
CREATE TABLE duo (
  du_name varchar(255) NOT NULL,
  du_type varchar(16) NOT NULL,
  du_key varchar(255) NOT NULL,
  PRIMARY KEY (du_name, du_type),
  FOREIGN KEY (du_type, du_name) REFERENCES objects(ob_type, ob_name)
);
INSERT INTO duo SELECT du_name,du_key,'duo' FROM duo_backup;
DROP TABLE duo_backup;

COMMIT;
