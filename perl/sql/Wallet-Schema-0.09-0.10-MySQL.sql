-- Convert schema 'sql/Wallet-Schema-0.09-MySQL.sql' to 'Wallet::Schema v0.10':;

BEGIN;

ALTER TABLE duo DROP PRIMARY KEY,
                ADD COLUMN du_type varchar(16) NOT NULL,
                ADD INDEX duo_idx_du_type_du_name (du_type, du_name),
                ADD PRIMARY KEY (du_name, du_type),
                ADD CONSTRAINT duo_fk_du_type_du_name FOREIGN KEY (du_type, du_name) REFERENCES objects (ob_type, ob_name),
                ENGINE=InnoDB;


COMMIT;

