-- Convert schema 'sql/Wallet-Schema-0.08-MySQL.sql' to 'Wallet::Schema v0.09':;

BEGIN;

SET foreign_key_checks=0;

CREATE TABLE `duo` (
  `du_name` varchar(255) NOT NULL,
  `du_key` varchar(255) NOT NULL,
  PRIMARY KEY (`du_name`)
);

SET foreign_key_checks=1;


COMMIT;

