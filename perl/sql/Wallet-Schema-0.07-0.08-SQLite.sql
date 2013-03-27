BEGIN;
DROP TABLE IF EXISTS flag_names;
DROP TABLE IF EXISTS metadata;
ALTER TABLE objects ADD ob_comment varchar(255) default null;
COMMIT;

