--
-- Run on installing wallet 1.3 in order to update what the Duo types
-- point to for modules.
--

UPDATE types set ty_class='Wallet::Object::Duo' where ty_name='duo-ldap';
UPDATE types set ty_class='Wallet::Object::Duo' where ty_name='duo-pam';
UPDATE types set ty_class='Wallet::Object::Duo' where ty_name='duo-radius';
UPDATE types set ty_class='Wallet::Object::Duo' where ty_name='duo-rdp';
