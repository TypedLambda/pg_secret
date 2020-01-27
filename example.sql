CREATE TABLE secret_test (name text, phone secret, email secret);

CREATE INDEX secret_phone_ind ON secret_test
   USING btree(phone secret_btree_ops);

CREATE INDEX secret_email_ind ON secret_test
   USING btree(email secret_btree_ops);
