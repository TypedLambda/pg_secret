CREATE FUNCTION secret_in(cstring)
   RETURNS secret
   AS '/Users/daniel/Projects/Modulo/spikes/ore_types/secret'
   LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION secret_out(secret)
   RETURNS cstring
   AS '/Users/daniel/Projects/Modulo/spikes/ore_types/secret'
   LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE secret (
   internallength = 600,
   input = secret_in,
   output = secret_out
);

create table secret_test (name text, phone secret);
