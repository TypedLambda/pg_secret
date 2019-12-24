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

CREATE FUNCTION secret_lt(secret, secret) RETURNS bool
  AS '/Users/daniel/Projects/Modulo/spikes/ore_types/secret'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION secret_eq(secret, secret) RETURNS bool
  AS '/Users/daniel/Projects/Modulo/spikes/ore_types/secret'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION secret_gt(secret, secret) RETURNS bool
  AS '/Users/daniel/Projects/Modulo/spikes/ore_types/secret'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION secret_lte(secret, secret) RETURNS bool
  AS '/Users/daniel/Projects/Modulo/spikes/ore_types/secret'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION secret_gte(secret, secret) RETURNS bool
  AS '/Users/daniel/Projects/Modulo/spikes/ore_types/secret'
  LANGUAGE C IMMUTABLE STRICT;

CREATE OPERATOR < (
  leftarg = secret, rightarg = secret, procedure = secret_lt,
  commutator = > , negator = >= ,
  restrict = scalarltsel, join = scalarltjoinsel
);

CREATE OPERATOR = (
  leftarg = secret, rightarg = secret, procedure = secret_eq,
  commutator = = ,
  restrict = eqsel, join = eqjoinsel
);

CREATE OPERATOR > (
   leftarg = secret, rightarg = secret, procedure = secret_gt,
   commutator = < , negator = <= ,
   restrict = scalargtsel, join = scalargtjoinsel
);

CREATE OPERATOR <= (
   leftarg = secret, rightarg = secret, procedure = secret_lte,
   commutator = >= , negator = > ,
   restrict = scalarlesel, join = scalarlejoinsel
);

CREATE OPERATOR >= (
   leftarg = secret, rightarg = secret, procedure = secret_gte,
   commutator = <= , negator = < ,
   restrict = scalargesel, join = scalargejoinsel
);

CREATE FUNCTION secret_cmp(secret, secret) RETURNS int4
  AS '/Users/daniel/Projects/Modulo/spikes/ore_types/secret'
  LANGUAGE C IMMUTABLE STRICT;

-- now we can make the operator class
CREATE OPERATOR CLASS secret_ops
    DEFAULT FOR TYPE secret USING btree AS
        OPERATOR        1       < ,
        OPERATOR        2       <= ,
        OPERATOR        3       = ,
        OPERATOR        4       >= ,
        OPERATOR        5       > ,
        FUNCTION        1       secret_cmp(secret, secret);

create table secret_test (name text, phone secret);

CREATE INDEX test_secret_ind ON secret_test
   USING btree(phone secret_ops);
