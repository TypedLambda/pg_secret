CREATE DOMAIN secret AS bytea CHECK (octet_length(VALUE) = 224);
CREATE DOMAIN key AS bytea;

CREATE FUNCTION make_secret(key, key, int8) RETURNS secret
  AS '$libdir/pgsecret', 'make_secret'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION make_secret(key, key, text) RETURNS secret
  AS '$libdir/pgsecret', 'make_secret_string'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION secret_lt(secret, secret) RETURNS bool
  AS '$libdir/pgsecret'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION secret_eq(secret, secret) RETURNS bool
  AS '$libdir/pgsecret'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION secret_gt(secret, secret) RETURNS bool
  AS '$libdir/pgsecret'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION secret_lte(secret, secret) RETURNS bool
  AS '$libdir/pgsecret'
  LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION secret_gte(secret, secret) RETURNS bool
  AS '$libdir/pgsecret'
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
  AS '$libdir/pgsecret'
  LANGUAGE C IMMUTABLE STRICT;

-- now we can make the operator class
CREATE OPERATOR CLASS secret_btree_ops
    DEFAULT FOR TYPE secret USING btree AS
        OPERATOR        1       < ,
        OPERATOR        2       <= ,
        OPERATOR        3       = ,
        OPERATOR        4       >= ,
        OPERATOR        5       > ,
        FUNCTION        1       secret_cmp(secret, secret);

