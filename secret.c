#include "postgres.h"

#include "fmgr.h"
#include "libpq/pqformat.h"   /* needed for send/recv functions */
#include "assert.h"

#include "common/base64.h"
#include "utils/builtins.h"

#include "ore_blk.h"
#include "internal.h"

#define ORE_NBITS 32
#define ORE_BLOCK_LEN 8

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(make_secret);
PG_FUNCTION_INFO_V1(make_secret_string);
PG_FUNCTION_INFO_V1(secret_lt);
PG_FUNCTION_INFO_V1(secret_gt);
PG_FUNCTION_INFO_V1(secret_eq);
PG_FUNCTION_INFO_V1(secret_lte);
PG_FUNCTION_INFO_V1(secret_gte);
PG_FUNCTION_INFO_V1(secret_cmp);

/*
 * Encrypt a 64 bit integer under ORE and return
 * as a postgres bytea. The left and right cipher texts
 * will be concatenated into a single binary
 */
Datum
make_secret(PG_FUNCTION_ARGS)
{
  bytea *prp_key = PG_GETARG_BYTEA_PP(0);
  bytea *prf_key = PG_GETARG_BYTEA_PP(1);
  int64 input      = PG_GETARG_INT64(2);

  bytea *result = make_secret_internal(prp_key, prf_key, input);
  // TODO: Should we clear the keys?
  PG_RETURN_BYTEA_P(result);
}

/*
 * Encrypt a string by first generating a 64bit siphash
 * and encrypting the resulting integer under ORE.
 */
Datum
make_secret_string(PG_FUNCTION_ARGS)
{
  bytea *prp_key = PG_GETARG_BYTEA_PP(0);
  bytea *prf_key = PG_GETARG_BYTEA_PP(1);
  text *input    = PG_GETARG_TEXT_PP(2);

  uint64_t hash = siphash24(VARDATA(input), VARSIZE_ANY_EXHDR(input), VARDATA(prf_key));
  bytea *result = make_secret_internal(prp_key, prf_key, hash);
  // TODO: Should we clear the keys?
  PG_RETURN_BYTEA_P(result);
}

/*
 * Compares two ORE encrypted ciphertexts.
 * Returns true if the first ciphertext (left and right concatenated)
 * encrypts a value less than the second.
 */
Datum
secret_lt(PG_FUNCTION_ARGS)
{
  bytea *a = PG_GETARG_BYTEA_P(0);
  bytea *b = PG_GETARG_BYTEA_P(1);

  PG_RETURN_BOOL(secret_cmp_internal(a, b) < 0);
}

/*
 * Compares two encrypted ciphertexts and returns
 * true if the first encrypts a value greater than the second.
 */
Datum
secret_gt(PG_FUNCTION_ARGS)
{
  bytea *a = PG_GETARG_BYTEA_P(0);
  bytea *b = PG_GETARG_BYTEA_P(1);

  PG_RETURN_BOOL(secret_cmp_internal(a, b) > 0);
}

/*
 * Compares to ciphertexts and returns true
 * if they encrypt equivalent plaintexts.
 */
Datum
secret_eq(PG_FUNCTION_ARGS)
{
  bytea *a = PG_GETARG_BYTEA_P(0);
  bytea *b = PG_GETARG_BYTEA_P(1);

  PG_RETURN_BOOL(secret_cmp_internal(a, b) == 0);
}

/*
 * Compares two encrypted ciphertexts and returns
 * true if the first encrypts a value less than or
 * equal to the second.
 */
Datum
secret_lte(PG_FUNCTION_ARGS)
{
  bytea *a = PG_GETARG_BYTEA_P(0);
  bytea *b = PG_GETARG_BYTEA_P(1);

  PG_RETURN_BOOL(secret_cmp_internal(a, b) <= 0);
}

/*
 * Compares two encrypted ciphertexts and returns
 * true if the first encrypts a value greater than
 * or equal to the second.
 */
Datum
secret_gte(PG_FUNCTION_ARGS)
{
  bytea *a = PG_GETARG_BYTEA_P(0);
  bytea *b = PG_GETARG_BYTEA_P(1);

  PG_RETURN_BOOL(secret_cmp_internal(a, b) >= 0);
}

/*
 * Compares two encrypted ciphertexts and returns
 * -1, 0 or 1 if the first encrypts a plaintext that
 * is less-than, equal to or greater than the one
 * encrypted by the second.
 */
Datum
secret_cmp(PG_FUNCTION_ARGS)
{
  bytea *a = PG_GETARG_BYTEA_P(0);
  bytea *b = PG_GETARG_BYTEA_P(1);

  PG_RETURN_INT32(secret_cmp_internal(a, b));
}

