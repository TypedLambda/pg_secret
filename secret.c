#include "postgres.h"

#include "fmgr.h"
#include "libpq/pqformat.h"   /* needed for send/recv functions */
#include "assert.h"

#include "common/base64.h"
#include "utils/builtins.h"

#include "ore_blk.h"
#include "secret.h"

#define ORE_NBITS 32
#define ORE_BLOCK_LEN 8

// TODO: This file should probably be called pg_type/secret and the file
// that wraps ORE should be called secret

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(make_secret);
PG_FUNCTION_INFO_V1(secret_lt);
PG_FUNCTION_INFO_V1(secret_gt);
PG_FUNCTION_INFO_V1(secret_eq);
PG_FUNCTION_INFO_V1(secret_lte);
PG_FUNCTION_INFO_V1(secret_gte);
PG_FUNCTION_INFO_V1(secret_cmp);

static int secret_cmp_internal(bytea *a, bytea *b)
{
  ore_blk_params params;
  int result = 0;

  ore_blk_ciphertext cipher_text_a;
  ore_blk_ciphertext cipher_text_b;

  if (init_ore_blk_params(params, ORE_NBITS, ORE_BLOCK_LEN) != ERROR_NONE) {
    // TODO: CLeanup?
    return -1;
  }
  if (init_ore_blk_ciphertext(cipher_text_a, params) != ERROR_NONE) {
    // TODO: CLeanup?
    return -1;
  }
  if (init_ore_blk_ciphertext(cipher_text_b, params) != ERROR_NONE) {
    // TODO: CLeanup?
    return -1;
  }

  memcpy(cipher_text_a->comp_left, VARDATA(a), 80);
  memcpy(cipher_text_a->comp_right, VARDATA(a) + 80, 144);
  memcpy(cipher_text_b->comp_left, VARDATA(b), 80);
  memcpy(cipher_text_b->comp_right, VARDATA(b) + 80, 144);

  if (ore_blk_compare(&result, cipher_text_a, cipher_text_b) != ERROR_NONE) {
    clear_ore_blk_ciphertext(cipher_text_a);
    clear_ore_blk_ciphertext(cipher_text_b);
    return -1;
  }

  clear_ore_blk_ciphertext(cipher_text_a);
  clear_ore_blk_ciphertext(cipher_text_b);

  return result;
}

static int
_setup_key(
    ore_blk_secret_key sk,
    ore_blk_params params,
    char *prf_key,
    char *prp_key) {

  int ret = 0;

  // TODO: Hardcoded magic numbers
  ret = setup_aes_key(&sk->prf_key, (byte *)prf_key, (uint32_t)16);
  if (ret != ERROR_NONE) return ret;
  ret = setup_aes_key(&sk->prp_key, (byte *)prp_key, (uint32_t)16);
  if (ret != ERROR_NONE) return ret;

  memcpy(sk->params, params, sizeof(ore_blk_params));
  sk->initialized = true;

  return ERROR_NONE;
}

Datum
make_secret(PG_FUNCTION_ARGS)
{
  bytea *prp_key = PG_GETARG_BYTEA_PP(0);
  bytea *prf_key = PG_GETARG_BYTEA_PP(1);
  int64 input      = PG_GETARG_INT64(2);
  int ret          = ERROR_NONE;

  elog(INFO, "prp_key = %s\n", VARDATA(prp_key));

  ore_blk_ciphertext ctxt;
  ore_blk_params params;
  ore_blk_secret_key sk;

  if (init_ore_blk_params(params, ORE_NBITS, ORE_BLOCK_LEN) != ERROR_NONE) {
    // TODO: CLeanup?
    return -1;
  }

  // TODO: hexdecode the keys
  if (_setup_key(sk, params, VARDATA(prf_key), VARDATA(prp_key)) != ERROR_NONE) {
    // TODO: CLeanup?
    return -1;
  }

  if (init_ore_blk_ciphertext(ctxt, params) != ERROR_NONE) {
    // TODO: CLeanup?
    return -1;
  }

  ret = ore_blk_encrypt_ui(ctxt, sk, input);
  if (ret != ERROR_NONE) {
    clear_ore_blk_ciphertext(ctxt);
    ore_blk_cleanup(sk);
    elog(ERROR, "ORE Encrypt failed (ERR %d)", ret);
    PG_RETURN_NULL();
  } else {
    bytea *result = (bytea *)palloc(224 + VARHDRSZ); // TODO: Use ore_params here to determine size
    SET_VARSIZE(result, 224 + VARHDRSZ);

    memcpy(VARDATA(result), ctxt->comp_left, 80);
    memcpy(VARDATA(result) + 80, ctxt->comp_right, 144);

    clear_ore_blk_ciphertext(ctxt);

    memset(prf_key, 0, 16);
    memset(prp_key, 0, 16);

    PG_RETURN_BYTEA_P(result);
  }
}

Datum
secret_lt(PG_FUNCTION_ARGS)
{
  bytea *a = PG_GETARG_BYTEA_P(0);
  bytea *b = PG_GETARG_BYTEA_P(1);

  PG_RETURN_BOOL(secret_cmp_internal(a, b) < 0);
}

Datum
secret_gt(PG_FUNCTION_ARGS)
{
  bytea *a = PG_GETARG_BYTEA_P(0);
  bytea *b = PG_GETARG_BYTEA_P(1);

  PG_RETURN_BOOL(secret_cmp_internal(a, b) > 0);
}

Datum
secret_eq(PG_FUNCTION_ARGS)
{
  bytea *a = PG_GETARG_BYTEA_P(0);
  bytea *b = PG_GETARG_BYTEA_P(1);

  PG_RETURN_BOOL(secret_cmp_internal(a, b) == 0);
}

Datum
secret_lte(PG_FUNCTION_ARGS)
{
  bytea *a = PG_GETARG_BYTEA_P(0);
  bytea *b = PG_GETARG_BYTEA_P(1);

  PG_RETURN_BOOL(secret_cmp_internal(a, b) <= 0);
}

Datum
secret_gte(PG_FUNCTION_ARGS)
{
  bytea *a = PG_GETARG_BYTEA_P(0);
  bytea *b = PG_GETARG_BYTEA_P(1);

  PG_RETURN_BOOL(secret_cmp_internal(a, b) >= 0);
}

Datum
secret_cmp(PG_FUNCTION_ARGS)
{
  bytea *a = PG_GETARG_BYTEA_P(0);
  bytea *b = PG_GETARG_BYTEA_P(1);

  PG_RETURN_INT32(secret_cmp_internal(a, b));
}

