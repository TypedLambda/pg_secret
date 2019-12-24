#include "postgres.h"

#include "fmgr.h"
#include "libpq/pqformat.h"   /* needed for send/recv functions */
#include "assert.h"

#include "api.h"
#include "b64.h"

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(secret_in);

// FIXME: The functions here should be fairly thin
// and work only with secrets. The functions in api.c should
// wrap the underlying ORE code and take and return Secret
Datum
secret_in(PG_FUNCTION_ARGS)
{
  char *str = PG_GETARG_CSTRING(0);
  uint64_t pt;
  unsigned char prf_key[16];
  unsigned char prp_key[16];
  Secret *result;
  ore_blk_ciphertext ctxt;


  // TODO: B64 decode the keys

  if (sscanf(str, " < %16s, %16s, %lld >", prp_key, prf_key, &pt) != 3) {
    ereport(ERROR,
        (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
         errmsg("invalid input syntax for type %s: \"%s\"",
            "secret", str)));
  }

  // TODO: Should ORE encrypt also return the lengths?
  if (ore_encrypt(pt, prf_key, prp_key, ctxt) != 0) {
    elog(ERROR, "ORE Encrypt failed");
  }

  result = (Secret *) palloc(sizeof(Secret));
  result->left = malloc(80);
  assert(result->left);
  result->right = malloc(144);
  assert(result->right);

  /* FIXME: In an ideal world this memcpy would not be required
   * and we woud generate the CTs directly into the target memory.
   * Not easy to do this now because the ore_blk_ciphertext struct
   * other info that needn't be stored */
  memcpy(result->left, ctxt->comp_left, 80);
  memcpy(result->right, ctxt->comp_right, 144);

  /* Clear the ORE CTXT */
  clear_ore_blk_ciphertext(ctxt);

  /* Clear the keys */
  memset(prf_key, 0, 16);
  memset(prp_key, 0, 16);

  PG_RETURN_POINTER(result);
}

PG_FUNCTION_INFO_V1(secret_out);

Datum
secret_out(PG_FUNCTION_ARGS)
{
  Secret *secret = (Secret *) PG_GETARG_POINTER(0);
  char *result;

  result = psprintf("<%s, %s>", secret->left, secret->right);
  PG_RETURN_CSTRING(result);
}


PG_FUNCTION_INFO_V1(secret_lt);

Datum
secret_lt(PG_FUNCTION_ARGS)
{
  Secret *a = (Secret *) PG_GETARG_POINTER(0);
  Secret *b = (Secret *) PG_GETARG_POINTER(1);

  PG_RETURN_BOOL(compare_secret(a, b) < 0);
}

PG_FUNCTION_INFO_V1(secret_gt);

Datum
secret_gt(PG_FUNCTION_ARGS)
{
  Secret *a = (Secret *) PG_GETARG_POINTER(0);
  Secret *b = (Secret *) PG_GETARG_POINTER(1);

  PG_RETURN_BOOL(compare_secret(a, b) > 0);
}

PG_FUNCTION_INFO_V1(secret_eq);

Datum
secret_eq(PG_FUNCTION_ARGS)
{
  Secret *a = (Secret *) PG_GETARG_POINTER(0);
  Secret *b = (Secret *) PG_GETARG_POINTER(1);

  PG_RETURN_BOOL(compare_secret(a, b) == 0);
}

PG_FUNCTION_INFO_V1(secret_lte);

Datum
secret_lte(PG_FUNCTION_ARGS)
{
  Secret *a = (Secret *) PG_GETARG_POINTER(0);
  Secret *b = (Secret *) PG_GETARG_POINTER(1);

  PG_RETURN_BOOL(compare_secret(a, b) <= 0);
}

PG_FUNCTION_INFO_V1(secret_gte);

Datum
secret_gte(PG_FUNCTION_ARGS)
{
  Secret *a = (Secret *) PG_GETARG_POINTER(0);
  Secret *b = (Secret *) PG_GETARG_POINTER(1);

  PG_RETURN_BOOL(compare_secret(a, b) >= 0);
}

PG_FUNCTION_INFO_V1(secret_cmp);

Datum
secret_cmp(PG_FUNCTION_ARGS)
{
  Secret *a = (Secret *) PG_GETARG_POINTER(0);
  Secret *b = (Secret *) PG_GETARG_POINTER(1);

  PG_RETURN_INT32(compare_secret(a, b));
}

