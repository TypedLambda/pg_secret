
#include "postgres.h"
#include "fmgr.h"
#include "ore_blk.h"

#define ORE_NBITS 32
#define ORE_BLOCK_LEN 8
#define KEY_SIZE 16 /* Num bytes for all keys */

#define CEIL(x, y) (((x) + (y) - 1) / (y))
#define CTL_LEN(params) (_ore_blk_ciphertext_len_left(params))
#define CTR_LEN(params) (_ore_blk_ciphertext_len_right(params))
#define CT_TOTAL_LEN(params) (CTL_LEN(params) + CTR_LEN(params))

static inline
int _ore_blk_ciphertext_len_left(ore_blk_params params)
{
  uint32_t nblocks = CEIL(params->nbits, params->block_len);

  return (AES_BLOCK_LEN + CEIL(params->nbits, 8)) * nblocks;
}

static inline
int _ore_blk_ciphertext_len_right(ore_blk_params params)
{
  uint32_t block_len = params->block_len;
  uint32_t nslots = 1 << block_len;
  uint32_t nblocks = CEIL(params->nbits, block_len);

  return AES_BLOCK_LEN + CEIL(nslots, 8) * nblocks;
}

int
uint64_to_byte(uint64_t input, unsigned char[8] output)
{
  plaintext[0] = (n >> 56) & 0xFF;
  plaintext[1] = (n >> 48) & 0xFF;
  plaintext[2] = (n >> 40) & 0xFF;
  plaintext[3] = (n >> 32) & 0xFF;
  plaintext[4] = (n >> 24) & 0xFF;
  plaintext[5] = (n >> 16) & 0xFF;
  plaintext[6] = (n >> 8) & 0xFF;
  plaintext[7] = n & 0xFF;

  return 1;
}

int
setup_key_internal(
    ore_blk_secret_key sk,
    ore_blk_params params,
    char *prf_key,
    char *prp_key)
{

  int ret = 0;

  ret = setup_aes_key(&sk->prf_key, (byte *)prf_key, KEY_SIZE);
  if (ret != ERROR_NONE) return ret;
  ret = setup_aes_key(&sk->prp_key, (byte *)prp_key, KEY_SIZE);
  if (ret != ERROR_NONE) return ret;

  memcpy(sk->params, params, sizeof(ore_blk_params));
  sk->initialized = true;

  return ERROR_NONE;
}

// TODO: Rename to make_ore_blk_pair_internal
bytea *
make_secret_internal(bytea *prp_key, bytea *prf_key, uint64_t input)
{
  int ret = ERROR_NONE;
  ore_blk_ciphertext ctxt;
  ore_blk_params params;
  ore_blk_secret_key sk;

  /* Check that the keys are the correct length */
  if (VARSIZE_ANY_EXHDR(prp_key) != KEY_SIZE) {
    ereport(ERROR,
      (errcode(ERRCODE_INVALID_BINARY_REPRESENTATION),
      errmsg("Incorrect PRP KEY length (must be %d bytes)", KEY_SIZE)));
  }

  if (VARSIZE_ANY_EXHDR(prf_key) != KEY_SIZE) {
    ereport(ERROR,
      (errcode(ERRCODE_INVALID_BINARY_REPRESENTATION),
      errmsg("Incorrect PRF KEY length (must be %d bytes)", KEY_SIZE)));
  }

  if (init_ore_blk_params(params, ORE_NBITS, ORE_BLOCK_LEN) != ERROR_NONE) {
    ereport(ERROR,
      (errcode(ERRCODE_SYSTEM_ERROR),
      errmsg("Invalid ORE Block parameters")));
  }

  if (setup_key_internal(sk, params, VARDATA(prf_key), VARDATA(prp_key)) != ERROR_NONE) {
    ereport(ERROR,
      (errcode(ERRCODE_SYSTEM_ERROR),
      errmsg("ORE Key Setup Failed")));
  }

  if (init_ore_blk_ciphertext(ctxt, params) != ERROR_NONE) {
    clear_ore_blk_ciphertext(ctxt);
    ore_blk_cleanup(sk);

    ereport(ERROR,
      (errcode(ERRCODE_SYSTEM_ERROR),
      errmsg("Unable to initialize CT")));
  }

  ret = ore_blk_encrypt_ui(ctxt, sk, input);
  if (ret != ERROR_NONE) {
    clear_ore_blk_ciphertext(ctxt);
    ore_blk_cleanup(sk);

    ereport(ERROR,
      (errcode(ERRCODE_SYSTEM_ERROR),
      errmsg("Encrypt Failed")));
  } else {
    int result_size = CT_TOTAL_LEN(params) + VARHDRSZ;
    bytea *result = (bytea *)palloc(result_size);
    SET_VARSIZE(result, result_size);

    memcpy(VARDATA(result), ctxt->comp_left, CTL_LEN(params));
    memcpy(VARDATA(result) + CTL_LEN(params), ctxt->comp_right, CTR_LEN(params));

    clear_ore_blk_ciphertext(ctxt);

    memset(prf_key, 0, KEY_SIZE);
    memset(prp_key, 0, KEY_SIZE);

    return result;
  }
}

int
secret_cmp_internal(bytea *a, bytea *b)
{
  ore_blk_params params;
  int result = 0;
  int ret = 0;

  ore_blk_ciphertext ctxt_a;
  ore_blk_ciphertext ctxt_b;

  ret = init_ore_blk_params(params, ORE_NBITS, ORE_BLOCK_LEN);
  if (ret != ERROR_NONE) {
    ereport(ERROR,
      (errcode(ERRCODE_SYSTEM_ERROR),
      errmsg("Invalid ORE Block parameters")));
  }

  ret = init_ore_blk_ciphertext(ctxt_a, params);
  if (ret != ERROR_NONE) {
    clear_ore_blk_ciphertext(ctxt_a);

    ereport(ERROR,
      (errcode(ERRCODE_SYSTEM_ERROR),
      errmsg("Unable to initialize CT")));
  }

  ret = init_ore_blk_ciphertext(ctxt_b, params);
  if (ret != ERROR_NONE) {
    clear_ore_blk_ciphertext(ctxt_a);
    clear_ore_blk_ciphertext(ctxt_b);

    // TODO: Look up ORE error
    ereport(ERROR,
      (errcode(ERRCODE_SYSTEM_ERROR),
      errmsg("Unable to initialize CT")));
  }

  memcpy(ctxt_a->comp_left, VARDATA(a), CTL_LEN(params));
  memcpy(ctxt_a->comp_right, VARDATA(a) + CTL_LEN(params), CTR_LEN(params));
  memcpy(ctxt_b->comp_left, VARDATA(b), CTL_LEN(params));
  memcpy(ctxt_b->comp_right, VARDATA(b) + CTL_LEN(params), CTR_LEN(params));

  ret = ore_blk_compare(&result, ctxt_a, ctxt_b);
  if (ret != ERROR_NONE) {
    clear_ore_blk_ciphertext(ctxt_a);
    clear_ore_blk_ciphertext(ctxt_b);

    // TODO: Look up ORE error
    ereport(ERROR,
      (errcode(ERRCODE_SYSTEM_ERROR),
      errmsg("Compare Failed")));
  }

  clear_ore_blk_ciphertext(ctxt_a);
  clear_ore_blk_ciphertext(ctxt_b);

  return result;
}

int
INTERNAL_gcm_encrypt(unsigned char *plaintext, int plaintext_len,
    unsigned char *aad, int aad_len,
    unsigned char *key,
    unsigned char *iv, int iv_len,
    unsigned char *ciphertext,
    unsigned char *tag)
{
  EVP_CIPHER_CTX *ctx;

  int len, ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) {
    handleErrors();
  }

  /* Initialise the encryption operation. */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
    handleErrors();
  }

  /*
   * Set IV length if default 12 bytes (96 bits) is not appropriate
   */
  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
    handleErrors();
  }

  /* Initialise key and IV */
  if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
    handleErrors();
  }

  /*
   * Provide any AAD data. This can be called zero or more times as
   * required
   */
  if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
    handleErrors();
  }

  /*
   * Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /*
   * Finalise the encryption. Normally ciphertext bytes may be written at
   * this stage, but this does not occur in GCM mode
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    handleErrors();
  ciphertext_len += len;

  /* Get the tag */
  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
    handleErrors();

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}


int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
    unsigned char *aad, int aad_len,
    unsigned char *tag,
    unsigned char *key,
    unsigned char *iv, int iv_len,
    unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  int ret;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  /* Initialise the decryption operation. */
  if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    handleErrors();

  /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    handleErrors();

  /* Initialise key and IV */
  if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    handleErrors();

  /*
   * Provide any AAD data. This can be called zero or more times as
   * required
   */
  if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    handleErrors();

  /*
   * Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
    handleErrors();

  /*
   * Finalise the decryption. A positive return value indicates success,
   * anything else is a failure - the plaintext is not trustworthy.
   */
  ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  if(ret > 0) {
    /* Success */
    plaintext_len += len;
    return plaintext_len;
  } else {
    /* Verify failed */
    return -1;
  }
}
