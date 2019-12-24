#include "crypto.h"
#include "ore_blk.h"
#include "aes.h"
#include "errors.h"
#include "debug.h"
#include <assert.h>
#include <stdio.h>

#include "api.h"

/* ORE settings for the NIF */
#define ORE_NBITS 32
#define ORE_BLOCK_LEN 8

// Helpers borrowed from fastore
#define CEIL(x, y) (((x) + (y) - 1) / (y))

static inline int _ore_blk_ciphertext_len_left(ore_blk_params params) {
  uint32_t nblocks = CEIL(params->nbits, params->block_len);

  return (AES_BLOCK_LEN + CEIL(params->nbits, 8)) * nblocks;
}

static inline int _ore_blk_ciphertext_len_right(ore_blk_params params) {
  uint32_t block_len = params->block_len;
  uint32_t nslots = 1 << block_len;
  uint32_t nblocks = CEIL(params->nbits, block_len);

  return AES_BLOCK_LEN + CEIL(nslots, 8) * nblocks;
}

#define CTL_LEN(params) (_ore_blk_ciphertext_len_left(params))
#define CTR_LEN(params) (_ore_blk_ciphertext_len_right(params))

// Helper macros for error handling
static int _error_flag;
#define ERR_CHECK(x) if((_error_flag = x) != ERROR_NONE) { return _error_flag; }

// Macros to validate arguments
#define CHECK_ARG_COUNT(argc, count) \
  if ((argc) != (count)) { return enif_make_badarg(env); }
#define CHECK_ARG(ret) \
  if (!(ret)) { return enif_make_badarg(env); }

// Assert and return an error tuple
#define ASSERT(x) if((_error_flag = x) != ERROR_NONE)

// Debugging
#ifdef DO_DEBUG
  static inline void _debug_b64(byte *data, int size) {
    BIO *bio, *b64;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO_push(b64, bio);
    BIO_write(b64, data, size);
    BIO_flush(b64);

    BIO_free_all(b64);
  }

  static inline void _debug_ct_b64(ore_blk_params params, ore_blk_ciphertext ct) {
    DEBUG("LEFT: ");
    _debug_b64(ct->comp_left, CTL_LEN(params));
    DEBUG("RIGHT: ");
    _debug_b64(ct->comp_right, CTR_LEN(params));
  }

  #define DEBUG_CT_B64(params, ct) _debug_ct_b64(params, ct)
#else
  #define DEBUG_CT_B64(params, ct)
#endif

static int
_setup_key(
    ore_blk_secret_key sk,
    ore_blk_params params,
    unsigned char *prf_key,
    unsigned char *prp_key) {

  // TODO: Hardcoded magic numbers
  ERR_CHECK(setup_aes_key(&sk->prf_key, (byte *)prf_key, (uint32_t)16));
  ERR_CHECK(setup_aes_key(&sk->prp_key, (byte *)prp_key, (uint32_t)16));

  memcpy(sk->params, params, sizeof(ore_blk_params));
  sk->initialized = true;

  return ERROR_NONE;
}

int ore_encrypt(
    uint64_t input,
    unsigned char *prf_key, //TODO: Byte? AES_KEY?
    unsigned char *prp_key,
    ore_blk_ciphertext cipher_text) {

  /* ORE stuff */
  ore_blk_params params;
  ore_blk_secret_key sk;

  /* Cipher texts */
  //ore_blk_ciphertext cipher_text;

  ASSERT(init_ore_blk_params(params, ORE_NBITS, ORE_BLOCK_LEN)) {
    // TODO: CLeanup?
    return -1;
  }
  ASSERT(_setup_key(sk, params, prf_key, prp_key)) {
    // TODO: CLeanup?
    return -1;
  }
  ASSERT(init_ore_blk_ciphertext(cipher_text, params)) {
    ore_blk_cleanup(sk);
    return -1;
  }

  ASSERT(ore_blk_encrypt_ui(cipher_text, sk, input)) {
    clear_ore_blk_ciphertext(cipher_text);
    ore_blk_cleanup(sk);
    return -1;
  }

  DEBUG_CT_B64(params, cipher_text);

  /* Clear/free the keys */
  ore_blk_cleanup(sk);

  return 0;
}

int compare_secret(Secret *a, Secret *b) {
  ore_blk_params params;
  int result = 0;

  ore_blk_ciphertext cipher_text_a;
  ore_blk_ciphertext cipher_text_b;

  ASSERT(init_ore_blk_params(params, ORE_NBITS, ORE_BLOCK_LEN)) {
    // TODO: CLeanup?
    return -1;
  }
  ASSERT(init_ore_blk_ciphertext(cipher_text_a, params)) {
    // TODO: CLeanup?
    return -1;
  }
  ASSERT(init_ore_blk_ciphertext(cipher_text_b, params)) {
    // TODO: CLeanup?
    return -1;
  }

  memcpy(cipher_text_a->comp_left, a->left, CTL_LEN(params));
  memcpy(cipher_text_a->comp_right, a->right, CTR_LEN(params));
  memcpy(cipher_text_b->comp_left, b->left, CTL_LEN(params));
  memcpy(cipher_text_b->comp_right, b->right, CTR_LEN(params));

  ASSERT(ore_blk_compare(&result, cipher_text_a, cipher_text_b)) {
    clear_ore_blk_ciphertext(cipher_text_a);
    clear_ore_blk_ciphertext(cipher_text_b);
    return -1;
  }

  clear_ore_blk_ciphertext(cipher_text_a);
  clear_ore_blk_ciphertext(cipher_text_b);

  return result;
}
