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

#define ERR_CHECK(x) if((_error_flag = x) != ERROR_NONE) { return _error_flag; }

