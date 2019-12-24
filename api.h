#include "ore_blk.h"
#include "secret.h"

int ore_encrypt(
    uint64_t input,
    unsigned char *prf_key,
    unsigned char *prp_key,
    ore_blk_ciphertext ctxt);

int compare_secret(Secret *a, Secret *b);
