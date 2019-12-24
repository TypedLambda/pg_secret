#include "crypto.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "api.h"

static void __debug_b64(byte *data, int size) {
    BIO *bio, *b64;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO_push(b64, bio);
    BIO_write(b64, data, size);
    BIO_flush(b64);

    BIO_free_all(b64);
  }

int main(int argc, char **args) {
  unsigned char prf_key[] = "abababababababab";
  unsigned char prp_key[] = "ababababababab12";

  uint64_t input = 15404;
  //byte *left = malloc(80);
  //byte *right = malloc(144);

  ore_blk_ciphertext ctxt;

  if (ore_encrypt(input, prf_key, prp_key, ctxt) == 0) {
    printf("\n*********\n");
    __debug_b64(ctxt->comp_left, 80);
    __debug_b64(ctxt->comp_right, 144);
  } else {
    printf("FAIL\n");
  }

  return 0;
}
