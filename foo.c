#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>

#define IV_LEN 16

void handleErrors(void);

static int do_gcm_encrypt(
    unsigned char *plaintext, int plaintext_len,
    unsigned char *aad, int aad_len,
    unsigned char *key,
    unsigned char *iv,
    unsigned char *ciphertext,
    unsigned char *tag);

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
    unsigned char *aad, int aad_len,
    unsigned char *tag,
    unsigned char *key,
    unsigned char *iv,
    unsigned char *plaintext);

int
uint64_to_bytes(uint64_t n, unsigned char output[8])
{
  output[0] = (n >> 56) & 0xFF;
  output[1] = (n >> 48) & 0xFF;
  output[2] = (n >> 40) & 0xFF;
  output[3] = (n >> 32) & 0xFF;
  output[4] = (n >> 24) & 0xFF;
  output[5] = (n >> 16) & 0xFF;
  output[6] = (n >> 8) & 0xFF;
  output[7] = n & 0xFF;

  return 1;
}

uint64_t
bytes_to_uint64(const unsigned char input[8])
{
  uint64_t n = (uint64_t)input[7];
  n += ((uint64_t)input[6] << 8);
  n += ((uint64_t)input[5] << 16);
  n += ((uint64_t)input[4] << 24);
  n += ((uint64_t)input[3] << 32);
  n += ((uint64_t)input[2] << 40);
  n += ((uint64_t)input[1] << 48);
  n += ((uint64_t)input[0] << 56);

  return n;
}

int
INTERNAL_gen_iv(unsigned char buf[IV_LEN])
{
  return RAND_bytes(buf, IV_LEN);
}

int
INTERNAL_gcm_encrypt_uint64(
    uint64_t input,
    unsigned char *key,
    unsigned char *iv,
    unsigned char *ciphertext,
    unsigned char *tag)
{
  unsigned char plaintext[8];
  int ciphertext_len;

  if (INTERNAL_gen_iv(iv) != 1) {
    handleErrors();
  }

  uint64_to_bytes(input, plaintext);

  ciphertext_len =
    do_gcm_encrypt(
      plaintext, 8,
      (unsigned char *)"", 0,
      key,
      iv,
      ciphertext, tag
    );

  /* We effectively took a copy of the plaintext
   * so let's clean up after ourselves */
  memset(plaintext, 0, 8);

  return ciphertext_len;
}

int
INTERNAL_gcm_encrypt_string(
    unsigned char *plaintext,
    unsigned char *key,
    unsigned char *iv,
    unsigned char *ciphertext,
    unsigned char *tag)
{
  int ciphertext_len;

  if (INTERNAL_gen_iv(iv) != 1) {
    handleErrors();
  }

  ciphertext_len =
    do_gcm_encrypt(
      plaintext, strlen((char *)plaintext),
      (unsigned char *)"", 0,
      key,
      iv,
      ciphertext, tag
    );

  return ciphertext_len;
}

int main_a(void) {
  unsigned char plaintext[8];
  uint64_t n = 1953750214886623795;
  //unsigned char iv[16];

  uint64_to_bytes(n, plaintext);
  printf("input is %llu\n", n);
  printf("Plaintext is:\n");
  BIO_dump_fp (stdout, (const char *)plaintext, 8);

  printf("Demarshalled: %llu\n", bytes_to_uint64(plaintext));

  return 0;
}

int main(void)
{
  /*
   * Set up the key and iv. Do I need to say to not hard code these in a
   * real application? :-)
   */

  /* A 256 bit key */
  unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

  /* Message to be encrypted */
  unsigned char *plaintext =
    (unsigned char *)"The quick brown fox jumps over the lazy dog";

  //uint64_t n = 1953750214886623795;
  unsigned char iv[16];
  unsigned char ciphertext[128];
  unsigned char tag[16];

  /* Buffer for the decrypted text */
  unsigned char decryptedtext[128];

  int decryptedtext_len, ciphertext_len;

  //ciphertext_len = INTERNAL_gcm_encrypt_uint64(n, key, iv, ciphertext, tag);
  ciphertext_len = INTERNAL_gcm_encrypt_string(plaintext, key, iv, ciphertext, tag);

  /* Do something useful with the ciphertext here */
  printf("Ciphertext is:\n");
  BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

  printf("Tag is:\n");
  BIO_dump_fp (stdout, (const char *)tag, 16);

  /* Decrypt the ciphertext */
  decryptedtext_len = gcm_decrypt(ciphertext, ciphertext_len,
      (unsigned char *)"", 0,
      tag,
      key, iv,
      decryptedtext);

  if (decryptedtext_len >= 0) {
    /* Add a NULL terminator if we are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);

    //printf("Decrypted text (len: %d) is: %llu\n", decryptedtext_len, bytes_to_uint64(decryptedtext));
  } else {
    printf("Decryption failed\n");
  }

  return 0;
}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

static int
do_gcm_encrypt(
    unsigned char *plaintext, int plaintext_len,
    unsigned char *aad, int aad_len,
    unsigned char *key,
    unsigned char iv[IV_LEN],
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
   * Set IV length to 16 bytes (128 bits)
   */
  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL)) {
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
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
    handleErrors();
  }

  ciphertext_len = len;

  /*
   * Finalise the encryption. Normally ciphertext bytes may be written at
   * this stage, but this does not occur in GCM mode
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
    handleErrors();
  }

  ciphertext_len += len;

  /* Get the tag */
  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
    handleErrors();
  }

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}


int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
    unsigned char *aad, int aad_len,
    unsigned char *tag,
    unsigned char *key,
    unsigned char iv[IV_LEN],
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

  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL))
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
