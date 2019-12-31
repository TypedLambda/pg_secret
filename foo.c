#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>

#define IV_LEN 16
#define TAG_LEN 16
#define BLOCKSIZE 16

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

// TODO: Make static
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

// TODO: Make static
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

// TODO: Make static
/*
 * We generate IV_LEN bytes for a the IV
 * so long as IV_LEN > 96 bits.
 * See https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
 */
int
INTERNAL_gen_iv(unsigned char buf[IV_LEN])
{
  if (IV_LEN > 12) {
    return RAND_bytes(buf, IV_LEN);
  } else {
    abort();
  }
}

int
INTERNAL_gcm_encrypt_uint64(
    uint64_t input,
    unsigned char *key,
    unsigned char *output)
{
  unsigned char plaintext[8];
  int ciphertext_len;
  unsigned char *iv = output;
  unsigned char *tag = iv + IV_LEN;
  unsigned char *ciphertext = tag + TAG_LEN;

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

  return ciphertext_len + IV_LEN + TAG_LEN;
}

// TODO: Rename these to SYM_... and the others ORE_..., anything else UTIL_...
int
INTERNAL_gcm_decrypt_uint64(
    unsigned char *input,
    int input_len,
    unsigned char *key,
    uint64_t *output)
{
  unsigned char *iv = input;
  unsigned char *tag = iv + IV_LEN;
  unsigned char *ciphertext = tag + TAG_LEN;
  unsigned char plaintext[8];

  int decrypted_len =
    gcm_decrypt(
        ciphertext,
        input_len - IV_LEN - TAG_LEN,
      (unsigned char *)"", 0,
      tag,
      key, iv,
      plaintext);

  if (decrypted_len != 8) {
    /* error if decrypted_len != 8*/
    memset(plaintext, 0, 8);
    return -1;
  }

  *output = bytes_to_uint64(plaintext);

  /* We effectively took a copy of the plaintext
   * so let's clean up after ourselves */
  memset(plaintext, 0, 8);

  return 8;
}

/*
 * output should be allocated to plaintext length + 1 (for null terminator)
 */
int
INTERNAL_gcm_decrypt_string(
    unsigned char *input,
    int input_len,
    unsigned char *key,
    unsigned char *output)
{
  unsigned char *iv = input;
  unsigned char *tag = iv + IV_LEN;
  unsigned char *ciphertext = tag + TAG_LEN;

  int decrypted_len =
    gcm_decrypt(
      ciphertext, input_len,
      (unsigned char *)"", 0,
      tag,
      key,
      iv,
      output
    );

  printf("Decrypted len = %d\n", decrypted_len);

  if (decrypted_len >= 0) {
    output[decrypted_len] = '\0';
    return decrypted_len;
  } else {
    /* Caller should memset 0 the plaintext */
    return -1;
  }
}

// TODO: This could be inlined
size_t
INTERNAL_gcm_ciphertext_string_len(unsigned char *plaintext)
{
  size_t plaintext_len = strlen((char *)plaintext);
  return (plaintext_len / BLOCKSIZE + 1) * BLOCKSIZE + IV_LEN + TAG_LEN;
}

// TODO: This could be inlined
size_t
INTERNAL_gcm_ciphertext_uint64_len()
{
  size_t plaintext_len = 8;
  size_t len = (plaintext_len / BLOCKSIZE + 1) * BLOCKSIZE + IV_LEN + TAG_LEN;
  printf("len = %zu\n", len);
  return len;
}

int
INTERNAL_gcm_encrypt_string(
    unsigned char *plaintext,
    unsigned char *key,
    unsigned char *output)
{
  int ciphertext_len;
  unsigned char *iv = output;
  unsigned char *tag = iv + IV_LEN;
  unsigned char *ciphertext = tag + TAG_LEN;

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

  printf("Input len = %d, String CT len = %d\n",strlen((char *)plaintext), ciphertext_len);
  return ciphertext_len;
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

  //unsigned char *output = (unsigned char *)malloc(INTERNAL_gcm_ciphertext_uint64_len());
  unsigned char *output = (unsigned char *)malloc(INTERNAL_gcm_ciphertext_string_len(plaintext));

  int output_len;

  //output_len = INTERNAL_gcm_encrypt_uint64(n, key, output);
  output_len = INTERNAL_gcm_encrypt_string(plaintext, key, output);

  /* Do something useful with the ciphertext here */
  printf("Output (len %d) is:\n", output_len);
  BIO_dump_fp (stdout, (const char *)output, output_len);

  unsigned char *decrypted = (unsigned char *)malloc(output_len + 1);
  //uint64_t decrypted;

  //INTERNAL_gcm_decrypt_uint64(output, output_len, key, &decrypted); 
  //printf("Decrypted int is %llu\n", decrypted);

  if (INTERNAL_gcm_decrypt_string(output, output_len, key, decrypted) >= 0) {
    printf("Decrypted string is %s\n", decrypted);
  } else {
    memset(decrypted, 0, output_len + 1);
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
  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag)) {
    handleErrors();
  }

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  // TODO: This is different to the size we calculate ahead of time - why?
  printf("CT len returned %d\n", ciphertext_len);
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
  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag))
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
