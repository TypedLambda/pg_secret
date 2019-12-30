uint64_t siphash24(const void *src, unsigned long src_sz, const char k[16]);

bytea * make_secret_internal(bytea *prp_key, bytea *prf_key, uint64_t input);

int secret_cmp_internal(bytea *a, bytea *b);
