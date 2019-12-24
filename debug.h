#define DO_DEBUG

#ifdef DO_DEBUG
  #define DEBUG(...) printf(__VA_ARGS__)
#else
  #define DEBUG(...)
#endif
