#include <stdint.h>
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING
#define WOLFSSL_CIPHER_TEXT_CHECK

#define HAVE_CHACHA
#define HAVE_POLY1305

#define CUSTOM_RAND_TYPE uint32_t
extern uint32_t true_random(void);
#undef CUSTOM_RAND_GENERATE
#define CUSTOM_RAND_GENERATE true_random

#undef WC_NO_HASHDRBG
#define WC_NO_HASHDRBG

extern int32_t true_random_block(uint8_t *output, uint32_t sz);
#undef CUSTOM_RAND_GENERATE_BLOCK
#define CUSTOM_RAND_GENERATE_BLOCK true_random_block