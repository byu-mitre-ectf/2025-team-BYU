#include <stdint.h>

#define CHACHA_KEY_LENGTH 32
#define POLY_KEY_LENGTH 16
#define RSA_KEY_LENGTH 32

typedef struct {
    uint8_t key[CHACHA_KEY_LENGTH];
} chacha_poly_key_t;

typedef struct {
    uint8_t key[POLY_KEY_LENGTH];
} poly_key_t;

typedef struct {
    uint8_t key[RSA_KEY_LENGTH];
} rsa_key_t;