/**
 * @file "adv_crypto.h"
 * @author Macen Bird
 * @brief Advanced Crypto API Header 
 * @date 2025
 * 
 */

#ifndef ECTF_ADV_CRYPTO_H
#define ECTF_ADV_CRYPTO_H

#include "wolfssl/wolfcrypt/chacha20_poly1305.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/poly1305.h"
#include "wolfssl/wolfcrypt/hmac.h"

#include <stdint.h>

/******************************** MACRO DEFINITIONS ********************************/
#define CHACHAPOLY_KEY_SIZE CHACHA20_POLY1305_AEAD_KEYSIZE
#define CHACHAPOLY_IV_SIZE CHACHA20_POLY1305_AEAD_IV_SIZE
#define AUTHTAG_SIZE CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE

/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Decrypts ciphertext using the ChaCha20-Poly1305 cipher
 * 
 * See: https://www.wolfssl.com/documentation/manuals/wolfssl/group__ChaCha20Poly1305.html
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *           ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt
 * @param authTag A pointer to a buffer of length AUTHTAG_SIZE (16 bytes)
 *           containing the digest for authentication
 * @param aad A pointer to a buffer containing arbitrary length "additional 
 *          assoiated data" for the Poly1305 hash
 * @param key A pointer to a buffer of length CHACHAPOLY_KEY_SIZE (32 bytes)
 *          containing the key to use for encryption
 * @param iv A pointer to a buffer of length CHACHAPOLY_IV_SIZE (12 bytes)
 *          containing the iv to use for encryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *           plaintext will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *authTag, uint8_t *aad, uint8_t *key, uint8_t *iv, uint8_t *plaintext);

#endif // ECTF_ADV_CRYPTO_H
