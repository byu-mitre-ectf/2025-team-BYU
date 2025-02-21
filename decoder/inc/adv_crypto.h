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
#define BLOCK_SIZE AES_BLOCK_SIZE
#define CHACHAPOLY_KEY_SIZE CHACHA20_POLY1305_AEAD_KEYSIZE
#define CHACHAPOLY_IV_SIZE CHACHA20_POLY1305_AEAD_IV_SIZE
#define AUTHTAG_SIZE CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE
#define MAC_KEY_SIZE 32
#define DIGEST_SIZE WC_SHA256_DIGEST_SIZE
#define RSA_KEY_SIZE 256

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

/** @brief Decrypts a ciphertext using RSA
 * 
 * See: https://www.wolfssl.com/documentation/manuals/wolfssl/group__RSA.html
 * 
 * @param ciphertext A pointer to a buffer of len ctSize containing the ciphertext
 * @param ctSize The length of the ciphertext to decrypt (sizeof doesn't play well with passed pointers)
 * @param keyData A pointer to the DER encoded RSA Key data
 * @param keyLen The length of keyData (sizeof doesn't play well with passed pointers)
 * @param plaintext A pointer to a buffer where the decrypted data will be stored (should be of sufficient size to hold the data)
 * @param ptSize The length of the plaintext buffer (sizeof doesn't play well with passed pointers)
 * 
 * @return 0 on success, non-zero for other error
 */
int decrypt_asym(uint8_t *ciphertext, size_t ctSize, uint8_t *keyData, size_t keyLen, uint8_t *plaintext, size_t ptSize);

/** @brief Hashes arbitrary-length data with the SHA256 HMAC to verify integrity
 * 
 * See: https://www.wolfssl.com/documentation/manuals/wolfssl/group__HMAC.html
 *
 * @param data A pointer to a buffer of length len containing the data
 *           to be hashed
 * @param len The length of the plaintext to hash
 * @param key A pointer to a buffer containing the HMAC key used in the hash check
 * @param key_len The length of the key input
 * @param mac A pointer to a buffer of length WC_SHA256_DIGEST_SIZE (16 bytes) where the resulting
 *           hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int digest(void *data, size_t len, uint8_t *key, int32_t key_len, uint8_t *mac);

#endif // ECTF_ADV_CRYPTO_H
