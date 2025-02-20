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

#include <stdint.h>

/******************************** MACRO DEFINITIONS ********************************/
#define BLOCK_SIZE AES_BLOCK_SIZE
#define CHACHAPOLY_KEY_SIZE CHACHA20_POLY1305_AEAD_KEYSIZE
#define CHACHAPOLY_IV_SIZE CHACHA20_POLY1305_AEAD_IV_SIZE
#define AUTHTAG_SIZE CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE
#define POLY_KEY_SIZE 32
#define DIGEST_SIZE POLY1305_DIGEST_SIZE
#define RSA_KEY_SIZE 256

/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts plaintext using the ChaCha20-Poly1305 cipher
 *
 * @param plaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param len The length of the plaintext to encrypt
 * @param aad A pointer to a buffer containing arbitrary length "additional 
 *          assoiated data" for the Poly1305 hash
 * @param aad_len The length of the AAD
 * @param key A pointer to a buffer of length CHACHAPOLY_KEY_SIZE (32 bytes)
 *          containing the key to use for encryption
 * @param iv A pointer to a buffer of length CHACHAPOLY_IV_SIZE (12 bytes)
 *          containing the iv to use for encryption
 * @param ciphertext A pointer to a buffer of length len to which the resulting
 *          ciphertext will be written
 * @param authTag A pointer to a buffer of length AUTHTAG_SIZE (16 bytes)
 *          to which the resulting digest will be written
 *
 * @return 0 on success, other non-zero for other error
 */
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *aad, uint8_t *key, uint8_t *iv, uint8_t *ciphertext, uint8_t *authTag);

/** @brief Decrypts ciphertext using the ChaCha20-Poly1305 cipher
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *           ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt
 * @param authTag A pointer to a buffer of length AUTHTAG_SIZE (16 bytes)
 *           containing the digest for authentication
 * @param aad A pointer to a buffer containing arbitrary length "additional 
 *          assoiated data" for the Poly1305 hash
 * @param aad_len The length of the AAD
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
 * @param ciphertext A pointer to a buffer of less than RSA_KEY_SIZE bytes
 *          for our purposes, this will always be ~52 bytes
 * @param keyData Ngl idk yet what this holds but it'll be the key information
 * @param plaintext A pointer to a buffer where the decrypted data will be stored
 * 
 * @return 0 on success, non-zero for other error
 */
int decrypt_asym(uint8_t *ciphertext, size_t ctSize, uint8_t *keyData, size_t keyLen, uint8_t *plaintext, size_t ptSize);

/** @brief Hashes arbitrary-length data with the Poly1305 cipher to verify integrity
 *
 * @param data A pointer to a buffer of length len containing the data
 *           to be hashed
 * @param len The length of the plaintext to hash
 * @param key A pointer to a buffer of length POLY_KEY_SIZE (32 bytes) for use in computing the hash/digest
 * @param mac A pointer to a buffer of length POLY1305_DIGEST_SIZE (16 bytes) where the resulting
 *           hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int digest(void *data, size_t len, uint8_t *aad, size_t aadLen, uint8_t *key, uint8_t *mac);

#endif // ECTF_ADV_CRYPTO_H
