/**
 * @file "simple_crypto.c"
 * @author Ben Janis
 * @brief Simplified Crypto API Implementation
 * @date 2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#include "adv_crypto.h"
#include <stdint.h>
#include <string.h>


/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts plaintext using the ChaCha20-Poly1305 cipher
 *
 * @param plaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param len The length of the plaintext to encrypt
 * @param aad A pointer to a buffer containing arbitrary length "additional 
 *          assoiated data" for the Poly1305 hash
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
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *aad, uint8_t *key, uint8_t *iv, uint8_t *ciphertext, uint8_t *authTag) {
    // returns 0 on success else non-zero
    size_t aad_len = sizeof(uint32_t)+CHACHAPOLY_IV_SIZE;
    return wc_ChaCha20Poly1305_Encrypt(key, iv, aad, aad_len, plaintext, len, ciphertext, authTag);
}

/** @brief Decrypts ciphertext using the ChaCha20-Poly1305 cipher
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
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *authTag, uint8_t *aad, uint8_t *key, uint8_t *iv, uint8_t *plaintext) {
    // returns 0 on success else non-zero
    size_t aad_len = sizeof(uint32_t)+CHACHAPOLY_IV_SIZE;
    return wc_ChaCha20Poly1305_Encrypt(key, iv, aad, aad_len, plaintext, len, ciphertext, authTag);
}

/** @brief Decrypts a ciphertext using RSA
 * 
 * @param ciphertext A pointer to a buffer of less than RSA_KEY_SIZE bytes
 *          for our purposes, this will always be ~52 bytes
 * @param keyData Ngl idk yet what this holds but it'll be the key information
 * @param plaintext A pointer to a buffer where the decrypted data will be stored
 * 
 * @return 0 on success, non-zero for other error
 */
int decrypt_asym(uint8_t *ciphertext, void *keyData, uint8_t *plaintext) {
    return 0;
}

/** @brief Hashes arbitrary-length data with the Poly1305 cipher to verify integrity
 *
 * @param data A pointer to a buffer of length len containing the data
 *           to be hashed
 * @param len The length of the plaintext to hash
 * @param mac A pointer to a buffer of length POLY1305_DIGEST_SIZE (16 bytes) where the resulting
 *           hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int digest(void *data, size_t len, uint8_t *key, uint8_t *mac) {
    // Pass values to hash
    return wc_Md5Hash((uint8_t *)data, len, mac);
}

