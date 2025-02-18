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

#if CRYPTO_ADV

#include "adv_crypto.h"
#include "wolfssl/wolfcrypt/chacha20_poly1305.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/poly1305.h"
#include <stdint.h>
#include <string.h>

#define SUCCESS 0

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
int decrypt_asym(uint8_t *ciphertext, size_t ctSize, uint8_t *keyData, size_t keyLen, uint8_t *plaintext, size_t ptSize) {
    // the plaintext and ciphertext objects must be big enough to work for RSA decrypted data (at least of keySize)
    WC_RNG rng;
    RsaKey rsaKey;
    int32_t ret;
    uint32_t idx = 0;

    // init rng : returns 0 on success
    ret = wc_InitRng(&rng);
    if (ret != SUCCESS) {
        return ret;
    }

    // init key : returns 0 on success
    ret = wc_InitRsaKey(&rsaKey, NULL);
    if (ret != SUCCESS) {
        return ret;
    }

    // set key rng : returns 0 on success. This is necessary for the decrypt function to succeed
    ret = wc_RsaSetRNG(&rsaKey, &rng);
    if (ret != SUCCESS) {
        return ret;
    }

    // takes the keyData array (as a der object), a pointer to an int index at which the key starts, usually 0, pointer to RsaKey object, and the size of the der
    ret = wc_RsaPrivateKeyDecode(keyData, &idx, &rsaKey, keyLen);
    if (ret != SUCCESS) {
        wc_FreeRsaKey(&rsaKey);
        return ret;
    }

    // specify ex for OAEP padding for compliance with the python library
    ret = wc_RsaPrivateDecrypt_ex(ciphertext, ctSize, plaintext, ptSize, &rsaKey, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);

    // make sure you free the objects
    wc_FreeRsaKey(&rsaKey);
    wc_FreeRng(&rng);

    // error codes will be returned on bad decrypt (all errors should be sub-zero)
    if (ret < SUCCESS) {
        return ret;
    }
    // can return ret to return the number of decrypted characters
    return SUCCESS;
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
int digest(void *data, size_t len, uint8_t *aad, uint8_t *key, uint8_t *mac) {
    // Pass values to hash
    Poly1305 ctx;

    wc_Poly1305SetKey(&ctx, key, sizeof(key));
    if(wc_Poly1305_MAC(&ctx, aad, sizeof(aad), (uint8_t *)data, len, mac, POLY1305_DIGEST_SIZE) != 0)
    {
        return 1;
    }
    return SUCCESS;
}

