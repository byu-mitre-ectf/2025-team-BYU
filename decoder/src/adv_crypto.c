/**
 * @file "adv_crypto.c"
 * @author Macen Bird
 * @brief Advanced Crypto API File
 * @date 2025
 * 
 */

#include "adv_crypto.h"

#include <string.h>

#define SUCCESS 0

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
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *authTag, uint8_t *aad, uint8_t *key, uint8_t *iv, uint8_t *plaintext) {
    // returns 0 on success else non-zero
    size_t aad_len = sizeof(uint32_t)+CHACHAPOLY_IV_SIZE;
    return wc_ChaCha20Poly1305_Decrypt(key, iv, aad, aad_len, ciphertext, len, authTag, plaintext);
}

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
int decrypt_asym(uint8_t *ciphertext, size_t ctSize, uint8_t *keyData, size_t keyLen, uint8_t *plaintext, size_t ptSize) {
    WC_RNG rng;
    RsaKey rsaKey;
    int32_t ret;
    word32 idx = 0;

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

    // set key rng : returns 0 on success. This is necessary for the decrypt function to succeed (see WC_RSA_BLINDING)
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

    // specify _ex for OAEP padding for compliance with the python library
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
int digest(void *data, size_t len, uint8_t *key, int32_t key_len, uint8_t *mac) {
    // just make sure you input 256 as size for data when you hash with the RSA data. sizeof may mess you up
    int32_t ret = 0;

    Hmac hmac;
    ret = wc_HmacSetKey(&hmac, WC_SHA256, key, key_len);
    if (ret != 0) {
        // error setting the key
        return ret;
    }
    ret = wc_HmacUpdate(&hmac, data, len);
    if (ret != 0) {
        // error updating message
        return ret;
    }
    ret = wc_HmacFinal(&hmac, mac);
    if (ret != 0) {
        // error updating message
        return ret;
    }

    return 0;
}

