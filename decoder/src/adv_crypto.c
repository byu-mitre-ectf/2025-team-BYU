/**
 * @file "adv_crypto.c"
 * @author Macen Bird
 * @brief Advanced Crypto API File
 * @date 2025
 * 
 */

#include "adv_crypto.h"

#include <string.h>

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

