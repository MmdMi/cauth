/** @file crypto.c
 * @brief PBKDF2 key derivation and AES-256-GCM encrypt/decrypt.
 */

#define OPENSSL_SUPPRESS_DEPRECATED

#include "crypto.h"
#include "memzero.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/** Number of PBKDF2 iterations (OWASP recommended minimum for 2023+). */
#define PBKDF2_ITERATIONS 200000

int crypto_derive_key(const char *password, const uint8_t *salt, uint8_t *key)
{
    if (!password || !salt || !key)
        return -1;

    int ret = PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                                salt, CAUTH_SALT_LEN,
                                PBKDF2_ITERATIONS,
                                EVP_sha256(),
                                CAUTH_KEY_LEN, key);
    return ret == 1 ? 0 : -1;
}

int crypto_encrypt(const uint8_t *plaintext, size_t plen,
                   const uint8_t *key,
                   uint8_t *nonce, uint8_t *tag,
                   uint8_t *ciphertext, size_t *clen)
{
    if (!plaintext || !key || !nonce || !tag || !ciphertext || !clen)
        return -1;

    if (RAND_bytes(nonce, CAUTH_NONCE_LEN) != 1)
        return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    int ret = -1;
    int len = 0;
    int total = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, CAUTH_NONCE_LEN, NULL) != 1)
        goto out;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto out;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plen) != 1)
        goto out;
    total = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + total, &len) != 1)
        goto out;
    total += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, CAUTH_TAG_LEN, tag) != 1)
        goto out;

    *clen = (size_t)total;
    ret = 0;

out:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int crypto_decrypt(const uint8_t *ciphertext, size_t clen,
                   const uint8_t *key,
                   const uint8_t *nonce, const uint8_t *tag,
                   uint8_t *plaintext, size_t *plen)
{
    if (!ciphertext || !key || !nonce || !tag || !plaintext || !plen)
        return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    int ret = -1;
    int len = 0;
    int total = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, CAUTH_NONCE_LEN, NULL) != 1)
        goto out;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto out;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)clen) != 1)
        goto out;
    total = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, CAUTH_TAG_LEN, (void *)tag) != 1)
        goto out;

    if (EVP_DecryptFinal_ex(ctx, plaintext + total, &len) != 1)
        goto out;
    total += len;

    *plen = (size_t)total;
    ret = 0;

out:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
