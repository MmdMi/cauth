/** @file crypto.h
 * @brief Cryptographic primitives: key derivation, AES-256-GCM encryption.
 */

#ifndef CAUTH_CRYPTO_H
#define CAUTH_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/** AES-256 key length in bytes. */
#define CAUTH_KEY_LEN   32

/** PBKDF2 salt length in bytes. */
#define CAUTH_SALT_LEN  16

/** AES-GCM nonce / IV length in bytes. */
#define CAUTH_NONCE_LEN 12

/** GCM authentication tag length in bytes. */
#define CAUTH_TAG_LEN   16

/**
 * @brief Derive a 256-bit encryption key from a password using PBKDF2-HMAC-SHA256.
 *
 * @param password  Master password (null-terminated).
 * @param salt      Salt buffer (CAUTH_SALT_LEN bytes).
 * @param key       Output key buffer (CAUTH_KEY_LEN bytes).
 * @return 0 on success, -1 on error.
 */
int crypto_derive_key(const char *password, const uint8_t *salt, uint8_t *key);

/**
 * @brief Encrypt plaintext with AES-256-GCM.
 *
 * Generates a random nonce internally via RAND_bytes.
 *
 * @param plaintext  Input plaintext.
 * @param plen       Plaintext length.
 * @param key        Encryption key (CAUTH_KEY_LEN bytes).
 * @param nonce      Output nonce (CAUTH_NONCE_LEN bytes, random).
 * @param tag        Output authentication tag (CAUTH_TAG_LEN bytes).
 * @param ciphertext Output ciphertext buffer (must be at least plen bytes).
 * @param clen       In: ciphertext capacity; Out: actual ciphertext length.
 * @return 0 on success, -1 on error.
 */
int crypto_encrypt(const uint8_t *plaintext, size_t plen,
                   const uint8_t *key,
                   uint8_t *nonce, uint8_t *tag,
                   uint8_t *ciphertext, size_t *clen);

/**
 * @brief Decrypt ciphertext with AES-256-GCM and verify authentication tag.
 *
 * @param ciphertext Input ciphertext.
 * @param clen       Ciphertext length.
 * @param key        Decryption key (CAUTH_KEY_LEN bytes).
 * @param nonce      Nonce used during encryption (CAUTH_NONCE_LEN bytes).
 * @param tag        Authentication tag to verify (CAUTH_TAG_LEN bytes).
 * @param plaintext  Output plaintext buffer (must be at least clen bytes).
 * @param plen       In: plaintext capacity; Out: actual plaintext length.
 * @return 0 on success, -1 on authentication failure or error.
 */
int crypto_decrypt(const uint8_t *ciphertext, size_t clen,
                   const uint8_t *key,
                   const uint8_t *nonce, const uint8_t *tag,
                   uint8_t *plaintext, size_t *plen);

#endif
