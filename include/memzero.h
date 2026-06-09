/** @file memzero.h
 * @brief Secure memory zeroing using OPENSSL_cleanse.
 */

#ifndef CAUTH_MEMZERO_H
#define CAUTH_MEMZERO_H

#include <stddef.h>

/**
 * @brief Securely zero a memory buffer.
 *
 * Uses OPENSSL_cleanse() which is guaranteed not to be optimized away
 * by the compiler, unlike a plain memset().
 *
 * @param ptr Pointer to the buffer (NULL-safe).
 * @param len Number of bytes to zero.
 */
void memzero(void *ptr, size_t len);

#endif
