/** @file memzero.c
 * @brief Secure memory zeroing wrapper around OPENSSL_cleanse.
 */

#include "memzero.h"
#include <openssl/crypto.h>

void memzero(void *ptr, size_t len)
{
    if (ptr && len > 0)
        OPENSSL_cleanse(ptr, len);
}
