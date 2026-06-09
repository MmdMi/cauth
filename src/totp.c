/** @file totp.c
 * @brief TOTP generation per RFC 6238 using HMAC-SHA1.
 */

#define OPENSSL_SUPPRESS_DEPRECATED

#include "totp.h"

#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

/**
 * @brief Write a 64-bit value as big-endian bytes.
 * @param buf  Output buffer (exactly 8 bytes).
 * @param val  Value to encode.
 */
static void int64_to_be(uint8_t *buf, uint64_t val)
{
    for (int i = 7; i >= 0; i--)
    {
        buf[i] = val & 0xFF;
        val >>= 8;
    }
}

/**
 * @brief Perform dynamic truncation (RFC 4226 Section 5.3).
 *
 * Extracts a 31-bit number from the HMAC result.
 *
 * @param hmac     HMAC output.
 * @param hmac_len Length of HMAC output.
 * @return 31-bit truncated value.
 */
static uint32_t dynamic_truncation(const uint8_t *hmac, size_t hmac_len)
{
    size_t offset = hmac[hmac_len - 1] & 0x0F;
    uint32_t code = ((uint32_t)hmac[offset] & 0x7F) << 24
                  | ((uint32_t)hmac[offset + 1] & 0xFF) << 16
                  | ((uint32_t)hmac[offset + 2] & 0xFF) << 8
                  | ((uint32_t)hmac[offset + 3] & 0xFF);
    return code;
}

uint32_t totp_generate(const uint8_t *secret, size_t secret_len, uint64_t timestamp)
{
    uint64_t counter = timestamp / TOTP_TIME_STEP;

    uint8_t counter_be[8];
    int64_to_be(counter_be, counter);

    uint8_t hmac_result[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;

    HMAC(EVP_sha1(), secret, (int)secret_len,
         counter_be, sizeof(counter_be),
         hmac_result, &hmac_len);

    uint32_t code = dynamic_truncation(hmac_result, hmac_len);
    uint32_t modulus = 1;
    for (int i = 0; i < TOTP_DIGITS; i++)
        modulus *= 10;

    return code % modulus;
}
