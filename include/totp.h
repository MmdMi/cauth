/** @file totp.h
 * @brief TOTP (Time-Based One-Time Password) generator per RFC 6238.
 */

#ifndef CAUTH_TOTP_H
#define CAUTH_TOTP_H

#include <stddef.h>
#include <stdint.h>

/** Number of digits in the generated token. */
#define TOTP_DIGITS 6

/** Time step window in seconds (RFC 6238 default). */
#define TOTP_TIME_STEP 30

/**
 * @brief Generate a TOTP token for a given secret and Unix timestamp.
 *
 * Uses HMAC-SHA1 for the underlying hash function.  The token is
 * computed as (HOTP(K, floor(t / T)) mod 10^TOTP_DIGITS) per RFC 6238.
 *
 * @param secret    Raw secret key bytes.
 * @param secret_len Length of the secret key.
 * @param timestamp  Unix timestamp (seconds since epoch).
 * @return TOTP token value (0 .. 10^TOTP_DIGITS - 1).
 */
uint32_t totp_generate(const uint8_t *secret, size_t secret_len, uint64_t timestamp);

#endif
