/** @file base32.h
 * @brief RFC 4648 Base32 decoding interface.
 */

#ifndef CAUTH_BASE32_H
#define CAUTH_BASE32_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Decode a Base32-encoded string into raw bytes.
 *
 * Supports the standard RFC 4648 alphabet (A-Z, 2-7) with optional
 * padding characters ('=').  Mixed-case input is accepted.
 *
 * @param in      Null-terminated Base32 input string.
 * @param out     Output buffer for decoded bytes.
 * @param out_len Size of the output buffer.
 * @return Number of bytes written on success, -1 on error.
 */
int base32_decode(const char *in, uint8_t *out, size_t out_len);

#endif
