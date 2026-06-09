/** @file base32.c
 * @brief RFC 4648 Base32 decoder implementation.
 */

#include "base32.h"

/**
 * @brief Map a Base32 character to its 5-bit value.
 * @param c  Input character.
 * @return 0-31 on success, -1 for invalid characters.
 */
static int base32_char_val(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a';
    if (c >= '2' && c <= '7')
        return c - '2' + 26;
    return -1;
}

int base32_decode(const char *in, uint8_t *out, size_t out_len)
{
    if (!in || !out || out_len == 0)
        return -1;

    size_t written = 0;
    int buffer = 0;
    int bits = 0;
    size_t padding = 0;

    while (*in)
    {
        if (*in == '=')
        {
            padding++;
            in++;
            continue;
        }

        int val = base32_char_val(*in);
        if (val < 0)
            return -1;

        if (padding > 0)
            return -1;

        buffer = (buffer << 5) | val;
        bits += 5;

        if (bits >= 8)
        {
            bits -= 8;
            if (written >= out_len)
                return -1;
            out[written++] = (buffer >> bits) & 0xFF;
        }

        in++;
    }

    return (int)written;
}
