/** @file vault.c
 * @brief Encrypted vault file I/O implementation.
 */

#include "vault.h"
#include "crypto.h"
#include "memzero.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/rand.h>

#define VAULT_DIR  ".config/cauth"
#define VAULT_FILE "vault.dat"

/**
 * @brief Build the full path to the vault file.
 * @param buf      Output buffer.
 * @param buf_size Buffer size.
 * @return 0 on success, -1 on error.
 */
static int get_vault_path(char *buf, size_t buf_size)
{
    const char *home = getenv("HOME");
    if (!home)
        return -1;
    int n = snprintf(buf, buf_size, "%s/%s/%s", home, VAULT_DIR, VAULT_FILE);
    if (n < 0 || (size_t)n >= buf_size)
        return -1;
    return 0;
}

/**
 * @brief Ensure the ~/.config/cauth directory exists.
 * @return 0 on success, -1 on error.
 */
static int ensure_vault_dir(void)
{
    const char *home = getenv("HOME");
    if (!home)
        return -1;
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/%s", home, VAULT_DIR);
    struct stat st;
    if (stat(dir, &st) == 0)
        return S_ISDIR(st.st_mode) ? 0 : -1;
    return mkdir(dir, 0700) == 0 ? 0 : -1;
}

/**
 * @brief Serialise vault entries into a plaintext byte buffer.
 *
 * Format: name\\tsecret\\n  (one line per entry).
 *
 * @param vault   Source vault.
 * @param out     Output buffer (allocated, caller must free).
 * @param out_len Output length.
 * @return 0 on success, -1 on error.
 */
static int serialize(const Vault *vault, uint8_t **out, size_t *out_len)
{
    size_t cap = 1024;
    char *buf = malloc(cap);
    if (!buf)
        return -1;

    size_t pos = 0;
    for (size_t i = 0; i < vault->count; i++)
    {
        int n = snprintf(buf + pos, cap - pos, "%s\t%s\n",
                         vault->entries[i].name,
                         vault->entries[i].secret);
        if (n < 0)
        {
            free(buf);
            return -1;
        }
        size_t needed = pos + (size_t)n + 1;
        if (needed > cap)
        {
            cap = needed * 2;
            char *tmp = realloc(buf, cap);
            if (!tmp)
            {
                free(buf);
                return -1;
            }
            buf = tmp;
            n = snprintf(buf + pos, cap - pos, "%s\t%s\n",
                         vault->entries[i].name,
                         vault->entries[i].secret);
            if (n < 0)
            {
                free(buf);
                return -1;
            }
        }
        pos += (size_t)n;
    }

    *out = (uint8_t *)buf;
    *out_len = pos;
    return 0;
}

/**
 * @brief Parse a plaintext buffer back into vault entries.
 *
 * @param data     Input buffer.
 * @param data_len Input length.
 * @param vault    Vault to populate.
 * @return 0 on success, -1 on error.
 */
static int deserialize(const uint8_t *data, size_t data_len, Vault *vault)
{
    const char *p = (const char *)data;
    const char *end = p + data_len;

    while (p < end)
    {
        const char *line_end = memchr(p, '\n', (size_t)(end - p));
        if (!line_end)
            line_end = end;

        size_t line_len = (size_t)(line_end - p);
        if (line_len > 0)
        {
            char *line = strndup(p, line_len);
            if (!line)
                return -1;

            char *tab = strchr(line, '\t');
            if (!tab)
            {
                free(line);
                p = line_end + 1;
                continue;
            }
            *tab = '\0';
            char *secret = tab + 1;

            vault_add(vault, line, secret);
            free(line);
        }

        p = line_end + 1;
    }

    return 0;
}

void vault_init(Vault *vault)
{
    vault->entries = NULL;
    vault->count = 0;
    vault->capacity = 0;
}

void vault_free(Vault *vault)
{
    for (size_t i = 0; i < vault->count; i++)
    {
        free(vault->entries[i].name);
        memzero(vault->entries[i].secret, strlen(vault->entries[i].secret));
        free(vault->entries[i].secret);
    }
    free(vault->entries);
    vault->entries = NULL;
    vault->count = 0;
    vault->capacity = 0;
}

int vault_add(Vault *vault, const char *name, const char *secret)
{
    if (!vault || !name || !secret)
        return -1;

    if (vault_find(vault, name))
        return -1;

    if (vault->count >= vault->capacity)
    {
        size_t new_cap = vault->capacity == 0 ? 8 : vault->capacity * 2;
        VaultEntry *new_entries = realloc(vault->entries, new_cap * sizeof(VaultEntry));
        if (!new_entries)
            return -1;
        vault->entries = new_entries;
        vault->capacity = new_cap;
    }

    vault->entries[vault->count].name = strdup(name);
    vault->entries[vault->count].secret = strdup(secret);
    if (!vault->entries[vault->count].name ||
        !vault->entries[vault->count].secret)
    {
        free(vault->entries[vault->count].name);
        free(vault->entries[vault->count].secret);
        return -1;
    }

    vault->count++;
    return 0;
}

int vault_remove(Vault *vault, const char *name)
{
    if (!vault || !name)
        return -1;

    for (size_t i = 0; i < vault->count; i++)
    {
        if (strcmp(vault->entries[i].name, name) == 0)
        {
            free(vault->entries[i].name);
            memzero(vault->entries[i].secret, strlen(vault->entries[i].secret));
            free(vault->entries[i].secret);

            vault->count--;
            if (i < vault->count)
                vault->entries[i] = vault->entries[vault->count];

            return 0;
        }
    }

    return -1;
}

VaultEntry *vault_find(const Vault *vault, const char *name)
{
    if (!vault || !name)
        return NULL;

    for (size_t i = 0; i < vault->count; i++)
    {
        if (strcmp(vault->entries[i].name, name) == 0)
        {
            return &vault->entries[i];
        }
    }

    return NULL;
}

int vault_save(const Vault *vault, const char *password)
{
    if (!vault || !password)
        return -1;

    if (ensure_vault_dir() != 0)
        return -1;

    uint8_t salt[CAUTH_SALT_LEN];
    uint8_t key[CAUTH_KEY_LEN];
    uint8_t nonce[CAUTH_NONCE_LEN];
    uint8_t tag[CAUTH_TAG_LEN];

    if (RAND_bytes(salt, CAUTH_SALT_LEN) != 1)
        return -1;

    if (crypto_derive_key(password, salt, key) != 0)
        return -1;

    uint8_t *plaintext = NULL;
    size_t plen = 0;
    if (serialize(vault, &plaintext, &plen) != 0)
    {
        memzero(key, sizeof(key));
        return -1;
    }

    size_t clen = plen + 16;
    uint8_t *ciphertext = malloc(clen);
    if (!ciphertext)
    {
        memzero(plaintext, plen);
        free(plaintext);
        memzero(key, sizeof(key));
        return -1;
    }

    int ret = -1;
    if (crypto_encrypt(plaintext, plen, key, nonce, tag, ciphertext, &clen) != 0)
        goto out;

    char path[512];
    if (get_vault_path(path, sizeof(path)) != 0)
        goto out;

    FILE *f = fopen(path, "wb");
    if (!f)
        goto out;

    if (fwrite(salt, 1, CAUTH_SALT_LEN, f) != CAUTH_SALT_LEN ||
        fwrite(nonce, 1, CAUTH_NONCE_LEN, f) != CAUTH_NONCE_LEN ||
        fwrite(tag, 1, CAUTH_TAG_LEN, f) != CAUTH_TAG_LEN ||
        fwrite(ciphertext, 1, clen, f) != clen)
    {
        fclose(f);
        goto out;
    }

    fclose(f);
    ret = 0;

out:
    memzero(plaintext, plen);
    free(plaintext);
    free(ciphertext);
    memzero(key, sizeof(key));
    return ret;
}

int vault_load(Vault *vault, const char *password)
{
    if (!vault || !password)
        return -1;

    char path[512];
    if (get_vault_path(path, sizeof(path)) != 0)
        return -1;

    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;

    uint8_t salt[CAUTH_SALT_LEN];
    uint8_t nonce[CAUTH_NONCE_LEN];
    uint8_t tag[CAUTH_TAG_LEN];

    if (fread(salt, 1, CAUTH_SALT_LEN, f) != CAUTH_SALT_LEN ||
        fread(nonce, 1, CAUTH_NONCE_LEN, f) != CAUTH_NONCE_LEN ||
        fread(tag, 1, CAUTH_TAG_LEN, f) != CAUTH_TAG_LEN)
    {
        fclose(f);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long clen = ftell(f) - CAUTH_SALT_LEN - CAUTH_NONCE_LEN - CAUTH_TAG_LEN;
    if (clen < 0)
    {
        fclose(f);
        return -1;
    }

    uint8_t key[CAUTH_KEY_LEN];
    if (crypto_derive_key(password, salt, key) != 0)
    {
        fclose(f);
        return -1;
    }

    if (clen == 0)
    {
        fclose(f);
        memzero(key, sizeof(key));
        return 0;
    }

    uint8_t *ciphertext = malloc((size_t)clen);
    if (!ciphertext)
    {
        fclose(f);
        memzero(key, sizeof(key));
        return -1;
    }

    rewind(f);
    fseek(f, CAUTH_SALT_LEN + CAUTH_NONCE_LEN + CAUTH_TAG_LEN, SEEK_SET);
    if (fread(ciphertext, 1, (size_t)clen, f) != (size_t)clen)
    {
        fclose(f);
        free(ciphertext);
        memzero(key, sizeof(key));
        return -1;
    }
    fclose(f);

    uint8_t *plaintext = malloc((size_t)clen + 16);
    if (!plaintext)
    {
        free(ciphertext);
        memzero(key, sizeof(key));
        return -1;
    }

    size_t plen = 0;
    int ret = -1;
    if (crypto_decrypt(ciphertext, (size_t)clen, key, nonce, tag, plaintext, &plen) != 0)
        goto out;

    if (deserialize(plaintext, plen, vault) != 0)
        goto out;

    ret = 0;

out:
    memzero(plaintext, plen);
    free(plaintext);
    free(ciphertext);
    memzero(key, sizeof(key));
    return ret;
}
