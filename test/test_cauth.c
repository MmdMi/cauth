#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "base32.h"
#include "totp.h"
#include "crypto.h"
#include "vault.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { printf("  %s ... ", name); tests_run++; } while (0)
#define PASS() do { printf("PASS\n"); tests_passed++; } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while (0)
#define ASSERT(cond, msg) do { if (!(cond)) { FAIL(msg); return; } } while (0)

static void test_base32_rfc4648(void)
{
    const char *in = "JBSWY3DPEHPK3PXP";
    uint8_t out[32];
    int len = base32_decode(in, out, sizeof(out));
    ASSERT(len == 10, "expected 10 bytes");
    PASS();
}

static void test_base32_padding(void)
{
    const char *in = "MZXW6YQ=";
    uint8_t out[32];
    int len = base32_decode(in, out, sizeof(out));
    ASSERT(len == 4, "expected 4 bytes");
    ASSERT(out[0] == 0x66 && out[1] == 0x6F && out[2] == 0x6F && out[3] == 0x62,
           "expected 'foob'");
    PASS();
}

static void test_base32_invalid(void)
{
    const char *in = "JBSWY3DPEHPK3P!X";
    uint8_t out[32];
    int len = base32_decode(in, out, sizeof(out));
    ASSERT(len < 0, "expected failure on invalid char");
    PASS();
}

static void test_base32_null(void)
{
    int len = base32_decode(NULL, NULL, 0);
    ASSERT(len < 0, "expected failure on NULL input");
    PASS();
}

static void test_totp_rfc6238(void)
{
    const char *b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    uint8_t secret[32];
    int slen = base32_decode(b32, secret, sizeof(secret));
    ASSERT(slen == 20, "expected 20-byte secret");

    uint32_t token = totp_generate(secret, (size_t)slen, 0);
    ASSERT(token == 755224, "unexpected TOTP for T=0");
    PASS();
}

static void test_crypto_key_derivation(void)
{
    uint8_t salt[CAUTH_SALT_LEN];
    memset(salt, 0x42, CAUTH_SALT_LEN);

    uint8_t key1[CAUTH_KEY_LEN];
    uint8_t key2[CAUTH_KEY_LEN];

    ASSERT(crypto_derive_key("testpassword", salt, key1) == 0, "key derivation failed");
    ASSERT(crypto_derive_key("testpassword", salt, key2) == 0, "key derivation failed");
    ASSERT(memcmp(key1, key2, CAUTH_KEY_LEN) == 0, "keys should be deterministic");
    PASS();
}

static void test_crypto_encrypt_decrypt(void)
{
    uint8_t key[CAUTH_KEY_LEN];
    uint8_t salt[CAUTH_SALT_LEN];
    memset(salt, 0x11, CAUTH_SALT_LEN);
    ASSERT(crypto_derive_key("password", salt, key) == 0, "key derivation failed");

    const char *plaintext = "Hello, cauth!";
    size_t plen = strlen(plaintext);

    uint8_t nonce[CAUTH_NONCE_LEN];
    uint8_t tag[CAUTH_TAG_LEN];
    uint8_t ciphertext[128];
    size_t clen = sizeof(ciphertext);

    ASSERT(crypto_encrypt((const uint8_t *)plaintext, plen,
                           key, nonce, tag, ciphertext, &clen) == 0,
           "encryption failed");

    uint8_t decrypted[128];
    size_t dlen = sizeof(decrypted);

    ASSERT(crypto_decrypt(ciphertext, clen, key, nonce, tag,
                           decrypted, &dlen) == 0,
           "decryption failed");
    ASSERT(dlen == plen, "decrypted length mismatch");
    ASSERT(memcmp(decrypted, plaintext, dlen) == 0, "decrypted content mismatch");
    PASS();
}

static void test_crypto_tamper_detection(void)
{
    uint8_t key[CAUTH_KEY_LEN];
    uint8_t salt[CAUTH_SALT_LEN];
    memset(salt, 0x22, CAUTH_SALT_LEN);
    ASSERT(crypto_derive_key("password", salt, key) == 0, "key derivation failed");

    uint8_t nonce[CAUTH_NONCE_LEN];
    uint8_t tag[CAUTH_TAG_LEN];
    uint8_t ciphertext[128];
    size_t clen = sizeof(ciphertext);

    ASSERT(crypto_encrypt((const uint8_t *)"data", 4,
                           key, nonce, tag, ciphertext, &clen) == 0,
           "encryption failed");

    ciphertext[0] ^= 1;

    uint8_t decrypted[128];
    size_t dlen = sizeof(decrypted);
    int ret = crypto_decrypt(ciphertext, clen, key, nonce, tag,
                              decrypted, &dlen);
    ASSERT(ret != 0, "tampered ciphertext should fail decryption");
    PASS();
}

static void test_vault_operations(void)
{
    Vault vault;
    vault_init(&vault);
    ASSERT(vault.count == 0, "vault should be empty");

    ASSERT(vault_add(&vault, "GitHub", "user@example.com", "JBSWY3DPEHPK3PXP") == 0,
           "add failed");
    ASSERT(vault_add(&vault, "Google", "user@gmail.com", "GEZDGNBVGY3TQOJQ") == 0,
           "add failed");
    ASSERT(vault.count == 2, "vault should have 2 entries");

    ASSERT(vault_find(&vault, "GitHub", "user@example.com") != NULL,
           "find GitHub failed");
    ASSERT(vault_find(&vault, "Nonexistent", "x") == NULL,
           "find nonexistent should return NULL");

    ASSERT(vault_add(&vault, "GitHub", "user@example.com", "x") != 0,
           "duplicate add should fail");

    ASSERT(vault_remove(&vault, "GitHub", "user@example.com") == 0,
           "remove failed");
    ASSERT(vault.count == 1, "vault should have 1 entry after remove");
    ASSERT(vault_find(&vault, "GitHub", "user@example.com") == NULL,
           "removed entry should not be found");

    vault_free(&vault);
    PASS();
}

int main(void)
{
    printf("base32 tests:\n");
    test_base32_rfc4648();
    test_base32_padding();
    test_base32_invalid();
    test_base32_null();

    printf("totp tests:\n");
    test_totp_rfc6238();

    printf("crypto tests:\n");
    test_crypto_key_derivation();
    test_crypto_encrypt_decrypt();
    test_crypto_tamper_detection();

    printf("vault tests:\n");
    test_vault_operations();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
