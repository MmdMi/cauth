/** @file vault.h
 * @brief Encrypted vault for storing TOTP account entries.
 */

#ifndef CAUTH_VAULT_H
#define CAUTH_VAULT_H

#include <stddef.h>

/**
 * @brief A single vault entry.
 */
typedef struct {
    char *name;    /**< Entry name (e.g. "GitHub"). */
    char *secret;  /**< Base32-encoded secret key. */
} VaultEntry;

/**
 * @brief Dynamic array of vault entries.
 */
typedef struct {
    VaultEntry *entries;   /**< Array of entries. */
    size_t count;          /**< Number of entries in use. */
    size_t capacity;       /**< Allocated capacity of the array. */
} Vault;

/**
 * @brief Initialise an empty vault.
 * @param vault  Vault to initialise (must not be NULL).
 */
void vault_init(Vault *vault);

/**
 * @brief Free all resources owned by a vault.
 *
 * Securely zeroes secrets before freeing.
 * @param vault  Vault to free.
 */
void vault_free(Vault *vault);

/**
 * @brief Add an entry to the vault.
 *
 * Duplicate names are rejected.
 *
 * @param vault  Target vault.
 * @param name   Entry name.
 * @param secret Base32-encoded secret.
 * @return 0 on success, -1 if the name already exists or on allocation failure.
 */
int vault_add(Vault *vault, const char *name, const char *secret);

/**
 * @brief Remove an entry by name.
 *
 * @param vault Target vault.
 * @param name  Entry name.
 * @return 0 on success, -1 if not found.
 */
int vault_remove(Vault *vault, const char *name);

/**
 * @brief Find an entry by name.
 *
 * @param vault Vault to search.
 * @param name  Entry name.
 * @return Pointer to the entry, or NULL if not found.
 */
VaultEntry *vault_find(const Vault *vault, const char *name);

/**
 * @brief Serialise and encrypt the vault to disk.
 *
 * File format: salt || nonce || tag || ciphertext.
 * Stored at ~/.config/cauth/vault.dat.
 *
 * @param vault    Vault to save.
 * @param password Master password for key derivation.
 * @return 0 on success, -1 on error.
 */
int vault_save(const Vault *vault, const char *password);

/**
 * @brief Read and decrypt the vault from disk.
 *
 * @param vault    Vault to populate (must be initialised first).
 * @param password Master password for key derivation.
 * @return 0 on success, -1 if the file does not exist, password is wrong,
 *         or data has been tampered with.
 */
int vault_load(Vault *vault, const char *password);

#endif
