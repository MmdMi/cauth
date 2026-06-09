# cauth — Security Model

## Threat Model

| Threat | Mitigation |
|---|---|
| Memory dumping (cold boot, core dumps) | Secrets zeroed immediately after use with `OPENSSL_cleanse()` |
| Vault file theft | AES-256-GCM encryption + authentication tag |
| Brute-force on vault | PBKDF2-HMAC-SHA256 with 200 000 iterations |
| Shoulder surfing | *(Phase 3)* Masked password input, optional clipboard copy |

## Current Protections (v0.2.0)

- **Secure zeroization:** `OPENSSL_cleanse()` wipes decrypted secrets, derived keys, and plaintext vault data from RAM after use.
- **Vault encryption:** AES-256-GCM with a random 12-byte nonce generated per write via `RAND_bytes`.
- **Key derivation:** PBKDF2-HMAC-SHA256 with 200 000 iterations. A random 16-byte salt is generated per vault.
- **Integrity:** GCM authentication tag is verified on every vault read; tampered data is rejected.
- **No persistent plaintext:** The vault file (`~/.config/cauth/vault.dat`) is always encrypted at rest.
- **Minimal secret lifetime:** Base32-decoded secrets are held on the stack and zeroed after TOTP generation.
- **Single-purpose binary:** No network, minimal file I/O, no unnecessary syscalls.

## Vault Storage Format

```
~/.config/cauth/vault.dat
  ├── salt      (16 bytes  — PBKDF2 salt)
  ├── nonce     (12 bytes  — AES-GCM nonce)
  ├── tag       (16 bytes  — GCM authentication tag)
  └── ciphertext          — AES-256-GCM encrypted entries
```

Entries in the plaintext are stored as:
```
name\tsecret\n
```

## Memory Management Strategy

```
Decode secret  →  raw bytes on stack
Generate TOTP  →  HMAC result on stack
Derive key     →  buffer zeroed with OPENSSL_cleanse()
Decrypt vault  →  plaintext zeroed after parsing
```
