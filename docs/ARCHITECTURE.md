# cauth — Architecture

## System Workflow

```
User Input (Base32 Secret)
         │
         ▼
   ┌─────────────┐
   │  main.c     │  CLI entry point, argument parsing
   └──────┬──────┘
          │
          ▼
   ┌─────────────┐
   │  base32.c   │  RFC 4648 Base32 → raw bytes
   └──────┬──────┘
          │
          ▼
   ┌─────────────┐
   │  totp.c     │  HMAC-SHA1 → dynamic truncation → 6-digit code
   └─────────────┘
```

## Module Responsibilities

| Module | File(s) | Role |
|---|---|---|
| CLI | `src/main.c` | Parse arguments, call core logic, print result |
| Base32 | `include/base32.h`, `src/base32.c` | Decode Base32-encoded secret keys |
| TOTP | `include/totp.h`, `src/totp.c` | Generate RFC 6238 TOTP tokens via HMAC-SHA1 |
| Crypto | *(Phase 2)* | AES-256-GCM vault encryption, PBKDF2 key derivation |

## Storage Layout (Future — v0.2.0)

Vault file: `~/.config/cauth/vault.dat`

- Encrypted with AES-256-GCM
- Key derived from Master Password via PBKDF2
- Each entry: `issuer:account\tsecret` (JSON in future)
