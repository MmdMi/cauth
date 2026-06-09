# cauth - Project Roadmap

This document outlines the development phases, milestones, and release plans for `cauth`. The project follows Semantic Versioning (SemVer) practices.

---

## Phase 1: Core Cryptography & Logic (v0.1.0)
*Goal: Implement the mathematical and cryptographic foundations required for TOTP generation.*

- [ ] **Base32 Decoder:** Implement a robust, bounds-checked Base32 decoding engine to handle standard secret keys.
- [ ] **OpenSSL Integration:** Set up the build system to link against `libcrypto`.
- [ ] **HMAC-SHA1 Engine:** Implement the core hashing logic according to RFC 4226.
- [ ] **TOTP Calculation:** Implement the time-step calculation and dynamic truncation according to RFC 6238.
- [ ] **Verification Logic:** Create a minimal test harness to verify generated tokens against Google Authenticator outputs.

## Phase 2: Security & Local Storage (v0.2.0)
*Goal: Secure the data at rest and protect sensitive data in memory.*

- [ ] **Secure Memory Zeroization:** Implement `explicit_bzero` or `memset_s` workflows to immediately wipe decrypted secrets from RAM after use.
- [ ] **Key Derivation Function (KDF):** Integrate PBKDF2 (via OpenSSL) to derive encryption keys from a user's Master Password.
- [ ] **Encrypted Vault Storage:** Implement AES-256-GCM encryption/decryption for saving account data locally (`~/.config/cauth/vault.dat`).
- [ ] **Integrity Checks:** Utilize GCM authentication tags to detect unauthorized tampering of the vault file.

## Phase 3: CLI Interface & User Experience (v0.3.0)
*Goal: Provide a functional, clean, and intuitive terminal-based user interface.*

- [ ] **Argument Parsing:** Design a robust CLI command structure (e.g., `cauth add`, `cauth show`, `cauth list`).
- [ ] **Secure Password Prompt:** Implement a masked or hidden terminal input for the Master Password (disabling echo).
- [ ] **Real-time Countdown UI:** Create a dynamic terminal view that shows the 6-digit token alongside a visual countdown bar (updating every second).

## Phase 4: Quality Assurance & Production Release (v1.0.0)
*Goal: Refine the codebase, eliminate vulnerabilities, and prepare for public portfolio presentation.*

- [ ] **Memory Leak Auditing:** Audit the entire codebase using **Valgrind** to guarantee zero memory leaks or dangling pointers.
- [ ] **Compiler Hardening:** Enable strict compiler flags (`-Wall -Wextra -Werror -O2 -fstack-protector-all`).
- [ ] **Doxygen Documentation:** Fully document all functions, headers, and data structures in English using Doxygen style comments.
- [ ] **GitHub Actions CI:** Set up a continuous integration pipeline to compile and run unit tests automatically on every push.

## Phase 5: Future Enhancements (v1.1.0+)
*Goal: Post-release features to maximize portfolio value.*

- [ ] **Alternative Hashes:** Add support for SHA-256 and SHA-512 variants of TOTP.
- [ ] **QR Code Processing:** Add a feature to parse QR code images from the terminal using a lightweight library to extract secrets directly.
- [ ] **Secure Export:** Implement a secure, encrypted backup mechanism for moving accounts between devices.