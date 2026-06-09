# cauth

`cauth` is a lightweight, secure, and minimalist command-line interface (CLI) TOTP (Time-Based One-Time Password) authenticator written in pure C for Linux environments. It serves as a terminal-based, open-source alternative to applications like Google Authenticator, built with a strong focus on memory safety and data security.

## Features

- **RFC 6238 Compliant:** Standard time-based one-time password generation utilizing HMAC-SHA1.
- **Secure Local Storage:** Data at rest is fully protected; the local vault (`~/.config/cauth/vault.dat`) is encrypted using **AES-256-GCM**.
- **Robust Key Derivation:** Incorporates **PBKDF2** (200 000 iterations, HMAC-SHA256) to derive encryption keys from the user's Master Password.
- **Integrity Guaranteed:** GCM authentication tags detect any tampering of the vault file.
- **Hardened Memory Safety:** Immediately zeroes out sensitive data (secret keys, decrypted buffers) in RAM after use via `OPENSSL_cleanse()`.
- **Modular Design:** Strict separation of concerns between the core cryptographic engine and the CLI user interface.
- **Minimal Dependencies:** Leverages standard Linux POSIX APIs and **OpenSSL (`libcrypto`)** for vetted cryptographic primitives.

## Requirements

- **Compiler:** GCC or Clang (C11 support)
- **Build system:** CMake >= 3.20
- **Library:** OpenSSL (`libssl-dev` / `openssl-devel`)
- **OS:** Linux

## Build

```sh
git clone <repo> && cd cauth
cmake -S . -B build
cmake --build build
```

Or use the build script:

```sh
./build.sh
```

The binary `build/cauth` and test binary `build/test_cauth` are produced.

## Demo

![cauth demo](docs/demo.gif)

## Usage

All vault operations require the Master Password (input is hidden).

### Initialize a vault

```sh
cauth init
```

Creates a new encrypted vault at `~/.config/cauth/vault.dat`. You are prompted for a Master Password (confirmed once).

### Add an account

```sh
cauth add <name> <base32_secret>
```

Example:

```sh
cauth add GitHub JBSWY3DPEHPK3PXP
```

### List accounts

```sh
cauth list
```

Prints all stored account names (secrets are never displayed).

### Show TOTP token

```sh
cauth show [--once] <name>
```

Displays a **live countdown** with the token and a progress bar, updating every second. Press `Ctrl+C` to exit.

```
654709  [##########          ]  15s
```

Use `--once` for a single snapshot (or when piping stdout to another command):

```sh
cauth show --once GitHub
```

Output: `654709  (15s left)`

### Remove an account

```sh
cauth remove <name>
```

### Show version

```sh
cauth version
```

## High-Level Architecture

```
src/main.c        CLI entry point, argument parsing, password prompt
src/base32.c      RFC 4648 Base32 decoder
src/totp.c        HMAC-SHA1 + dynamic truncation → 6-digit TOTP
src/crypto.c      AES-256-GCM encrypt/decrypt + PBKDF2 key derivation
src/vault.c       Vault file I/O (read/write ~/.config/cauth/vault.dat)
src/memzero.c     Secure memory zeroing (OPENSSL_cleanse wrapper)
```

## Project Structure

```
cauth/
├── CMakeLists.txt
├── readme.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SECURITY.md
│   └── ROADMAP.md
├── include/
│   ├── base32.h
│   ├── totp.h
│   ├── crypto.h
│   ├── vault.h
│   └── memzero.h
├── src/
│   ├── main.c
│   ├── base32.c
│   ├── totp.c
│   ├── crypto.c
│   ├── vault.c
│   └── memzero.c
├── test/
│   └── test_cauth.c
└── build/
```

## Running Tests

```sh
cmake --build build && ./build/test_cauth
```

## Documentation

Detailed design specifications and planning are available in the `docs/` directory:
- `docs/ARCHITECTURE.md` — System workflow and storage layout.
- `docs/SECURITY.md` — Threat modeling, vault format, and memory management strategy.
- `docs/ROADMAP.md` — Development phases and SemVer release plan.

## License

This project is licensed under the MIT License.