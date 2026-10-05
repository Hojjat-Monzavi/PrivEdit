# PrivEdit

> Privacy-first Windows text editor. Each `.exe` you save **is** the document.

[![Build](https://github.com/OWNER/REPO/actions/workflows/build.yml/badge.svg)](../../actions/workflows/build.yml)
[![Release](https://github.com/OWNER/REPO/actions/workflows/release.yml/badge.svg)](../../actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

PrivEdit is a Notepad-style editor whose saved files are self-contained
executables: the document, the encryption envelope, and the editor itself
live in a single `.exe`. No installer, no runtime, no cloud.

- **Target:** Windows 7 SP1 → Windows 11
- **Architectures:** x86_64, ARM64
- **Runtime deps:** none (fully static)

---

## Download

Pre-built binaries are attached to every [release](../../releases):

| File | Architecture |
|---|---|
| `privedit_gui-x64.exe` | x86_64 |
| `privedit_gui-arm64.exe` | ARM64 |

Verify with `SHA256SUMS.txt`, included in each release.

---

## Features

- **Self-contained `.exe` notes** — double-click to open, no editor needed.
- **Argon2id + XChaCha20-Poly1305** (see [Security](#security)).
- **COVER mode** — type your real note while the screen shows a decoy,
  character for character. Toggle with `Ctrl+R`.
- **Full Unicode** (RichEdit 4.1), Word Wrap, Font picker, Find / Find Next,
  Time/Date, standard Cut/Copy/Paste/Undo.
- **Night theme.**
- **Notepad-familiar UI.**

---

## Usage

```
File      New, Open, Save, Save As
Edit      Undo, Cut, Copy, Paste, Delete, Find, Find Next, Time/Date
Format    Word Wrap, Font
View      Status Bar, Night Theme
Privacy   Reveal Real Text, Set Cover Text, Change Password, Lock Now
Help      About
```

| Key | Action |
|---|---|
| `Ctrl+N` | New |
| `Ctrl+O` | Open |
| `Ctrl+S` | Save |
| `Ctrl+F` | Find |
| `F3` | Find next |
| `Ctrl+R` | Toggle REVEAL / COVER |
| `Ctrl+L` | Lock (wipe keys, return to COVER) |
| `F5` | Insert time/date |

### COVER mode

Enter COVER with `Ctrl+R`. Type normally. Every keystroke goes into the
hidden real note; the visible buffer streams out the next character of the
cover. An observer sees the decoy being typed.

The only thing that leaves COVER is `Ctrl+R` (or **Privacy → Reveal Real
Text**). Keystrokes, clicks, `Ctrl+S`, and navigation keys do **not** reveal.

Set the cover with **Privacy → Set Cover Text…**. It should be longer than
any covert session.

---

## Security

| Component | Choice |
|---|---|
| KDF | Argon2id — 64 MiB, t=3, p=4 (OWASP 2025) |
| Cipher | XChaCha20-Poly1305 AEAD (192-bit nonce, 128-bit tag) |
| Compression | zlib, level 9 (applied before encryption) |
| Library | libsodium |

### Container versions

| Version | KDF | Cipher | Status |
|---|---|---|---|
| v1 | PBKDF2-HMAC-SHA256 (600 000) | AES-256-CBC + HMAC-SHA256 | legacy, read-only |
| v2 | scrypt (N=2¹⁷, r=8, p=1) | AES-256-CBC + HMAC-SHA256 | legacy, read-only |
| **v3** | **Argon2id** | **XChaCha20-Poly1305** | **current** |

This build reads v3 only. Convert v1/v2 files once with an older release
(open → save) before upgrading.

### Notes

- No asymmetric cryptography is used. Quantum computers threaten RSA/ECC,
  not symmetric primitives. A 256-bit key remains safe against Grover's
  algorithm.
- The 192-bit XChaCha20 nonce eliminates the nonce-reuse hazard that has
  historically broken AES-GCM deployments.
- Passwords and derived keys are pinned with `VirtualLock` where the OS
  permits, and zeroised with `sodium_memzero` on exit, on lock, and on
  password change.

---

## Building

### x64 (MSYS2 MinGW64)

```bash
pacman -S --needed mingw-w64-x86_64-{gcc,cmake,ninja,pkgconf,libsodium,zlib}

cmake -S . -B build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_TOOLCHAIN_FILE=cmake/mingw64-toolchain.cmake
cmake --build build --parallel
```

### ARM64 (MSYS2 CLANGARM64)

```bash
pacman -S --needed mingw-w64-clang-aarch64-{clang,cmake,ninja,pkgconf,libsodium,zlib}

cmake -S . -B build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_TOOLCHAIN_FILE=cmake/clangarm64-toolchain.cmake
cmake --build build --parallel
```

### Verify the binary is static

```bash
objdump -p build/privedit_gui.exe | grep "DLL Name"
```

Only Windows system DLLs should be listed.

### Build options

| Option | Default | Effect |
|---|---|---|
| `PRIVEDIT_LTO` | `ON` | Link-time optimization |
| `PRIVEDIT_STRIP` | `ON` | Strip symbols in Release |
| `PRIVEDIT_HARDENING` | `ON` | NXCOMPAT, DYNAMICBASE, HIGHENTROPYVA |

---

## CI

Two workflows, both in `.github/workflows/`:

- **`build.yml`** — CI on push to `main` and ready pull requests. Path
  filters limit it to `src/`, `cmake/`, `CMakeLists.txt`, and the workflow
  itself. Draft PRs are skipped. Manual trigger via `workflow_dispatch`.
- **`release.yml`** — tag-driven (`v*`). Builds both architectures, attaches
  binaries and `SHA256SUMS.txt` to a GitHub Release.

### Reducing build minutes

- **Path filters** — doc-only changes do not build.
- **Concurrency** — superseded runs on the same ref are cancelled.
- **`[skip ci]`** in the last commit message skips all workflows (native
  GitHub behaviour).
- **Draft PRs** — the `build` jobs skip until the PR is marked ready.
- **Manual trigger** — `Actions → Build → Run workflow` for an on-demand run.

### Cross-compiling ARM64 from x64

If the ARM64 Windows runner is unavailable, cross-compile with
[LLVM-MinGW](https://github.com/mstorsjo/llvm-mingw). Build `libsodium` and
`zlib` for `aarch64-w64-mingw32` first. See `cmake/` for templates.

---

## Project layout

```
.
├── .github/workflows/       CI and release pipelines
├── cmake/                   Toolchain files
├── src/
│   ├── privedit_crypto.h    PENC container, Argon2id, XChaCha20-Poly1305
│   ├── privedit_gui.cpp     Win32 GUI, editor, COVER mode
│   ├── privedit.rc          Menus, accelerators, dialogs
│   ├── privedit.manifest    Common Controls v6, DPI-aware
│   └── resource.h
└── CMakeLists.txt
```

---

## Contributing

Issues and pull requests are welcome. Keep the surface small: this is an
LTS-oriented project, so stability and clarity outrank features.

- Run the CI-equivalent build locally before opening a PR.
- Do not introduce new runtime dependencies. Static linking is a requirement.
- Preserve the PENC container layout unless you are adding a new version
  byte; never mutate an existing version in a way that breaks older readers.

---

## FAQ

**Why not AES-256-GCM?**
XChaCha20's 192-bit nonce eliminates nonce-reuse failures by construction.
It is also faster in software on CPUs without AES acceleration, including
some ARM64 silicon.

**Is it safe to store notes on Google Drive / OneDrive / Dropbox?**
The file uploads and syncs fine. Google Drive's web UI filters `.exe`
downloads — use the desktop client or `rclone --drive-acknowledge-abuse`.

**Will it run on Windows 12?**
It uses only Win32 APIs Microsoft has committed to preserving for backward
compatibility. The binary is fully static, so system library updates do not
affect it.

---

## License

MIT — see [LICENSE](LICENSE).

Bundles code from [libsodium](https://github.com/jedisct1/libsodium) (ISC)
and [zlib](https://zlib.net/) (zlib).