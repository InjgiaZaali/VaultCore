<div align="center">

# VaultCore

### Fast, versioned, content-addressed backups in modern C++

**C++20** · **SHA-256** · **Chunk Deduplication** · **Cross-Platform** · **Zero Runtime Dependencies**

[![CI](https://github.com/InjgiaZaali/VaultCore/actions/workflows/ci.yml/badge.svg)](https://github.com/InjgiaZaali/VaultCore/actions/workflows/ci.yml)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C.svg)](https://en.cppreference.com/w/cpp/20)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

VaultCore is a **local-first backup and recovery engine**. It stores directory snapshots as immutable manifests and file contents as SHA-256-addressed, 1 MiB chunks. Identical chunks are stored only once, even across different files and different backups. You can inspect versions, compare snapshots, restore prior states, verify corruption, and safely garbage-collect unreferenced data.

> **Status: v0.1 (technical preview).** VaultCore is designed as an educational systems project, not a substitute for independently tested backup software. Keep another verified copy of important files. It does **not** encrypt data, preserve permissions, guarantee crash-durable writes, or offer atomic point-in-time snapshots of files changing during backup.

## Highlights

- **Deduplicated storage:** SHA-256 naming and fixed-size chunking avoid duplicates across repeated backups.
- **Immutable snapshots:** Separate, checksummed binary manifest for each backup; snapshots remain independently restorable.
- **Integrity first:** Rehash reused objects; validate whole-file and chunk hashes during restore and verify.
- **Safe-by-default recovery:** Refuse to overwrite existing files without `--overwrite`; reject symlinked destination directories and unsafe manifest paths.
- **Explicit retention:** `delete` removes only a snapshot manifest; `gc` previews orphaned chunk reclamation until `--apply`.
- **Portable C++20:** Standard-library-only library and executable; CMake and CTest; continuous integration on Linux, macOS, Windows.

## Quick start

**Prerequisites:** CMake 3.20+, a C++20 compiler (GCC 11+, Clang 14+, or a recent MSVC), and Git.

```bash
git clone https://github.com/InjgiaZaali/VaultCore.git
cd VaultCore
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

On Linux/macOS run `./build/vaultcore`; with MSVC multi-configuration generators, run `build\\Release\\vaultcore.exe`. If using a Windows single-configuration generator, the executable may be in `build\\vaultcore.exe`.

```bash
# Create a vault OUTSIDE the folder being backed up (recommended).
./build/vaultcore init ./my-vault

# Back up your files and remember the displayed snapshot ID.
./build/vaultcore backup ./my-vault ./my-projects

# Browse history and individual files.
./build/vaultcore list ./my-vault
./build/vaultcore show ./my-vault <snapshot-id>

# Restore an earlier version into a NEW destination.
./build/vaultcore restore ./my-vault <snapshot-id> ./recovered

# Validate every referenced object and the file data it reconstructs.
./build/vaultcore verify ./my-vault

# See actual disk usage.
./build/vaultcore stats ./my-vault
```

## Command reference

| Command | Purpose |
|---|---|
| `vaultcore init <vault>` | Initialize a new empty vault (will not overwrite existing contents) |
| `vaultcore backup <vault> <directory>` | Capture all regular files recursively; skip symlinks |
| `vaultcore list <vault>` | Display snapshot IDs, dates, original roots and file counts |
| `vaultcore show <vault> <id>` | Display per-file size and SHA-256 in a snapshot |
| `vaultcore diff <vault> <older> <newer>` | Report `+` added, `~` modified, `-` removed |
| `vaultcore restore <vault> <id> <out> [--overwrite]` | Reconstruct and verify a snapshot |
| `vaultcore verify <vault> [id]` | Detect corrupted manifests, missing or corrupt chunks and file hash mismatches |
| `vaultcore stats <vault>` | Logical bytes, physical object count, live chunks and dedupe ratio |
| `vaultcore delete <vault> <id>` | Delete one manifest, leaving shared objects untouched |
| `vaultcore gc <vault> [--apply]` | Show / reclaim unreferenced chunks; defaults to dry run |

### Example version comparison

```text
$ vaultcore diff my-vault 1711111111111-aaaaaaaaaaaaaaaa 1711111122222-bbbbbbbbbbbbbbbb
~ src/main.cpp
+ src/recovery.cpp
- notes/old-plan.txt
3 changed paths.
```

## How it works

```text
folder to back up
  ├── src/app.cpp    ─┬── [SHA-256 chunk A] ─────┐
  │                   └── [SHA-256 chunk B] ───┐ │
  └── src/tool.cpp   ──── [SHA-256 chunk A] ──┐│ │  (shared)
                                               ▼▼ ▼
  vault/objects/ab/ab...                  unique chunks only
  vault/snapshots/<snapshot-id>.vcs       immutable manifest
  vault/vault.meta                         format marker
```

Each snapshot manifest contains a timestamp, original source path, and an ordered record for every file (relative UTF-8 path, byte count, full-file SHA-256, ordered chunk digests). The manifest is versioned and protected against accidental corruption with its own trailing SHA-256 checksum. Objects use a 2-character prefix directory to avoid keeping all files in one folder.

**Deduplication example:** Two backups containing the same 1 GiB of data store ~1 GiB of chunk payloads, not ~2 GiB, assuming identical chunks and no extra changed files. Because chunks are **fixed-size**, inserting bytes near a file's beginning can shift chunk boundaries and lower deduplication efficiency. Metadata and filesystem overhead are additional.

For design decisions, data format, complexity and invariants, see [Architecture](docs/ARCHITECTURE.md). For limits and threat assumptions, see [Security](docs/SECURITY.md).

## Tests and quality checks

```bash
# Regular unit/integration suite
cmake -S . -B build -DVAULTCORE_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure

# AddressSanitizer + UndefinedBehaviorSanitizer on supported GCC/Clang environments
cmake -S . -B build-asan -DVAULTCORE_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-asan
ctest --test-dir build-asan --output-on-failure
```

The test suite covers published SHA-256 vectors, chunk boundaries, empty files, repeated backups, deduplication, snapshot diffs, restore collision handling, overwrites, corruption detection, orphan collection, vault-inside-source exclusion, and symlink escape prevention (when the OS permits symlink creation).

## Roadmap

- [x] Streaming hashing, content-addressed storage, snapshots, restore, verify, diff
- [x] Safe overwrite handling, dry-run garbage collection, CTest, cross-platform CI
- [ ] Optional zstd compression with chunk format negotiation
- [ ] Content-defined chunking for insert-heavy workflows
- [ ] Authenticated encryption and key rotation
- [ ] Checkpoint/resume, cancellation, and richer progress reporting
- [ ] Portable file metadata, symlink policies and platform-specific crash durability
- [ ] Differential benchmarking against standard backup tools

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for conventions, local validation, and suggested improvements. Bugs and code reviews are welcome.

## License

MIT — see [LICENSE](LICENSE).
