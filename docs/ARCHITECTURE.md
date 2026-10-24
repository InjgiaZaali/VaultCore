# Architecture and invariants

## Components

1. `vaultcore::Sha256` is a streaming FIPS 180-4 SHA-256 implementation with published test vectors.
2. `Vault` owns the vault format, snapshot orchestration, chunk store, and verification/restore operations.
3. The `vaultcore` CLI is a thin adapter over the library, with exceptions mapped to nonzero exit codes.
4. Tests use isolated temporary directories; CI exercises the project on three operating systems.

## On-disk layout

```text
vault/
  vault.meta                        format marker
  objects/
    ab/
      ab0123...(64 lowercase hex)    raw bytes of one <= 1 MiB SHA-256 chunk
  snapshots/
    17...-hex.vcs                    one immutable snapshot manifest
  .lock/                             transient exclusive operation lock
```

## Manifest format (v1)

Binary values are **little-endian**, strings are 32-bit length-prefixed UTF-8 byte sequences, and hashes are 32 raw bytes. No native struct-layout serialization is used.

| Field | Representation |
|---|---|
| Magic | 8 ASCII bytes: `VCORE01\n` |
| Version | `uint32`, currently 1 |
| Snapshot ID | length-prefixed string |
| Source directory | length-prefixed UTF-8 string |
| Creation timestamp | `uint64` Unix seconds (UTC) |
| File count | `uint32` |
| Each file | path string; `uint64` size; 32-byte whole-file digest; `uint32` chunk count; N chunk digests |
| Trailer | SHA-256 of every preceding manifest byte (32 bytes) |

The reader caps manifest size at 256 MiB and validates the magic, version, checksum, paths, counts, and duplicate filenames before using the data. The writer publishes manifests **after** all referenced chunks are stored, via same-directory temporary-file rename.

## Backup lifecycle

1. Acquire `.lock` directory; refuse concurrent operations.
2. Resolve source directory, walk regular files recursively, skip symlinks and exclude the vault if nested in the source.
3. Stream file content in 1 MiB units; update a whole-file hash as chunks are read.
4. For each chunk, derive its SHA-256 content key. Store new chunks via temporary file + rename; re-verify existing objects before reuse.
5. After all files and sizes have been checked, write the checksummed manifest to a temporary file then rename it to final name.
6. Release `.lock`.

A failed backup can leave unreachable chunks, but **must not** publish a manifest referencing partially written chunks; `gc --apply` can later reclaim them. This is logical atomicity, not a guarantee of durability against power loss.

## Restore lifecycle

1. Acquire lock, validate manifest checksum and all filenames.
2. Preflight every output path: no pre-existing file clobber without `--overwrite`, no symlinked intermediate destination directories.
3. Stream each chunk into a temporary output file while verifying each chunk and the reconstructed whole-file SHA-256.
4. Only after hash validation rename the file into place. With `--overwrite`, move a regular existing file aside first and restore it if the new-file rename fails.
5. Release lock. Files already restored before a later failure are not rolled back (per-file safety, **not transactional multi-file restore**).

## Garbage collection

Mark referenced digest keys by reading all valid manifests; scan object fanout directories for known-format keys; count orphaned objects; delete only with explicit `--apply`. Snapshot removal does **not** delete shared objects. GC and restore hold the same exclusive lock.

## Complexity and performance

- Backup time: **O(bytes read + existing bytes rehashed + files sorted)**. Memory: O(chunk size + total manifest metadata).
- Verify time: O(sum of bytes referenced in the selected snapshot(s)); duplicate referenced chunks may be read again to validate full-file hashes.
- Restore time: O(snapshot bytes); memory: O(1 MiB chunk plus metadata).
- Fixed chunk size: 1 MiB, a deliberate simplicity/performance tradeoff; a future release could implement content-defined chunking.

## Format compatibility

Only manifest version 1 is currently supported. Future breaking changes require a version bump and a defined migration path; no backward/forward compatibility is claimed before implementation.
