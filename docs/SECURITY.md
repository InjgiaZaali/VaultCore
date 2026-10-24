# Security, safety, and limitations

VaultCore v0.1 is an educational, **local** backup engine. Please read these limitations before using it on valuable files.

## Threat assumptions

- The backup source and vault are on storage controlled by the local user. A malicious local process modifying files during operation is **out of scope**.
- SHA-256 detects accidental corruption and mismatched content; it is **not an authentication mechanism**. An attacker who can rewrite both the manifest and its checksum can forge a valid manifest.
- Vaults are **not encrypted**. Original data, source paths, filenames and history may be readable to anybody with filesystem access. Put sensitive vaults on an encrypted volume.
- VaultCore is not a backup consistency layer: files changing while read may generate inconsistent snapshots, even when the beginning and ending sizes are the same. For databases or VMs, snapshot/quiesce at the source first.

## Restore path safety

- Manifest paths must be relative, slash-delimited and contain no `.`/`..` segments, Windows drive separators, or ambiguous Windows device names.
- Existing symlinks along the destination's generated relative path are rejected; existing destination files are protected unless `--overwrite` is specified.
- Source symlinks are not followed; directory ownership, permissions, timestamps and symlink identities are not saved.
- There is no openat-style race-resistant directory traversal: a hostile process racing symlink changes against restore is not prevented on every platform. Do not restore into directories other processes can mutate maliciously.
- Cross-platform filename semantics are not identical. Invalid/reserved Windows names are rejected consistently; macOS normalization and Windows case-folding may still lead to filename collisions when moving vaults across machines.
- No disk quota, free-space reservation, or multi-file transactional restore currently exists. A power failure or full disk can leave temporary or partially restored files.

## Vault consistency

- A directory `.lock` prevents cooperating VaultCore commands from operating at once. A crash may leave a stale lock; **only remove it after confirming no VaultCore process is running**.
- Chunks and manifests are written via temporary files then renamed; calls do not explicitly fsync directories or file contents. Crash/power-loss durability is not guaranteed.
- A failed backup may leave orphan chunks; run `gc` to preview and `gc --apply` to reclaim them. Garbage collection is permanent.
- Any direct edit to `objects/`, `snapshots/` or `vault.meta` can permanently damage the vault.
- The storage layout and CLI are an evolving v0.1 format and may change between releases.

## Responsible workflow

1. Maintain at least one independent backup separate from a VaultCore vault.
2. Periodically run `vaultcore verify <vault>` and test-restore into a new directory.
3. Store vaults on a volume with appropriate access controls and ideally full-disk encryption.
4. Use `gc` dry-run before `gc --apply` and never run it while manually editing the vault.
5. Report security bugs privately to the repository owner before public disclosure.
