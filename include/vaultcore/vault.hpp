#pragma once

#include "vaultcore/hash.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace vaultcore {
namespace fs = std::filesystem;
inline constexpr std::size_t CHUNK_SIZE = 1024 * 1024;

struct FileRecord {
    std::string path; // UTF-8 relative path with forward slashes
    std::uint64_t size = 0;
    Digest sha256{};
    std::vector<Digest> chunks;
};
struct Snapshot {
    std::string id;
    std::string source;
    std::uint64_t created_at = 0; // UTC Unix epoch seconds
    std::vector<FileRecord> files;
};
struct BackupResult {
    Snapshot snapshot;
    std::uint64_t logical_bytes = 0;
    std::uint64_t new_bytes = 0;
    std::uint64_t reused_bytes = 0;
    std::size_t new_chunks = 0;
};
struct VerifyResult {
    std::size_t snapshots = 0;
    std::size_t files = 0;
    std::size_t unique_chunks = 0;
    std::uint64_t verified_bytes = 0;
};
struct Stats {
    std::size_t snapshots = 0;
    std::uint64_t logical_bytes = 0;
    std::size_t stored_chunks = 0;
    std::uint64_t stored_bytes = 0;
    std::size_t live_chunks = 0;
};
struct GcResult {
    std::size_t orphan_chunks = 0;
    std::uint64_t reclaimable_bytes = 0;
    std::size_t deleted_chunks = 0;
};
struct Difference {
    char kind = '?'; // '+' added, '-' deleted, '~' modified
    std::string path;
};

class Vault {
public:
    // Initializes an empty (or nonexistent) directory. Never silently replaces files.
    static void initialize(const fs::path& root);
    explicit Vault(fs::path root);
    BackupResult backup(const fs::path& source);
    std::vector<Snapshot> snapshots() const;
    Snapshot load(const std::string& id) const;
    void restore(const std::string& id, const fs::path& destination, bool overwrite = false) const;
    VerifyResult verify(const std::optional<std::string>& id = std::nullopt) const;
    Stats stats() const;
    std::vector<Difference> diff(const std::string& first, const std::string& second) const;
    void remove_snapshot(const std::string& id);
    GcResult garbage_collect(bool apply = false);

private:
    fs::path root_;
    fs::path object_path(const Digest& digest) const;
    fs::path snapshot_path(const std::string& id) const;
    Snapshot read_snapshot(const fs::path& path) const;
    void write_snapshot(const Snapshot& snapshot);
};

} // namespace vaultcore
