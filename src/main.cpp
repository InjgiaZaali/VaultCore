#include "vaultcore/vault.hpp"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {
void usage() {
    std::cout << R"(VaultCore - versioned, deduplicated local backups (C++20)

Usage:
  vaultcore init <vault>
  vaultcore backup <vault> <source-directory>
  vaultcore list <vault>
  vaultcore show <vault> <snapshot-id>
  vaultcore restore <vault> <snapshot-id> <destination> [--overwrite]
  vaultcore verify <vault> [snapshot-id]
  vaultcore diff <vault> <older-id> <newer-id>
  vaultcore stats <vault>
  vaultcore delete <vault> <snapshot-id>
  vaultcore gc <vault> [--apply]
  vaultcore help

Warnings:
  * Vaults are NOT encrypted. Use an encrypted filesystem for sensitive files.
  * Backups skip symbolic links and do not preserve ownership/permissions.
  * GC defaults to dry run; --apply permanently removes unreferenced chunks.
)";
}
std::string format_bytes(std::uint64_t bytes) {
    static constexpr const char* names[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(bytes);
    std::size_t i = 0;
    while (value >= 1024 && i < 4) { value /= 1024; ++i; }
    std::ostringstream out;
    out << std::fixed << std::setprecision(i == 0 ? 0 : 2) << value << ' ' << names[i];
    return out.str();
}
std::string format_time(std::uint64_t unix_seconds) {
    const auto time = static_cast<std::time_t>(unix_seconds);
    const auto* tm = std::gmtime(&time);
    if (!tm) return "unknown";
    std::ostringstream out;
    out << std::put_time(tm, "%Y-%m-%d %H:%M:%S UTC");
    return out.str();
}
[[noreturn]] void bad_usage(const std::string& reason) {
    throw std::invalid_argument(reason + ". Run 'vaultcore help' for syntax");
}
void require_argc(int actual, int expected) { if (actual != expected) bad_usage("Incorrect argument count"); }
} // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 1 || (argc == 2 && (std::string_view(argv[1]) == "help" || std::string_view(argv[1]) == "--help" || std::string_view(argv[1]) == "-h"))) {
            usage();
            return 0;
        }
        if (argc < 3) bad_usage("Missing vault directory");
        const std::string command = argv[1];
        if (command == "init") {
            require_argc(argc, 3);
            vaultcore::Vault::initialize(argv[2]);
            std::cout << "Initialized VaultCore vault at " << argv[2] << '\n';
            return 0;
        }
        vaultcore::Vault vault(argv[2]);
        if (command == "backup") {
            require_argc(argc, 4);
            const auto result = vault.backup(argv[3]);
            std::cout << "Snapshot: " << result.snapshot.id << '\n'
                      << "Files: " << result.snapshot.files.size() << '\n'
                      << "Logical size: " << format_bytes(result.logical_bytes) << '\n'
                      << "Newly stored: " << format_bytes(result.new_bytes) << " (" << result.new_chunks << " chunks)\n"
                      << "Reused data: " << format_bytes(result.reused_bytes) << '\n';
        } else if (command == "list") {
            require_argc(argc, 3);
            const auto snapshots = vault.snapshots();
            if (snapshots.empty()) std::cout << "No snapshots yet.\n";
            for (const auto& s : snapshots) {
                std::cout << s.id << "  " << format_time(s.created_at) << "  " << s.files.size() << " files  " << s.source << '\n';
            }
        } else if (command == "show") {
            require_argc(argc, 4);
            const auto s = vault.load(argv[3]);
            std::cout << "Snapshot: " << s.id << "\nCreated: " << format_time(s.created_at)
                      << "\nSource: " << s.source << "\nFiles: " << s.files.size() << "\n";
            for (const auto& file : s.files) {
                std::cout << "  " << format_bytes(file.size) << "  " << file.path << "  " << vaultcore::to_hex(file.sha256) << '\n';
            }
        } else if (command == "restore") {
            if (argc != 5 && argc != 6) bad_usage("restore needs snapshot and destination");
            const bool overwrite = argc == 6 && std::string_view(argv[5]) == "--overwrite";
            if (argc == 6 && !overwrite) bad_usage("Unknown restore option");
            vault.restore(argv[3], argv[4], overwrite);
            std::cout << "Restored snapshot " << argv[3] << " into " << argv[4] << '\n';
        } else if (command == "verify") {
            if (argc != 3 && argc != 4) bad_usage("verify accepts at most one snapshot ID");
            const auto result = vault.verify(argc == 4 ? std::optional<std::string>(argv[3]) : std::nullopt);
            std::cout << "OK: " << result.snapshots << " snapshots, " << result.files << " files, "
                      << result.unique_chunks << " unique chunks (" << format_bytes(result.verified_bytes) << ") verified.\n";
        } else if (command == "diff") {
            require_argc(argc, 5);
            const auto changes = vault.diff(argv[3], argv[4]);
            for (const auto& change : changes) std::cout << change.kind << " " << change.path << '\n';
            std::cout << changes.size() << " changed paths.\n";
        } else if (command == "stats") {
            require_argc(argc, 3);
            const auto s = vault.stats();
            std::cout << "Snapshots: " << s.snapshots << "\nLogical bytes across snapshots: " << format_bytes(s.logical_bytes)
                      << "\nStored objects: " << s.stored_chunks << " (" << format_bytes(s.stored_bytes) << ")"
                      << "\nReferenced objects: " << s.live_chunks << '\n';
            if (s.stored_bytes) std::cout << "Logical / physical ratio: "
                                          << std::fixed << std::setprecision(2)
                                          << static_cast<double>(s.logical_bytes) / static_cast<double>(s.stored_bytes) << "x\n";
        } else if (command == "delete") {
            require_argc(argc, 4);
            vault.remove_snapshot(argv[3]);
            std::cout << "Deleted snapshot " << argv[3] << ". Run 'gc' to inspect reclaimable objects.\n";
        } else if (command == "gc") {
            if (argc != 3 && argc != 4) bad_usage("gc accepts optional --apply");
            const bool apply = argc == 4 && std::string_view(argv[3]) == "--apply";
            if (argc == 4 && !apply) bad_usage("Unknown gc option");
            const auto result = vault.garbage_collect(apply);
            std::cout << "Orphaned chunks: " << result.orphan_chunks << "\nReclaimable: " << format_bytes(result.reclaimable_bytes) << '\n';
            if (apply) std::cout << "Deleted chunks: " << result.deleted_chunks << '\n';
            else std::cout << "Dry run: no files removed. Use --apply to delete orphaned chunks.\n";
        } else {
            bad_usage("Unknown command '" + command + "'");
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "vaultcore: " << error.what() << '\n';
        return 1;
    }
}
