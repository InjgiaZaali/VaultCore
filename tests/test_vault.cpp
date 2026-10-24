#include "vaultcore/vault.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;
using namespace vaultcore;

namespace {
struct Temp {
    fs::path path;
    Temp() {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        path = fs::temp_directory_path() / ("vaultcore-test-" + std::to_string(stamp));
        fs::create_directories(path);
    }
    ~Temp() { std::error_code ec; fs::remove_all(path, ec); }
};
void check(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}
void throws(const std::function<void()>& action, std::string_view message) {
    try { action(); }
    catch (const std::exception&) { return; }
    throw std::runtime_error(std::string(message));
}
void write_text(const fs::path& p, const std::string& content) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!out) throw std::runtime_error("Test setup write failed");
}
std::string read_text(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}
void test_sha256() {
    check(to_hex(sha256("")) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256 empty vector");
    check(to_hex(sha256("abc")) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 abc vector");
    check(to_hex(sha256(std::string(1'000'000, 'a'))) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "SHA-256 million a vector");
    Sha256 streaming;
    streaming.update(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>("a"), 1));
    streaming.update(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>("bc"), 2));
    check(streaming.finish() == sha256("abc"), "Streaming SHA-256");
    check(from_hex(to_hex(sha256("hi"))) == sha256("hi"), "Digest hex roundtrip");
    throws([] { (void)from_hex("abcd"); }, "Reject short digest");
}
void test_cycle() {
    Temp temp;
    const auto vaultpath = temp.path / "backup-vault";
    const auto src = temp.path / "university";
    write_text(src / "src" / "main.cpp", "int main() { return 0; }\n");
    write_text(src / "empty.txt", "");
    write_text(src / "my notes.txt", "first version");
    const auto one_meg = std::string(CHUNK_SIZE, 'Q');
    write_text(src / "large.bin", one_meg + "tail");
    Vault::initialize(vaultpath);
    throws([&] { Vault::initialize(vaultpath); }, "Initialization refuses existing data");
    Vault v(vaultpath);
    const auto first = v.backup(src);
    check(first.snapshot.files.size() == 4, "First snapshot file count");
    check(first.new_chunks > 0, "First backup creates chunks");
    check(v.verify().files == 4, "Verify first snapshot");
    const auto repeated = v.backup(src);
    check(repeated.new_bytes == 0, "Identical backup is fully deduplicated");
    check(repeated.reused_bytes == repeated.logical_bytes, "Reuse count matches size");
    check(v.snapshots().size() == 2, "Two snapshots listed");
    const auto original_bytes = read_text(src / "large.bin");
    write_text(src / "my notes.txt", "edited notes");
    fs::remove(src / "src" / "main.cpp");
    write_text(src / "new.txt", "new content");
    const auto third = v.backup(src);
    check(third.snapshot.files.size() == 4, "Third snapshot file count");
    const auto changes = v.diff(first.snapshot.id, third.snapshot.id);
    check(changes.size() == 3, "Diff detects add/update/delete");
    check(std::any_of(changes.begin(), changes.end(), [](const auto& c) { return c.kind == '+' && c.path == "new.txt"; }), "Diff add");
    check(std::any_of(changes.begin(), changes.end(), [](const auto& c) { return c.kind == '~' && c.path == "my notes.txt"; }), "Diff modification");
    check(std::any_of(changes.begin(), changes.end(), [](const auto& c) { return c.kind == '-' && c.path == "src/main.cpp"; }), "Diff deletion");
    const auto destination = temp.path / "recovered";
    v.restore(first.snapshot.id, destination);
    check(read_text(destination / "large.bin") == original_bytes, "Large file roundtrip");
    check(read_text(destination / "my notes.txt") == "first version", "Original version restored");
    check(fs::file_size(destination / "empty.txt") == 0, "Empty file restored");
    throws([&] { v.restore(first.snapshot.id, destination); }, "Restore refuses to overwrite");
    v.restore(third.snapshot.id, destination, true);
    check(read_text(destination / "my notes.txt") == "edited notes", "Overwrite restores newer version");
    check(read_text(destination / "new.txt") == "new content", "New file restored");
    check(v.stats().snapshots == 3, "Stats snapshot count");
    check(v.verify(third.snapshot.id).files == 4, "Single-snapshot verification");
    v.remove_snapshot(first.snapshot.id);
    v.remove_snapshot(repeated.snapshot.id);
    check(v.snapshots().size() == 1, "Deletion keeps latest snapshot");
    const auto preview = v.garbage_collect();
    check(preview.orphan_chunks > 0, "GC discovers old unreachable chunks");
    check(v.garbage_collect(true).deleted_chunks == preview.orphan_chunks, "GC deletes orphans");
    check(v.garbage_collect().orphan_chunks == 0, "GC idempotent");
    check(v.verify().files == 4, "Verify after GC");
}
void test_corruption() {
    Temp temp;
    Vault::initialize(temp.path / "vault");
    write_text(temp.path / "data" / "a.txt", "original");
    Vault vault(temp.path / "vault");
    const auto snap = vault.backup(temp.path / "data").snapshot;
    const auto chunk = to_hex(snap.files.front().chunks.front());
    const auto object = temp.path / "vault" / "objects" / chunk.substr(0,2) / chunk;
    write_text(object, "tampered");
    throws([&] { (void)vault.verify(); }, "Detect corrupted chunk");
    throws([&] { vault.restore(snap.id, temp.path / "recover"); }, "Restore must reject corruption");
    throws([&] { (void)vault.backup(temp.path / "data"); }, "Backup must reject corruption");
    write_text(temp.path / "vault" / "snapshots" / (snap.id + ".vcs"), "bad manifest");
    throws([&] { (void)vault.load(snap.id); }, "Detect corrupted manifest");
}
void test_vault_nested_in_source() {
    Temp temp;
    const auto src = temp.path / "data";
    write_text(src / "file.txt", "data");
    Vault::initialize(src / "vault");
    Vault vault(src / "vault");
    check(vault.backup(src).snapshot.files.size() == 1, "Vault nested in source is excluded");
    throws([&] { (void)vault.backup(src / "vault"); }, "Cannot back up vault itself");
    throws([&] { vault.restore(vault.snapshots().front().id, src / "vault" / "elsewhere"); }, "Cannot restore inside vault");
}
void test_symlink_restore() {
    Temp temp;
    const auto src = temp.path / "files";
    write_text(src / "nested" / "file.txt", "safe");
    Vault::initialize(temp.path / "vault");
    Vault v(temp.path / "vault");
    const auto snap = v.backup(src);
    const auto dest = temp.path / "output";
    fs::create_directories(dest);
    const auto redirected = temp.path / "redirected";
    fs::create_directories(redirected);
    std::error_code ec;
    fs::create_directory_symlink(redirected, dest / "nested", ec);
    if (!ec) {
        throws([&] { v.restore(snap.snapshot.id, dest); }, "Reject symlink parent");
        check(!fs::exists(redirected / "file.txt"), "No file written via symlink");
    }
}
} // namespace

int main() {
    const std::vector<std::pair<std::string_view, std::function<void()>>> tests = {
        {"SHA-256 test vectors", test_sha256},
        {"Backup / dedup / diff / restore / GC", test_cycle},
        {"Corruption detection", test_corruption},
        {"Nested vault exclusion", test_vault_nested_in_source},
        {"Symlink restore safety", test_symlink_restore}
    };
    std::size_t passed = 0;
    for (const auto& [name, test] : tests) {
        try { test(); ++passed; std::cout << "[PASS] " << name << '\n'; }
        catch (const std::exception& e) { std::cerr << "[FAIL] " << name << ": " << e.what() << '\n'; return 1; }
    }
    std::cout << "All " << passed << " tests passed.\n";
    return 0;
}
