#include "vaultcore/vault.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <fstream>
#include <limits>
#include <map>
#include <random>
#include <set>
#include <span>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <vector>

namespace vaultcore {
namespace {
constexpr std::string_view MAGIC = "VCORE01\n";
constexpr std::string_view MARKER = "VaultCore vault format 1\n";
constexpr std::uint32_t FORMAT_VERSION = 1;
constexpr std::uint64_t MANIFEST_LIMIT = 256ULL * 1024 * 1024;
constexpr std::uint32_t FILE_LIMIT = 1'000'000;
constexpr std::uint32_t PATH_LIMIT = 16'384;

[[noreturn]] void fail(const std::string& message) { throw std::runtime_error(message); }

std::string utf8(const fs::path& path) {
    const auto chars = path.generic_u8string();
    return {reinterpret_cast<const char*>(chars.data()), chars.size()};
}
fs::path native(const std::string& value) {
    return fs::path(std::u8string(reinterpret_cast<const char8_t*>(value.data()), value.size()));
}
fs::path absolute_normal(const fs::path& path) { return fs::weakly_canonical(fs::absolute(path)); }

bool inside(const fs::path& path, const fs::path& parent) {
    auto a = path.begin();
    auto b = parent.begin();
    while (b != parent.end()) {
        if (a == path.end() || *a != *b) return false;
        ++a;
        ++b;
    }
    return true;
}

bool valid_id(std::string_view id) {
    if (id.empty() || id.size() > 100) return false;
    return std::all_of(id.begin(), id.end(), [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '-';
    });
}

bool valid_relative(std::string_view path) {
    if (path.empty() || path.size() > PATH_LIMIT || path.front() == '/') return false;
    if (path.find_first_of("\\:") != std::string_view::npos || path.find('\0') != std::string_view::npos) return false;
    std::size_t start = 0;
    while (start < path.size()) {
        const std::size_t end = path.find('/', start);
        const auto part = path.substr(start, end == std::string_view::npos ? end : end - start);
        if (part.empty() || part == "." || part == ".." || part.back() == '.' || part.back() == ' ') return false;
        // Windows device names are special even with extensions.
        const auto stem = part.substr(0, part.find('.'));
        std::string upper(stem);
        std::transform(upper.begin(), upper.end(), upper.begin(), [](unsigned char c) { return char(std::toupper(c)); });
        if (upper == "CON" || upper == "PRN" || upper == "AUX" || upper == "NUL" ||
            (upper.size() == 4 && (upper.starts_with("COM") || upper.starts_with("LPT")) && upper[3] >= '1' && upper[3] <= '9')) return false;
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    return path.back() != '/';
}

std::string unique_id() {
    const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::random_device device;
    const std::uint64_t random = (std::uint64_t(device()) << 32) | device();
    constexpr char digits[] = "0123456789abcdef";
    std::string suffix(16, '0');
    for (unsigned i = 0; i < 16; ++i) suffix[15 - i] = digits[(random >> (i*4)) & 15];
    return std::to_string(now) + "-" + suffix;
}

bool exists_no_follow(const fs::path& path) {
    std::error_code ec;
    const auto status = fs::symlink_status(path, ec);
    if (ec == std::errc::no_such_file_or_directory) return false;
    if (ec) throw fs::filesystem_error("Cannot inspect path", path, ec);
    return fs::exists(status);
}

void require_regular(const fs::path& path) {
    const auto status = fs::symlink_status(path);
    if (!fs::is_regular_file(status)) fail("Not a regular file (or is a symlink): " + utf8(path));
}

class Guard {
public:
    explicit Guard(const fs::path& root) : lock_(root / ".lock") {
        std::error_code ec;
        if (!fs::create_directory(lock_, ec)) {
            if (ec) throw fs::filesystem_error("Cannot acquire vault lock", lock_, ec);
            fail("Vault is locked. If a previous process crashed, check that no operation is running, then remove .lock manually.");
        }
    }
    Guard(const Guard&) = delete;
    Guard& operator=(const Guard&) = delete;
    ~Guard() { std::error_code ec; fs::remove(lock_, ec); }
private:
    fs::path lock_;
};

class Cleanup {
public:
    explicit Cleanup(fs::path path) : path_(std::move(path)) {}
    Cleanup(const Cleanup&) = delete;
    Cleanup& operator=(const Cleanup&) = delete;
    ~Cleanup() { std::error_code ec; fs::remove(path_, ec); }
private:
    fs::path path_;
};

void put_u32(std::vector<std::uint8_t>& b, std::uint32_t x) {
    for (unsigned i=0; i<4; ++i) b.push_back(std::uint8_t(x >> (i*8)));
}
void put_u64(std::vector<std::uint8_t>& b, std::uint64_t x) {
    for (unsigned i=0; i<8; ++i) b.push_back(std::uint8_t(x >> (i*8)));
}
void put_string(std::vector<std::uint8_t>& b, const std::string& text) {
    if (text.size() > PATH_LIMIT) fail("Manifest string too long");
    put_u32(b, static_cast<std::uint32_t>(text.size()));
    b.insert(b.end(), text.begin(), text.end());
}
void put_digest(std::vector<std::uint8_t>& b, const Digest& hash) { b.insert(b.end(), hash.begin(), hash.end()); }

class Reader {
public:
    explicit Reader(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}
    std::span<const std::uint8_t> take(std::size_t count) {
        if (count > bytes_.size() - index_) fail("Truncated snapshot manifest");
        auto part = bytes_.subspan(index_, count);
        index_ += count;
        return part;
    }
    std::uint32_t u32() {
        auto b = take(4);
        std::uint32_t x = 0;
        for (unsigned i=0; i<4; ++i) x |= std::uint32_t(b[i]) << (8*i);
        return x;
    }
    std::uint64_t u64() {
        auto b = take(8);
        std::uint64_t x = 0;
        for (unsigned i=0; i<8; ++i) x |= std::uint64_t(b[i]) << (8*i);
        return x;
    }
    std::string str() {
        const auto len = u32();
        if (len > PATH_LIMIT) fail("Oversized manifest string");
        auto b = take(len);
        return {reinterpret_cast<const char*>(b.data()), b.size()};
    }
    Digest digest() {
        Digest result{};
        auto b = take(32);
        std::copy(b.begin(), b.end(), result.begin());
        return result;
    }
    bool at_end() const { return index_ == bytes_.size(); }
private:
    std::span<const std::uint8_t> bytes_;
    std::size_t index_ = 0;
};

std::vector<std::uint8_t> read_bytes(const fs::path& path, std::size_t limit) {
    require_regular(path);
    const auto size = fs::file_size(path);
    if (size > limit) fail("File exceeds supported size: " + utf8(path));
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    std::ifstream in(path, std::ios::binary);
    if (!in) fail("Cannot open " + utf8(path));
    if (!bytes.empty()) in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!in || static_cast<std::size_t>(in.gcount()) != bytes.size()) {
        if (!bytes.empty()) fail("Cannot fully read " + utf8(path));
    }
    return bytes;
}

void write_atomic(const fs::path& path, std::span<const std::uint8_t> bytes) {
    fs::create_directories(path.parent_path());
    if (exists_no_follow(path)) fail("Refusing to replace existing file: " + utf8(path));
    const fs::path temp = path.parent_path() / (".vaultcore-" + unique_id() + ".tmp");
    Cleanup cleanup(temp);
    {
        std::ofstream out(temp, std::ios::binary | std::ios::trunc);
        if (!out) fail("Cannot create " + utf8(temp));
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        out.flush();
        if (!out) fail("Cannot write " + utf8(temp));
        out.close();
        if (!out) fail("Cannot close " + utf8(temp));
    }
    fs::rename(temp, path); // Same-directory rename; no in-place partial manifest.
}

void check_safe_directory(const fs::path& path) {
    if (!exists_no_follow(path)) { fs::create_directory(path); return; }
    if (!fs::is_directory(fs::symlink_status(path))) fail("Unsafe target directory (symlink or file): " + utf8(path));
}

void prepare_parent(const fs::path& destination, const std::string& relative) {
    check_safe_directory(destination);
    const fs::path rel = native(relative);
    fs::path current = destination;
    for (auto it = rel.begin(); it != rel.end(); ++it) {
        auto next = it;
        ++next;
        if (next == rel.end()) break;
        current /= *it;
        check_safe_directory(current);
    }
}

void verify_chunk(const fs::path& object, const Digest& expected) {
    const auto data = read_bytes(object, CHUNK_SIZE);
    if (sha256(data) != expected) fail("Corrupted chunk: " + utf8(object));
}

} // namespace

void Vault::initialize(const fs::path& root) {
    const auto path = absolute_normal(root);
    if (exists_no_follow(path)) {
        if (!fs::is_directory(fs::symlink_status(path))) fail("Vault path is not a directory");
        if (fs::directory_iterator(path) != fs::directory_iterator{}) fail("Vault directory must be empty");
    }
    fs::create_directories(path);
    fs::create_directories(path / "objects");
    fs::create_directories(path / "snapshots");
    const auto bytes = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(MARKER.data()), MARKER.size());
    write_atomic(path / "vault.meta", bytes);
}

Vault::Vault(fs::path root) : root_(absolute_normal(root)) {
    const auto marker = read_bytes(root_ / "vault.meta", 1024);
    if (std::string(marker.begin(), marker.end()) != MARKER) fail("Not a supported VaultCore vault: " + utf8(root_));
    if (!fs::is_directory(root_ / "objects") || !fs::is_directory(root_ / "snapshots")) fail("Incomplete vault directory");
}

fs::path Vault::object_path(const Digest& digest) const {
    const auto hex = to_hex(digest);
    return root_ / "objects" / hex.substr(0,2) / hex;
}
fs::path Vault::snapshot_path(const std::string& id) const {
    if (!valid_id(id)) fail("Invalid snapshot ID");
    return root_ / "snapshots" / (id + ".vcs");
}

void Vault::write_snapshot(const Snapshot& snap) {
    if (!valid_id(snap.id) || snap.files.size() > FILE_LIMIT) fail("Invalid snapshot metadata");
    std::vector<std::uint8_t> b;
    b.reserve(4096);
    b.insert(b.end(), MAGIC.begin(), MAGIC.end());
    put_u32(b, FORMAT_VERSION);
    put_string(b, snap.id);
    put_string(b, snap.source);
    put_u64(b, snap.created_at);
    put_u32(b, static_cast<std::uint32_t>(snap.files.size()));
    for (const auto& file : snap.files) {
        if (!valid_relative(file.path)) fail("Unsafe path in snapshot: " + file.path);
        if (file.chunks.size() != file.size / CHUNK_SIZE + (file.size % CHUNK_SIZE != 0)) fail("Inconsistent chunk count");
        if (file.chunks.size() > UINT32_MAX) fail("File has too many chunks");
        put_string(b, file.path);
        put_u64(b, file.size);
        put_digest(b, file.sha256);
        put_u32(b, static_cast<std::uint32_t>(file.chunks.size()));
        for (const auto& chunk : file.chunks) put_digest(b, chunk);
        if (b.size() > MANIFEST_LIMIT - 32) fail("Snapshot manifest too large");
    }
    const auto checksum = sha256(b);
    put_digest(b, checksum);
    write_atomic(snapshot_path(snap.id), b);
}

Snapshot Vault::read_snapshot(const fs::path& path) const {
    const auto bytes = read_bytes(path, MANIFEST_LIMIT);
    if (bytes.size() < MAGIC.size() + 4 + 32) fail("Manifest too small: " + utf8(path));
    const auto payload = std::span<const std::uint8_t>(bytes.data(), bytes.size() - 32);
    Digest footer{};
    std::copy(bytes.end() - 32, bytes.end(), footer.begin());
    if (sha256(payload) != footer) fail("Manifest checksum failed: " + utf8(path));
    Reader reader(payload);
    const auto magic = reader.take(MAGIC.size());
    if (!std::equal(magic.begin(), magic.end(), MAGIC.begin())) fail("Unsupported manifest magic");
    if (reader.u32() != FORMAT_VERSION) fail("Unsupported manifest version");
    Snapshot snap;
    snap.id = reader.str();
    snap.source = reader.str();
    snap.created_at = reader.u64();
    if (!valid_id(snap.id) || snapshot_path(snap.id).filename() != path.filename()) fail("Manifest ID mismatch");
    const auto files = reader.u32();
    if (files > FILE_LIMIT) fail("Manifest has too many files");
    snap.files.reserve(files);
    std::set<std::string> seen;
    for (std::uint32_t i=0; i<files; ++i) {
        FileRecord f;
        f.path = reader.str();
        if (!valid_relative(f.path) || !seen.insert(f.path).second) fail("Unsafe or duplicate path in manifest");
        f.size = reader.u64();
        f.sha256 = reader.digest();
        const auto count = reader.u32();
        if (f.size / CHUNK_SIZE + (f.size % CHUNK_SIZE != 0) != count) fail("Malformed chunk count in manifest");
        if (count > (MANIFEST_LIMIT / 32)) fail("Oversized chunk list");
        f.chunks.reserve(count);
        for (std::uint32_t c=0; c<count; ++c) f.chunks.push_back(reader.digest());
        snap.files.push_back(std::move(f));
    }
    if (!reader.at_end()) fail("Unexpected data in manifest");
    return snap;
}

BackupResult Vault::backup(const fs::path& source) {
    Guard lock(root_);
    const auto base = absolute_normal(source);
    if (!fs::is_directory(fs::symlink_status(base))) fail("Source must be a real directory");
    if (inside(base, root_)) fail("Cannot back up the vault itself");
    BackupResult result;
    result.snapshot.id = unique_id();
    result.snapshot.source = utf8(base);
    result.snapshot.created_at = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    std::vector<fs::path> files;
    for (fs::recursive_directory_iterator it(base), end; it != end; ++it) {
        const auto entry = it->path();
        const auto status = it->symlink_status();
        if (fs::is_symlink(status)) { it.disable_recursion_pending(); continue; }
        if (fs::is_directory(status)) {
            if (inside(absolute_normal(entry), root_)) it.disable_recursion_pending();
        } else if (fs::is_regular_file(status)) {
            if (!inside(absolute_normal(entry), root_)) files.push_back(entry);
        }
    }
    std::sort(files.begin(), files.end());
    if (files.size() > FILE_LIMIT) fail("Too many files in source");
    std::vector<std::uint8_t> buffer(CHUNK_SIZE);
    for (const auto& file : files) {
        FileRecord record;
        record.path = utf8(file.lexically_relative(base));
        if (!valid_relative(record.path)) fail("Unsupported filename: " + record.path);
        const auto expected_size = fs::file_size(file);
        std::ifstream input(file, std::ios::binary);
        if (!input) fail("Cannot open source file: " + utf8(file));
        Sha256 file_hash;
        while (true) {
            input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
            const auto n = input.gcount();
            if (input.bad()) fail("Read error: " + utf8(file));
            if (n == 0) break;
            const auto block = std::span<const std::uint8_t>(buffer.data(), static_cast<std::size_t>(n));
            file_hash.update(block);
            const auto digest = sha256(block);
            const auto location = object_path(digest);
            if (!exists_no_follow(location)) {
                write_atomic(location, block);
                ++result.new_chunks;
                result.new_bytes += block.size();
            } else {
                verify_chunk(location, digest); // Refuse to build on an already-damaged vault.
                result.reused_bytes += block.size();
            }
            record.chunks.push_back(digest);
            record.size += block.size();
            if (n != static_cast<std::streamsize>(buffer.size())) break;
        }
        if (record.size != expected_size || fs::file_size(file) != expected_size) {
            fail("Source file changed size during backup: " + utf8(file));
        }
        record.sha256 = file_hash.finish();
        result.logical_bytes += record.size;
        result.snapshot.files.push_back(std::move(record));
    }
    write_snapshot(result.snapshot); // Publish snapshot only after every object has been written.
    return result;
}

std::vector<Snapshot> Vault::snapshots() const {
    Guard lock(root_);
    std::vector<Snapshot> items;
    for (const auto& entry : fs::directory_iterator(root_ / "snapshots")) {
        if (entry.path().extension() == ".vcs") items.push_back(read_snapshot(entry.path()));
    }
    std::sort(items.begin(), items.end(), [](const Snapshot& a, const Snapshot& b) { return a.id < b.id; });
    return items;
}

Snapshot Vault::load(const std::string& id) const {
    Guard lock(root_);
    return read_snapshot(snapshot_path(id));
}

void Vault::restore(const std::string& id, const fs::path& destination, bool overwrite) const {
    Guard lock(root_);
    const auto snap = read_snapshot(snapshot_path(id));
    const auto target = fs::absolute(destination).lexically_normal();
    if (inside(absolute_normal(target), root_)) fail("Cannot restore into the vault directory");
    if (exists_no_follow(target) && !fs::is_directory(fs::symlink_status(target))) fail("Target is not a real directory");
    // Preflight destination collisions before writing any file.
    for (const auto& file : snap.files) {
        const auto dest = target / native(file.path);
        if (exists_no_follow(dest)) {
            const auto status = fs::symlink_status(dest);
            if (!fs::is_regular_file(status) || !overwrite) fail("Destination exists (use --overwrite for regular files): " + utf8(dest));
        }
        // Existing parents must not be symlinks or files.
        fs::path parent = target;
        const auto rel = native(file.path);
        for (auto it=rel.begin(); it!=rel.end(); ++it) {
            auto next=it; ++next;
            if (next==rel.end()) break;
            parent /= *it;
            if (exists_no_follow(parent) && !fs::is_directory(fs::symlink_status(parent))) fail("Unsafe destination parent: " + utf8(parent));
        }
    }
    fs::create_directories(target.parent_path());
    check_safe_directory(target);
    for (const auto& file : snap.files) {
        prepare_parent(target, file.path);
        const auto output = target / native(file.path);
        const auto temp = output.parent_path() / (".vaultcore-" + unique_id() + ".tmp");
        Cleanup cleanup(temp);
        {
            std::ofstream out(temp, std::ios::binary | std::ios::trunc);
            if (!out) fail("Cannot create restore temporary file: " + utf8(temp));
            std::uint64_t remaining = file.size;
            Sha256 file_hash;
            for (const auto& digest : file.chunks) {
                const auto block = read_bytes(object_path(digest), CHUNK_SIZE);
                const auto expected = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, CHUNK_SIZE));
                if (block.size() != expected || sha256(block) != digest) fail("Corrupt chunk while restoring " + file.path);
                out.write(reinterpret_cast<const char*>(block.data()), static_cast<std::streamsize>(block.size()));
                if (!out) fail("Failed writing restored file: " + utf8(temp));
                file_hash.update(block);
                remaining -= block.size();
            }
            if (remaining != 0 || file_hash.finish() != file.sha256) fail("Restored file integrity check failed: " + file.path);
            out.flush();
            if (!out) fail("Failed flushing restored file");
            out.close();
            if (!out) fail("Failed closing restored file");
        }
        if (exists_no_follow(output)) {
            if (!overwrite || !fs::is_regular_file(fs::symlink_status(output))) fail("Unsafe overwrite target: " + utf8(output));
            const auto previous = output.parent_path() / (".vaultcore-previous-" + unique_id());
            fs::rename(output, previous);
            try { fs::rename(temp, output); }
            catch (...) { fs::rename(previous, output); throw; }
            fs::remove(previous);
        } else {
            fs::rename(temp, output);
        }
    }
}

VerifyResult Vault::verify(const std::optional<std::string>& id) const {
    Guard lock(root_);
    VerifyResult result;
    std::vector<Snapshot> snaps;
    if (id) snaps.push_back(read_snapshot(snapshot_path(*id)));
    else {
        for (const auto& entry : fs::directory_iterator(root_ / "snapshots")) {
            if (entry.path().extension() == ".vcs") snaps.push_back(read_snapshot(entry.path()));
        }
    }
    std::unordered_set<std::string> seen;
    for (const auto& snap : snaps) {
        ++result.snapshots;
        for (const auto& file : snap.files) {
            ++result.files;
            Sha256 file_hash;
            std::uint64_t remaining = file.size;
            for (const auto& chunk : file.chunks) {
                const auto b = read_bytes(object_path(chunk), CHUNK_SIZE);
                const auto expected = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, CHUNK_SIZE));
                if (b.size() != expected || sha256(b) != chunk) fail("Corrupt object: " + to_hex(chunk));
                file_hash.update(b);
                remaining -= b.size();
                if (seen.insert(to_hex(chunk)).second) {
                    ++result.unique_chunks;
                    result.verified_bytes += b.size();
                }
            }
            if (remaining != 0 || file_hash.finish() != file.sha256) fail("File checksum mismatch: " + file.path);
        }
    }
    return result;
}

Stats Vault::stats() const {
    Guard lock(root_);
    Stats result;
    std::unordered_set<std::string> live;
    for (const auto& entry : fs::directory_iterator(root_ / "snapshots")) {
        if (entry.path().extension() != ".vcs") continue;
        const auto snap = read_snapshot(entry.path());
        ++result.snapshots;
        for (const auto& file : snap.files) {
            result.logical_bytes += file.size;
            for (const auto& chunk : file.chunks) live.insert(to_hex(chunk));
        }
    }
    result.live_chunks = live.size();
    for (const auto& dir : fs::directory_iterator(root_ / "objects")) {
        if (!dir.is_directory() || dir.is_symlink()) continue;
        for (const auto& entry : fs::directory_iterator(dir.path())) {
            if (!entry.is_regular_file() || entry.is_symlink()) continue;
            ++result.stored_chunks;
            result.stored_bytes += entry.file_size();
        }
    }
    return result;
}

std::vector<Difference> Vault::diff(const std::string& first, const std::string& second) const {
    Guard lock(root_);
    const auto a = read_snapshot(snapshot_path(first));
    const auto b = read_snapshot(snapshot_path(second));
    std::map<std::string, Digest> old_files;
    std::map<std::string, Digest> new_files;
    for (const auto& f : a.files) old_files[f.path] = f.sha256;
    for (const auto& f : b.files) new_files[f.path] = f.sha256;
    std::vector<Difference> out;
    for (const auto& [path, hash] : new_files) {
        const auto it = old_files.find(path);
        if (it == old_files.end()) out.push_back({'+', path});
        else if (it->second != hash) out.push_back({'~', path});
    }
    for (const auto& [path, hash] : old_files) {
        if (!new_files.contains(path)) out.push_back({'-', path});
    }
    std::sort(out.begin(), out.end(), [](const Difference& x, const Difference& y) { return x.path < y.path; });
    return out;
}

void Vault::remove_snapshot(const std::string& id) {
    Guard lock(root_);
    const auto path = snapshot_path(id);
    (void)read_snapshot(path);
    if (!fs::remove(path)) fail("Could not remove snapshot");
}

GcResult Vault::garbage_collect(bool apply) {
    Guard lock(root_);
    std::unordered_set<std::string> live;
    for (const auto& entry : fs::directory_iterator(root_ / "snapshots")) {
        if (entry.path().extension() != ".vcs") continue;
        const auto snap = read_snapshot(entry.path());
        for (const auto& file : snap.files) {
            for (const auto& hash : file.chunks) live.insert(to_hex(hash));
        }
    }
    GcResult result;
    for (const auto& dir : fs::directory_iterator(root_ / "objects")) {
        if (!dir.is_directory() || dir.is_symlink()) continue;
        for (const auto& entry : fs::directory_iterator(dir.path())) {
            if (!entry.is_regular_file() || entry.is_symlink()) continue;
            const auto name = entry.path().filename().string();
            if (name.size() != 64 || name.substr(0, 2) != dir.path().filename().string() ||
                !std::all_of(name.begin(), name.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); })) continue;
            if (live.contains(name)) continue;
            ++result.orphan_chunks;
            result.reclaimable_bytes += entry.file_size();
            if (apply && fs::remove(entry.path())) ++result.deleted_chunks;
        }
    }
    return result;
}
} // namespace vaultcore
