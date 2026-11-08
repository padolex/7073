#include "util.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <fstream>
#include <stdexcept>

namespace bibifi {

std::string toHex(const unsigned char* data, std::size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0F]);
    }
    return out;
}

static int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::optional<Bytes> fromHex(const std::string& s) {
    if (s.size() % 2 != 0) return std::nullopt;
    Bytes out(s.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        int hi = hexVal(s[2 * i]);
        int lo = hexVal(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return out;
}

bool isLowerHex(const std::string& s, std::size_t len) {
    if (s.size() != len) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

Bytes randomBytes(std::size_t n) {
    Bytes out(n);
    if (n > 0 && RAND_bytes(out.data(), static_cast<int>(n)) != 1) {
        throw std::runtime_error("random number generator failure");
    }
    return out;
}

std::string randomHex(std::size_t nBytes) { return toHex(randomBytes(nBytes)); }

std::optional<Bytes> readFile(const fs::path& p, bool followSymlinks, std::uintmax_t maxSize) {
    std::error_code ec;
    fs::file_status st = followSymlinks ? fs::status(p, ec) : fs::symlink_status(p, ec);
    if (ec || !fs::is_regular_file(st)) return std::nullopt;
    std::uintmax_t size = fs::file_size(p, ec);
    if (ec || size > maxSize) return std::nullopt;
    std::ifstream in(p, std::ios::binary);
    if (!in) return std::nullopt;
    Bytes buf(static_cast<std::size_t>(size));
    if (size > 0 && !in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(size))) {
        return std::nullopt;
    }
    return buf;
}

namespace {

// Writes `data` to `tmp` and closes it; throws on any failure.
void writeAll(const fs::path& tmp, const Bytes& data) {
    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("cannot create file");
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    out.flush();
    const bool ok = static_cast<bool>(out);
    out.close();
    if (!ok) throw std::runtime_error("cannot write file");
}

constexpr fs::perms kOwnerOnlyDir = fs::perms::owner_all;
constexpr fs::perms kOwnerOnlyFile = fs::perms::owner_read | fs::perms::owner_write;

}  // namespace

void writeFileAtomic(const fs::path& p, const Bytes& data, bool secret) {
    std::error_code ec;
    if (!secret) {
        fs::path tmp = p;
        tmp += ".tmp-" + randomHex(8);
        try {
            writeAll(tmp, data);
        } catch (...) {
            fs::remove(tmp, ec);
            throw;
        }
        fs::rename(tmp, p, ec);  // atomic replace; replaces a symlink, never follows it
        if (ec) {
            fs::remove(tmp, ec);
            throw std::runtime_error("cannot commit file");
        }
        return;
    }

    // Secret files (keyfiles) must never be readable by anyone else, not even
    // for an instant. Standard C++ cannot create a file with restricted
    // permissions (there is no umask), so the file is staged inside a fresh
    // directory that is made owner-only BEFORE anything is created in it.
    // Directory permissions are checked on every path lookup, so nobody else
    // can open the staged file, even with a handle to the directory taken
    // earlier. The finished file is made 0600 and then renamed into place.
    const fs::path stage = p.parent_path() / (".stage-" + randomHex(16));
    if (!fs::create_directory(stage, ec) || ec) throw std::runtime_error("cannot create staging directory");
    try {
        fs::permissions(stage, kOwnerOnlyDir, fs::perm_options::replace, ec);
        // Until the line above ran, the directory had default permissions.
        // Refuse to continue if anything appeared in it meanwhile.
        if (ec || fs::status(stage).permissions() != kOwnerOnlyDir || !fs::is_empty(stage)) {
            throw std::runtime_error("staging directory is not private");
        }
        const fs::path tmp = stage / randomHex(16);
        writeAll(tmp, data);
        fs::permissions(tmp, kOwnerOnlyFile, fs::perm_options::replace, ec);
        if (ec || fs::status(tmp).permissions() != kOwnerOnlyFile) throw std::runtime_error("cannot restrict file");
        fs::rename(tmp, p, ec);  // same directory tree, so rename is atomic
        if (ec) throw std::runtime_error("cannot commit file");
    } catch (...) {
        fs::remove_all(stage, ec);
        throw;
    }
    fs::remove(stage, ec);
}

Bytes toBytes(const std::string& s) { return Bytes(s.begin(), s.end()); }
std::string toString(const Bytes& b) { return std::string(b.begin(), b.end()); }

void wipe(Bytes& b) {
    if (!b.empty()) OPENSSL_cleanse(b.data(), b.size());
    b.clear();
}
void wipe(std::string& s) {
    if (!s.empty()) OPENSSL_cleanse(&s[0], s.size());
    s.clear();
}

bool isPrintableAscii(const std::string& s) {
    for (unsigned char c : s) {
        if (c < 0x20 || c > 0x7E) return false;
    }
    return true;
}

std::vector<std::string> splitPath(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == '/') {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

std::vector<std::string> splitLines(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == '\n') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

std::string joinPath(const std::vector<std::string>& comps, std::size_t from) {
    std::string out;
    for (std::size_t i = from; i < comps.size(); ++i) {
        if (i > from) out.push_back('/');
        out += comps[i];
    }
    return out;
}

}  // namespace bibifi
