// util.h - small, dependency-free helpers (hex, safe file I/O, parsing).
#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace bibifi {

namespace fs = std::filesystem;
using Bytes = std::vector<unsigned char>;

// Hard upper bounds used to stop resource-exhaustion via oversized on-disk
// objects or input lines.
constexpr std::uintmax_t kMaxObjectSize = 64ull * 1024 * 1024;  // 64 MiB
constexpr std::size_t kMaxLineLength = 1024 * 1024;             // 1 MiB
constexpr std::size_t kMaxNameLength = 255;

std::string toHex(const unsigned char* data, std::size_t len);
inline std::string toHex(const Bytes& b) { return toHex(b.data(), b.size()); }
std::optional<Bytes> fromHex(const std::string& s);
// True iff s is exactly `len` lowercase hex characters. Used to validate every
// identifier that ends up in an on-disk path (prevents path traversal).
bool isLowerHex(const std::string& s, std::size_t len);

// Cryptographically secure randomness (OpenSSL RAND_bytes). Throws on failure.
Bytes randomBytes(std::size_t n);
std::string randomHex(std::size_t nBytes);

// Reads a whole regular file (refusing symlinks/devices unless followSymlinks).
std::optional<Bytes> readFile(const fs::path& p, bool followSymlinks = false,
                              std::uintmax_t maxSize = kMaxObjectSize);
// Writes via temp-file + rename so readers never observe a partial object.
// When `secret` is set the file is staged in a fresh owner-only directory and
// made 0600 before it is moved into place, so no other account can open it at
// any point (standard C++ only: no umask).
void writeFileAtomic(const fs::path& p, const Bytes& data, bool secret = false);

Bytes toBytes(const std::string& s);
std::string toString(const Bytes& b);
// Overwrites a buffer holding sensitive material (OPENSSL_cleanse).
void wipe(Bytes& b);
void wipe(std::string& s);

// Every byte in 0x20..0x7E (printable ASCII, space allowed).
bool isPrintableAscii(const std::string& s);
// Splits on '/', dropping empty components ("a//b/" -> {a, b}).
std::vector<std::string> splitPath(const std::string& s);
std::vector<std::string> splitLines(const std::string& s);
std::string joinPath(const std::vector<std::string>& comps, std::size_t from = 0);

}  // namespace bibifi
