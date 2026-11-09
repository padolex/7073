// crypto.h - thin RAII wrappers over OpenSSL 3 EVP. No cryptography is
// implemented here; every primitive is delegated to OpenSSL.
//
//   User keys  : Ed25519 (SSH-style login: sign a fresh challenge)
//   Symmetric  : AES-256-GCM (96-bit random nonce, 128-bit tag) with associated data
//   MAC / KDF  : HMAC-SHA-256, HKDF-SHA-256
#pragma once

#include <openssl/evp.h>

#include <array>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

#include "util.h"

namespace bibifi {

struct CryptoError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct PKeyDeleter {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
using PKey = std::unique_ptr<EVP_PKEY, PKeyDeleter>;

// 256-bit symmetric key that is wiped from memory when destroyed.
struct Key256 {
    std::array<unsigned char, 32> b{};
    Key256() = default;
    Key256(const Key256&) = default;
    Key256& operator=(const Key256&) = default;
    ~Key256();
    static std::optional<Key256> fromBytes(const unsigned char* p, std::size_t n);
};

// --- User key pairs (Ed25519) ------------------------------------------------
PKey generateUserKey();
std::string privateKeyToPem(EVP_PKEY* key);
std::string publicKeyToPem(EVP_PKEY* key);
// Return nullptr on any parse failure or a key that is not Ed25519. Encrypted
// PEMs are rejected (no interactive passphrase prompt).
PKey loadPrivateKeyPem(const std::string& pem);
PKey loadPublicKeyPem(const std::string& pem);
// Lowercase hex SHA-256 of the DER SubjectPublicKeyInfo.
std::string fingerprint(EVP_PKEY* key);
Bytes sign(EVP_PKEY* priv, const Bytes& msg);
bool verify(EVP_PKEY* pub, const Bytes& msg, const Bytes& sig);

// --- Symmetric authenticated encryption --------------------------------------
// Output: nonce(12) || ciphertext || tag(16). The plaintext is length-prefixed
// and zero-padded to a multiple of kPadBlock to blur exact sizes on disk.
constexpr std::size_t kPadBlock = 256;
Bytes aeadEncrypt(const Key256& key, const Bytes& plaintext, const std::string& aad);
std::optional<Bytes> aeadDecrypt(const Key256& key, const Bytes& blob, const std::string& aad);

Bytes hmacSha256(const Key256& key, const std::string& msg);
// Lowercase hex SHA-256 of `data` (Merkle hashes of stored objects).
std::string sha256Hex(const Bytes& data);
// HKDF-SHA-256 (RFC 5869) with an empty salt: derives an independent subkey
// for each `info` label from one master key.
Key256 hkdfSha256(const Key256& ikm, const std::string& info);
// Constant-time equality for equal-length strings.
bool constTimeEqual(const std::string& a, const std::string& b);

}  // namespace bibifi
