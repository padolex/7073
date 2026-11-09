#include "crypto.h"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <climits>
#include <cstring>

namespace bibifi {

namespace {

struct CipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); }
};
struct MdCtxDeleter {
    void operator()(EVP_MD_CTX* c) const { EVP_MD_CTX_free(c); }
};
struct BioDeleter {
    void operator()(BIO* b) const { BIO_free(b); }
};
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;
using MdCtx = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;
using Bio = std::unique_ptr<BIO, BioDeleter>;

constexpr std::size_t kNonceLen = 12;
constexpr std::size_t kTagLen = 16;

[[noreturn]] void fail(const char* what) {
    ERR_clear_error();
    throw CryptoError(what);
}

// Refuse to prompt for a passphrase on the terminal if handed an encrypted PEM.
int noPassphrase(char*, int, int, void*) { return 0; }

std::string bioContents(BIO* b) {
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(b, &mem);
    if (mem == nullptr) fail("BIO read failed");
    return std::string(mem->data, mem->length);
}

bool isEd25519(EVP_PKEY* k) { return k != nullptr && EVP_PKEY_is_a(k, "ED25519"); }

Bytes pad(const Bytes& pt) {
    if (pt.size() > 0xFFFFFFFFull) fail("plaintext too large");
    std::size_t total = 4 + pt.size();
    total = ((total + kPadBlock - 1) / kPadBlock) * kPadBlock;
    Bytes out(total, 0);
    std::uint32_t n = static_cast<std::uint32_t>(pt.size());
    out[0] = static_cast<unsigned char>(n >> 24);
    out[1] = static_cast<unsigned char>(n >> 16);
    out[2] = static_cast<unsigned char>(n >> 8);
    out[3] = static_cast<unsigned char>(n);
    if (!pt.empty()) std::memcpy(out.data() + 4, pt.data(), pt.size());
    return out;
}

std::optional<Bytes> unpad(const Bytes& padded) {
    if (padded.size() < 4) return std::nullopt;
    std::uint32_t n = (std::uint32_t(padded[0]) << 24) | (std::uint32_t(padded[1]) << 16) |
                      (std::uint32_t(padded[2]) << 8) | std::uint32_t(padded[3]);
    if (n > padded.size() - 4) return std::nullopt;
    return Bytes(padded.begin() + 4, padded.begin() + 4 + n);
}

}  // namespace

// --- Key256 -----------------------------------------------------------------

Key256::~Key256() { OPENSSL_cleanse(b.data(), b.size()); }

std::optional<Key256> Key256::fromBytes(const unsigned char* p, std::size_t n) {
    if (n != 32) return std::nullopt;
    Key256 k;
    std::memcpy(k.b.data(), p, 32);
    return k;
}

// --- User key pairs (Ed25519) ------------------------------------------------

PKey generateUserKey() {
    EVP_PKEY* k = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
    if (k == nullptr) fail("key generation failed");
    return PKey(k);
}

std::string privateKeyToPem(EVP_PKEY* key) {
    Bio b(BIO_new(BIO_s_secmem()));  // secure heap: wiped on free
    if (!b || PEM_write_bio_PrivateKey(b.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        fail("private key serialisation failed");
    }
    return bioContents(b.get());
}

std::string publicKeyToPem(EVP_PKEY* key) {
    Bio b(BIO_new(BIO_s_mem()));
    if (!b || PEM_write_bio_PUBKEY(b.get(), key) != 1) fail("public key serialisation failed");
    return bioContents(b.get());
}

PKey loadPrivateKeyPem(const std::string& pem) {
    if (pem.empty() || pem.size() > 64 * 1024) return nullptr;
    Bio b(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!b) return nullptr;
    PKey k(PEM_read_bio_PrivateKey(b.get(), nullptr, noPassphrase, nullptr));
    ERR_clear_error();
    if (!isEd25519(k.get())) return nullptr;
    return k;
}

PKey loadPublicKeyPem(const std::string& pem) {
    if (pem.empty() || pem.size() > 64 * 1024) return nullptr;
    Bio b(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!b) return nullptr;
    PKey k(PEM_read_bio_PUBKEY(b.get(), nullptr, noPassphrase, nullptr));
    ERR_clear_error();
    if (!isEd25519(k.get())) return nullptr;
    return k;
}

std::string fingerprint(EVP_PKEY* key) {
    unsigned char* der = nullptr;
    int len = i2d_PUBKEY(key, &der);
    if (len <= 0) fail("public key encoding failed");
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdLen = 0;
    int ok = EVP_Digest(der, static_cast<std::size_t>(len), md, &mdLen, EVP_sha256(), nullptr);
    OPENSSL_free(der);
    if (ok != 1) fail("digest failed");
    return toHex(md, mdLen);
}

Bytes sign(EVP_PKEY* priv, const Bytes& msg) {
    MdCtx m(EVP_MD_CTX_new());
    // Ed25519 hashes internally (PureEdDSA), so no digest is passed.
    if (!m || EVP_DigestSignInit(m.get(), nullptr, nullptr, nullptr, priv) != 1) fail("sign init failed");
    std::size_t len = 0;
    if (EVP_DigestSign(m.get(), nullptr, &len, msg.data(), msg.size()) != 1) fail("sign failed");
    Bytes sig(len);
    if (EVP_DigestSign(m.get(), sig.data(), &len, msg.data(), msg.size()) != 1) fail("sign failed");
    sig.resize(len);
    return sig;
}

bool verify(EVP_PKEY* pub, const Bytes& msg, const Bytes& sig) {
    MdCtx m(EVP_MD_CTX_new());
    if (!m || EVP_DigestVerifyInit(m.get(), nullptr, nullptr, nullptr, pub) != 1) fail("verify init failed");
    const int rc = EVP_DigestVerify(m.get(), sig.data(), sig.size(), msg.data(), msg.size());
    ERR_clear_error();
    return rc == 1;
}

// --- Symmetric authenticated encryption ------------------------------------

Bytes aeadEncrypt(const Key256& key, const Bytes& plaintext, const std::string& aad) {
    Bytes padded = pad(plaintext);
    if (padded.size() > static_cast<std::size_t>(INT_MAX) || aad.size() > static_cast<std::size_t>(INT_MAX)) {
        fail("input too large");
    }
    Bytes out(kNonceLen + padded.size() + kTagLen);
    Bytes nonce = randomBytes(kNonceLen);
    std::memcpy(out.data(), nonce.data(), kNonceLen);

    CipherCtx c(EVP_CIPHER_CTX_new());
    int len = 0;
    int finalLen = 0;
    if (!c || EVP_EncryptInit_ex(c.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceLen), nullptr) != 1 ||
        EVP_EncryptInit_ex(c.get(), nullptr, nullptr, key.b.data(), out.data()) != 1 ||
        EVP_EncryptUpdate(c.get(), nullptr, &len, reinterpret_cast<const unsigned char*>(aad.data()),
                          static_cast<int>(aad.size())) != 1 ||
        EVP_EncryptUpdate(c.get(), out.data() + kNonceLen, &len, padded.data(),
                          static_cast<int>(padded.size())) != 1 ||
        EVP_EncryptFinal_ex(c.get(), out.data() + kNonceLen + len, &finalLen) != 1 ||
        EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagLen),
                            out.data() + kNonceLen + padded.size()) != 1) {
        wipe(padded);
        fail("encryption failed");
    }
    wipe(padded);
    return out;
}

std::optional<Bytes> aeadDecrypt(const Key256& key, const Bytes& blob, const std::string& aad) {
    if (blob.size() < kNonceLen + kTagLen || blob.size() > static_cast<std::size_t>(INT_MAX) ||
        aad.size() > static_cast<std::size_t>(INT_MAX)) {
        return std::nullopt;
    }
    const std::size_t ctLen = blob.size() - kNonceLen - kTagLen;
    Bytes padded(ctLen);
    unsigned char tag[kTagLen];
    std::memcpy(tag, blob.data() + kNonceLen + ctLen, kTagLen);

    CipherCtx c(EVP_CIPHER_CTX_new());
    int len = 0;
    int finalLen = 0;
    bool ok = c && EVP_DecryptInit_ex(c.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceLen), nullptr) == 1 &&
              EVP_DecryptInit_ex(c.get(), nullptr, nullptr, key.b.data(), blob.data()) == 1 &&
              EVP_DecryptUpdate(c.get(), nullptr, &len, reinterpret_cast<const unsigned char*>(aad.data()),
                                static_cast<int>(aad.size())) == 1 &&
              EVP_DecryptUpdate(c.get(), padded.data(), &len, blob.data() + kNonceLen,
                                static_cast<int>(ctLen)) == 1 &&
              EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagLen), tag) == 1 &&
              EVP_DecryptFinal_ex(c.get(), padded.data() + len, &finalLen) == 1;  // tag check
    ERR_clear_error();
    if (!ok) {
        wipe(padded);
        return std::nullopt;
    }
    auto pt = unpad(padded);
    wipe(padded);
    return pt;
}

Bytes hmacSha256(const Key256& key, const std::string& msg) {
    Bytes out(32);
    std::size_t outLen = 0;
    if (EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr, key.b.data(), key.b.size(),
                  reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), out.data(), out.size(),
                  &outLen) == nullptr) {
        fail("HMAC failed");
    }
    out.resize(outLen);
    return out;
}

std::string sha256Hex(const Bytes& data) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdLen = 0;
    if (EVP_Digest(data.data(), data.size(), md, &mdLen, EVP_sha256(), nullptr) != 1) fail("digest failed");
    return toHex(md, mdLen);
}

Key256 hkdfSha256(const Key256& ikm, const std::string& info) {
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (kdf == nullptr) fail("HKDF unavailable");
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == nullptr) fail("HKDF context failed");
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<unsigned char*>(ikm.b.data()),
                                          ikm.b.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<char*>(info.data()), info.size()),
        OSSL_PARAM_construct_end()};
    Key256 out;
    const int ok = EVP_KDF_derive(ctx, out.b.data(), out.b.size(), params);
    EVP_KDF_CTX_free(ctx);
    if (ok != 1) fail("HKDF failed");
    return out;
}

bool constTimeEqual(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

}  // namespace bibifi
