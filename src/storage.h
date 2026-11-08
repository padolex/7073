// storage.h - the encrypted on-disk object store (single master key, JSON).
//
// Host layout (everything except private keyfiles is world-readable/writable):
//
//   ./<name>_keyfile          JSON keyfile with the user's Ed25519 private key (0600)
//   ./public_keys/<uid>.pem   Ed25519 public keys, named by an opaque random uid
//   ./filesystem/<N(label)>   every object, in ONE flat directory, where
//                             N(label) = hex HMAC-SHA-256(K_names, label)
//
// Every object file is   nonce(12) || AES-256-GCM_K_enc(JSON document) || tag(16)
// with associated data  "bibifi-new/v1|" + label,  so the WHOLE file is
// ciphertext and a copied, moved or edited object fails authentication.
//
//   label                              JSON document (after decryption)
//   "registry"                         {"users":[{"name","uid","role","fpr"},...]}
//   "tree|<uid>"                       nested /personal tree of that user
//   "blob|<uid>|<blob>"                {"content": "<file contents>"}
//   "share|<uid>"                      every file shared WITH that user:
//      {"shares":[{"owner":<uid>,"blob":<id>,"path":"<path below owner's /personal>"},...]}
//
// The directory is completely flat: there are no subdirectories.
//
// K_enc and K_names are HKDF subkeys of the master key compiled into the
// binary (internal_secret.h). Without it, nothing on disk can be read,
// linked to a user, or forged.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "crypto.h"
#include "jsonio.h"
#include "util.h"

namespace bibifi {

constexpr std::size_t kUidHexLen = 32;     // 128-bit random user id
constexpr std::size_t kBlobHexLen = 32;    // 128-bit random file id
constexpr std::size_t kFprHexLen = 64;     // SHA-256 public-key fingerprint
constexpr std::size_t kMaxDirDepth = 64;   // directory levels below /personal

struct UserRec {
    std::string name;
    std::string uid;
    std::string role;  // "admin" or "user"
    std::string fpr;   // fingerprint of the user's public key
    bool isAdmin() const { return role == "admin"; }
};

struct Registry {
    std::vector<UserRec> users;
    const UserRec* byName(const std::string& name) const;
    const UserRec* byUid(const std::string& uid) const;
};

// A file shared with a recipient: read access to the owner's blob, so the
// recipient always sees the owner's latest contents. `path` is where the file
// lives below the owner's /personal (e.g. "a/file"); the recipient sees it at
// /shared/<owner>/<path>.
struct ShareRec {
    std::string ownerUid;
    std::string blob;
    std::string path;
};

struct KeyfileData {
    std::string username;
    std::string uid;
    PKey priv;
};

// [A-Za-z0-9_-]{1,32}, excluding "personal" and "shared", which name the
// admin's own top-level directories next to the per-user directories.
bool isValidUsername(const std::string& name);
// A single path component a user may create: printable, no '/', no space,
// not "." or "..", at most kMaxNameLength bytes.
bool isValidName(const std::string& name);

// --- /personal tree: nested JSON -----------------------------------------------
//   dir  : {"type":"dir",  "children": { "<name>": <node>, ... }}
//   file : {"type":"file", "blob": "<32 hex>"}
json makeDirNode();
json makeFileNode(const std::string& blob);
bool isDirNode(const json& node);
bool isFileNode(const json& node);
// Follows `path` (components below /personal) from `root`; nullptr if absent.
const json* findNode(const json& root, const std::vector<std::string>& path);
json* findNode(json& root, const std::vector<std::string>& path);
// Blob id of a (validated) file node.
std::string fileBlob(const json& fileNode);

// SSH-style challenge/response: signs a fresh random nonce with `priv` and
// verifies it with `pub`. True iff the two keys form a pair.
bool proveKeyPossession(EVP_PKEY* priv, EVP_PKEY* pub);

class Store {
public:
    explicit Store(fs::path root, const std::string& fsDirName = "filesystem");

    // True when the encrypted filesystem has not been created yet.
    bool needsInit() const;
    // Creates ./filesystem, ./public_keys and ./admin_keyfile.
    void initialize() const;

    // --- keyfiles ---
    std::optional<KeyfileData> readKeyfile(const fs::path& path) const;
    void writeKeyfile(const std::string& username, const std::string& uid, EVP_PKEY* priv) const;

    // --- public keys ---
    void writePublicKey(const std::string& uid, EVP_PKEY* pub) const;
    // Loads public_keys/<uid>.pem and checks it against the fingerprint held
    // in the (authenticated) registry; nullptr on any mismatch.
    PKey loadPinnedPublicKey(const std::string& uid, const std::string& fpr) const;

    // --- registry: who exists, uid <-> name <-> key fingerprint, roles ---
    std::optional<Registry> loadRegistry() const;
    void saveRegistry(const Registry& reg) const;

    // --- a user's /personal tree (fully validated on load) ---
    std::optional<json> loadTree(const std::string& uid) const;
    void saveTree(const std::string& uid, const json& tree) const;

    // --- file contents ---
    std::optional<std::string> loadBlob(const std::string& ownerUid, const std::string& blob) const;
    void saveBlob(const std::string& ownerUid, const std::string& blob, const std::string& content) const;

    // --- sharing: one object per recipient, label "share|<uid>" ---
    // Adds (or refreshes) one entry in the recipient's share list. Returns
    // false, writing nothing, if the existing list fails authentication (it is
    // never silently replaced). There is no lock: two shares to the same
    // recipient at the same instant can lose one entry (see ARCH.md §7).
    bool saveShare(const std::string& recipientUid, const ShareRec& rec) const;
    // The recipient's share list: empty if nothing was ever shared with them,
    // nullopt if the object exists but is tampered or malformed.
    std::optional<std::vector<ShareRec>> loadShares(const std::string& recipientUid) const;

private:
    fs::path root_;
    fs::path fsDir_;
    fs::path pubDir_;
    Key256 encKey_;   // K_enc
    Key256 nameKey_;  // K_names

    fs::path objectPath(const std::string& label) const;
    // Encrypts `doc` under K_enc with AAD bound to `aadLabel` and writes it
    // atomically to `path`.
    void putObject(const fs::path& path, const std::string& aadLabel, const json& doc) const;
    // Reads, authenticates, decrypts and parses one object; nullopt if it is
    // missing, a symlink, tampered, relocated or malformed.
    std::optional<json> getObject(const fs::path& path, const std::string& aadLabel, std::size_t maxDepth) const;
};

}  // namespace bibifi
