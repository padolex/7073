// storage.h - the encrypted on-disk object store (single master key, JSON,
// Merkle-linked for rollback detection).
//
// Host layout (everything except private keyfiles is world-readable/writable):
//
//   ./<name>_keyfile          JSON keyfile with the user's Ed25519 private key (0600);
//                             written once at adduser, never modified
//   ./public_keys/<uid>.pem   Ed25519 public keys, named by an opaque random uid
//   ./internal/state          the current root's epoch and SHA-256 (encrypted).
//                             ASSUMED SAFE: not readable or writable by clients
//   ./filesystem/<N(label)>   every object, in ONE flat directory, where
//                             N(label) = hex HMAC-SHA-256(K_names, label)
//
// Every object file is   nonce(12) || AES-256-GCM_K_enc(JSON document) || tag(16)
// with associated data  "bibifi-new/v1|" + label,  so the WHOLE file is
// ciphertext and a copied, moved or edited object fails authentication.
//
// Objects form a Merkle tree. Every write creates a NEW version of an object
// (its version is part of its label, hence of its name and associated data),
// and every parent records the version and SHA-256 of each child:
//
//   "root"                      {"epoch":E, "registry":REF,
//                                "trees":{uid:REF,...}, "shares":{uid:REF,...}}
//   "registry|<ver>"            {"users":[{"name","uid","role","fpr"},...]}
//   "tree|<uid>|<ver>"          nested /personal tree; each file node holds the
//                               REF of its contents
//   "blob|<uid>|<blob>|<ver>"   {"content": "<file contents>"}
//   "share|<uid>|<ver>"         {"shares":[{"owner","blob","path"},...]}
//
//   REF = {"ver": <epoch at which the child was written>,
//          "hash": "<hex SHA-256 of the child's bytes on disk>"}
//
// The root is the single commit point: a command writes its new objects, then
// the root, then ./internal/state, then deletes the versions it replaced.
// Every parent pins its children by version and hash, so restoring old copies
// of SOME objects is detected by the Merkle links; ./internal/state pins the
// root itself, so restoring a complete old snapshot of ./filesystem is
// detected too.
#pragma once

#include <cstdint>
#include <map>
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
constexpr std::size_t kHashHexLen = 64;    // SHA-256 object hash
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

// A parent's reference to one exact version of a child object.
struct ObjRef {
    std::uint64_t ver = 0;  // root epoch at which the child was written
    std::string hash;       // hex SHA-256 of the child's bytes on disk
};

// The Merkle root: references the current version of every top-level object.
struct Root {
    std::uint64_t epoch = 0;               // +1 on every committed change
    std::string hash;                      // SHA-256 of this root's bytes on disk (not stored in it)
    ObjRef registry;
    std::map<std::string, ObjRef> trees;   // uid -> that user's tree
    std::map<std::string, ObjRef> shares;  // uid -> files shared WITH that user
};

// A file shared with a recipient: read access to the owner's file at `path`
// (below the owner's /personal, e.g. "a/file"); the recipient sees it at
// /shared/<owner>/<path> and always reads the owner's latest version.
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
//   file : {"type":"file", "blob": "<32 hex>", "ver": <u64>, "hash": "<64 hex>"}
json makeDirNode();
json makeFileNode(const std::string& blob, const ObjRef& ref);
bool isDirNode(const json& node);
bool isFileNode(const json& node);
// Follows `path` (components below /personal) from `root`; nullptr if absent.
const json* findNode(const json& root, const std::vector<std::string>& path);
json* findNode(json& root, const std::vector<std::string>& path);
// Blob id and content reference of a (validated) file node.
std::string fileBlob(const json& fileNode);
ObjRef fileRef(const json& fileNode);

// Object labels (see the header comment). Exposed so the shell can name the
// versions it replaces.
std::string registryLabel(std::uint64_t ver);
std::string treeLabel(const std::string& uid, std::uint64_t ver);
std::string blobLabel(const std::string& owner, const std::string& blob, std::uint64_t ver);
std::string shareLabel(const std::string& uid, std::uint64_t ver);

// SSH-style challenge/response: signs a fresh random nonce with `priv` and
// verifies it with `pub`. True iff the two keys form a pair.
bool proveKeyPossession(EVP_PKEY* priv, EVP_PKEY* pub);

class Store {
public:
    explicit Store(fs::path root, const std::string& fsDirName = "filesystem");

    // Nothing exists yet: no filesystem, no admin keyfile, no public keys.
    bool needsInit() const;
    // ./filesystem is missing or empty but keys exist: it was deleted or
    // rolled back to nothing. Never re-initialised over (that would replace
    // admin_keyfile); the program refuses to run instead.
    bool isWiped() const;
    // Creates ./filesystem (root epoch 1), ./public_keys and ./admin_keyfile.
    void initialize() const;

    // --- keyfiles ---
    std::optional<KeyfileData> readKeyfile(const fs::path& path) const;
    void writeKeyfile(const std::string& username, const std::string& uid, EVP_PKEY* priv) const;

    // --- public keys ---
    void writePublicKey(const std::string& uid, EVP_PKEY* pub) const;
    // Loads public_keys/<uid>.pem and checks it against the fingerprint held
    // in the (authenticated) registry; nullptr on any mismatch.
    PKey loadPinnedPublicKey(const std::string& uid, const std::string& fpr) const;

    // --- the Merkle root (commit point) ---
    std::optional<Root> loadRoot() const;
    // Writes the root and returns the SHA-256 of the bytes written.
    std::string saveRoot(const Root& root) const;

    // --- ./internal/state: the trusted record of the current root ---
    // Current: `root` is the root recorded in ./internal/state, or exactly one
    // epoch newer (a crash between writing the root and the state; the state
    // is repaired). Stale: anything else, i.e. ./filesystem was rolled back,
    // forked, or the state is missing.
    enum class Freshness { Current, Stale };
    Freshness checkFresh(const Root& root) const;
    void saveState(std::uint64_t epoch, const std::string& rootHash) const;

    // --- versioned objects: each save returns the reference its parent must
    //     store; each load verifies the bytes against that reference ---
    ObjRef saveRegistry(const Registry& reg, std::uint64_t ver) const;
    std::optional<Registry> loadRegistry(const ObjRef& ref) const;

    ObjRef saveTree(const std::string& uid, const json& tree, std::uint64_t ver) const;
    std::optional<json> loadTree(const std::string& uid, const ObjRef& ref) const;  // fully validated

    ObjRef saveBlob(const std::string& ownerUid, const std::string& blob, const std::string& content,
                    std::uint64_t ver) const;
    std::optional<std::string> loadBlob(const std::string& ownerUid, const std::string& blob,
                                        const ObjRef& ref) const;

    ObjRef saveShares(const std::string& recipientUid, const std::vector<ShareRec>& shares,
                      std::uint64_t ver) const;
    std::optional<std::vector<ShareRec>> loadShares(const std::string& recipientUid, const ObjRef& ref) const;

    // Deletes a replaced version after the root that dropped it is committed.
    void discard(const std::string& label) const;

private:
    fs::path root_;
    fs::path fsDir_;
    fs::path pubDir_;
    fs::path internalDir_;
    Key256 encKey_;   // K_enc
    Key256 nameKey_;  // K_names

    fs::path objectPath(const std::string& label) const;
    // Encrypts `doc` under K_enc with AAD bound to `label`, writes it
    // atomically, and returns the SHA-256 of the bytes written.
    std::string putObject(const std::string& label, const json& doc) const;
    // Reads one object, checks its SHA-256 against `expectedHash` (empty: no
    // hash check, used only for the root), authenticates, decrypts and parses
    // it; nullopt if it is missing, a symlink, replaced, tampered or malformed.
    // `bytesHash`, if given, receives the SHA-256 of the bytes read.
    std::optional<json> getObject(const std::string& label, const std::string& expectedHash,
                                  std::size_t maxDepth, std::string* bytesHash = nullptr) const;
};

}  // namespace bibifi
