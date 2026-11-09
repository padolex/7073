#include "storage.h"

#include "internal_secret.h"

namespace bibifi {

namespace {

const char* kTypeKeyfile = "bibifi.keyfile";
constexpr std::uint64_t kKeyfileVersion = 1;
const char* kAadPrefix = "bibifi-new/v2|";    // every object's AES-GCM associated data
const char* kRootLabel = "root";
const char* kStateAad = "bibifi-new/v2|internal-state";
const char* kLoginContext = "bibifi-new-login-v1|";

std::string verString(std::uint64_t v) { return std::to_string(v); }

// --- references --------------------------------------------------------------------

json refJson(const ObjRef& r) { return {{"ver", r.ver}, {"hash", r.hash}}; }

std::optional<ObjRef> refFromJson(const json& j) {
    ObjRef r;
    if (!hasExactKeys(j, {"ver", "hash"}) || !getU64(j, "ver", r.ver) || !getString(j, "hash", r.hash) ||
        r.ver == 0 || !isLowerHex(r.hash, kHashHexLen)) {
        return std::nullopt;
    }
    return r;
}

// {uid: REF, ...}
bool refMapFromJson(const json& j, std::map<std::string, ObjRef>& out) {
    if (!j.is_object()) return false;
    for (auto it = j.begin(); it != j.end(); ++it) {
        auto r = refFromJson(it.value());
        if (!isLowerHex(it.key(), kUidHexLen) || !r) return false;
        out[it.key()] = *r;
    }
    return true;
}

// --- tree validation -------------------------------------------------------------

bool validNode(const json& n, std::size_t dirDepth) {
    std::string type;
    if (!getString(n, "type", type)) return false;
    if (type == "file") {
        std::string blob;
        std::string hash;
        std::uint64_t ver = 0;
        return hasExactKeys(n, {"type", "blob", "ver", "hash"}) && getString(n, "blob", blob) &&
               isLowerHex(blob, kBlobHexLen) && getU64(n, "ver", ver) && ver > 0 && getString(n, "hash", hash) &&
               isLowerHex(hash, kHashHexLen);
    }
    if (type != "dir" || dirDepth > kMaxDirDepth || !hasExactKeys(n, {"type", "children"})) return false;
    const json& children = n.at("children");
    if (!children.is_object()) return false;
    for (auto it = children.begin(); it != children.end(); ++it) {
        if (!isValidName(it.key()) || !validNode(it.value(), dirDepth + 1)) return false;
    }
    return true;
}

// --- share lists ---------------------------------------------------------------------

// "a/b/file": 1..kMaxDirDepth+1 valid components, no empty, "." or ".." parts.
bool isValidSharePath(const std::string& p) {
    const auto comps = splitPath(p);
    if (comps.empty() || comps.size() > kMaxDirDepth + 1 || joinPath(comps) != p) return false;
    for (const auto& c : comps) {
        if (!isValidName(c)) return false;
    }
    return true;
}

json shareJson(const ShareRec& r) { return {{"owner", r.ownerUid}, {"blob", r.blob}, {"path", r.path}}; }

std::optional<ShareRec> shareFromJson(const json& j) {
    ShareRec r;
    if (!hasExactKeys(j, {"owner", "blob", "path"}) || !getString(j, "owner", r.ownerUid) ||
        !getString(j, "blob", r.blob) || !getString(j, "path", r.path)) {
        return std::nullopt;
    }
    if (!isLowerHex(r.ownerUid, kUidHexLen) || !isLowerHex(r.blob, kBlobHexLen) || !isValidSharePath(r.path)) {
        return std::nullopt;
    }
    return r;
}

// --- keyfiles ------------------------------------------------------------------------

void wipeKeyfileJson(json& j) {
    if (j.is_object() && j.contains("private_key") && j["private_key"].is_string()) {
        wipe(j["private_key"].get_ref<std::string&>());
    }
}

}  // namespace

// --- validation --------------------------------------------------------------------

bool isValidUsername(const std::string& name) {
    if (name.empty() || name.size() > 32 || name == "personal" || name == "shared") return false;
    for (char c : name) {
        const bool ok =
            (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok) return false;
    }
    return true;
}

bool isValidName(const std::string& name) {
    if (name.empty() || name.size() > kMaxNameLength || name == "." || name == "..") return false;
    for (unsigned char c : name) {
        if (c <= 0x20 || c > 0x7E || c == '/') return false;
    }
    return true;
}

const UserRec* Registry::byName(const std::string& name) const {
    for (const auto& u : users) {
        if (u.name == name) return &u;
    }
    return nullptr;
}

const UserRec* Registry::byUid(const std::string& uid) const {
    for (const auto& u : users) {
        if (u.uid == uid) return &u;
    }
    return nullptr;
}

// --- labels --------------------------------------------------------------------------

std::string registryLabel(std::uint64_t ver) { return "registry|" + verString(ver); }
std::string treeLabel(const std::string& uid, std::uint64_t ver) { return "tree|" + uid + "|" + verString(ver); }
std::string blobLabel(const std::string& owner, const std::string& blob, std::uint64_t ver) {
    return "blob|" + owner + "|" + blob + "|" + verString(ver);
}
std::string shareLabel(const std::string& uid, std::uint64_t ver) { return "share|" + uid + "|" + verString(ver); }

// --- tree helpers --------------------------------------------------------------------

json makeDirNode() { return {{"type", "dir"}, {"children", json::object()}}; }

json makeFileNode(const std::string& blob, const ObjRef& ref) {
    return {{"type", "file"}, {"blob", blob}, {"ver", ref.ver}, {"hash", ref.hash}};
}

bool isDirNode(const json& node) { return node.is_object() && node.value("type", "") == "dir"; }
bool isFileNode(const json& node) { return node.is_object() && node.value("type", "") == "file"; }

const json* findNode(const json& root, const std::vector<std::string>& path) {
    const json* cur = &root;
    for (const auto& comp : path) {
        if (!isDirNode(*cur)) return nullptr;
        const json& children = cur->at("children");
        auto it = children.find(comp);
        if (it == children.end()) return nullptr;
        cur = &*it;
    }
    return cur;
}

json* findNode(json& root, const std::vector<std::string>& path) {
    return const_cast<json*>(findNode(static_cast<const json&>(root), path));
}

std::string fileBlob(const json& fileNode) { return fileNode.at("blob").get<std::string>(); }

ObjRef fileRef(const json& fileNode) {
    return {fileNode.at("ver").get<std::uint64_t>(), fileNode.at("hash").get<std::string>()};
}

bool proveKeyPossession(EVP_PKEY* priv, EVP_PKEY* pub) {
    Bytes challenge = toBytes(kLoginContext);
    Bytes nonce = randomBytes(32);
    challenge.insert(challenge.end(), nonce.begin(), nonce.end());
    return verify(pub, challenge, sign(priv, challenge));
}

// --- Store -----------------------------------------------------------------------------

Store::Store(fs::path root, const std::string& fsDirName)
    : root_(std::move(root)),
      fsDir_(root_ / fsDirName),
      pubDir_(root_ / "public_keys"),
      internalDir_(root_ / "internal") {
    const auto master = Key256::fromBytes(kInternalMasterKey, sizeof(kInternalMasterKey));
    encKey_ = hkdfSha256(*master, "bibifi-new/v1/encryption");
    nameKey_ = hkdfSha256(*master, "bibifi-new/v1/names");
}

// Flat layout: every object lives directly in ./filesystem under a 64-hex name
// that only the program can compute, so no name reveals a user, a file, a
// version, or which objects belong together.
fs::path Store::objectPath(const std::string& label) const { return fsDir_ / toHex(hmacSha256(nameKey_, label)); }

std::string Store::putObject(const std::string& label, const json& doc) const {
    Bytes pt = dumpJsonBytes(doc);
    Bytes ct = aeadEncrypt(encKey_, pt, kAadPrefix + label);
    wipe(pt);
    writeFileAtomic(objectPath(label), ct);
    return sha256Hex(ct);
}

std::optional<json> Store::getObject(const std::string& label, const std::string& expectedHash,
                                     std::size_t maxDepth, std::string* bytesHash) const {
    auto raw = readFile(objectPath(label));  // refuses symlinks and non-regular files
    if (!raw) return std::nullopt;
    const std::string hash = sha256Hex(*raw);
    // Merkle check first: these must be exactly the bytes the parent recorded.
    if (!expectedHash.empty() && !constTimeEqual(hash, expectedHash)) return std::nullopt;
    if (bytesHash != nullptr) *bytesHash = hash;
    auto pt = aeadDecrypt(encKey_, *raw, kAadPrefix + label);  // authenticate before parsing
    if (!pt) return std::nullopt;
    auto doc = parseJson(*pt, maxDepth);
    wipe(*pt);
    return doc;
}

void Store::discard(const std::string& label) const {
    std::error_code ec;
    fs::remove(objectPath(label), ec);  // best effort: a leftover is unreferenced and harmless
}

namespace {
bool emptyOrMissing(const fs::path& dir) {
    std::error_code ec;
    const fs::file_status st = fs::symlink_status(dir, ec);
    if (ec || !fs::exists(st)) return true;
    return fs::is_directory(st) && fs::is_empty(dir, ec) && !ec;
}
}  // namespace

bool Store::needsInit() const {
    std::error_code ec;
    return emptyOrMissing(fsDir_) && !fs::exists(fs::symlink_status(root_ / "admin_keyfile", ec)) &&
           emptyOrMissing(pubDir_) && emptyOrMissing(internalDir_);
}

bool Store::isWiped() const { return emptyOrMissing(fsDir_) && !needsInit(); }

void Store::initialize() const {
    // Build in a staging directory and rename it into place at the end, so a
    // crash never leaves a half-initialised ./filesystem behind.
    const std::string stagingName = "filesystem.init-" + randomHex(8);
    const fs::path staging = root_ / stagingName;
    Store st(root_, stagingName);
    std::error_code ec;
    try {
        fs::create_directories(pubDir_);
        fs::create_directory(staging);

        PKey admin = generateUserKey();
        const std::string uid = randomHex(kUidHexLen / 2);
        writePublicKey(uid, admin.get());
        Root root;
        root.epoch = 1;
        root.trees[uid] = st.saveTree(uid, makeDirNode(), root.epoch);
        Registry reg;
        reg.users.push_back({"admin", uid, "admin", fingerprint(admin.get())});
        root.registry = st.saveRegistry(reg, root.epoch);
        saveState(root.epoch, st.saveRoot(root));  // ./internal is next to, not inside, the staging dir
        writeKeyfile("admin", uid, admin.get());

        if (fs::exists(fs::symlink_status(fsDir_, ec))) fs::remove(fsDir_);  // empty dir only
        fs::rename(staging, fsDir_);
    } catch (...) {
        fs::remove_all(staging, ec);
        throw;
    }
}

// --- keyfiles ----------------------------------------------------------------------------
// {"type":"bibifi.keyfile","v":1,"user":..,"uid":..,"private_key":"<PEM>"}
// The keyfile is the user's credential, held by the user; it is deliberately
// NOT encrypted with K_M (it is not part of ./filesystem). It is written once,
// at adduser, and never modified. Its fields are claims checked against the
// registry at login.

void Store::writeKeyfile(const std::string& username, const std::string& uid, EVP_PKEY* priv) const {
    json j = {{"type", kTypeKeyfile}, {"v", kKeyfileVersion}, {"user", username}, {"uid", uid},
              {"private_key", privateKeyToPem(priv)}};
    std::string text = j.dump(2) + "\n";
    wipeKeyfileJson(j);
    Bytes data = toBytes(text);
    wipe(text);
    try {
        writeFileAtomic(root_ / (username + "_keyfile"), data, /*secret=*/true);
    } catch (...) {
        wipe(data);
        throw;
    }
    wipe(data);
}

std::optional<KeyfileData> Store::readKeyfile(const fs::path& path) const {
    auto raw = readFile(path, /*followSymlinks=*/true, 64 * 1024);
    if (!raw) return std::nullopt;
    auto j = parseJson(*raw, 1);
    wipe(*raw);
    if (!j) return std::nullopt;

    KeyfileData kf;
    std::string type;
    std::string pem;
    std::uint64_t v = 0;
    const bool ok = hasExactKeys(*j, {"type", "v", "user", "uid", "private_key"}) && getString(*j, "type", type) &&
                    type == kTypeKeyfile && getU64(*j, "v", v) && v == kKeyfileVersion &&
                    getString(*j, "user", kf.username) && getString(*j, "uid", kf.uid) &&
                    getString(*j, "private_key", pem) && isValidUsername(kf.username) &&
                    isLowerHex(kf.uid, kUidHexLen);
    wipeKeyfileJson(*j);
    if (ok) kf.priv = loadPrivateKeyPem(pem);
    wipe(pem);
    if (!ok || !kf.priv) return std::nullopt;
    return kf;
}

// --- public keys ---------------------------------------------------------------------------

void Store::writePublicKey(const std::string& uid, EVP_PKEY* pub) const {
    if (!isLowerHex(uid, kUidHexLen)) throw std::runtime_error("invalid uid");
    writeFileAtomic(pubDir_ / (uid + ".pem"), toBytes(publicKeyToPem(pub)));
}

PKey Store::loadPinnedPublicKey(const std::string& uid, const std::string& fpr) const {
    if (!isLowerHex(uid, kUidHexLen)) return nullptr;
    auto raw = readFile(pubDir_ / (uid + ".pem"), false, 64 * 1024);
    if (!raw) return nullptr;
    PKey k = loadPublicKeyPem(toString(*raw));
    if (!k || !constTimeEqual(fingerprint(k.get()), fpr)) return nullptr;
    return k;
}

// --- root ----------------------------------------------------------------------------------
// The root is the only object with a fixed name. It is authenticated like
// every object (AAD "root"), so only the program can have written it; its
// freshness is checked against ./internal/state.

std::string Store::saveRoot(const Root& root) const {
    json trees = json::object();
    for (const auto& [uid, ref] : root.trees) trees[uid] = refJson(ref);
    json shares = json::object();
    for (const auto& [uid, ref] : root.shares) shares[uid] = refJson(ref);
    return putObject(kRootLabel, {{"epoch", root.epoch},
                                  {"registry", refJson(root.registry)},
                                  {"trees", trees},
                                  {"shares", shares}});
}

std::optional<Root> Store::loadRoot() const {
    Root root;
    auto doc = getObject(kRootLabel, "", 3, &root.hash);
    if (!doc || !hasExactKeys(*doc, {"epoch", "registry", "trees", "shares"}) || !getU64(*doc, "epoch", root.epoch) ||
        root.epoch == 0) {
        return std::nullopt;
    }
    auto reg = refFromJson(doc->at("registry"));
    if (!reg || !refMapFromJson(doc->at("trees"), root.trees) || !refMapFromJson(doc->at("shares"), root.shares)) {
        return std::nullopt;
    }
    root.registry = *reg;
    return root;
}

// --- ./internal/state ------------------------------------------------------------------------
// {"epoch": E, "root": "<SHA-256 of the root's bytes>"}, encrypted with K_enc.
// ./internal is assumed to be out of the clients' reach (see README.md), so
// it can't be rolled back together with ./filesystem: it is the trusted
// record of which root is current.

void Store::saveState(std::uint64_t epoch, const std::string& rootHash) const {
    fs::create_directories(internalDir_);
    Bytes pt = dumpJsonBytes({{"epoch", epoch}, {"root", rootHash}});
    writeFileAtomic(internalDir_ / "state", aeadEncrypt(encKey_, pt, kStateAad));
}

Store::Freshness Store::checkFresh(const Root& root) const {
    auto raw = readFile(internalDir_ / "state", false, 4096);
    if (!raw) return Freshness::Stale;
    auto pt = aeadDecrypt(encKey_, *raw, kStateAad);
    if (!pt) return Freshness::Stale;
    auto doc = parseJson(*pt, 1);
    std::uint64_t epoch = 0;
    std::string hash;
    if (!doc || !hasExactKeys(*doc, {"epoch", "root"}) || !getU64(*doc, "epoch", epoch) ||
        !getString(*doc, "root", hash) || !isLowerHex(hash, kHashHexLen)) {
        return Freshness::Stale;
    }
    if (root.epoch == epoch) return constTimeEqual(root.hash, hash) ? Freshness::Current : Freshness::Stale;
    if (root.epoch == epoch + 1) {
        // Crash recovery: the root was committed but the state update was not.
        // Only a genuine commit can produce a root one epoch ahead.
        saveState(root.epoch, root.hash);
        return Freshness::Current;
    }
    return Freshness::Stale;  // older (rolled back), or a gap that no commit produces
}

// --- registry --------------------------------------------------------------------------------

ObjRef Store::saveRegistry(const Registry& reg, std::uint64_t ver) const {
    json users = json::array();
    for (const auto& u : reg.users) {
        users.push_back({{"name", u.name}, {"uid", u.uid}, {"role", u.role}, {"fpr", u.fpr}});
    }
    return {ver, putObject(registryLabel(ver), {{"users", users}})};
}

std::optional<Registry> Store::loadRegistry(const ObjRef& ref) const {
    auto doc = getObject(registryLabel(ref.ver), ref.hash, 3);
    if (!doc || !hasExactKeys(*doc, {"users"}) || !doc->at("users").is_array()) return std::nullopt;
    Registry reg;
    std::size_t admins = 0;
    for (const json& u : doc->at("users")) {
        UserRec r;
        if (!hasExactKeys(u, {"name", "uid", "role", "fpr"}) || !getString(u, "name", r.name) ||
            !getString(u, "uid", r.uid) || !getString(u, "role", r.role) || !getString(u, "fpr", r.fpr) ||
            !isValidUsername(r.name) || !isLowerHex(r.uid, kUidHexLen) || (r.role != "admin" && r.role != "user") ||
            !isLowerHex(r.fpr, kFprHexLen) || reg.byName(r.name) || reg.byUid(r.uid)) {
            return std::nullopt;
        }
        if (r.isAdmin()) ++admins;
        reg.users.push_back(r);
    }
    if (admins != 1) return std::nullopt;  // exactly one admin
    return reg;
}

// --- trees ---------------------------------------------------------------------------------

ObjRef Store::saveTree(const std::string& uid, const json& tree, std::uint64_t ver) const {
    if (!isLowerHex(uid, kUidHexLen)) throw std::runtime_error("invalid uid");
    return {ver, putObject(treeLabel(uid, ver), tree)};
}

std::optional<json> Store::loadTree(const std::string& uid, const ObjRef& ref) const {
    if (!isLowerHex(uid, kUidHexLen)) return std::nullopt;
    auto tree = getObject(treeLabel(uid, ref.ver), ref.hash, kMaxJsonDepth);
    if (!tree || !isDirNode(*tree) || !validNode(*tree, 0)) return std::nullopt;
    return tree;
}

// --- blobs -----------------------------------------------------------------------------------

ObjRef Store::saveBlob(const std::string& ownerUid, const std::string& blob, const std::string& content,
                       std::uint64_t ver) const {
    if (!isLowerHex(ownerUid, kUidHexLen) || !isLowerHex(blob, kBlobHexLen)) throw std::runtime_error("invalid id");
    json doc = {{"content", content}};
    ObjRef ref{ver, putObject(blobLabel(ownerUid, blob, ver), doc)};
    wipe(doc["content"].get_ref<std::string&>());
    return ref;
}

std::optional<std::string> Store::loadBlob(const std::string& ownerUid, const std::string& blob,
                                           const ObjRef& ref) const {
    if (!isLowerHex(ownerUid, kUidHexLen) || !isLowerHex(blob, kBlobHexLen)) return std::nullopt;
    auto doc = getObject(blobLabel(ownerUid, blob, ref.ver), ref.hash, 1);
    std::string content;
    if (!doc || !hasExactKeys(*doc, {"content"}) || !getString(*doc, "content", content)) return std::nullopt;
    return content;
}

// --- shares ----------------------------------------------------------------------------------
// One object per recipient: {"shares":[{"owner","blob","path"},...]}. The
// label (and thus the AAD) names the recipient, so a list copied to another
// user's object fails authentication.

ObjRef Store::saveShares(const std::string& recipientUid, const std::vector<ShareRec>& shares,
                         std::uint64_t ver) const {
    if (!isLowerHex(recipientUid, kUidHexLen)) throw std::runtime_error("invalid uid");
    json list = json::array();
    for (const ShareRec& r : shares) {
        if (!isLowerHex(r.ownerUid, kUidHexLen) || !isLowerHex(r.blob, kBlobHexLen) || !isValidSharePath(r.path)) {
            throw std::runtime_error("invalid share");
        }
        list.push_back(shareJson(r));
    }
    return {ver, putObject(shareLabel(recipientUid, ver), {{"shares", list}})};
}

std::optional<std::vector<ShareRec>> Store::loadShares(const std::string& recipientUid, const ObjRef& ref) const {
    if (!isLowerHex(recipientUid, kUidHexLen)) return std::nullopt;
    auto doc = getObject(shareLabel(recipientUid, ref.ver), ref.hash, 3);
    if (!doc || !hasExactKeys(*doc, {"shares"}) || !doc->at("shares").is_array()) return std::nullopt;
    std::vector<ShareRec> out;
    for (const json& e : doc->at("shares")) {
        auto rec = shareFromJson(e);
        if (!rec) return std::nullopt;
        out.push_back(*rec);
    }
    return out;
}

}  // namespace bibifi
