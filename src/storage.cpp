#include "storage.h"

#include <fcntl.h>     // open: a descriptor on ./filesystem to lock
#include <sys/file.h>  // flock: serialises share-list updates between sessions
#include <unistd.h>    // close


#include "internal_secret.h"

namespace bibifi {

namespace {

const char* kTypeKeyfile = "bibifi.keyfile";
constexpr std::uint64_t kVersion = 1;
const char* kAadPrefix = "bibifi-new/v1|";  // every object's AES-GCM associated data
const char* kLoginContext = "bibifi-new-login-v1|";

std::string treeLabel(const std::string& uid) { return "tree|" + uid; }
std::string blobLabel(const std::string& owner, const std::string& blob) { return "blob|" + owner + "|" + blob; }
std::string shareLabel(const std::string& recipient) { return "share|" + recipient; }

// Exclusive advisory lock on the ./filesystem directory itself, so no extra
// (unencrypted) lock file is needed. Released when destroyed.
class DirLock {
public:
    explicit DirLock(const fs::path& dir) : fd_(::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)) {
        if (fd_ < 0 || ::flock(fd_, LOCK_EX) != 0) {
            if (fd_ >= 0) ::close(fd_);
            throw std::runtime_error("cannot lock filesystem");
        }
    }
    ~DirLock() { ::close(fd_); }  // closing the descriptor releases the lock
    DirLock(const DirLock&) = delete;
    DirLock& operator=(const DirLock&) = delete;

private:
    int fd_;
};

// --- tree validation -------------------------------------------------------------

bool validNode(const json& n, std::size_t dirDepth) {
    std::string type;
    if (!getString(n, "type", type)) return false;
    if (type == "file") {
        std::string blob;
        return hasExactKeys(n, {"type", "blob"}) && getString(n, "blob", blob) && isLowerHex(blob, kBlobHexLen);
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

// --- tree helpers --------------------------------------------------------------------

json makeDirNode() { return {{"type", "dir"}, {"children", json::object()}}; }

json makeFileNode(const std::string& blob) { return {{"type", "file"}, {"blob", blob}}; }

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

bool proveKeyPossession(EVP_PKEY* priv, EVP_PKEY* pub) {
    Bytes challenge = toBytes(kLoginContext);
    Bytes nonce = randomBytes(32);
    challenge.insert(challenge.end(), nonce.begin(), nonce.end());
    return verify(pub, challenge, sign(priv, challenge));
}

// --- Store -----------------------------------------------------------------------------

Store::Store(fs::path root, const std::string& fsDirName)
    : root_(std::move(root)), fsDir_(root_ / fsDirName), pubDir_(root_ / "public_keys") {
    const auto master = Key256::fromBytes(kInternalMasterKey, sizeof(kInternalMasterKey));
    encKey_ = hkdfSha256(*master, "bibifi-new/v1/encryption");
    nameKey_ = hkdfSha256(*master, "bibifi-new/v1/names");
}

// Flat layout: every object lives directly in ./filesystem under a 64-hex name
// that only the program can compute, so no name reveals a user, a file, or
// which objects belong together.
fs::path Store::objectPath(const std::string& label) const { return fsDir_ / toHex(hmacSha256(nameKey_, label)); }

void Store::putObject(const fs::path& path, const std::string& aadLabel, const json& doc) const {
    Bytes pt = dumpJsonBytes(doc);
    Bytes ct = aeadEncrypt(encKey_, pt, kAadPrefix + aadLabel);
    wipe(pt);
    writeFileAtomic(path, ct);
}

std::optional<json> Store::getObject(const fs::path& path, const std::string& aadLabel, std::size_t maxDepth) const {
    auto raw = readFile(path);  // refuses symlinks and non-regular files
    if (!raw) return std::nullopt;
    auto pt = aeadDecrypt(encKey_, *raw, kAadPrefix + aadLabel);  // authenticate before parsing
    if (!pt) return std::nullopt;
    auto doc = parseJson(*pt, maxDepth);
    wipe(*pt);
    return doc;
}

bool Store::needsInit() const {
    std::error_code ec;
    fs::file_status st = fs::symlink_status(fsDir_, ec);
    if (ec || !fs::exists(st)) return true;
    return fs::is_directory(st) && fs::is_empty(fsDir_, ec) && !ec;
}

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
        st.saveTree(uid, makeDirNode());
        Registry reg;
        reg.users.push_back({"admin", uid, "admin", fingerprint(admin.get())});
        st.saveRegistry(reg);
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
// NOT encrypted with K_M (it is not part of ./filesystem). Its fields are not
// trusted: login checks them against the authenticated registry.

void Store::writeKeyfile(const std::string& username, const std::string& uid, EVP_PKEY* priv) const {
    json j = {{"type", kTypeKeyfile}, {"v", kVersion}, {"user", username}, {"uid", uid},
              {"private_key", privateKeyToPem(priv)}};
    std::string text = j.dump(2) + "\n";
    wipe(j["private_key"].get_ref<std::string&>());
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
                    type == kTypeKeyfile && getU64(*j, "v", v) && v == kVersion &&
                    getString(*j, "user", kf.username) && getString(*j, "uid", kf.uid) &&
                    getString(*j, "private_key", pem) && isValidUsername(kf.username) &&
                    isLowerHex(kf.uid, kUidHexLen);
    if (j->contains("private_key") && (*j)["private_key"].is_string()) {
        wipe((*j)["private_key"].get_ref<std::string&>());
    }
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

// --- registry --------------------------------------------------------------------------------

void Store::saveRegistry(const Registry& reg) const {
    json users = json::array();
    for (const auto& u : reg.users) {
        users.push_back({{"name", u.name}, {"uid", u.uid}, {"role", u.role}, {"fpr", u.fpr}});
    }
    putObject(objectPath("registry"), "registry", {{"users", users}});
}

std::optional<Registry> Store::loadRegistry() const {
    auto doc = getObject(objectPath("registry"), "registry", 3);
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

void Store::saveTree(const std::string& uid, const json& tree) const {
    if (!isLowerHex(uid, kUidHexLen)) throw std::runtime_error("invalid uid");
    putObject(objectPath(treeLabel(uid)), treeLabel(uid), tree);
}

std::optional<json> Store::loadTree(const std::string& uid) const {
    if (!isLowerHex(uid, kUidHexLen)) return std::nullopt;
    auto tree = getObject(objectPath(treeLabel(uid)), treeLabel(uid), kMaxJsonDepth);
    if (!tree || !isDirNode(*tree) || !validNode(*tree, 0)) return std::nullopt;
    return tree;
}

// --- blobs -----------------------------------------------------------------------------------

void Store::saveBlob(const std::string& ownerUid, const std::string& blob, const std::string& content) const {
    if (!isLowerHex(ownerUid, kUidHexLen) || !isLowerHex(blob, kBlobHexLen)) throw std::runtime_error("invalid id");
    json doc = {{"content", content}};
    putObject(objectPath(blobLabel(ownerUid, blob)), blobLabel(ownerUid, blob), doc);
    wipe(doc["content"].get_ref<std::string&>());
}

std::optional<std::string> Store::loadBlob(const std::string& ownerUid, const std::string& blob) const {
    if (!isLowerHex(ownerUid, kUidHexLen) || !isLowerHex(blob, kBlobHexLen)) return std::nullopt;
    auto doc = getObject(objectPath(blobLabel(ownerUid, blob)), blobLabel(ownerUid, blob), 1);
    std::string content;
    if (!doc || !hasExactKeys(*doc, {"content"}) || !getString(*doc, "content", content)) return std::nullopt;
    return content;
}

// --- shares ----------------------------------------------------------------------------------
// One object per recipient: {"shares":[{"owner","blob","path"},...]}, label
// "share|<recipient-uid>". The label (and thus the AAD) names the recipient, so
// a list copied to another user's object fails authentication.

std::optional<std::vector<ShareRec>> Store::loadShares(const std::string& recipientUid) const {
    if (!isLowerHex(recipientUid, kUidHexLen)) return std::nullopt;
    const fs::path path = objectPath(shareLabel(recipientUid));
    std::error_code ec;
    if (!fs::exists(fs::symlink_status(path, ec))) return std::vector<ShareRec>{};  // nothing shared yet
    auto doc = getObject(path, shareLabel(recipientUid), 3);
    if (!doc || !hasExactKeys(*doc, {"shares"}) || !doc->at("shares").is_array()) return std::nullopt;
    std::vector<ShareRec> out;
    for (const json& e : doc->at("shares")) {
        auto rec = shareFromJson(e);
        if (!rec) return std::nullopt;
        out.push_back(*rec);
    }
    return out;
}

bool Store::saveShare(const std::string& recipientUid, const ShareRec& rec) const {
    if (!isLowerHex(recipientUid, kUidHexLen) || !isLowerHex(rec.ownerUid, kUidHexLen) ||
        !isLowerHex(rec.blob, kBlobHexLen) || !isValidSharePath(rec.path)) {
        throw std::runtime_error("invalid share");
    }
    DirLock lock(fsDir_);  // read-modify-write of a list other sessions also update
    auto shares = loadShares(recipientUid);
    if (!shares) return false;
    // One entry per (owner, file): sharing the same file again is a no-op
    // apart from refreshing its path.
    bool found = false;
    for (ShareRec& r : *shares) {
        if (r.ownerUid == rec.ownerUid && r.blob == rec.blob) {
            r.path = rec.path;
            found = true;
        }
    }
    if (!found) shares->push_back(rec);
    json list = json::array();
    for (const ShareRec& r : *shares) list.push_back(shareJson(r));
    putObject(objectPath(shareLabel(recipientUid)), shareLabel(recipientUid), {{"shares", list}});
    return true;
}

}  // namespace bibifi
