#include "shell.h"

#include <ostream>
#include <set>

namespace bibifi {

namespace {

struct IntegrityError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

std::string nextToken(const std::string& s, std::size_t& pos) {
    while (pos < s.size() && s[pos] == ' ') ++pos;
    std::size_t start = pos;
    while (pos < s.size() && s[pos] != ' ') ++pos;
    return s.substr(start, pos - start);
}

// Never let stored bytes drive the terminal. mkfile already accepts only
// printable ASCII, so this is defence in depth against stored control bytes.
std::string sanitizeForTerminal(const std::string& s) {
    std::string out = s;
    for (char& c : out) {
        unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x20 || u > 0x7E) c = '?';
    }
    return out;
}


}  // namespace

// --- authentication ----------------------------------------------------------------

std::optional<Identity> login(const Store& store, const fs::path& keyfile) {
    try {
        // 1. Parse the keyfile. Its fields are claims, not facts.
        auto kf = store.readKeyfile(keyfile);
        if (!kf) return std::nullopt;

        // 2. The registry is authenticated with the master key, so only this
        //    program can have written it. It must list this uid under this
        //    exact name, with this exact key.
        auto reg = store.loadRegistry();
        if (!reg) return std::nullopt;
        const UserRec* me = reg->byUid(kf->uid);
        if (me == nullptr || me->name != kf->username || !constTimeEqual(me->fpr, fingerprint(kf->priv.get()))) {
            return std::nullopt;
        }

        // 3. SSH-style public-key authentication: sign a fresh challenge and
        //    verify it with public_keys/<uid>.pem, which must itself match the
        //    fingerprint pinned in the registry.
        PKey pub = store.loadPinnedPublicKey(me->uid, me->fpr);
        if (!pub || !proveKeyPossession(kf->priv.get(), pub.get())) return std::nullopt;

        Identity id;
        id.name = me->name;
        id.uid = me->uid;
        id.admin = me->isAdmin();
        return id;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// --- shell ---------------------------------------------------------------------------

Shell::Shell(const Store& store, Identity id, std::ostream& out) : store_(store), id_(std::move(id)), out_(out) {}

void Shell::printHelp() {
    out_ << "Available commands:\n";
    out_ << "  cd <directory>\n";
    out_ << "  pwd\n";
    out_ << "  ls\n";
    out_ << "  cat <filename>\n";
    out_ << "  share <filename> <username>\n";
    out_ << "  mkdir <directory_name>\n";
    out_ << "  mkfile <filename> <contents>\n";
    if (id_.admin) out_ << "  adduser <username>\n";
    out_ << "  exit\n";
}

void Shell::refresh() {
    cache_.clear();
    auto reg = store_.loadRegistry();
    if (!reg) throw IntegrityError("filesystem integrity check failed");
    reg_ = std::move(*reg);
}

Shell::UserData& Shell::data(const std::string& uid) {
    auto it = cache_.find(uid);
    if (it != cache_.end()) return it->second;

    // Only locate() calls this, and it only ever names the caller's own uid
    // or, for the admin, another user's uid (read-only).
    UserData d;
    auto tree = store_.loadTree(uid);
    if (!tree) throw IntegrityError("filesystem integrity check failed");
    d.tree = std::move(*tree);

    auto shares = store_.loadShares(uid);
    if (!shares) throw IntegrityError("filesystem integrity check failed");
    for (const ShareRec& r : *shares) {
        const UserRec* owner = reg_.byUid(r.ownerUid);
        if (owner == nullptr || owner->uid == uid) continue;
        SharedFrom& from = d.shares[owner->name];
        if (from.tree.is_null()) {
            from.ownerUid = owner->uid;
            from.tree = makeDirNode();
        }
        // Rebuild the owner's path: /shared/<owner>/a/b/file. Intermediate
        // directories exist only as far as shared files need them.
        const auto comps = splitPath(r.path);
        json* dir = &from.tree;
        for (std::size_t i = 0; dir != nullptr && i + 1 < comps.size(); ++i) {
            json& children = dir->at("children");
            if (!children.contains(comps[i])) children[comps[i]] = makeDirNode();
            dir = isDirNode(children[comps[i]]) ? &children[comps[i]] : nullptr;
        }
        // A path can only clash with another share if the stored list is
        // inconsistent; the first entry wins and the rest are ignored.
        if (dir != nullptr && !dir->at("children").contains(comps.back())) {
            dir->at("children")[comps.back()] = makeFileNode(r.blob);
        }
    }
    return cache_.emplace(uid, std::move(d)).first->second;
}

// Maps a virtual absolute path to the data it denotes.
//   user  view:  /personal/...  /shared/<owner>/<path in owner's /personal>
//   admin view:  /personal/...  /shared/<owner>/<path>            (the admin's own)
//                /<user>/personal/...  /<user>/shared/<owner>/<path>   (read-only)
// "personal" and "shared" are reserved usernames, so the admin root is unambiguous.
Shell::Loc Shell::locate(const std::vector<std::string>& comps) {
    Loc l;
    std::size_t idx = 0;
    if (id_.admin) {
        if (comps.empty()) {
            l.type = NType::Dir;
            l.area = Area::AdminRoot;
            return l;
        }
        if (comps[0] == "personal" || comps[0] == "shared") {
            l.targetUid = id_.uid;
        } else {
            const UserRec* u = reg_.byName(comps[0]);
            if (u == nullptr || u->isAdmin()) return l;
            l.targetUid = u->uid;
            idx = 1;
        }
    } else {
        l.targetUid = id_.uid;
    }
    if (comps.size() == idx) {
        l.type = NType::Dir;
        l.area = Area::UserRoot;
        return l;
    }
    const std::string& area = comps[idx];
    l.rest.assign(comps.begin() + static_cast<std::ptrdiff_t>(idx) + 1, comps.end());
    if (area == "personal") {
        l.area = Area::Personal;
        if (l.rest.empty()) {
            l.type = NType::Dir;
        } else {
            const json* node = findNode(data(l.targetUid).tree, l.rest);
            if (node != nullptr) l.type = isDirNode(*node) ? NType::Dir : NType::File;
        }
    } else if (area == "shared") {
        l.area = Area::Shared;
        const auto& sh = data(l.targetUid).shares;
        if (l.rest.empty()) {
            l.type = NType::Dir;
        } else if (auto it = sh.find(l.rest[0]); it != sh.end()) {
            const json* node = findNode(it->second.tree, {l.rest.begin() + 1, l.rest.end()});
            if (node != nullptr) l.type = isDirNode(*node) ? NType::Dir : NType::File;
        }
    }
    return l;
}

// Resolves a relative or absolute path one component at a time, so that
// "missing/.." fails just like it does on a real filesystem. ".." at the root
// stays at the root: the user can never climb out of their own view.
std::optional<Shell::Walk> Shell::walk(const std::string& path) {
    Walk w{path.empty() || path[0] != '/' ? cwd_ : std::vector<std::string>{}, NType::Dir};
    const auto parts = splitPath(path);
    for (std::size_t i = 0; i < parts.size(); ++i) {
        const std::string& p = parts[i];
        if (p == ".") continue;
        if (p == "..") {
            if (!w.comps.empty()) w.comps.pop_back();
            w.type = NType::Dir;
            continue;
        }
        w.comps.push_back(p);
        Loc l = locate(w.comps);
        if (l.type == NType::None) return std::nullopt;
        if (l.type == NType::File && i + 1 < parts.size()) return std::nullopt;
        w.type = l.type;
    }
    return w;
}

std::string Shell::prompt() const { return id_.name + ":/" + joinPath(cwd_) + "> "; }

bool Shell::execute(const std::string& rawLine) {
    std::string line = rawLine;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.size() > kMaxLineLength || !isPrintableAscii(line)) {
        out_ << "Invalid Command\n";
        return true;
    }

    std::size_t pos = 0;
    const std::string cmd = nextToken(line, pos);
    if (cmd.empty()) return true;  // blank line

    try {
        refresh();
        if (cmd == "mkfile") {
            // Contents are the raw remainder of the line (may contain spaces).
            std::string name = nextToken(line, pos);
            while (pos < line.size() && line[pos] == ' ') ++pos;
            std::string contents = line.substr(pos);
            if (name.empty() || contents.empty()) {
                out_ << "Invalid Command\n";
            } else {
                cmdMkfile(name, contents);
            }
            return true;
        }

        std::vector<std::string> args;
        for (std::string t = nextToken(line, pos); !t.empty(); t = nextToken(line, pos)) args.push_back(t);

        if (cmd == "exit" && args.empty()) return false;
        if (cmd == "pwd" && args.empty()) {
            cmdPwd();
        } else if (cmd == "ls" && args.empty()) {
            cmdLs();
        } else if (cmd == "cd" && args.size() == 1) {
            cmdCd(args[0]);
        } else if (cmd == "cat" && args.size() == 1) {
            cmdCat(args[0]);
        } else if (cmd == "share" && args.size() == 2) {
            cmdShare(args[0], args[1]);
        } else if (cmd == "mkdir" && args.size() == 1) {
            cmdMkdir(args[0]);
        } else if (cmd == "adduser" && args.size() == 1 && id_.admin) {
            cmdAdduser(args[0]);
        } else {
            out_ << "Invalid Command\n";
        }
    } catch (const IntegrityError& e) {
        out_ << "Error: " << e.what() << "\n";
    } catch (const std::exception&) {
        out_ << "Error: operation failed\n";
    }
    return true;
}

void Shell::cmdCd(const std::string& path) {
    auto w = walk(path);
    if (w && w->type == NType::Dir) cwd_ = w->comps;
    // Otherwise stay in the current directory (spec).
}

void Shell::cmdPwd() { out_ << "/" << joinPath(cwd_) << "\n"; }

void Shell::cmdLs() {
    std::set<std::string> dirs;
    std::set<std::string> files;
    Loc l = locate(cwd_);
    switch (l.area) {
        case Area::AdminRoot:
            dirs.insert("personal");
            dirs.insert("shared");
            for (const auto& u : reg_.users) {
                if (!u.isAdmin()) dirs.insert(u.name);
            }
            break;
        case Area::UserRoot:
            dirs.insert("personal");
            dirs.insert("shared");
            break;
        case Area::Personal: {
            const json* node = findNode(data(l.targetUid).tree, l.rest);
            if (node != nullptr && isDirNode(*node)) {
                const json& children = node->at("children");
                for (auto it = children.begin(); it != children.end(); ++it) {
                    (isDirNode(it.value()) ? dirs : files).insert(it.key());
                }
            }
            break;
        }
        case Area::Shared: {
            const auto& sh = data(l.targetUid).shares;
            if (l.rest.empty()) {
                for (const auto& kv : sh) dirs.insert(kv.first);
            } else if (auto it = sh.find(l.rest[0]); it != sh.end()) {
                const json* node = findNode(it->second.tree, {l.rest.begin() + 1, l.rest.end()});
                if (node != nullptr && isDirNode(*node)) {
                    const json& children = node->at("children");
                    for (auto c = children.begin(); c != children.end(); ++c) {
                        (isDirNode(c.value()) ? dirs : files).insert(c.key());
                    }
                }
            }
            break;
        }
        case Area::None:
            break;
    }
    out_ << "d -> .\n";
    out_ << "d -> ..\n";
    for (const auto& d : dirs) out_ << "d -> " << d << "\n";
    for (const auto& f : files) out_ << "f -> " << f << "\n";
}

void Shell::cmdCat(const std::string& path) {
    auto w = walk(path);
    if (!w || w->type != NType::File) {
        out_ << path << " doesn't exist\n";
        return;
    }
    Loc l = locate(w->comps);
    std::optional<std::string> content;
    if (l.area == Area::Personal) {
        content = store_.loadBlob(l.targetUid, fileBlob(*findNode(data(l.targetUid).tree, l.rest)));
    } else {
        const SharedFrom& from = data(l.targetUid).shares.at(l.rest[0]);
        content = store_.loadBlob(from.ownerUid, fileBlob(*findNode(from.tree, {l.rest.begin() + 1, l.rest.end()})));
    }
    if (!content) throw IntegrityError("filesystem integrity check failed");
    out_ << sanitizeForTerminal(*content) << "\n";
}

// Common validation for mkdir/mkfile. Prints the error and returns nullopt on
// failure; otherwise returns the parent directory (below /personal) and leaf.
std::optional<Shell::CreateTarget> Shell::resolveCreateTarget(const std::string& arg) {
    std::string p = arg;
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    if (p == "/") {
        out_ << "Forbidden\n";
        return std::nullopt;
    }
    std::string parentStr;
    std::string leaf;
    auto slash = p.rfind('/');
    if (slash == std::string::npos) {
        parentStr = ".";
        leaf = p;
    } else {
        parentStr = slash == 0 ? "/" : p.substr(0, slash);
        leaf = p.substr(slash + 1);
    }

    if (leaf == "." || leaf == "..") {
        // Names an existing directory: the root and /shared stay forbidden.
        auto w = walk(p);
        if (!w) {
            out_ << "Directory doesn't exist\n";
            return std::nullopt;
        }
        Loc l = locate(w->comps);
        const bool own = l.area == Area::Personal && l.targetUid == id_.uid;
        out_ << (own ? "Directory already exists\n" : "Forbidden\n");
        return std::nullopt;
    }

    auto parent = walk(parentStr);
    if (!parent || parent->type != NType::Dir) {
        out_ << "Directory doesn't exist\n";
        return std::nullopt;
    }
    Loc pl = locate(parent->comps);
    // Writes are allowed only below the caller's OWN /personal: never in "/",
    // anywhere under /shared, or (for the admin) in another user's directory.
    if (pl.area != Area::Personal || pl.targetUid != id_.uid) {
        out_ << "Forbidden\n";
        return std::nullopt;
    }
    if (!isValidName(leaf) || pl.rest.size() + 1 > kMaxDirDepth) {
        out_ << "Invalid Command\n";
        return std::nullopt;
    }
    return CreateTarget{pl.targetUid, pl.rest, leaf};
}

void Shell::cmdMkdir(const std::string& path) {
    auto t = resolveCreateTarget(path);
    if (!t) return;
    UserData& d = data(t->targetUid);
    json updated = d.tree;
    json& children = findNode(updated, t->parent)->at("children");
    auto it = children.find(t->leaf);
    if (it != children.end()) {
        out_ << (isDirNode(*it) ? "Directory already exists\n" : "File already exists\n");
        return;
    }
    children[t->leaf] = makeDirNode();
    store_.saveTree(t->targetUid, updated);
}

void Shell::cmdMkfile(const std::string& path, const std::string& contents) {
    auto t = resolveCreateTarget(path);
    if (!t) return;
    UserData& d = data(t->targetUid);
    json updated = d.tree;
    json& children = findNode(updated, t->parent)->at("children");
    auto it = children.find(t->leaf);
    if (it != children.end()) {
        if (isDirNode(*it)) {
            out_ << "Directory already exists\n";
            return;
        }
        // Overwrite in place: same blob id, fresh nonce. Every share record
        // keeps pointing at this blob, so recipients see the new contents.
        store_.saveBlob(t->targetUid, fileBlob(*it), contents);
        return;
    }
    const std::string blob = randomHex(kBlobHexLen / 2);
    store_.saveBlob(t->targetUid, blob, contents);  // blob first, then commit the tree
    children[t->leaf] = makeFileNode(blob);
    store_.saveTree(t->targetUid, updated);
}

void Shell::cmdShare(const std::string& path, const std::string& user) {
    auto w = walk(path);  // the first check is on the file (spec)
    if (!w || w->type != NType::File) {
        out_ << "File " << path << " doesn't exist\n";
        return;
    }
    Loc l = locate(w->comps);
    // Only the owner can share a file: not a file shared with you (FAQ 2), and
    // not, for the admin, a file in another user's directory.
    if (l.area != Area::Personal || l.targetUid != id_.uid) {
        out_ << "Forbidden\n";
        return;
    }
    const UserRec* target = reg_.byName(user);
    if (target == nullptr) {
        out_ << "User " << user << " doesn't exist\n";
        return;
    }
    if (target->uid == id_.uid) {
        out_ << "Forbidden\n";
        return;
    }
    ShareRec rec;
    rec.ownerUid = id_.uid;
    rec.blob = fileBlob(*findNode(data(l.targetUid).tree, l.rest));
    rec.path = joinPath(l.rest);  // e.g. "a/file": shown as /shared/<me>/a/file
    if (!store_.saveShare(target->uid, rec)) throw IntegrityError("filesystem integrity check failed");
}

void Shell::cmdAdduser(const std::string& user) {
    if (!isValidUsername(user)) {  // also blocks path traversal in "<user>_keyfile"
        out_ << "Invalid username\n";
        return;
    }
    if (reg_.byName(user) != nullptr) {
        out_ << "User " << user << " already exists\n";
        return;
    }
    PKey key = generateUserKey();
    std::string uid;
    do {
        uid = randomHex(kUidHexLen / 2);
    } while (reg_.byUid(uid) != nullptr);

    store_.writePublicKey(uid, key.get());
    store_.saveTree(uid, makeDirNode());
    store_.writeKeyfile(user, uid, key.get());

    // The registry is the commit point: the user exists only once it is
    // listed here.
    Registry updated = reg_;
    updated.users.push_back({user, uid, "user", fingerprint(key.get())});
    store_.saveRegistry(updated);
}

}  // namespace bibifi
