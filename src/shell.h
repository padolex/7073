// shell.h - authentication and the interactive command interpreter.
//
// The shell is the reference monitor: every access-control decision
// (read-only /shared, admin read-only outside its own /personal, no writes
// in "/", only owners share) is made here, and the
// encryption under the master key (storage.h) guarantees that nothing can be
// learned or forged by bypassing it and using the host directory directly.
#pragma once

#include <iosfwd>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "crypto.h"
#include "storage.h"

namespace bibifi {

struct Identity {
    std::string name;
    std::string uid;
    bool admin = false;
};

// Returns std::nullopt for any authentication failure ("Invalid keyfile").
std::optional<Identity> login(const Store& store, const fs::path& keyfile);

class Shell {
public:
    Shell(const Store& store, Identity id, std::ostream& out);
    void printHelp();
    std::string prompt();
    // Executes one input line. Returns false when the session should end.
    bool execute(const std::string& line);

private:
    enum class NType { None, Dir, File };
    enum class Area { None, AdminRoot, UserRoot, Personal, Shared };
    struct Loc {
        NType type = NType::None;
        Area area = Area::None;
        std::string targetUid;          // whose data this path refers to
        std::vector<std::string> rest;  // components below /personal or /shared
    };
    // Files one owner shared with this user, as a read-only tree mirroring
    // their paths in the owner's /personal (same node format as the tree).
    struct SharedFrom {
        std::string ownerUid;
        json tree;
    };
    struct UserData {
        json tree;                                  // nested /personal tree (see storage.h)
        std::map<std::string, SharedFrom> shares;   // owner name -> files shared by them
    };
    struct Walk {
        std::vector<std::string> comps;
        NType type;
    };
    struct CreateTarget {
        std::string targetUid;
        std::vector<std::string> parent;  // components below /personal
        std::string leaf;
    };

    const Store& store_;
    Identity id_;
    std::ostream& out_;
    std::vector<std::string> cwd_;

    // Reloaded for every command so concurrent sessions (e.g. a new share or
    // a new user) are always observed.
    Registry reg_;
    std::map<std::string, UserData> cache_;

    void refresh();
    UserData& data(const std::string& uid);
    Loc locate(const std::vector<std::string>& comps);
    std::optional<Walk> walk(const std::string& path);
    std::optional<CreateTarget> resolveCreateTarget(const std::string& arg);

    void cmdCd(const std::string& path);
    void cmdPwd();
    void cmdLs();
    void cmdCat(const std::string& path);
    void cmdShare(const std::string& path, const std::string& user);
    void cmdMkdir(const std::string& path);
    void cmdMkfile(const std::string& path, const std::string& contents);
    void cmdAdduser(const std::string& user);
};

}  // namespace bibifi
