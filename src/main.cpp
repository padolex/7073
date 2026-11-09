// fileserver - encrypted secure file system middleware (CMPT 785 BIBIFI).
//
// Usage: ./fileserver <keyfile>
#include <iostream>
#include <string>

#include "shell.h"
#include "storage.h"

using namespace bibifi;

namespace {

// Reads one line from stdin without letting an attacker grow it unboundedly.
// Over-long lines are truncated to kMaxLineLength + 1 so they are rejected.
bool readLine(std::istream& in, std::string& line) {
    line.clear();
    char c = 0;
    bool any = false;
    while (in.get(c)) {
        any = true;
        if (c == '\n') return true;
        if (line.size() <= kMaxLineLength) line.push_back(c);
    }
    return any;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cout << "Usage: ./fileserver keyfile_name\n";
        return 1;
    }

    Store store(fs::current_path());
    // Keys exist but the filesystem is gone or empty: it was deleted or rolled
    // back to nothing. Re-initialising would replace admin_keyfile, so refuse.
    if (store.isWiped()) {
        std::cout << "Error: filesystem missing; refusing to re-initialise\n";
        return 1;
    }
    try {
        if (store.needsInit()) store.initialize();
    } catch (const std::exception&) {
        std::cout << "Error: could not initialise filesystem\n";
        return 1;
    }

    // ./filesystem must be the state ./internal/state records: a restored old
    // snapshot (or a fork of one) is refused before anyone logs in.
    if (auto root = store.loadRoot(); root && store.checkFresh(*root) != Store::Freshness::Current) {
        std::cout << "Error: filesystem change detected\n";
        return 1;
    }

    auto id = login(store, argv[1]);
    if (!id) {
        std::cout << "Invalid keyfile\n";
        return 1;
    }
    std::cout << "Logged in as " << id->name << "\n";

    Shell shell(store, std::move(*id), std::cout);
    shell.printHelp();
    std::string line;
    while (true) {
        std::cout << shell.prompt() << std::flush;
        if (!readLine(std::cin, line)) break;
        if (!shell.execute(line)) break;
        std::cout.flush();
    }
    return 0;
}
