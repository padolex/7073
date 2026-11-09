# cc-new: Encrypted Secure File System, single-master-key variant

A third implementation of the CMPT 785 BIBIFI `fileserver`, written in **C++17 using only the STL,
OpenSSL 3 (`libcrypto`) and nlohmann/json**, all approved libraries. It builds as a **standalone
static executable**.

The commands, messages and access rules are the same as in [`../cc`](../cc). What differs is the
storage design:

* **Every file under `filesystem/` is encrypted with one server master key** embedded in the
  executable. There are no per-user or per-file keys.
* **All data is stored as JSON** (nlohmann/json), and each JSON document is encrypted as a whole.
  Not a single byte of plaintext JSON is on disk.

Details:
- [`ARCH.md`](ARCH.md): architecture and the JSON schema of every stored object.
- [`crypto.md`](crypto.md): how the cryptography works: keys, encryption, naming, login,
  guarantees and limits.

| | |
|---|---|
| Language | C++17, STL (incl. `std::filesystem`) |
| Libraries | OpenSSL 3 `libcrypto`; nlohmann/json 3.11.3, header-only, vendored in `third_party/` (MIT) |
| Binary | **static-PIE** ELF, full RELRO, stack protector, `_FORTIFY_SOURCE=2`, zero compiler warnings |
| Tests | `tests/run_tests.sh`: 98 end-to-end checks; also clean under ASan + UBSan (`make test-asan`) |

---

## 1. Key design: one master key

```
            K_M  (32 bytes, compiled into the binary: src/internal_secret.h)
       HKDF  ┌──────────┴───────────┐  HKDF
             ▼                      ▼
   K_enc ("bibifi-new/v1/encryption")   K_names ("bibifi-new/v1/names")
   AES-256-GCM of EVERY object          HMAC-SHA-256 name of every object

   user Ed25519 key pair (keyfile)  ──►  login only (SSH-style challenge/response)
```

* `K_M` is an **internal secret** under course clarification 2: a key held inside the program. It
  is never written to disk or placed in a keyfile.
* `K_M` is used only through two HKDF subkeys, so the encryption key and the naming key are
  independent.
* **User key pairs are only for authentication.** They don't encrypt data. The program decrypts
  everything with `K_enc` and enforces access control itself.

### Why a single master key (and what it costs)

The course allows either a single master key or per-user keys, and asks for the choice to be
explained.

**What the single master key buys:**
- A far smaller design. There are no key envelopes, file keys, admin signatures or per-object
  signatures: `../cc` needs about 1,150 lines of storage and crypto code, this variant about 850.
- Every confidentiality requirement holds without the master key. File contents, file and
  directory names, tree structure, usernames, who owns what, and who shared with whom are all
  inside AES-GCM ciphertext under `K_enc`, or hidden behind HMAC names under `K_names`.
- Integrity comes free from AES-GCM. A forged, edited, copied or moved object fails
  authentication, because every object's associated data names its exact location (§2).
- Sharing and the admin's read-everything rule are just access-control decisions: no keys to
  distribute or wrap.

**What it costs:**
- **All security rests on `K_M`.** Anyone who extracts it from the binary can read and forge
  everything. Under clarification 2 that is not a valid attack, because compiled-in keys are
  internal secrets. `../cc` is the defence-in-depth alternative: with per-user keys and
  signatures, a leaked `K_M` reveals neither file contents nor names and allows no forgery.
- **Access control is enforced only by the program.** Users have no keys that separate their
  data cryptographically. That is fine under the course model, where all access goes through the
  binary.

---

## 2. On-disk format

```
./<user>_keyfile                JSON keyfile with the user's Ed25519 private key (0600, never modified)
./public_keys/<uid>.pem         Ed25519 public keys, named by an opaque random 128-bit uid
./internal/state                the current root's epoch and SHA-256, encrypted (ASSUMED SAFE, see below)
./filesystem/<N(label)>         every object, in ONE flat directory
                                N(label) = hex HMAC-SHA-256(K_names, label)
```

Every file in `filesystem/` has exactly this format:

```
nonce (12 bytes) || AES-256-GCM_K_enc( pad256( JSON document ) ) || tag (16 bytes)
associated data = "bibifi-new/v2|" + label          (labels include a version)
```

| Label | JSON document after decryption | Written by |
|---|---|---|
| `root` | `{"epoch":E, "registry":REF, "trees":{uid:REF}, "shares":{uid:REF}}` | every change (commit point) |
| `registry\|<ver>` | `{"users":[{"name","uid","role","fpr"}, …]}` (exactly one `admin`) | `init`, `adduser` |
| `tree\|<uid>\|<ver>` | the user's `/personal` tree as nested JSON (below) | `mkdir`, `mkfile` |
| `blob\|<uid>\|<blob>\|<ver>` | `{"content": "<file contents>"}` | `mkfile` |
| `share\|<uid>\|<ver>` | every file shared **with** that user: `{"shares":[{"owner","blob","path"}, …]}` | `share` |

`REF` is `{"ver": n, "hash": "<SHA-256 of the child's bytes on disk>"}`. The nested tree after
decryption:

```json
{"type":"dir","children":{
  "docs":{"type":"dir","children":{
    "a.txt":{"type":"file","blob":"94219130b2c9fc4b096a5197ec4a817e","ver":8,
             "hash":"6510494aed965eb9e80fe295a5a4dc52a7c7a21dfccb5068eb1012998d292a2a"}}}}}
```

**The objects form a Merkle tree.** The root references the current version of the registry,
every tree and every share list; each tree references the current version of each of its files.
Every change writes **new versions under new names**, then the new root (epoch + 1) as the single
commit point, then deletes the replaced versions. Every read checks each link's hash. Details are
in `ARCH.md` §3–§8.

A share entry names the owner's file and its path, and is checked against the owner's current
tree, so recipients always see the owner's latest contents. The entry's `path` is the file's
location in the owner's `/personal`, so Bob sharing `a/file` with Alice appears to her as
`/shared/bob/a/file`. Same-name files from different folders don't clash.

**One writing session at a time.** There are no locks (standard C++ has none). Sessions that only
read are always safe. If two sessions commit at the same instant, the second one aborts with
`Error: filesystem changed by another session, try again` instead of overwriting the other's
change.

### What a host observer sees

- Only 64-hex names in one flat directory, with no subdirectories.
- Sizes in 256-byte steps (284, 540, …).
- No username, uid, file or directory name, contents, tree shape, ownership or sharing relation.
  The tests check this.

### What tampering and rollback do

The associated data names each object's owner, location and version, and each parent pins its
children's hashes. So:
- copying Bob's tree or share list over Alice's, swapping two files' contents, putting an old
  version under a current name, a flipped bit, or plaintext junk all fail;
- restoring old versions under their old names does nothing: nothing references them;
- restoring a **complete**, consistent old snapshot of `filesystem/` is caught too:
  `internal/state` records which root is current, and is checked at start-up and before every
  command. This works for every user, even those who never saw the newer state;
- a crash between writing a new root and `internal/state` is recognised (the root is exactly one
  epoch ahead) and repaired;
- an empty or deleted `filesystem/` is refused while keys exist; it is never re-initialised over
  `admin_keyfile`.

> **Assumption, to confirm with the teaching team:** `internal/` (next to the binary) is **safe**:
> clients can't read, modify or restore it. The spec protects only keyfiles, so this is an extra
> assumption ("Any more assumptions, you can run it by the teaching team"). Keyfiles stay static.
> If the assumption is rejected, an attacker who restores `filesystem/` *and* `internal/` together
> rolls back undetected, and only partial rollbacks are caught.

The results are `Error: filesystem integrity check failed`, `Error: filesystem change detected`,
or `Invalid keyfile` if the root or registry is damaged.

---

## 3. Keyfiles and login

```json
{
  "private_key": "-----BEGIN PRIVATE KEY-----\n…Ed25519 PKCS#8…\n-----END PRIVATE KEY-----\n",
  "type": "bibifi.keyfile",
  "uid": "4d8cbbd92b3a01e87ccb976023891e7b",
  "user": "alice",
  "v": 1
}
```

The keyfile is the user's credential and lives outside `filesystem/`. It isn't encrypted, so it
looks and works like an SSH private key. Its fields are claims, checked at login (`login()` in
`src/shell.cpp`):

1. **Parse** strictly: exact keys and types, username charset, a 32-hex uid, an **Ed25519** key
   only, no encrypted PEM, at most 64 KiB, nesting depth 1.
2. **Registry** (decrypted and authenticated with `K_enc`; only this program can have written it):
   the entry for `uid` must have **this username** and **this key's fingerprint**.
3. **SSH-style public-key authentication:** `public_keys/<uid>.pem` must match the fingerprint in
   the registry, and the keyfile's private key must sign a fresh 32-byte random challenge that
   verifies under it.

The keyfile is **static**: written once by `adduser` and never modified; sessions only read it.

Any failure prints `Invalid keyfile`. The admin flag comes from the registry's role
for the user's own uid, never from the keyfile.

| Attack | Result |
|---|---|
| Edit `user`, or `uid` + `user`, in your keyfile | rejected at step 2 (name or fingerprint mismatch) |
| Keyfile with a self-generated key for someone else's uid | rejected at step 2 |
| RSA (non-Ed25519) key, nesting bomb, extra field, wrong type, trailing data | rejected at step 1 |
| Replace someone's `public_keys/<uid>.pem` | that user can't log in (denial of service), but nobody can impersonate them |
| A keyfile from another filesystem | rejected (its uid isn't in this registry) |

---

## 4. Behaviour

The same as `../cc` (see `../cc/REPORT.md` §7 for every message):

* Users see `/personal` (read/write) and `/shared/<owner>/<path>` (read-only), where `<path>` is
  the file's path in the owner's `/personal`. Creating anything in `/` or anywhere under `/shared`
  prints `Forbidden`.
* **The admin is a regular user** with its own `/personal` and `/shared`, and can share its own
  files. Its `/` also lists one directory per user. The admin can read all of them but never
  modify or share from them (`Forbidden`). `personal` and `shared` are reserved usernames.
* **Only the owner shares a file.** Re-sharing a file shared with you, or sharing with yourself,
  is `Forbidden`. Users can share with the admin.
* Directory depth is capped at 64 levels below `/personal` (`Invalid Command` beyond), which
  bounds JSON nesting.
* **Prompt.** Before every command the shell prints `<user>:/<cwd>> `, for example
  `alice:/personal/docs> `, using `std::cout` only. Standard C++ can't tell a terminal from a pipe,
  so the prompt is printed in both cases: piped output contains the prompts too (the test suite
  strips them).
* **Standard C++ only.** Apart from OpenSSL and nlohmann/json, the code uses only the C++17
  standard library. It makes no POSIX calls (`umask`, `isatty`, `flock`); see "Secure-coding
  choices" for how keyfiles stay private without `umask`.

---

## 5. Secure-coding choices

* **No custom cryptography.** Every primitive is an OpenSSL 3 EVP call: AES-256-GCM, HMAC-SHA-256,
  HKDF-SHA-256, Ed25519, `RAND_bytes`.
* **Authenticate before parsing.** An object's bytes reach the JSON parser only after the GCM tag
  verifies under `K_enc`.
* **Hostile-JSON hygiene** (`src/jsonio.cpp`):
  - a string-aware depth limit checked *before* parsing;
  - `allow_exceptions=false` parsing that rejects trailing data;
  - exact key sets (`hasExactKeys`) and type-checked getters only;
  - every id, name and username validated after parsing.
* **Fresh randomness:** a random 96-bit nonce per encryption, a 128-bit random uid per user and
  blob id per file, and a fresh challenge per login.
* **Size hiding:** plaintexts are length-prefixed and padded to 256-byte buckets.
* **Safe files:**
  - atomic writes (temporary file, then `rename`);
  - keyfiles are written inside a fresh directory that is made owner-only before anything is
    created in it, set to 0600, and then renamed into place, so no other account can open them
    at any point. This uses only `std::filesystem`, with no `umask`;
  - symlinked or non-regular objects refused;
  - size caps (64 MiB objects, 64 KiB keyfiles, 1 MiB input lines);
  - ids validated as fixed-length hex before use in any path, so there is no path traversal.
* **Secret hygiene:** keys live in `Key256`, which is wiped with `OPENSSL_cleanse`. Decrypted
  plaintexts and PEM strings are wiped after use, and private keys are serialised through
  OpenSSL's secure heap.
* **Output safety:** mkfile accepts only printable ASCII. `cat` replaces any control byte, so no
  terminal escape sequences can be injected.
* **Fails closed:** tampered data gives `Error: filesystem integrity check failed` and is never
  shown. Every authentication failure gives the same `Invalid keyfile`.

### Known limitations

* **Rollback protection depends on `internal/` being safe.** If clients can restore `internal/`
  together with `filesystem/`, a complete old snapshot is accepted. Partial rollbacks are always
  caught. See `crypto.md` §7.3.
* **Denial of service:** anyone with write access to the host can delete or corrupt objects. The
  program fails closed but can't prevent it.
* **Metadata:** object counts, size classes and modification times are visible. Someone who
  watches which objects change, and when, can link objects to users (see `crypto.md` §7.5); no
  stored byte reveals it.
* **The master key is the single point of trust** (§1), and keyfiles are bearer credentials
  (required by the spec: no passphrase).

---

## 6. Build

### Requirements

| | Tested with |
|---|---|
| OS | Ubuntu 24.04 (x86-64) |
| Compiler | g++ 13.3 (any g++ with C++17 and `<filesystem>`, i.e. g++ 9+) |
| OpenSSL | 3.0.13: headers and the **static** `libcrypto.a` |
| nlohmann/json | vendored in `third_party/`, nothing to install |

```bash
sudo apt-get install build-essential libssl-dev
```

### Build and check

```bash
cd cc-new
make                  # -> ./fileserver   ("linked fileserver (static-pie)")
file fileserver       # ... static-pie linked ...
ldd fileserver        # statically linked
```

glibc prints warnings that `dlopen`/`getaddrinfo` in static binaries need shared libraries. Those
calls are in OpenSSL code this program never calls, so the `Makefile` filters out just those lines.
Real link errors still fail the build.

### Run

`fileserver` creates `filesystem/`, `public_keys/` and keyfiles in the **current directory**, so use
a scratch directory:

```bash
mkdir -p ~/play && cd ~/play && cp /path/to/cc-new/fileserver .
./fileserver admin_keyfile                 # first run creates everything
printf 'adduser alice\nexit\n' | ./fileserver admin_keyfile
./fileserver alice_keyfile
```

This format is **not compatible** with `../cc`. Run each binary in its own directory.

---

## 7. Test

```bash
make test             # 98 checks in a throwaway sandbox (mktemp -d)
```

The suite covers:
- **Functional:** bootstrap, authentication, navigation, files, every error message, a share
  appearing in an already-running session.
- **Admin rules:** the admin as a regular user, read-everything, and `Forbidden` writes in other
  users' directories.
- **Confidentiality:**
  - no plaintext names or contents on disk;
  - every name is 64 hex characters, and no uid appears anywhere;
  - **every object has the AES-GCM shape** (12 + 256·n + 16 bytes), and none contains plaintext
    JSON;
  - padded sizes are equal.
- **Tampering:** a swapped blob, another user's tree copied in, a bit-flipped tree, a corrupted
  root, a corrupted registry, and another user's, bit-flipped, plaintext or symlinked share lists
  (also: a corrupt list is never overwritten by a new share).
- **Versioning and rollback:**
  - each change creates new versions, removes the replaced ones and rewrites only the root;
  - keyfiles are never modified by sessions, and `internal/state` is ciphertext;
  - a complete old snapshot of `filesystem/` is refused, also for a user who never saw the newer
    state, and so is an old root alone;
  - crash recovery: a state one epoch behind is repaired; two behind, or missing, is refused;
  - old versions put back under their old names are ignored;
  - an old version under **every** current name is rejected;
  - a rollback during a running session is caught on the next command;
  - an emptied or deleted `filesystem/` is refused and `admin_keyfile` is untouched.
- **Sharing with paths:** the owner's folders appear under `/shared/<owner>/`, same-name files in
  different folders are both visible, nested shared folders are read-only, unshared siblings stay
  hidden, and shares from several owners to one user are all kept.
- **Keyfile attacks:**
  - edited name or uid, a path-traversal uid;
  - JSON nesting bomb, extra field, wrong type, trailing data;
  - a self-generated Ed25519 key, an RSA key, and a control check that a re-wrapped genuine key is
    accepted;
  - a swapped public key, a foreign filesystem.

To test another build: `BIN=/abs/path/to/binary ./tests/run_tests.sh`.

### Sanitizers (`-fsanitize`)

```bash
make fileserver-asan  # ASan + UBSan, dynamically linked, objects in build-asan/
make test-asan        # whole suite against it; any sanitizer report fails the target
```

`test-asan` builds with `-fsanitize=address,undefined -fno-sanitize-recover=all
-fno-omit-frame-pointer -g -O1` and writes reports to `san-logs/`. Expected output ends with
`passed: 98  failed: 0` and `sanitizers: no reports`. The sanitizer runtimes can't be linked
statically, so this binary is for development only. **Submit `./fileserver`.**

| Target | Result |
|---|---|
| `make` | static release binary `./fileserver` |
| `make test` | build, then run the test suite |
| `make fileserver-asan` / `make test-asan` | sanitizer build / test suite under sanitizers |
| `make clean` | remove binaries, objects, `build-asan/`, `san-logs/` |

---

## 8. Source layout

| Path | Contents |
|---|---|
| `src/main.cpp` | argument check, first-run initialisation, login, bounded input loop |
| `src/shell.h/.cpp` | `login()`, path resolution, access control (the reference monitor), all commands |
| `src/storage.h/.cpp` | encrypted object store: `putObject`/`getObject`, registry, trees, blobs, shares, keyfiles |
| `src/jsonio.h/.cpp` | defensive nlohmann/json helpers (depth limit, exact keys, typed getters) |
| `src/crypto.h/.cpp` | OpenSSL EVP wrappers: AES-256-GCM, HMAC, HKDF, Ed25519 |
| `src/util.h/.cpp` | hex, randomness, safe file reads, atomic writes, memory wiping |
| `src/internal_secret.h` | the compiled-in master key `K_M` |
| `third_party/nlohmann/` | nlohmann/json 3.11.3 (MIT) |
| `tests/run_tests.sh` | end-to-end test suite |
