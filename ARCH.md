# cc-new architecture: how the filesystem is organised as JSON

This document describes how `cc-new` organises its data:
- the program's layers;
- every file it creates on the host;
- the JSON schema of every document it stores;
- how the shell's virtual paths map to stored objects;
- what each command reads and writes;
- how the state stays consistent.

The cryptography (keys, encryption, authentication) is described in [`crypto.md`](crypto.md).

All examples in this document come from **one** real run of the binary, decrypted with the
program's own code:

```
admin: adduser alice; adduser bob
       mkdir /personal/notes; mkfile /personal/notes/todo.txt buy milk
       share /personal/notes/todo.txt alice
alice: mkdir /personal/docs; mkfile /personal/docs/a.txt top secret
       mkfile /personal/readme hello
       share /personal/docs/a.txt bob; share /personal/readme bob
```

Ids from that run, used throughout:

| | uid | Files (blob ids) |
|---|---|---|
| admin | `e1ff97a9208cc8f5128a60c3bd4bf968` | `notes/todo.txt` → `253272c3c0fabb3ada6a10308b469c20` |
| alice | `501fa15f7723a9c8531967daeac2245f` | `docs/a.txt` → `9384233fb27e3d3d6e93b61a9cc43d85`, `readme` → `cad8b2978cc771207cfdb44322cd9a7a` |
| bob | `024294d92600451c21eea7fe1af8317a` | — |

---

## 1. Program layers

```
            stdin / stdout
                  │
┌─────────────────▼────────────────────────────────────────────────────┐
│ main.cpp     arguments · first-run init · login · bounded line reader│
├──────────────────────────────────────────────────────────────────────┤
│ shell.cpp    REFERENCE MONITOR                                       │
│   login()    keyfile → registry → challenge/response → Identity      │
│   Shell      virtual namespace (user view / admin view)              │
│              access control: Forbidden, read-only /shared, owners    │
│              commands: cd pwd ls cat share mkdir mkfile adduser exit │
├──────────────────────────────────────────────────────────────────────┤
│ storage.cpp  ENCRYPTED JSON OBJECT STORE                             │
│   putObject / getObject: JSON ⇄ AES-GCM ciphertext under K_enc       │
│   registry · trees · blobs · share lists · keyfiles · public keys    │
├────────────────────────┬──────────────────────┬──────────────────────┤
│ jsonio.cpp             │ crypto.cpp           │ util.cpp             │
│ strict nlohmann/json   │ OpenSSL EVP wrappers │ safe file I/O, hex,  │
│ parse/dump, typed get  │ AES-GCM HMAC HKDF    │ randomness, wiping   │
│                        │ Ed25519              │                      │
└────────────────────────┴──────────────────────┴──────────────────────┘
```

* **Only `shell.cpp` decides who may do what.** `storage.cpp` stores and authenticates objects but
  makes no access decisions.
* **Only `storage.cpp` knows the on-disk format.** The shell works with plain JSON values (`json`
  trees, `Registry`, `ShareRec`).
* **There is no daemon, cache or background state.** Every command reloads what it needs from
  disk, so concurrent sessions see each other's changes (§7).

---

## 2. Host layout

```
./fileserver                       the binary (contains the master key)
./admin_keyfile, ./<user>_keyfile  JSON keyfiles: the users' credentials (mode 0600)
./public_keys/<uid>.pem            Ed25519 public keys (PEM), one per user
./filesystem/                      the encrypted store: ONE flat directory, no subdirectories
    <64 hex>                       an object: registry, tree, blob or share list
```

From the example run, as any host user sees it:

```
filesystem/
  9 files with 64-hex names: 8 × 284 bytes, 1 × 540 bytes; no directories
public_keys/
  024294d92600451c21eea7fe1af8317a.pem   113 bytes
  501fa15f7723a9c8531967daeac2245f.pem   113 bytes
  e1ff97a9208cc8f5128a60c3bd4bf968.pem   113 bytes
admin_keyfile  alice_keyfile  bob_keyfile           (0600; the names are required by the spec)
```

No stored name or byte says which user, file or share an object belongs to. Watching *which*
objects change and *when* can still reveal relationships; see `crypto.md` §7.5.

---

## 3. Object naming

Every object has a **label**: a short string that says what it is and where it belongs. The label
is never stored. The object's file name is derived from it:

```
file name = hex( HMAC-SHA-256(K_names, label) )        64 hex characters
```

| Label | Object | One per |
|---|---|---|
| `registry` | the user table | filesystem |
| `tree\|<uid>` | the user's `/personal` directory tree | user |
| `blob\|<owner-uid>\|<blob-id>` | one file's contents | file |
| `share\|<uid>` | the list of every file shared **with** `<uid>` | user who has received at least one share |

* `uid`: 32 lowercase hex (128 random bits), assigned at `adduser`.
* `blob-id`: 32 lowercase hex (128 random bits), assigned when a file is first created.

Because names are deterministic, the program can find any object directly. A given file always
lives at the same name, even when its contents are overwritten. Without `K_names`, nobody can
compute a name, link two objects to the same user, or tell which kind an object is. For example:

```
label "registry"                                   → 865eb8daa606139e84ec3231a4a7ddb239f84a0d9715a82b13481f26257da630
label "tree|501fa15f7723a9c8531967daeac2245f"      → 90564c0f22ac4b416138ca47ea4051258ebe49ade367e838351981439d15ec65
label "share|024294d92600451c21eea7fe1af8317a"     → a9d3ec3118212f9817137640486ef1dd81bc66a438c733b90983cc3fe4265ed0
```

---

## 4. Object format (every file under `filesystem/`)

```
┌──────────┬──────────────────────────────────────────────┬──────────┐
│ nonce    │ AES-256-GCM ciphertext of the padded JSON    │ tag      │
│ 12 bytes │ 256 · n bytes                                │ 16 bytes │
└──────────┴──────────────────────────────────────────────┴──────────┘
padded JSON = u32 big-endian length || JSON text (UTF-8) || zero bytes up to a multiple of 256
associated data = "bibifi-new/v1|" + label
```

* Sizes on disk are therefore 284, 540, 796, … bytes (12 + 256·n + 16).
* There is no plaintext header and no plaintext JSON. The whole file is nonce, ciphertext and
  tag.
* `putObject(path, label, doc)` serialises, pads, encrypts and writes atomically.
  `getObject(path, label, maxDepth)` reads (refusing symlinks), authenticates and decrypts, and
  only then parses with a depth limit.

---

## 5. JSON schemas

Rules that apply to every document:
- the **exact** key set is required (missing *and* extra keys are rejected);
- every field is type-checked;
- every value is validated, as listed below.

Objects are compact JSON. nlohmann/json writes keys in sorted order, which is why the examples
show `children` before `type`.

### 5.1 Registry: label `registry`

```json
{"users":[
  {"fpr":"5930fa59f332efa33a017ceffa3a7d8025da6579f5f6d2022dae3c8e601b4599",
   "name":"admin","role":"admin","uid":"e1ff97a9208cc8f5128a60c3bd4bf968"},
  {"fpr":"0e013818d8d4384b4ec85335d9b2c32d19637a9814f6f2a48e3c202f704900d5",
   "name":"alice","role":"user","uid":"501fa15f7723a9c8531967daeac2245f"},
  {"fpr":"fbb17fa47a7b7b29048dd36347ca02c92172ceb49f6ca27db01deafa0d58ed47",
   "name":"bob","role":"user","uid":"024294d92600451c21eea7fe1af8317a"}]}
```

| Field | Type | Constraint |
|---|---|---|
| `users` | array | the only key; contains **exactly one** `admin` |
| `users[].name` | string | `[A-Za-z0-9_-]{1,32}`, not `personal` or `shared`, unique |
| `users[].uid` | string | 32 lowercase hex, unique |
| `users[].role` | string | `"admin"` or `"user"` |
| `users[].fpr` | string | 64 lowercase hex: SHA-256 of the user's public key (DER SubjectPublicKeyInfo) |

This is the authoritative list of users: login, `share` (resolving recipient names), the admin's
`/` listing and owner names in `/shared` all read it. Maximum JSON depth: 3.

### 5.2 Tree: label `tree|<uid>`

The user's `/personal` as **nested JSON**. The root node *is* `/personal`. Alice's:

```json
{"type":"dir","children":{
  "docs":{"type":"dir","children":{
    "a.txt":{"type":"file","blob":"9384233fb27e3d3d6e93b61a9cc43d85"}}},
  "readme":{"type":"file","blob":"cad8b2978cc771207cfdb44322cd9a7a"}}}
```

| Node | Exact keys | Constraint |
|---|---|---|
| directory | `type`, `children` | `type == "dir"`; `children` is an object mapping names to nodes |
| file | `type`, `blob` | `type == "file"`; `blob` is 32 lowercase hex (points to `blob\|<uid>\|<blob>`) |
| child name (key) | | printable ASCII, no space or `/`, not `.`/`..`, 1–255 bytes |

* The root must be a directory, and directories may be nested at most **64** levels deep. The
  shell enforces the limit (`Invalid Command`), and the validator rechecks it on every load.
  Two JSON levels per directory gives the parser limit of 160.
* `ls` lists `children`, `cd` follows `children`, and a file node's `blob` field leads to its
  contents.
* A new user's tree, like bob's, is `{"children":{},"type":"dir"}`.

### 5.3 Blob: label `blob|<owner-uid>|<blob-id>`

Alice's `docs/a.txt`:

```json
{"content":"top secret"}
```

| Field | Type | Constraint |
|---|---|---|
| `content` | string | the exact `mkfile` contents: printable ASCII, non-empty, at most 1 MiB (the input line limit) |

There is one blob per file. Overwriting a file re-encrypts **the same** blob (same label, same
name, fresh nonce), which is how share recipients see updates. Maximum JSON depth: 1.

### 5.4 Share list: label `share|<recipient-uid>`

One object per recipient lists every file shared **with** that user. Bob's:

```json
{"shares":[
  {"blob":"9384233fb27e3d3d6e93b61a9cc43d85","owner":"501fa15f7723a9c8531967daeac2245f","path":"docs/a.txt"},
  {"blob":"cad8b2978cc771207cfdb44322cd9a7a","owner":"501fa15f7723a9c8531967daeac2245f","path":"readme"}]}
```

| Field | Type | Constraint |
|---|---|---|
| `shares` | array | the only key; one entry per (owner, file) |
| `shares[].owner` | string | uid of the sharer; must be in the registry and differ from the recipient (otherwise the entry is skipped) |
| `shares[].blob` | string | 32 hex: the owner's file this entry grants read access to |
| `shares[].path` | string | where the file lives below the **owner's** `/personal`, e.g. `docs/a.txt`: 1–65 valid names joined by `/` |

* **The recipient sees `/shared/<owner>/<path>`.** Bob sees `/shared/alice/docs/a.txt` and
  `/shared/alice/readme`.
* **Read-only tree per owner.** The shell builds it from the paths, with the same node format as
  §5.2. Directories exist only as far as shared files need them, so files alice didn't share stay
  invisible. Bob sees the folder names on the path to a shared file (`docs`), nothing else.
* **No name collisions.** Two files with the same name in different directories (`pa/same`,
  `pb/same`) are both visible at their own paths.
* **Paths stay accurate.** The path is recorded at share time. The spec has no rename, move or
  delete command, so a file never changes path afterwards.
* **Re-sharing the same file** updates its entry instead of adding one, so sharing is idempotent.
* **Bound to the recipient.** The label, and therefore the associated data, contains the
  recipient's uid, so a list copied over another user's list fails authentication.
* **Fails closed.** If the list fails authentication, the recipient gets
  `Error: filesystem integrity check failed`. A later `share` refuses to overwrite it, so entries
  are never silently replaced.
* **No lock.** `saveShare` reads the list, adds the entry and writes the list back. If two users
  share with the same recipient at the very same instant, both may read the old list, and the
  second write then replaces the first: one share is lost (see §7, Concurrency).
* Maximum JSON depth: 3.

### 5.5 Keyfile: `./<user>_keyfile` (outside `filesystem/`, not encrypted)

Bob's:

```json
{
  "private_key": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIG+l…\n-----END PRIVATE KEY-----\n",
  "type": "bibifi.keyfile",
  "uid": "024294d92600451c21eea7fe1af8317a",
  "user": "bob",
  "v": 1
}
```

| Field | Type | Constraint |
|---|---|---|
| `type` | string | `"bibifi.keyfile"` |
| `v` | unsigned integer | `1` |
| `user` | string | valid username |
| `uid` | string | 32 lowercase hex |
| `private_key` | string | PEM, PKCS#8, **Ed25519 only**, unencrypted |

* The file is at most 64 KiB, with maximum JSON depth 1 and no trailing data.
* It is pretty-printed so it reads like an SSH key file.
* It is the only per-user secret, and its fields are **claims** checked against the registry at
  login (see `crypto.md` §5).

### 5.6 Public key: `./public_keys/<uid>.pem`

Bob's, `public_keys/024294d92600451c21eea7fe1af8317a.pem`:

```
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAPtK3Sad3SKakanJzFp/WAbVaoUFShKkK0PLL4ItB8O8=
-----END PUBLIC KEY-----
```

This is a standard Ed25519 SubjectPublicKeyInfo PEM, as the spec requires ("public keys stored
under public_keys"). It is trusted only if its SHA-256 fingerprint equals the user's `fpr` in the
registry.

---

## 6. Virtual namespace → stored objects

| Path the user types | User view | Admin view | Backed by |
|---|---|---|---|
| `/` | lists `personal`, `shared` | lists `personal`, `shared` and **every user** | registry (admin) |
| `/personal/...` | own tree | the admin's own tree | `tree\|<self>`, blobs |
| `/shared` | one directory per owner who shared with you | same, for the admin | own share list + registry (owner names) |
| `/shared/<owner>/<path>` | read-only, with the owner's folders | read-only | share entry → `blob\|<owner>\|<blob>` |
| `/<user>/personal/...` | n/a | read-only | `tree\|<user>`, blobs |
| `/<user>/shared/...` | n/a | read-only | `<user>`'s share list |

`Shell::locate()` performs this mapping. `personal` and `shared` are reserved usernames, so the
admin's `/` is never ambiguous.

**The single write rule:** `mkdir`, `mkfile` and `share` are allowed only when the target lies
under the caller's **own** `/personal`. Anywhere else (in `/`, anywhere under `/shared`, or for
the admin in another user's directory) they print `Forbidden`.

---

## 7. Commands → objects read and written

At the start of every command, the shell reloads the registry and drops its per-command cache.
Trees and share lists are loaded on demand, at most once per command.

| Command | Reads | Writes (in this order) |
|---|---|---|
| *first run* | — | public key → admin tree → registry → `admin_keyfile`, all built in `filesystem.init-<rand>/` and then renamed to `filesystem/` |
| *login* | keyfile, registry, own public key | — |
| `cd`, `pwd`, `ls` | registry; the tree and share list being browsed | — |
| `cat` | registry; tree or share list; the blob | — |
| `mkdir` | registry, own tree | own tree |
| `mkfile` (new file) | registry, own tree | **blob first**, then own tree |
| `mkfile` (existing file) | registry, own tree | that blob only (same name, fresh nonce) |
| `share` | registry, own tree; the recipient's share list | the recipient's share list (created if missing) |
| `adduser` | registry | public key → new user's empty tree → keyfile → **registry last** |

### Commit points and crash safety

* Each object is written with **temporary file + `rename()`**, so a reader never sees a half-written
  object. Temporary files are named `<64hex>.tmp-<16hex>` and exist only for an instant.
* **New file:** the blob is written before the tree that points to it. A crash leaves an
  unreferenced blob (harmless), never a tree pointing at nothing.
* **New user:** the registry is the commit point. A crash before it leaves an unused public key,
  tree and keyfile, but the user doesn't exist and the keyfile is rejected.
* **Share:** the whole list is rewritten atomically. A crash leaves either the old
  list or the new one.
* **First run:** staging plus rename means `filesystem/` is either complete or absent.
  Initialisation runs only when `filesystem/` is missing or empty, so deleting objects can never
  trigger a re-initialisation that overwrites `admin_keyfile`.

### Concurrency

* Every command reloads from disk, so a share made by another session shows up at once (tested
  with two live sessions).
* Each user writes only their own tree and blobs, and the registry is written only by the admin.
* **There is no locking** (standard C++ has no file locks). Objects are replaced atomically, so a
  reader never sees a half-written one, but two read-modify-writes of the same object at the same
  instant can lose one update (last writer wins). Two cases can do that:
  - **Share lists:** the only object several users write. Two users sharing with the same
    recipient at the same moment can lose one share, silently. Without a lock, removing this
    requires a separate list per (recipient, owner), so that each list has a single writer.
  - **Trees:** only if one user runs two sessions that `mkdir`/`mkfile` at the same moment.
* For interactive use, where commands from different users are seconds apart, neither happens;
  the test suite checks that shares from several owners, one after another, are all kept.

---

## 8. Validation and limits

| What | Limit or rule | Enforced in |
|---|---|---|
| Input line | 1 MiB, printable ASCII only (else `Invalid Command`) | `main.cpp`, `Shell::execute` |
| Object size on disk | 64 MiB | `readFile` |
| Keyfile size | 64 KiB | `readKeyfile` |
| File or directory name | 1–255 printable bytes, no space or `/`, not `.`/`..` | `isValidName` |
| Username | `[A-Za-z0-9_-]{1,32}`, not `personal`/`shared` | `isValidUsername` |
| Directory depth | 64 levels below `/personal` | shell, plus `validNode` on load |
| Shared path | 1–65 valid names joined by `/`, no empty, `.` or `..` parts | `isValidSharePath` |
| JSON depth | keyfile 1, blob 1, registry 3, share list 3, tree 160 (checked **before** parsing) | `parseJson` |
| Ids in paths | fixed-length lowercase hex, checked before any path is built (no traversal) | `isLowerHex` |
| Symlinks | refused for every object (keyfiles may be symlinks, so the user can point to theirs) | `readFile` |

---

## 9. Worked example: the run above, decrypted

All 9 objects in `filesystem/` (names shortened to 16 hex):

| File name | Size | Label | Decrypted JSON |
|---|---|---|---|
| `865eb8daa606139e…` | 540 | `registry` | admin, alice, bob (§5.1) |
| `ff970cb7d3c63570…` | 284 | `tree\|e1ff97a9…` (admin) | `{"children":{"notes":{"children":{"todo.txt":{"blob":"253272c3…","type":"file"}},"type":"dir"}},"type":"dir"}` |
| `4ad69383216912d4…` | 284 | `blob\|e1ff97a9…\|253272c3…` | `{"content":"buy milk"}` |
| `90564c0f22ac4b41…` | 284 | `tree\|501fa15f…` (alice) | `docs/a.txt` and `readme` (§5.2) |
| `9f6a0894bc324050…` | 284 | `blob\|501fa15f…\|9384233f…` | `{"content":"top secret"}` |
| `807260e282781fa6…` | 284 | `blob\|501fa15f…\|cad8b297…` | `{"content":"hello"}` |
| `df809e6e0b7bd753…` | 284 | `share\|501fa15f…` (alice's list) | `{"shares":[{"blob":"253272c3…","owner":"e1ff97a9…","path":"notes/todo.txt"}]}` |
| `1d6ab8e00f7f9084…` | 284 | `tree\|024294d9…` (bob) | `{"children":{},"type":"dir"}` |
| `a9d3ec3118212f98…` | 284 | `share\|024294d9…` (bob's list) | two entries from alice: `docs/a.txt`, `readme` (§5.4) |

The admin has no share list, because nothing was shared with the admin.

Resolving `cat /shared/admin/notes/todo.txt` as alice:
1. Alice's keyfile and the registry give her uid, `501fa15f…`, so the shell loads her share list,
   object `N("share|501fa15f…")` = `df809e6e…`.
2. The list has one entry. Its owner is `e1ff97a9…`, which the registry names `admin`, and its path
   is `notes/todo.txt`. So `/shared/admin/notes/todo.txt` exists.
3. The entry's `blob` is `253272c3…`, which leads to object `N("blob|e1ff97a9…|253272c3…")` =
   `4ad69383…`.
4. Decrypting it gives `{"content":"buy milk"}`, and the shell prints `buy milk`.

What bob sees (checked against the binary):
```
cd /shared ; ls        →  d -> alice
cd alice ; ls          →  d -> docs    f -> readme
cd docs ; ls           →  f -> a.txt
cat a.txt              →  top secret
```
