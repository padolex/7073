# cc-new architecture: how the filesystem is organised as JSON

This document describes how `cc-new` organises its data:
- the program's layers;
- every file it creates on the host;
- the JSON schema of every document it stores;
- how the objects are linked into a Merkle tree, and which rollbacks that detects;
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
| admin | `fd677c86571226212ebca4d7351ab408` | `notes/todo.txt` → `c0ed831254d73094382a7f5e9e39927e` |
| alice | `4d8cbbd92b3a01e87ccb976023891e7b` | `docs/a.txt` → `94219130b2c9fc4b096a5197ec4a817e`, `readme` → `8f2fec68e9e709b8fd403c70324abde8` |
| bob | `52690a52e47bc2d938c5058c27c1e175` | — |

---

## 1. Program layers

```
            stdin / stdout
                  │
┌─────────────────▼────────────────────────────────────────────────────┐
│ main.cpp     arguments · wiped-filesystem check · first-run init ·   │
│              login · prompt + bounded line reader                    │
├──────────────────────────────────────────────────────────────────────┤
│ shell.cpp    REFERENCE MONITOR                                       │
│   login()    keyfile → root → registry → challenge/response          │
│   refresh()  each command: root must not go backwards in a session   │
│   Shell      virtual namespace (user view / admin view)              │
│              access control: Forbidden, read-only /shared, owners    │
│              commit(): new versions → root → delete old versions     │
│              commands: cd pwd ls cat share mkdir mkfile adduser exit │
├──────────────────────────────────────────────────────────────────────┤
│ storage.cpp  ENCRYPTED, MERKLE-LINKED JSON OBJECT STORE              │
│   putObject / getObject: JSON ⇄ AES-GCM under K_enc, SHA-256 checked │
│   root · registry · trees · blobs · share lists (all versioned)      │
│   keyfiles (static) · public keys                                    │
├────────────────────────┬──────────────────────┬──────────────────────┤
│ jsonio.cpp             │ crypto.cpp           │ util.cpp             │
│ strict nlohmann/json   │ OpenSSL EVP wrappers │ safe file I/O, hex,  │
│ parse/dump, typed get  │ AES-GCM HMAC HKDF    │ randomness, wiping,  │
│                        │ SHA-256 Ed25519      │ private keyfile write│
└────────────────────────┴──────────────────────┴──────────────────────┘
```

* **Only `shell.cpp` decides who may do what.** `storage.cpp` stores, links and authenticates
  objects, but makes no access decisions.
* **Only `storage.cpp` knows the on-disk format.** The shell works with plain values (`json`
  trees, `Registry`, `Root`, `ObjRef`, `ShareRec`).
* **There is no daemon, cache or background state.** Every command reloads the root and what it
  needs from disk, so a session sees changes made by other sessions (§8).
* **Standard C++ only**, apart from OpenSSL and nlohmann/json: no POSIX calls, no locks.

> **Assumption (to confirm with the teaching team):** the `internal/` folder next to the binary is
> **safe**: clients can't read, modify or restore it. This is an extra assumption beyond the spec,
> which says only keyfiles are private ("Any more assumptions, you can run it by the teaching
> team"). It is used for one thing: a trusted record of the current root, so that rolling back
> `filesystem/` is detected (§6). If it doesn't hold, the only loss is that guarantee, and the
> design falls back to detecting partial rollbacks only.

---

## 2. Host layout

```
./fileserver                       the binary (contains the master key)
./admin_keyfile, ./<user>_keyfile  JSON keyfiles: credentials (mode 0600, never modified)
./public_keys/<uid>.pem            Ed25519 public keys (PEM), one per user
./internal/state                   the current root's epoch and SHA-256 (encrypted); ASSUMED SAFE
./filesystem/                      the encrypted store: ONE flat directory, no subdirectories
    <64 hex>                       an object: the root, or one version of a registry, tree,
                                   blob or share list
```

From the example run, as any host user sees it:

```
filesystem/
  10 files with 64-hex names: 7 × 284 bytes, 2 × 540 bytes, 1 × 796 bytes; no directories
public_keys/
  4d8cbbd92b3a01e87ccb976023891e7b.pem   113 bytes
  52690a52e47bc2d938c5058c27c1e175.pem   113 bytes
  fd677c86571226212ebca4d7351ab408.pem   113 bytes
admin_keyfile  alice_keyfile  bob_keyfile           (0600; the names are required by the spec)
```

No stored name or byte says which user, file or share an object belongs to. Watching *which*
objects change and *when* can still reveal relationships; see `crypto.md` §7.5.

---

## 3. Object naming and versions

Every object has a **label**: a short string that says what it is, where it belongs, and which
version it is. The label is never stored. The object's file name is derived from it:

```
file name = hex( HMAC-SHA-256(K_names, label) )        64 hex characters
```

| Label | Object | One per |
|---|---|---|
| `root` | the Merkle root: the current version of everything (§5.1) | filesystem (the only fixed name) |
| `registry\|<ver>` | the user table | filesystem |
| `tree\|<uid>\|<ver>` | the user's `/personal` directory tree | user |
| `blob\|<owner-uid>\|<blob-id>\|<ver>` | one file's contents | file |
| `share\|<uid>\|<ver>` | the list of every file shared **with** `<uid>` | user who has received at least one share |

* `uid`: 32 lowercase hex (128 random bits), assigned at `adduser`.
* `blob-id`: 32 lowercase hex (128 random bits), assigned when a file is first created. It never
  changes, which is what share entries refer to.
* `ver`: the root epoch of the change that wrote this version (§4.2).

**Every change writes new versions under new names.** Overwriting a file, adding a directory or
sharing never rewrites an object in place, except the root. The old version is deleted once the
new root is committed (§7). For example, with alice's uid shortened:

```
label "root"                       → eec13974af3f1368…   (fixed)
label "registry|3"                 → 6bc86c4354ad5354…
label "tree|4d8cbbd9…|9"           → 02a661fb61d61e54…   (alice's tree, version 9)
label "share|52690a52…|11"         → 6eb17be46439603e…   (bob's share list, version 11)
```

Without `K_names`, nobody can compute a name, link two objects or two versions to the same user,
or tell which kind an object is.

---

## 4. Object format, and the Merkle links

### 4.1 Every file under `filesystem/`

```
┌──────────┬──────────────────────────────────────────────┬──────────┐
│ nonce    │ AES-256-GCM ciphertext of the padded JSON    │ tag      │
│ 12 bytes │ 256 · n bytes                                │ 16 bytes │
└──────────┴──────────────────────────────────────────────┴──────────┘
padded JSON = u32 big-endian length || JSON text (UTF-8) || zero bytes up to a multiple of 256
associated data = "bibifi-new/v2|" + label          (the label includes the version)
```

* Sizes on disk are therefore 284, 540, 796, … bytes (12 + 256·n + 16).
* There is no plaintext header and no plaintext JSON.

### 4.2 References: how a parent pins a child

Every parent stores a **reference** for each child:

```json
{"ver": 9, "hash": "f3572b76b61806b1b3b7b72eaf1b576cc0151e4072485976edc591f3365e3665"}
```

* `ver` names the exact version (and hence the file name and associated data) to read.
* `hash` is the SHA-256 of that version's **bytes on disk**: nonce, ciphertext and tag.

Reading a child (`getObject(label, expectedHash, maxDepth)`):
1. Read the file, refusing symlinks.
2. Check its SHA-256 against the reference.
3. Authenticate and decrypt it with AES-GCM.
4. Parse it with a depth limit.

Writing (`putObject(label, doc)`) encrypts, writes atomically, and returns the hash for the
parent to record.

```
                          root (epoch 11)
          ┌──────────────┬──────┴──────────┬──────────────────┐
     registry|3     tree|admin|5      tree|alice|9        share|bob|11   …
                          │             ┌──┴───────────┐
                  blob|admin|c0ed…|5  blob|alice|9421…|8  blob|alice|8f2f…|9
```

Because every parent pins its children by version **and** hash, the whole filesystem state is
determined by the root: change, replace or roll back any object, and some parent's reference no
longer matches.

---

## 5. JSON schemas

Rules that apply to every document:
- the **exact** key set is required (missing *and* extra keys are rejected);
- every field is type-checked;
- every value is validated, as listed below.

Objects are compact JSON. nlohmann/json writes keys in sorted order, which is why the examples
show `children` before `type`.

### 5.1 Root: label `root`

```json
{"epoch":11,
 "registry":{"hash":"d440346a1b980419110eec7ed3c968616f12f2894da458b5bc119e1fa83178ee","ver":3},
 "shares":{
   "4d8cbbd92b3a01e87ccb976023891e7b":{"hash":"6f35be979bbdafd82b0ba8e9f0708b45e0bf93b72bf0bfa95281953c833d58ca","ver":6},
   "52690a52e47bc2d938c5058c27c1e175":{"hash":"49ada8013b2ca7759b85ef523c34d2af08ea2799d1acd628077b3618b1beeac1","ver":11}},
 "trees":{
   "4d8cbbd92b3a01e87ccb976023891e7b":{"hash":"f3572b76b61806b1b3b7b72eaf1b576cc0151e4072485976edc591f3365e3665","ver":9},
   "52690a52e47bc2d938c5058c27c1e175":{"hash":"35446083c3a57081141e0a747a6cca17b46fe027ffe4e673ae5377166a32c7f7","ver":3},
   "fd677c86571226212ebca4d7351ab408":{"hash":"1c871717d30ff977991957d0dea140d1df6db6c22180000a9d986938be2b00d8","ver":5}}}
```

| Field | Type | Constraint |
|---|---|---|
| `epoch` | unsigned integer | ≥ 1; increases by exactly 1 on every committed change |
| `registry` | reference | the current registry version |
| `trees` | object: uid → reference | one entry per user |
| `shares` | object: uid → reference | one entry per user who has received a share |

* The root is the **only** object with a fixed name and the only one rewritten in place
  (atomically). It is the commit point (§7).
* Like every object, it is encrypted and authenticated, so only the program can have written it.
  Which root is **current** is recorded outside `filesystem/`, in `internal/state` (§5.8).
* Maximum JSON depth: 3.

### 5.2 Registry: label `registry|<ver>`

```json
{"users":[
  {"fpr":"98398d9f690bdad556fb9220a9191a28dc531afcfdfc2775a1357133cfb8113e",
   "name":"admin","role":"admin","uid":"fd677c86571226212ebca4d7351ab408"},
  {"fpr":"53cb8dc3ddd77306ab0a2eb0d1a37b2bba382c425ed7b27b6020c175c92241d8",
   "name":"alice","role":"user","uid":"4d8cbbd92b3a01e87ccb976023891e7b"},
  {"fpr":"616564da5ec11c644cffa238890c325bab7b0a197b2d71994f2562ca4b129b5a",
   "name":"bob","role":"user","uid":"52690a52e47bc2d938c5058c27c1e175"}]}
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

### 5.3 Tree: label `tree|<uid>|<ver>`

The user's `/personal` as **nested JSON**. The root node *is* `/personal`. Alice's, version 9:

```json
{"type":"dir","children":{
  "docs":{"type":"dir","children":{
    "a.txt":{"type":"file","blob":"94219130b2c9fc4b096a5197ec4a817e","ver":8,
             "hash":"6510494aed965eb9e80fe295a5a4dc52a7c7a21dfccb5068eb1012998d292a2a"}}},
  "readme":{"type":"file","blob":"8f2fec68e9e709b8fd403c70324abde8","ver":9,
            "hash":"03b368671843fcc5622d81ea5d11dff86ccde3274d0fda2fdc8c494bf35c8ff6"}}}
```

| Node | Exact keys | Constraint |
|---|---|---|
| directory | `type`, `children` | `type == "dir"`; `children` is an object mapping names to nodes |
| file | `type`, `blob`, `ver`, `hash` | `blob`: 32 hex (the file's stable id); `ver` ≥ 1 and `hash` (64 hex): the reference to the current contents, `blob\|<uid>\|<blob>\|<ver>` |
| child name (key) | | printable ASCII, no space or `/`, not `.`/`..`, 1–255 bytes |

* The root must be a directory, and directories may be nested at most **64** levels deep. The
  shell enforces the limit (`Invalid Command`), and the validator rechecks it on every load.
  Two JSON levels per directory gives the parser limit of 160.
* `ls` lists `children`, `cd` follows `children`, and a file node's reference leads to its
  contents.
* A new user's tree, like bob's, is `{"children":{},"type":"dir"}`.

### 5.4 Blob: label `blob|<owner-uid>|<blob-id>|<ver>`

Alice's `docs/a.txt`, version 8:

```json
{"content":"top secret"}
```

| Field | Type | Constraint |
|---|---|---|
| `content` | string | the exact `mkfile` contents: printable ASCII, non-empty, at most 1 MiB (the input line limit) |

Overwriting a file writes a **new version** of the same blob id. The tree's reference moves to it,
and the old version is deleted. Share entries name the blob id, not a version, so recipients
always read the version the owner's tree currently points to. Maximum JSON depth: 1.

### 5.5 Share list: label `share|<recipient-uid>|<ver>`

One object per recipient lists every file shared **with** that user. Bob's, version 11:

```json
{"shares":[
  {"blob":"94219130b2c9fc4b096a5197ec4a817e","owner":"4d8cbbd92b3a01e87ccb976023891e7b","path":"docs/a.txt"},
  {"blob":"8f2fec68e9e709b8fd403c70324abde8","owner":"4d8cbbd92b3a01e87ccb976023891e7b","path":"readme"}]}
```

| Field | Type | Constraint |
|---|---|---|
| `shares` | array | the only key; one entry per (owner, file) |
| `shares[].owner` | string | uid of the sharer; must be in the registry and differ from the recipient (otherwise the entry is skipped) |
| `shares[].blob` | string | 32 hex: the owner's file this entry grants read access to |
| `shares[].path` | string | where the file lives below the **owner's** `/personal`, e.g. `docs/a.txt`: 1–65 valid names joined by `/` |

* **The recipient sees `/shared/<owner>/<path>`.** Bob sees `/shared/alice/docs/a.txt` and
  `/shared/alice/readme`.
* **Verified against the owner's tree.** The node at `path` in the owner's current tree must be a
  file with this `blob`; its reference is what the recipient reads. A mismatch is an integrity
  error.
* **Read-only tree per owner.** The shell builds it from the paths, with the same node format as
  §5.3. Directories exist only as far as shared files need them, so files alice didn't share stay
  invisible. Bob sees the folder names on the path to a shared file (`docs`), nothing else.
* **No name collisions.** Two files with the same name in different directories (`pa/same`,
  `pb/same`) are both visible at their own paths.
* **Paths stay accurate.** The spec has no rename, move or delete command, so a file never changes
  path after it is shared.
* **Re-sharing the same file writes nothing.**
* **Bound to the recipient.** The label, and so the associated data, contains the recipient's uid,
  and the root pins the hash. A list copied over another user's list fails.
* **Fails closed.** A list that fails verification gives `Error: filesystem integrity check
  failed`. A later `share` refuses to replace it.
* Maximum JSON depth: 3.

### 5.6 Keyfile: `./<user>_keyfile` (outside `filesystem/`, not encrypted)

Bob's:

```json
{
  "private_key": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIE…\n-----END PRIVATE KEY-----\n",
  "type": "bibifi.keyfile",
  "uid": "52690a52e47bc2d938c5058c27c1e175",
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
* `user`, `uid` and the key are **claims** checked against the registry at login (see
  `crypto.md` §5).
* **Static:** written once by `adduser` (or at first run, for the admin) and never modified.
  Sessions only read it.

### 5.7 Public key: `./public_keys/<uid>.pem`

Bob's, `public_keys/52690a52e47bc2d938c5058c27c1e175.pem`, is a standard Ed25519
SubjectPublicKeyInfo PEM, as the spec requires ("public keys stored under public_keys"). It is
trusted only if its SHA-256 fingerprint equals the user's `fpr` in the registry.

---

### 5.8 Trusted state: `./internal/state` (outside `filesystem/`, assumed safe)

```json
{"epoch":11,"root":"2698794e8c87…"}
```

Encrypted with `K_enc` like every object (associated data `bibifi-new/v2|internal-state`), so it
contains no readable text either.

| Field | Type | Constraint |
|---|---|---|
| `epoch` | unsigned integer | the epoch of the current root |
| `root` | string | 64 hex: SHA-256 of the current root's bytes on disk |

* **Written** right after every new root (§8) and at first run.
* **Checked** at start-up (before login) and at the start of every command
  (`Store::checkFresh`). The root on disk is accepted only if it matches:
  - same epoch and same hash: current;
  - root exactly **one** epoch ahead: a crash between writing the root and the state. Only a
    genuine commit produces this, so it is accepted and the state is repaired;
  - anything else (older, a different root at the same epoch, a gap, a missing or unreadable
    state): `Error: filesystem change detected`.
* **Why it closes the gap:** keyfiles are static, and everything else the spec mentions is
  attacker-controlled. `internal/` is the one place, by assumption, that a rollback of
  `filesystem/` can't reach.

---

## 6. Rollback detection

An attacker can copy files in `filesystem/` and restore them later. Two mechanisms make every such
rollback an error:
- **The Merkle links** catch any **partial** rollback: old copies of some objects next to new ones.
- **`internal/state`** catches a **complete** rollback: a whole, consistent old snapshot of
  `filesystem/`. It pins the current root, and by assumption the attacker can't restore it along
  with `filesystem/`.

| What the attacker restores | Why it fails | Result |
|---|---|---|
| An old version of one object, under its **old** name | nothing references that name any more | ignored (tested) |
| An old version under a **current** name | the parent's hash no longer matches (and the AAD names the old version) | `Error: filesystem integrity check failed` (tested for every current object) |
| Any **mix** of old and new objects | some parent's reference doesn't match | `Error: filesystem integrity check failed` |
| An old **root** | it isn't the root `internal/state` records | `Error: filesystem change detected` at start-up (tested) |
| A **complete old snapshot** of `filesystem/` | same: its root is older than the recorded one | `Error: filesystem change detected`, **for every user**, including users who never saw the newer state (tested) |
| A **fork** (old snapshot + new commits on top) | committing needs the recorded root to match first, and a forked root never matches the recorded hash | `Error: filesystem change detected` |
| An old state **while a session is running** | checked at the start of every command | `Error: filesystem change detected` on the next command (tested) |
| An **empty or deleted** `filesystem/` | never re-initialised while keys or `internal/` exist | `Error: filesystem missing; refusing to re-initialise`; `admin_keyfile` untouched (tested) |
| `internal/state` deleted or out of step | fails closed | `Error: filesystem change detected` (tested) |
| A snapshot of `filesystem/` **and** `internal/` together | violates the assumption | not detected: this is exactly what the assumption excludes |

Rollback can never produce content the program didn't write: every object is authenticated with
`K_enc`. Keyfiles stay **static**; they play no part in rollback detection.

---

## 7. Virtual namespace → stored objects

| Path the user types | User view | Admin view | Backed by |
|---|---|---|---|
| `/` | lists `personal`, `shared` | lists `personal`, `shared` and **every user** | registry (admin) |
| `/personal/...` | own tree | the admin's own tree | `tree\|<self>\|…`, blobs |
| `/shared` | one directory per owner who shared with you | same, for the admin | own share list + registry (owner names) |
| `/shared/<owner>/<path>` | read-only, with the owner's folders | read-only | share entry → owner's tree node → `blob\|<owner>\|<blob>\|<ver>` |
| `/<user>/personal/...` | n/a | read-only | `tree\|<user>\|…`, blobs |
| `/<user>/shared/...` | n/a | read-only | `<user>`'s share list |

`Shell::locate()` performs this mapping. `personal` and `shared` are reserved usernames, so the
admin's `/` is never ambiguous.

**The single write rule:** `mkdir`, `mkfile` and `share` are allowed only when the target lies
under the caller's **own** `/personal`. Anywhere else (in `/`, anywhere under `/shared`, or for
the admin in another user's directory) they print `Forbidden`.

---

## 8. Commands → objects read and written

At the start of every command, the shell reloads the root, checks it against `internal/state`
(and that it hasn't gone backwards during this session), and reloads the registry. Trees and share lists are loaded on demand, each verified
against the root, at most once per command.

Every command that changes something follows the same steps (`Shell::commit`), with
**E = current epoch + 1**:
1. **Write the new versions**, each labelled with version E: the changed tree, file contents,
   share list or registry.
2. **Re-read the root** and abort if another session has committed meanwhile (§9).
3. **Write the new root** (epoch E), with references to the new versions. This is the commit
   point.
4. **Write `internal/state`** = {E, SHA-256 of the new root}.
5. **Delete the replaced versions.**

| Command | Reads | New versions written | Replaced (deleted after commit) |
|---|---|---|---|
| *first run* | — | admin tree, registry, root (epoch 1) in `filesystem.init-<rand>/`; `internal/state`; `admin_keyfile`; then the staging directory is renamed to `filesystem/` | — |
| *login* | keyfile, root, registry, own public key | — | — |
| `cd`, `pwd`, `ls`, `cat` | root, registry, the trees, share lists and blobs involved | — | — |
| `mkdir` | own tree | own tree | old tree version |
| `mkfile` (new file) | own tree | the file's contents, own tree | old tree version |
| `mkfile` (existing file) | own tree | the file's contents, own tree | old contents version, old tree version |
| `share` | own tree, recipient's share list | recipient's share list (nothing if already shared) | old share list version |
| `adduser` | registry | public key, new user's tree, keyfile, registry | old registry version |

### Commit points and crash safety

* Every file is written with **temporary file + `rename()`**, so a reader never sees a
  half-written object. Temporary files are named `<64hex>.tmp-<16hex>`.
* **Before the root is written**, the new versions are unreferenced. A crash leaves the old root,
  which still points at the old, complete versions: the command simply didn't happen.
* **After the root is written**, the change is committed. A crash before `internal/state` is
  updated leaves the state exactly one epoch behind, which the next start-up accepts and repairs
  (tested). A crash before the deletions leaves unreferenced old versions, which are harmless.
* **New user:** the root that references the new registry is the commit point. A crash before it
  leaves an unused public key, tree and keyfile; the user doesn't exist, and the keyfile is
  rejected.
* **First run:** staging plus rename means `filesystem/` is either complete or absent.

### Concurrency (§9 in short)

The design assumes **one writing session at a time**, as the spec's scenario is one user at a time.
There are no locks (standard C++ has none).
* **Reading sessions are always safe.** A session that only reads (like bob waiting at his
  prompt while alice works) reloads the root before every command, and sees new shares at once
  (tested with two live sessions).
* **Two sessions writing at once** could commit roots built on the same epoch. Overwriting the
  other session's root would drop its change and could leave its data unreferenced.
* **A guard narrows that window to an instant:** `commit()` re-reads the root just before
  writing and aborts if it changed (`Error: filesystem changed by another session, try again`).

---

## 9. Validation and limits

| What | Limit or rule | Enforced in |
|---|---|---|
| Input line | 1 MiB, printable ASCII only (else `Invalid Command`) | `main.cpp`, `Shell::execute` |
| Object size on disk | 64 MiB | `readFile` |
| Keyfile size | 64 KiB | `readKeyfile` |
| File or directory name | 1–255 printable bytes, no space or `/`, not `.`/`..` | `isValidName` |
| Username | `[A-Za-z0-9_-]{1,32}`, not `personal`/`shared` | `isValidUsername` |
| Directory depth | 64 levels below `/personal` | shell, plus `validNode` on load |
| Shared path | 1–65 valid names joined by `/`, no empty, `.` or `..` parts | `isValidSharePath` |
| References | `ver` ≥ 1, `hash` 64 lowercase hex, uids 32 hex | `refFromJson`, `validNode` |
| JSON depth | keyfile 1, blob 1, root 3, registry 3, share list 3, tree 160 (checked **before** parsing) | `parseJson` |
| Ids in paths | fixed-length lowercase hex, checked before any path is built (no traversal) | `isLowerHex` |
| Symlinks | refused for every object (keyfiles may be symlinks, so the user can point to theirs) | `readFile` |

---

## 10. Worked example: the run above, decrypted

All 10 objects in `filesystem/` (names shortened to 16 hex):

| File name | Size | Label | Decrypted JSON |
|---|---|---|---|
| `eec13974af3f1368…` | 796 | `root` | epoch 11, references to everything below (§5.1) |
| `6bc86c4354ad5354…` | 540 | `registry\|3` | admin, alice, bob (§5.2) |
| `7242327feeb82e89…` | 284 | `tree\|fd677c86…\|5` (admin) | `notes/todo.txt` → blob `c0ed8312…` ver 5 |
| `8518528c801b11e8…` | 284 | `blob\|fd677c86…\|c0ed8312…\|5` | `{"content":"buy milk"}` |
| `02a661fb61d61e54…` | 540 | `tree\|4d8cbbd9…\|9` (alice) | `docs/a.txt` ver 8 and `readme` ver 9 (§5.3) |
| `d65e1bc75111a4d9…` | 284 | `blob\|4d8cbbd9…\|94219130…\|8` | `{"content":"top secret"}` |
| `24541e748189d95f…` | 284 | `blob\|4d8cbbd9…\|8f2fec68…\|9` | `{"content":"hello"}` |
| `1e3284f7d97bc9d1…` | 284 | `tree\|52690a52…\|3` (bob) | `{"children":{},"type":"dir"}` |
| `f32d99dd1858ea07…` | 284 | `share\|4d8cbbd9…\|6` (alice's list) | `{"shares":[{"blob":"c0ed8312…","owner":"fd677c86…","path":"notes/todo.txt"}]}` |
| `6eb17be46439603e…` | 284 | `share\|52690a52…\|11` (bob's list) | two entries from alice: `docs/a.txt`, `readme` (§5.5) |

Resolving `cat /shared/admin/notes/todo.txt` as alice:
1. Load the root (epoch 11) and the registry it pins (`registry|3`, hash
   `d440346a…` checked).
2. Load alice's share list, `share|4d8cbbd9…|6`, hash `6f35be97…` checked. It has one entry:
   owner `fd677c86…` (the registry names it `admin`), blob `c0ed8312…`, path `notes/todo.txt`.
3. Load the admin's tree, `tree|fd677c86…|5`, hash checked. The node at `notes/todo.txt` is a file
   with blob `c0ed8312…`, which matches the entry, so `/shared/admin/notes/todo.txt` exists. Its
   reference is ver 5, hash `909e3b86…`.
4. Load `blob|fd677c86…|c0ed8312…|5`, check the hash, decrypt it: `{"content":"buy milk"}`. The
   shell prints `buy milk`.

What bob sees:
```
cd /shared ; ls        →  d -> alice
cd alice ; ls          →  d -> docs    f -> readme
cd docs ; ls           →  f -> a.txt
cat a.txt              →  top secret
```
