# cc-new cryptography

This document explains how cryptography works in `cc-new`:
- which primitives it uses;
- where every key comes from and lives;
- how objects are encrypted, named and linked into a Merkle tree;
- how login works, and how rollback is detected;
- what each mechanism guarantees;
- the known limits.

The data layout is described in [`ARCH.md`](ARCH.md).

**Short version:**
- One **master key** compiled into the binary protects everything in `filesystem/`.
- Two independent keys are derived from it: one encrypts every object with AES-256-GCM, the other
  names every object with HMAC.
- Objects are linked into a **Merkle tree** by SHA-256, so restoring old copies of *some* objects
  is always detected. The current root is pinned in `internal/state`, a folder **assumed safe**,
  so restoring a *complete* old snapshot is detected too (§5a). Keyfiles stay static.
- Users hold **Ed25519** key pairs that are used **only to log in**, never to encrypt.
- No cryptography is implemented by hand. Every primitive is an OpenSSL 3 EVP call.

---

## 1. Primitives

| Purpose | Algorithm | OpenSSL 3 API |
|---|---|---|
| Object encryption | AES-256-GCM: 96-bit random nonce, 128-bit tag, associated data | `EVP_aes_256_gcm`, `EVP_Encrypt*`/`EVP_Decrypt*`, `EVP_CTRL_GCM_*` |
| Object names | HMAC-SHA-256 | `EVP_Q_mac(…"HMAC"…"SHA256"…)` |
| Key derivation | HKDF-SHA-256 (RFC 5869), empty salt | `EVP_KDF_fetch("HKDF")`, `EVP_KDF_derive` |
| User keys, login | Ed25519 (PureEdDSA, RFC 8032) | `EVP_PKEY_Q_keygen("ED25519")`, `EVP_DigestSign`/`EVP_DigestVerify` (no digest) |
| Key fingerprints | SHA-256 of the DER SubjectPublicKeyInfo | `i2d_PUBKEY`, `EVP_Digest(EVP_sha256())` |
| Merkle links | SHA-256 of each object's bytes on disk | `EVP_Digest(EVP_sha256())` (`sha256Hex`) |
| Randomness | OpenSSL CSPRNG | `RAND_bytes` |
| Key serialisation | PKCS#8 / SubjectPublicKeyInfo PEM | `PEM_write_bio_PrivateKey` (to `BIO_s_secmem`), `PEM_read_bio_*` |
| Constant-time compare | memory compare | `CRYPTO_memcmp` |
| Wiping secrets | memory cleanse | `OPENSSL_cleanse` |

**Why these:**
- AES-GCM is authenticated encryption, so one primitive gives both confidentiality and
  integrity.
- HKDF keeps the subkeys independent.
- HMAC is a keyed, deterministic function, so names can be recomputed but not guessed.
- SHA-256 is collision-resistant, so a parent's recorded hash pins exactly one child version.
- Ed25519 is the modern SSH default: deterministic signatures, no padding modes to misconfigure,
  fast key generation.

---

## 2. Keys

```
                 K_M — 32 bytes, compiled into the binary (src/internal_secret.h)
                    │
        HKDF-SHA-256│ info = "bibifi-new/v1/encryption"     info = "bibifi-new/v1/names"
          ┌─────────┴──────────────┐                   ┌──────────────┐
          ▼                                            ▼
        K_enc  (AES-256 key)                         K_names  (HMAC key)
        encrypts + authenticates EVERY object        names EVERY object

 per user:  Ed25519 private key ── in <user>_keyfile (0600)        ─┐
            Ed25519 public key  ── in public_keys/<uid>.pem         ├─ login only
            fingerprint (SHA-256) ─ in the encrypted registry       ─┘
```

| Key | Created | Stored | Used for | Lifetime |
|---|---|---|---|---|
| `K_M` | `openssl rand -hex 32` at development time | inside the executable only | HKDF input only | the life of the build: changing it makes the filesystem unreadable |
| `K_enc` | HKDF from `K_M` when the program starts | memory only (`Key256`, wiped on destruction) | AES-256-GCM of all objects | one process |
| `K_names` | HKDF from `K_M` when the program starts | memory only | HMAC names | one process |
| User Ed25519 private key | `EVP_PKEY_Q_keygen` at first run (admin) or `adduser` | `<user>_keyfile`, PEM, mode 0600 | signing the login challenge | forever (no rotation) |
| User Ed25519 public key | with the private key | `public_keys/<uid>.pem` | verifying the login challenge | forever |

**Why derive two keys instead of using `K_M` directly?** Using one key for two different
algorithms (AES and HMAC) is poor practice. HKDF with distinct `info` labels gives keys that are
independent: knowing one reveals nothing about the other, or about `K_M`. The `v1` in the labels
lets a future format derive fresh keys.

**`K_M` is an internal secret.** Course clarification 2 says "A key held inside your program (e.g.,
compiled into it) counts as an internal secret." It is never written to disk, never placed in a
keyfile, and never derived from anything public.

---

## 3. Object encryption

Every file under `filesystem/` is produced by `Store::putObject` and read by `Store::getObject`.

### Encrypt (`aeadEncrypt`)

```
plaintext  = JSON document (UTF-8 text)
padded     = u32_be(len(plaintext)) || plaintext || 0x00 … up to a multiple of 256 bytes
nonce      = RAND_bytes(12)                                     fresh for every write
aad        = "bibifi-new/v2|" + label          (the label includes the version)
ct, tag    = AES-256-GCM-Encrypt(K_enc, nonce, padded, aad)     128-bit tag
file       = nonce || ct || tag                                 written via temp file + rename()
```

### Decrypt (`aeadDecrypt`)

1. Read the file, refusing symlinks, non-regular files and anything over 64 MiB.
2. **Check the Merkle link:** the SHA-256 of the file's bytes must equal the hash the parent
   recorded (§3a). The root has no parent; it must be the root recorded in `internal/state`
   (§5a).
3. Split it into nonce, ciphertext and tag, and run AES-256-GCM decryption with
   `aad = "bibifi-new/v2|" + label`.
4. **Verify the tag first.** On any mismatch, return nothing, so no unauthenticated byte is used.
5. Remove the padding: the length prefix must fit inside the buffer.
6. Only now parse the JSON, with a depth limit, exact keys and typed fields.

### The associated data binds each object to its location

GCM authenticates the associated data together with the ciphertext, but doesn't store it. The
reader supplies the label it *expects*. If the ciphertext was produced for any other label,
authentication fails:

| Attack | Why it fails |
|---|---|
| Copy Bob's tree over Alice's tree | encrypted for `tree\|bob-uid\|…`, decrypted as `tree\|alice-uid\|…` |
| Swap the contents of two files | `blob\|uid\|id1\|…` ≠ `blob\|uid\|id2\|…` |
| Copy Bob's share list over Alice's (to see Bob's shares) | `share\|bob-uid\|…` ≠ `share\|alice-uid\|…` |
| Put an old version under a current version's name | `…\|<old ver>` ≠ `…\|<current ver>`, and the parent's hash differs |
| Move Alice's blob into Bob's name | the owner uid is part of the label |
| Use a blob as a tree, or the registry as anything else | the object kind is the first part of the label |
| Flip any bit, truncate, append | the GCM tag no longer verifies |
| Write any JSON by hand | no valid tag without `K_enc` |

**Share lists.** Each recipient has one share list, label `share|<recipient-uid>|<ver>`. Its associated
data names the recipient, so a list belongs to exactly one user. Each entry inside it names the
owner, the file and its path, all under the same authentication tag, so entries can't be added,
removed or edited individually either. A list that fails authentication is never shown and never
overwritten; the recipient gets `Error: filesystem integrity check failed`.

### 3a. Merkle links: every parent pins its children

Encryption alone proves an object was written by the program for this label. It doesn't prove it
is the **current** one. So every parent also records, for each child, a reference
`{"ver": n, "hash": SHA-256(child's bytes on disk)}`:

```
root ──► registry|v, tree|uid|v (one per user), share|uid|v (one per recipient)
tree ──► blob|uid|id|v (one per file)
```

* **Every change writes new versions under new labels.** The version is part of the label, so it
  is part of both the file name and the associated data. The new root (epoch + 1) is written
  last, and then the replaced versions are deleted.
* **Reading checks every link on the way down:** root → tree → file, or root → share list →
  owner's tree → file. Any object that isn't exactly the version its parent recorded fails.
* **What this rules out:** mixing old and new state. A *complete*, consistent old snapshot,
  root included, is caught by `internal/state` instead (§5a).

### Padding hides sizes

Plaintexts are padded to 256-byte buckets, so objects on disk are 284, 540, 796, … bytes long. A
one-character file and a 200-character file both produce a 284-byte object. File sizes leak only
in steps of 256 bytes.

### Nonce safety

Nonces are random 96-bit values under a single key, `K_enc`. GCM stays safe while the chance of a
nonce repeating is negligible. NIST SP 800-38D limits random-nonce use to 2³² encryptions per key,
where the collision probability is below 2⁻³². Each command writes at most a handful of objects,
so this system would need billions of writes to approach the limit. Every write, including an
overwrite of the same object, uses a **fresh** nonce.

---

## 4. Object names

```
file name = hex( HMAC-SHA-256(K_names, label) )      e.g. label "tree|4d8cbbd9…|9" → "02a661fb…"
```

* **Deterministic:** the program can find any object without an index.
* **Unlinkable without `K_names`:** names look random and unrelated. Nobody can compute the name
  for a given user or file, tell which objects belong to the same user, or tell a tree from a blob.
* **No information in names:** labels contain uids, blob ids and versions, but only their HMAC
  reaches the disk. A test checks that no uid appears in any file name or content. Two versions
  of the same object have unrelated names.

---

## 5. Authentication (login)

The spec asks for "authentication … similar to ssh key (public/private)". `login()` in
`src/shell.cpp`:

```
1. kf   = parse keyfile                   strict JSON; Ed25519 key only; no encrypted PEM
2. root = getObject("root")               AES-GCM under K_enc: only the program can have written it
   reg  = getObject(registry|v, hash)     pinned by the root
   me   = reg.byUid(kf.uid)
   require me.name == kf.user
   require me.fpr  == SHA-256(SPKI(kf.private_key))           constant-time compare
3. pub = public_keys/<uid>.pem
   require SHA-256(SPKI(pub)) == me.fpr                         public key pinned by the registry
   challenge = "bibifi-new-login-v1|" || RAND_bytes(32)
   require Ed25519.Verify(pub, challenge, Ed25519.Sign(kf.private_key, challenge))
4. Identity = { me.name, me.uid, admin = (me.role == "admin") }
```

Any failure prints `Invalid keyfile`; the cause is never revealed. The keyfile is only read, never
written.

**What makes it sound:**
- **The registry is the trust anchor.** It is authenticated with `K_enc`, so nobody without the
  master key can add a user or change a name, uid, role or fingerprint.
- **Steps 2 and 3 bind three things together:** the claimed identity in the keyfile, the key
  registered for it, and the published public key.
- **The challenge proves possession** of the private key, SSH-style. It is fresh random bytes with
  a context prefix, so a signature can't be reused for anything else.
- **The admin flag comes from the registry role of the user's own uid**, never from the keyfile.

| Attempt | Fails at |
|---|---|
| Edit `user` in your keyfile | step 2: the registry name differs |
| Put someone else's `uid` and `user` in your keyfile | step 2: the fingerprint differs (it is your key, not theirs) |
| Generate your own key and claim alice's uid and name | step 2: the fingerprint differs |
| Replace alice's `public_keys/<uid>.pem` with your key | step 3: the fingerprint differs; alice is locked out (denial of service), but nobody gets in as her |
| An RSA or other non-Ed25519 key | step 1 |
| An encrypted PEM (would prompt for a passphrase) | step 1: rejected without prompting |

### 5a. Rollback detection: `internal/state`

Keyfiles are **static**: written once at `adduser` and never modified. The trusted record of
"which root is current" lives instead in `internal/state`, next to the binary:

```
internal/state = AES-256-GCM_K_enc( {"epoch": E, "root": SHA-256(root bytes)} ),  AAD "bibifi-new/v2|internal-state"
```

* **Assumption:** clients can't read, modify or restore `internal/`. This goes beyond the spec,
  which protects only keyfiles, so it must be confirmed with the teaching team. Encryption and
  authentication stop forgery, and the assumption stops rollback of the record itself.
* **Written** after every new root: new versions → root → `internal/state` → delete old versions.
* **Checked** at start-up (before login) and before every command. The root on disk must be the
  recorded one (same epoch and SHA-256), or exactly one epoch ahead. The second case is a crash
  between writing the root and the state; only a genuine commit can produce it, so it is accepted
  and repaired. Anything else gives `Error: filesystem change detected`.
* **What it catches:** any rollback of `filesystem/`, partial or complete, and any fork built on an
  old snapshot (the program refuses to start on it, so nobody can commit on top of it). This holds
  for every user, including users who never saw the newer state.
* **Also:** within a session the root never goes backwards (an in-memory check), and an empty or
  missing `filesystem/` is never re-initialised while keys or `internal/` exist.

**After login, the user's private key isn't needed.** The session keeps only the name, uid and
admin flag. Every later decision about what the user may read or write is made by the shell
(reference monitor), and cryptography stops anyone from going around it on disk.

---

## 6. What the cryptography guarantees

The attacker considered here is any local user who can read and write everything under
`filesystem/` and `public_keys/` (spec: "everything else is directly accessible") but doesn't have
`K_M` or other users' keyfiles.

| Property | Mechanism | Holds against that attacker? |
|---|---|---|
| File contents are secret | AES-256-GCM under `K_enc` | yes |
| File and directory names, tree structure are secret | the tree is an encrypted JSON object | yes |
| Who exists, usernames, roles are secret | the registry is encrypted | yes |
| Who owns which object, who shared with whom | HMAC names, no uid on disk, encrypted share lists | yes (for the stored data; see §7.5 for what watching changes reveals) |
| Exact file sizes | 256-byte padding | yes (sizes leak only in 256-byte steps) |
| Forging or editing any object | GCM tag | yes |
| Copying or moving an object between users or locations | label in the associated data, parent's hash | yes |
| Impersonating another user | registry fingerprint plus challenge/response | yes |
| Restoring older copies of some objects (mixing old and new state) | Merkle links (hash + version) | yes |
| Restoring a complete older snapshot of `filesystem/` | `internal/state` pins the current root | yes, under the `internal/` assumption (§5a, §7.3) |
| **Deleting objects** | — | **no:** fails closed (denial of service) |

All failures **fail closed**: tampered data gives `Error: filesystem integrity check failed` and
is never shown, a broken root, registry or keyfile gives `Invalid keyfile`, and a root that isn't the
one `internal/state` records gives `Error: filesystem change detected`.

---

## 7. Limits

### 7.1 Everything rests on `K_M`
This is the single-master-key trade-off.
- Anyone who extracts `K_M` from the binary can derive `K_enc` and `K_names`, then read every file,
  forge any object, and edit the registry to log in as anyone.
- Under the course rules this is not a valid attack, because a compiled-in key is an internal
  secret.
- `../cc` is the alternative: with per-user keys, file keys and signatures, a leaked `K_M` there
  reveals no contents and allows no forgery.

### 7.2 User keys don't separate users' data
All users' files are encrypted with the same `K_enc`. "Bob can't read Alice's files" is enforced
by the program's access rules, backed by the fact that nobody can decrypt anything outside the
program. There is no per-user cryptographic isolation.

### 7.3 Rollback rests on the `internal/` assumption
Every rollback of `filesystem/` is detected **as long as `internal/` is safe**. What that means:
- **If the assumption is rejected** (clients can also restore `internal/`), an attacker can
  restore `filesystem/` and `internal/` together, and that complete snapshot is accepted. The
  Merkle links still catch every partial rollback, so the attacker still can't roll back one
  chosen file, tree or share.
- **Why not use the keyfiles instead:** they are the only place the spec protects, but they are
  deliberately static (written once, never modified). Keeping state in them would also need the
  root to record its own history, because otherwise a user could lower their own value and replay
  an old snapshot forward.
- **What rollback can never do:** produce content the program didn't write. Every object is
  authenticated with `K_enc`.

### 7.4 Keyfiles are bearer credentials
The private key is stored unencrypted, as the spec requires (no passphrase prompt). Whoever copies
a keyfile *is* that user. The program writes keyfiles with mode 0600 and never prints them. Each
keyfile is first written inside a fresh directory that is made owner-only before anything is
created in it, then set to 0600 and renamed into place, so no other account can open it at any
point. This uses only `std::filesystem` (`writeFileAtomic` in `src/util.cpp`).

### 7.5 Metadata
Visible to anyone:
- the number of objects and their size classes, and modification times;
- which objects change together, and when. An observer who watches over time (or a user who
  shares a dummy file with someone) can link objects to users this way, even though no stored byte
  says so;
- the number of users (`public_keys/` has one file per user, named by a random uid).

*Which* user or file any of these belongs to stays hidden.

### 7.6 No forward secrecy, no key rotation
`K_M` is fixed per build, and user keys never change. These match the spec's scope, which has no
revocation or rotation command.

---

## 8. Secret handling in memory

* `Key256` (which holds `K_enc` and `K_names`) wipes itself with `OPENSSL_cleanse` when destroyed.
* Decrypted plaintexts, keyfile bytes, PEM strings and file contents being written are wiped
  after use (`wipe()`).
* Private keys are serialised to PEM through `BIO_s_secmem`, OpenSSL's secure heap, which is
  wiped when freed.
* Fingerprints are compared with `CRYPTO_memcmp`, in constant time.
* Error messages never contain key material and never say which check failed.

---

## 9. Where to find it in the code

| Topic | File and function |
|---|---|
| Master key | `src/internal_secret.h`: `kInternalMasterKey` |
| Subkey derivation | `src/storage.cpp`: `Store::Store` (HKDF `info` strings) |
| AES-GCM and padding | `src/crypto.cpp`: `aeadEncrypt`, `aeadDecrypt`, `pad`, `unpad` |
| Object encryption, naming, Merkle hash check | `src/storage.cpp`: `putObject`, `getObject`, `objectPath`; `src/crypto.cpp`: `sha256Hex` |
| Root, references, versioned labels | `src/storage.cpp`: `saveRoot`, `loadRoot`, `refFromJson`, `treeLabel`… |
| Commit and in-session rollback check | `src/shell.cpp`: `Shell::commit`, `Shell::refresh` |
| Trusted root record | `src/storage.cpp`: `saveState`, `checkFresh`; `src/main.cpp` (start-up check) |
| Wiped-filesystem refusal | `src/storage.cpp`: `needsInit`, `isWiped`; `src/main.cpp` |
| Share lists | `src/storage.cpp`: `saveShares`, `loadShares`; `src/shell.cpp`: `sharedWith` |
| Ed25519 keys and signatures | `src/crypto.cpp`: `generateUserKey`, `sign`, `verify`, `fingerprint` |
| Login | `src/shell.cpp`: `login`; `src/storage.cpp`: `proveKeyPossession`, `loadPinnedPublicKey` |
| Randomness, wiping, atomic writes | `src/util.cpp`: `randomBytes`, `wipe`, `writeFileAtomic` |
