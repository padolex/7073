#!/usr/bin/env bash
# End-to-end tests for ./fileserver: functional spec, edge cases, on-disk
# confidentiality and tamper/insider attacks. Usage: tests/run_tests.sh
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BIN:-$ROOT/fileserver}"   # override to test another build, e.g. BIN=$PWD/fileserver-asan
[ -x "$BIN" ] || { echo "build first: make"; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
cp "$BIN" ./fileserver

PASS=0
FAIL=0

# kf <field> <keyfile>  -> value of a top-level string field in a JSON keyfile
kf() { sed -n "s/^  \"$1\": \"\([^\"]*\)\",\{0,1\}\$/\1/p" "$2"; }

# Object names are HMACs under the master key, so tests locate objects by
# watching what a command creates or modifies.
snap() { find filesystem -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort; }
# created_by <before-snapshot>  -> names that did not exist before
created_by() { comm -13 <(printf '%s\n' "$1") <(snap); }
# modified_since <before-snapshot> <marker> -> pre-existing names rewritten after marker
modified_since() { comm -12 <(printf '%s\n' "$1") <(find filesystem -mindepth 1 -maxdepth 1 -newer "$2" -printf '%f\n' | LC_ALL=C sort); }

# strip_prompts: remove the "<user>:/<cwd>> " prompts the shell prints before
# every command (paths never contain spaces, so a prompt ends at the first "> ").
strip_prompts() { sed -E -e 's/^([A-Za-z0-9_-]+:\/[^ ]*> )+//' -e '/^$/d'; }

# run <keyfile> <stdin>  -> prints session output with the login banner/help and prompts removed
run() {
    printf '%s' "$2" | ./fileserver "$1" | sed -e '/^Available commands:$/d' -e '/^  /d' -e '/^Logged in as /d' | strip_prompts
}

check() {  # check <name> <expected> <actual>
    if [ "$2" == "$3" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: $1"
        diff <(printf '%s\n' "$2") <(printf '%s\n' "$3") | sed 's/^/    /'
    fi
}

# ---------------------------------------------------------------- bootstrap
out=$(printf 'exit\n' | ./fileserver admin_keyfile | head -1)
check "first run creates fs and logs in admin" "Logged in as admin" "$out"
check "filesystem dir exists" "yes" "$([ -d filesystem ] && echo yes)"
check "public_keys dir exists" "yes" "$([ -d public_keys ] && echo yes)"
check "admin keyfile is 0600" "600" "$(stat -c %a admin_keyfile)"

out=$(printf 'exit\n' | ./fileserver admin_keyfile | head -1)
check "second run reuses fs" "Logged in as admin" "$out"

check "missing keyfile" "Invalid keyfile" "$(./fileserver nosuchfile < /dev/null)"
echo garbage > junk_keyfile
check "garbage keyfile" "Invalid keyfile" "$(./fileserver junk_keyfile < /dev/null)"
check "directory as keyfile" "Invalid keyfile" "$(./fileserver filesystem < /dev/null)"
check "public key as keyfile" "Invalid keyfile" "$(./fileserver "$(ls public_keys/*.pem | head -1)" < /dev/null)"
check "no args" "Usage: ./fileserver keyfile_name" "$(./fileserver < /dev/null)"

# ---------------------------------------------------------------- admin
out=$(run admin_keyfile $'pwd\nls\nadduser alice\nadduser bobby\nadduser carol\nadduser alice\nadduser admin\nadduser ../evil\nadduser a/b\nadduser personal\nadduser shared\nmkdir x\nmkfile x y\nshare x alice\nbogus\nexit\n')
check "admin session" "/
d -> .
d -> ..
d -> personal
d -> shared
User alice already exists
User admin already exists
Invalid username
Invalid username
Invalid username
Invalid username
Forbidden
Forbidden
File x doesn't exist
Invalid Command" "$out"
check "alice keyfile created 0600" "600" "$(stat -c %a alice_keyfile)"
check "keyfile staging leaves nothing behind" "0" "$(find . -maxdepth 1 -name '.stage-*' | wc -l)"
check "no traversal keyfile" "no" "$([ -e ../evil_keyfile ] || [ -e evil_keyfile ] && echo yes || echo no)"

out=$(run admin_keyfile $'ls\n')
check "admin root: own personal/shared + every user" "d -> .
d -> ..
d -> alice
d -> bobby
d -> carol
d -> personal
d -> shared" "$out"

# ---------------------------------------------------------------- user basics
out=$(printf 'exit\n' | ./fileserver alice_keyfile | head -1)
check "alice login" "Logged in as alice" "$out"

out=$(run alice_keyfile $'pwd\nls\nadduser zed\nmkdir x\nmkfile x y\ncd shared\nmkdir x\nmkfile x y\npwd\ncd /personal\npwd\nexit\n')
check "user root / shared forbidden" "/
d -> .
d -> ..
d -> personal
d -> shared
Invalid Command
Forbidden
Forbidden
Forbidden
Forbidden
/shared
/personal" "$out"

out=$(run alice_keyfile $'cd personal\nmkdir dir1\nmkdir dir1\ncd dir1\nmkdir dir2\ncd dir2\npwd\ncd ../../dir1/dir2\npwd\ncd ../..\npwd\ncd ../../../..\npwd\ncd /personal/dir1/./dir2/\npwd\ncd nonexistent\npwd\ncd /personal/nonexistent/..\npwd\ncd /\npwd\n')
check "cd navigation" "Directory already exists
/personal/dir1/dir2
/personal/dir1/dir2
/personal
/
/personal/dir1/dir2
/personal/dir1/dir2
/personal/dir1/dir2
/" "$out"

out=$(run alice_keyfile $'cd personal\nmkfile file1 hello world  with   spaces\nmkdir adir\nmkfile zfile z\nls\ncat file1\ncat nofile\ncat adir\ncd file1\npwd\nmkfile file1 replaced\ncat file1\nmkdir file1\nmkfile adir x\ncat dir1/../file1\ncat /personal/file1\ncat file1/x\n')
check "files" "d -> .
d -> ..
d -> adir
d -> dir1
f -> file1
f -> zfile
hello world  with   spaces
nofile doesn't exist
adir doesn't exist
/personal
replaced
File already exists
Directory already exists
replaced
replaced
file1/x doesn't exist" "$out"

out=$(run alice_keyfile $'cd personal\nmkdir dir1/sub\nmkfile dir1/sub/f deep\ncat dir1/sub/f\nmkdir nope/sub\nmkfile nope/f x\nmkdir .\nmkdir ..\nmkdir /\nmkdir /shared/x\nmkdir /x\nmkfile\nmkfile onlyname\ncd\ncd a b\nls x\npwd x\ncat\nshare\nshare a\n')
check "paths and arg errors" "deep
Directory doesn't exist
Directory doesn't exist
Directory already exists
Forbidden
Forbidden
Forbidden
Forbidden
Invalid Command
Invalid Command
Invalid Command
Invalid Command
Invalid Command
Invalid Command
Invalid Command
Invalid Command
Invalid Command" "$out"

long=$(printf 'a%.0s' $(seq 1 300))
out=$(run alice_keyfile "cd personal"$'\n'"mkdir $long"$'\n'"mkfile ok"$'\t'"x"$'\n'"mkfile esc "$'\e'"[31mred"$'\n')
check "name length / control chars" "Invalid Command
Invalid Command
Invalid Command" "$out"

check "prompt shows user and current directory" "alice:/> alice:/personal> /personal" \
    "$(printf 'cd personal\npwd\n' | ./fileserver alice_keyfile | grep -F '/personal> /personal')"
check "blank lines and EOF without exit" "" "$(run alice_keyfile $'\n\n   \n')"

deep=$(printf 'cd personal\n'; for i in $(seq 1 64); do printf 'mkdir d\ncd d\n'; done; printf 'mkdir d\npwd\n')
out=$(run bobby_keyfile "$deep")
check "directory depth limit (64)" "Invalid Command
/personal$(printf '/d%.0s' $(seq 1 64))" "$out"

# ---------------------------------------------------------------- sharing
out=$(run alice_keyfile $'cd personal\nmkfile secret.txt top secret alpha\nshare secret.txt bobby\nshare nofile bobby\nshare nofile nouser\nshare secret.txt nouser\nshare secret.txt alice\nshare secret.txt admin\nshare adir bobby\nshare dir1/sub/f bobby\nshare /personal/file1 carol\n')
check "share errors (sharing with admin is allowed)" "File nofile doesn't exist
File nofile doesn't exist
User nouser doesn't exist
Forbidden
File adir doesn't exist" "$out"

out=$(run bobby_keyfile $'cd shared\nls\ncd alice\nls\ncat secret.txt\ncat dir1/sub/f\nmkfile x y\nmkdir x\nshare secret.txt carol\ncd ..\nmkfile x y\npwd\n')
check "recipient view keeps the owner's path (read-only)" "d -> .
d -> ..
d -> alice
d -> .
d -> ..
d -> dir1
f -> secret.txt
top secret alpha
deep
Forbidden
Forbidden
Forbidden
Forbidden
/shared" "$out"

run alice_keyfile $'cd personal\nmkfile secret.txt top secret beta\n' > /dev/null
check "recipient sees updated contents" "top secret beta" "$(run bobby_keyfile $'cat /shared/alice/secret.txt\n')"
run alice_keyfile $'share personal/secret.txt bobby\n' > /dev/null
check "re-share is idempotent" "d -> .
d -> ..
d -> dir1
f -> secret.txt" "$(run bobby_keyfile $'cd shared/alice\nls\n')"
check "non-recipient sees nothing" "d -> .
d -> ..
d -> alice" "$(run carol_keyfile $'cd shared\nls\n')"
check "carol got file1" "replaced" "$(run carol_keyfile $'cat shared/alice/file1\n')"
check "carol cannot read bobby's shares" "/shared/alice/secret.txt doesn't exist" "$(run carol_keyfile $'cat /shared/alice/secret.txt\n')"

# Concurrent sessions: bobby is logged in while alice shares a new file.
mkfifo bob_in
./fileserver bobby_keyfile < bob_in > bob_out &
BOB_PID=$!
exec 3> bob_in
echo 'cd /shared/alice' >&3
sleep 0.3
run alice_keyfile $'cd personal\nmkfile live.txt fresh\nshare live.txt bobby\n' > /dev/null
echo 'cat live.txt' >&3
echo 'exit' >&3
exec 3>&-
wait "$BOB_PID"
out=$(strip_prompts < bob_out | tail -1)
check "live session sees new share" "fresh" "$out"

# ---------------------------------------------------------------- admin read-all
out=$(run admin_keyfile $'cd alice\nls\ncd personal\nls\ncat secret.txt\ncd /bobby/shared/alice\ncat secret.txt\ncd /carol/personal\nls\ncd /nouser\npwd\nmkfile /alice/personal/x y\ncd /alice/personal\nmkdir z\nmkfile secret.txt hacked\ncat secret.txt\n')
check "admin reads everything, writes nothing" "d -> .
d -> ..
d -> personal
d -> shared
d -> .
d -> ..
d -> adir
d -> dir1
f -> file1
f -> live.txt
f -> secret.txt
f -> zfile
top secret beta
top secret beta
d -> .
d -> ..
/carol/personal
Forbidden
Forbidden
Forbidden
top secret beta" "$out"

# ---------------------------------------------------------------- admin as a regular user
out=$(run admin_keyfile $'cd /personal\nmkdir adm\nmkfile adm/notice.txt hello from admin\nls\ncat adm/notice.txt\nshare adm/notice.txt alice\nshare /alice/personal/secret.txt bobby\nshare /shared/alice/secret.txt bobby\ncd /shared\nls\ncd alice\nls\ncat secret.txt\nmkfile /shared/alice/x y\nshare /personal/adm/notice.txt admin\nmkdir /alice/x\nmkdir /alice/shared/x\npwd\n')
check "admin own /personal and /shared" "d -> .
d -> ..
d -> adm
hello from admin
Forbidden
Forbidden
d -> .
d -> ..
d -> alice
d -> .
d -> ..
f -> secret.txt
top secret beta
Forbidden
Forbidden
Forbidden
Forbidden
/shared/alice" "$out"
check "user sees file shared by admin" "d -> .
d -> ..
d -> admin
hello from admin" "$(run alice_keyfile $'cd shared\nls\ncat admin/adm/notice.txt\n')"
run admin_keyfile $'mkfile /personal/adm/notice.txt updated by admin\n' > /dev/null
check "admin's update reaches recipient" "updated by admin" "$(run alice_keyfile $'cat /shared/admin/adm/notice.txt\n')"
check "admin views a user's shared dir" "d -> .
d -> ..
d -> admin
updated by admin" "$(run admin_keyfile $'cd /alice/shared\nls\ncat admin/adm/notice.txt\n')"

# ---------------------------------------------------------------- confidentiality on disk
ALICE_UID=$(kf uid alice_keyfile)
BOB_UID=$(kf uid bobby_keyfile)
CAROL_UID=$(kf uid carol_keyfile)
check "keyfile is JSON with expected fields" "alice" "$(kf user alice_keyfile)"

# Objects are raw ciphertext, so only grep for strings long enough (>= 5
# chars) that a random match is negligible.
leak=0
for s in alice bobby carol secret.txt "top secret" "hello world" file1 live.txt notice.txt "from admin" personal shared; do
    if grep -rqaF -- "$s" filesystem public_keys; then echo "    leak: '$s'"; leak=1; fi
done
check "no plaintext names/contents on disk" "0" "$leak"
check "no plaintext dirs on host" "" "$(find filesystem -type d | grep -E 'alice|bobby|dir1|adir' )"
check "flat layout: every name is 64 hex" "0" "$(find filesystem -mindepth 1 -printf '%f\n' | grep -cvE '^[0-9a-f]{64}$')"
check "flat layout: no subdirectories at all" "0" "$(find filesystem -mindepth 1 -type d | wc -l)"
uidleak=0
for u in "$ALICE_UID" "$BOB_UID" "$CAROL_UID"; do
    if find filesystem | grep -q "$u" || grep -rqaF "$u" filesystem; then uidleak=1; fi
done
check "no user id appears in any name or content (no ownership grouping)" "0" "$uidleak"

before=$(snap); run alice_keyfile $'cd personal\nmkfile s1 a\n' > /dev/null; S1=$(created_by "$before")
before=$(snap); run alice_keyfile "cd personal"$'\n'"mkfile s2 $(printf 'b%.0s' $(seq 1 200))"$'\n' > /dev/null
S2=$(created_by "$before")
check "one new object per new file" "1 1" "$(printf '%s\n' "$S1" | wc -l) $(printf '%s\n' "$S2" | wc -l)"
check "blob sizes are padded to one bucket" "$(stat -c %s filesystem/$S1)" "$(stat -c %s filesystem/$S2)"

# Every file under filesystem/ is AES-GCM output: nonce(12) + 256-byte-padded
# ciphertext + tag(16). Nothing is stored as plaintext JSON.
bad=0
while IFS= read -r f; do
    sz=$(stat -c %s "$f")
    if [ $(( (sz - 28) % 256 )) -ne 0 ] || [ "$sz" -lt 284 ]; then bad=1; echo "    not ciphertext-shaped: $f ($sz)"; fi
done < <(find filesystem -type f)
check "every object is nonce + padded ciphertext + tag" "0" "$bad"
check "no object is plaintext JSON" "0" "$(grep -rlaF -e '"type"' -e '"users"' -e '"children"' -e '"content"' -e '"owner"' filesystem | wc -l)"

# ---------------------------------------------------------------- keyfile forgery / insider attacks

sed 's/"user": "alice"/"user": "bobby"/' alice_keyfile > forged1
check "username swapped in keyfile" "Invalid keyfile" "$(./fileserver forged1 < /dev/null | head -1)"
sed "s/\"uid\": \"$ALICE_UID\"/\"uid\": \"$BOB_UID\"/; s/\"user\": \"alice\"/\"user\": \"bobby\"/" alice_keyfile > forged2
check "uid+user swapped in keyfile" "Invalid keyfile" "$(./fileserver forged2 < /dev/null | head -1)"
sed "s/\"uid\": \"$ALICE_UID\"/\"uid\": \"..\/..\/..\/etc\/passwd\"/" alice_keyfile > forged3
check "path traversal uid" "Invalid keyfile" "$(./fileserver forged3 < /dev/null | head -1)"
{ printf '%.0s{"a":' $(seq 1 50000); printf '1'; printf '%.0s}' $(seq 1 50000); } > bomb_keyfile
check "JSON nesting-bomb keyfile" "Invalid keyfile" "$(./fileserver bomb_keyfile < /dev/null | head -1)"
sed 's/"v": 1/"v": 1, "extra": true/' alice_keyfile > extra_keyfile
check "keyfile with unexpected field" "Invalid keyfile" "$(./fileserver extra_keyfile < /dev/null | head -1)"
sed 's/"user": "alice"/"user": 42/' alice_keyfile > type_keyfile
check "keyfile with wrong field type" "Invalid keyfile" "$(./fileserver type_keyfile < /dev/null | head -1)"
{ cat alice_keyfile; echo '{}'; } > trailing_keyfile
check "keyfile with trailing data" "Invalid keyfile" "$(./fileserver trailing_keyfile < /dev/null | head -1)"
# A keyfile the program did not issue: valid JSON, alice's name and uid, but
# a key pair generated by the attacker -> not the key pinned in the registry.
mkkeyfile() {  # mkkeyfile <user> <uid> <pem-file>
    printf '{\n  "private_key": "%s",\n  "type": "bibifi.keyfile",\n  "uid": "%s",\n  "user": "%s",\n  "v": 1\n}\n' \
        "$(awk '{printf "%s\\n", $0}' "$3")" "$2" "$1"
}
if command -v openssl > /dev/null; then
    openssl genpkey -algorithm ED25519 -out own.pem 2>/dev/null
    mkkeyfile alice "$ALICE_UID" own.pem > selfmade_keyfile
    check "self-made Ed25519 key for alice" "Invalid keyfile" "$(./fileserver selfmade_keyfile < /dev/null | head -1)"
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.pem 2>/dev/null
    mkkeyfile alice "$ALICE_UID" rsa.pem > rsa_keyfile
    check "non-Ed25519 key rejected" "Invalid keyfile" "$(./fileserver rsa_keyfile < /dev/null | head -1)"
    # Same key, re-wrapped by the test's own JSON writer: the format is
    # accepted, so the two rejections above are about the key, not parsing.
    grep '^  "private_key": ' alice_keyfile | sed 's/^  "private_key": "//; s/",$//; s/\\n/\n/g' | sed '/^$/d' > alice.pem
    mkkeyfile alice "$ALICE_UID" alice.pem > rewrapped_keyfile
    check "control: re-wrapped genuine key logs in" "Logged in as alice" "$(./fileserver rewrapped_keyfile < /dev/null | head -1)"
fi
cp alice_keyfile renamed_keyfile
check "renamed keyfile still identifies alice" "Logged in as alice" "$(./fileserver renamed_keyfile < /dev/null | head -1)"

# Attacker replaces bobby's public key with alice's -> bobby can no longer log
# in (DoS) but cannot be impersonated, and alice still cannot log in as bobby.
cp public_keys/$BOB_UID.pem bob.bak
cp public_keys/$ALICE_UID.pem public_keys/$BOB_UID.pem
check "swapped public key rejects bobby" "Invalid keyfile" "$(./fileserver bobby_keyfile < /dev/null | head -1)"
check "swapped public key does not admit forged2" "Invalid keyfile" "$(./fileserver forged2 < /dev/null | head -1)"
cp bob.bak public_keys/$BOB_UID.pem

# Blob swap: put s2's ciphertext in place of s1's (copy/move attack) -> detected.
cp filesystem/$S1 save1
cp filesystem/$S2 filesystem/$S1
out=$(run alice_keyfile $'cd personal\ncat secret.txt\ncat file1\ncat zfile\ncat live.txt\ncat s1\ncat s2\ncat dir1/sub/f\n' | grep -c 'integrity check failed')
check "swapped blob detected (AAD/signature bound to location)" "1" "$out"
cp save1 filesystem/$S1

# Bit flip in alice's tree (the only object rewritten by mkdir) -> refused.
before=$(snap); touch marker; sleep 0.01
run alice_keyfile $'mkdir personal/newdir\n' > /dev/null
META=$(modified_since "$before" marker)
check "mkdir rewrites exactly one object" "1" "$(printf '%s\n' "$META" | grep -c .)"
cp filesystem/$META meta.bak
printf '\xff' | dd of=filesystem/$META bs=1 seek=40 conv=notrunc 2>/dev/null
check "tampered tree detected" "Error: filesystem integrity check failed" "$(run alice_keyfile $'cd personal\nls\n')"
cp meta.bak filesystem/$META

# Cross-user swap: copy alice's tree over bobby's -> bobby must NOT see alice's
# files (the AAD names the owner), he gets an integrity error instead.
touch marker; sleep 0.01
run bobby_keyfile $'mkdir personal/bdir\n' > /dev/null
BMETA=$(modified_since "$(snap)" marker)
cp filesystem/$BMETA bmeta.bak
cp filesystem/$META filesystem/$BMETA
check "another user's tree copied in is rejected" "Error: filesystem integrity check failed" "$(run bobby_keyfile $'cd personal\nls\n')"
cp bmeta.bak filesystem/$BMETA

# Registry = the pre-existing object that adduser rewrites. Tamper -> fail closed.
before=$(snap); touch marker; sleep 0.01
run admin_keyfile $'adduser dave\n' > /dev/null
REG=$(modified_since "$before" marker)
check "adduser rewrites exactly one existing object" "1" "$(printf '%s\n' "$REG" | grep -c .)"
cp filesystem/$REG reg.bak
printf '\x00' | dd of=filesystem/$REG bs=1 seek=100 conv=notrunc 2>/dev/null
check "tampered registry rejected" "Invalid keyfile" "$(./fileserver alice_keyfile < /dev/null | head -1)"
cp reg.bak filesystem/$REG

# ---------------------------------------------------------------- share objects (share|<uid>)
# Nested paths: two files with the same name in different directories are
# both visible, under the owner's path, read-only all the way down.
run alice_keyfile $'cd personal\nmkdir pa\nmkdir pb\nmkfile pa/same one\nmkfile pb/same two\nshare pa/same carol\nshare pb/same carol\n' > /dev/null
check "same file name in two directories: both shared" "d -> .
d -> ..
d -> pa
d -> pb
f -> file1
one
two" "$(run carol_keyfile $'cd /shared/alice\nls\ncat pa/same\ncat /shared/alice/pb/same\n')"
check "nested shared directory is read-only" "/shared/alice/pa
Forbidden
Forbidden
Forbidden
/shared/alice/pa" "$(run carol_keyfile $'cd /shared/alice/pa\npwd\nmkfile x y\nmkdir d\nshare same bobby\npwd\n')"
check "unshared sibling directories are not revealed" "/shared/alice/adir doesn't exist" "$(run carol_keyfile $'cat /shared/alice/adir\n')"

# A share rewrites exactly one object: the recipient's share list.
before=$(snap); touch marker; sleep 0.01
run alice_keyfile $'share personal/zfile carol\n' > /dev/null
CAROL_SH=$(modified_since "$before" marker)
check "share rewrites exactly the recipient's list" "1 0" \
    "$(printf '%s\n' "$CAROL_SH" | grep -c .) $(created_by "$before" | grep -c .)"
before=$(snap); touch marker; sleep 0.01
run alice_keyfile $'share personal/secret.txt bobby\n' > /dev/null
BOB_SH=$(modified_since "$before" marker)
check "share objects located" "yes" "$([ -f "filesystem/$CAROL_SH" ] && [ -f "filesystem/$BOB_SH" ] && [ "$CAROL_SH" != "$BOB_SH" ] && echo yes)"

CAROL_VIEW=$(run carol_keyfile $'cd shared/alice\nls\n')
cp "filesystem/$CAROL_SH" carol_sh.bak
# Bobby's list copied over carol's: authenticated for share|<bobby>, not carol.
cp "filesystem/$BOB_SH" "filesystem/$CAROL_SH"
check "another user's share list is rejected" "Error: filesystem integrity check failed" "$(run carol_keyfile $'cd shared\n')"
cp carol_sh.bak "filesystem/$CAROL_SH"
printf '\x01' | dd of="filesystem/$CAROL_SH" bs=1 seek=50 conv=notrunc 2>/dev/null
check "bit-flipped share list is rejected" "Error: filesystem integrity check failed" "$(run carol_keyfile $'cd shared\n')"
printf '{"shares":[{"owner":"%s","blob":"%s","path":"x"}]}' "$BOB_UID" "$(printf 'ab%.0s' $(seq 1 16))" > "filesystem/$CAROL_SH"
check "plaintext JSON share list is rejected" "Error: filesystem integrity check failed" "$(run carol_keyfile $'cd shared\n')"
check "a corrupt list is never overwritten by a new share" "Error: filesystem integrity check failed" "$(run alice_keyfile $'share personal/file1 carol\n')"
ln -sf /etc/passwd "filesystem/$CAROL_SH"
check "symlinked share list is refused" "Error: filesystem integrity check failed" "$(run carol_keyfile $'cd shared\n')"
rm -f "filesystem/$CAROL_SH"; cp carol_sh.bak "filesystem/$CAROL_SH"
check "restored list works again" "$CAROL_VIEW" "$(run carol_keyfile $'cd shared/alice\nls\n')"

# Several owners share with the same recipient, one after another: the list
# keeps every entry. (There is no lock: shares at the very same instant may
# race, see ARCH.md §7.)
run bobby_keyfile $'mkfile personal/fromb x\nshare personal/fromb carol\n' > /dev/null
run admin_keyfile $'mkfile personal/froma y\nshare personal/froma carol\n' > /dev/null
check "shares from several owners all kept" "d -> .
d -> ..
d -> admin
d -> alice
d -> bobby" "$(run carol_keyfile $'cd /shared\nls\n')"

# ---------------------------------------------------------------- fresh dir & existing empty fs dir
mkdir fresh && cd fresh && cp ../fileserver . && mkdir filesystem
check "empty filesystem dir gets initialised" "Logged in as admin" "$(./fileserver admin_keyfile < /dev/null | head -1)"
check "other fs keyfile rejected" "Invalid keyfile" "$(./fileserver ../alice_keyfile < /dev/null | head -1)"
cd ..

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
