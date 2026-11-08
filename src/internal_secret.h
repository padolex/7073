// internal_secret.h - the server master key K_M, embedded in the executable.
//
// Course clarification #2: "A key held inside your program (e.g., compiled
// into it) counts as an internal secret." K_M is that secret. It is never
// written to disk, never placed in a keyfile, and never derived from public
// information.
//
// In this variant K_M protects EVERYTHING under ./filesystem (single master
// key design, see README.md "Key design"). It is only used through two
// HKDF-derived subkeys (storage.cpp):
//
//   K_enc   = HKDF(K_M, "bibifi-new/v1/encryption")  -> AES-256-GCM of every object
//   K_names = HKDF(K_M, "bibifi-new/v1/names")       -> HMAC object names on disk
//
// Generated with `openssl rand -hex 32`. Changing it makes every existing
// filesystem unreadable.
#pragma once

namespace bibifi {

inline constexpr unsigned char kInternalMasterKey[32] = {
    0xd3, 0xde, 0xb9, 0x3b, 0x21, 0x0e, 0xf4, 0x88, 0x1e, 0x5c, 0x04, 0x8c, 0x81, 0x5e, 0x71, 0xfc,
    0x09, 0x94, 0x88, 0xb9, 0xa5, 0x57, 0x2c, 0xc5, 0x25, 0xc9, 0xef, 0xa0, 0xa5, 0x01, 0xd7, 0xde};

}  // namespace bibifi
