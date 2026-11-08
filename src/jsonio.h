// jsonio.h - defensive helpers around nlohmann::json.
//
// Keyfiles are attacker-controlled JSON. Objects under ./filesystem are only
// parsed after AES-GCM authentication under K_M, but are parsed just as
// strictly (defence in depth):
//   * nesting depth is bounded *before* parsing,
//   * parsing never throws (allow_exceptions = false) and rejects trailing junk,
//   * fields are read only through type-checked accessors (no operator[] on
//     untrusted input, which would throw or silently insert).
#pragma once

#include <optional>
#include <string>

#include <nlohmann/json.hpp>  // vendored in third_party/ (MIT), FAQ 10
#include "util.h"

namespace bibifi {

using json = nlohmann::json;

constexpr std::size_t kMaxJsonDepth = 160;  // trees: 2 levels per directory, max 64 directories deep

// Parses `text` as one JSON document. Returns nullopt on any syntax error,
// trailing data, or nesting deeper than maxDepth.
std::optional<json> parseJson(const std::string& text, std::size_t maxDepth = kMaxJsonDepth);
std::optional<json> parseJson(const Bytes& bytes, std::size_t maxDepth = kMaxJsonDepth);

// Compact serialisation. Invalid UTF-8 is replaced, never thrown on.
std::string dumpJson(const json& j);
Bytes dumpJsonBytes(const json& j);

// Type-checked field access; all return false/nullopt when the field is
// missing or has the wrong type.
bool getString(const json& obj, const char* key, std::string& out);
bool getU64(const json& obj, const char* key, std::uint64_t& out);
// True iff `obj` is an object whose keys are exactly `keys` (no extras).
bool hasExactKeys(const json& obj, std::initializer_list<const char*> keys);

}  // namespace bibifi
