#include "jsonio.h"

namespace bibifi {

namespace {

// Linear scan that tracks string literals so brackets inside strings do not
// count. Runs before the real parser to cap the depth of untrusted input.
bool depthWithin(const std::string& text, std::size_t maxDepth) {
    std::size_t depth = 0;
    bool inString = false;
    bool escaped = false;
    for (char c : text) {
        if (inString) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                inString = false;
            }
        } else if (c == '"') {
            inString = true;
        } else if (c == '{' || c == '[') {
            if (++depth > maxDepth) return false;
        } else if (c == '}' || c == ']') {
            if (depth > 0) --depth;
        }
    }
    return true;
}

}  // namespace

std::optional<json> parseJson(const std::string& text, std::size_t maxDepth) {
    if (text.size() > kMaxObjectSize || !depthWithin(text, maxDepth)) return std::nullopt;
    json j = json::parse(text, /*cb=*/nullptr, /*allow_exceptions=*/false, /*ignore_comments=*/false);
    if (j.is_discarded()) return std::nullopt;
    return j;
}

std::optional<json> parseJson(const Bytes& bytes, std::size_t maxDepth) {
    std::string text(bytes.begin(), bytes.end());
    auto j = parseJson(text, maxDepth);
    wipe(text);
    return j;
}

std::string dumpJson(const json& j) { return j.dump(-1, ' ', false, json::error_handler_t::replace); }

Bytes dumpJsonBytes(const json& j) { return toBytes(dumpJson(j)); }

bool getString(const json& obj, const char* key, std::string& out) {
    if (!obj.is_object()) return false;
    auto it = obj.find(key);
    if (it == obj.end() || !it->is_string()) return false;
    out = it->get<std::string>();
    return true;
}

bool getU64(const json& obj, const char* key, std::uint64_t& out) {
    if (!obj.is_object()) return false;
    auto it = obj.find(key);
    if (it == obj.end() || !it->is_number_unsigned()) return false;
    out = it->get<std::uint64_t>();
    return true;
}

bool hasExactKeys(const json& obj, std::initializer_list<const char*> keys) {
    if (!obj.is_object() || obj.size() != keys.size()) return false;
    for (const char* k : keys) {
        if (!obj.contains(k)) return false;
    }
    return true;
}

}  // namespace bibifi
