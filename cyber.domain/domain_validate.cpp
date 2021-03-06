#include <eosio/domain.hpp>
#include <string>
#include <vector>

namespace eosiosystem {

using std::string;
using std::vector;

// now we have 2 validator implementations, here and in core. TODO: fix
// 1. reuse core implementation, buut looks like it's costly to swich from wasm
// 2. embed in cdt, looks good, but still 2 implementations
// 3. embed in serializer/deserializer, so input guaranteed to be valid

// constants
constexpr size_t domain_max_size = 253;
constexpr size_t domain_min_part_size = 1;
constexpr size_t domain_max_part_size = 63;

constexpr size_t username_max_size = 32;        // it's 16 in Golos
constexpr size_t username_min_part_size = 1;    // it's 3 in Golos
constexpr size_t username_max_part_size = 32;


inline bool is_digit(char c) {
    return c >= '0' && c <= '9';
}
inline bool is_letter(char c) {
    return c >= 'a' && c <= 'z';
}
inline bool is_allowed_punct(char c) {
    return c == '-' || c == '.';
}
inline bool is_valid_char(char c) {
    return is_letter(c) || is_digit(c) || is_allowed_punct(c);
}

// TODO: optimize to use tokenizer-like processing instead of vector of strings
vector<string> split(const string& s, char d) {
    vector<string> r;
    size_t pos = 0, len = s.size();
    while (pos <= len) {
        auto next = s.find(d, pos);
        auto end = next != string::npos ? next : len;
        r.emplace_back(s.substr(pos, end - pos));
        pos = end + 1;
    };
    return r;
}

enum name_error {
    valid = 0,
    name_too_long,
    part_too_short,
    part_too_long,
    bad_part_edge,
    bad_char,
    all_numeric
};

// name consists of 1 or more parts delimited by dots
name_error validate_part(const string& n, size_t min_size, size_t max_size) {
    if (n.size() < min_size) return part_too_short;
    if (n.size() > max_size) return part_too_long;
    if (n[0] == '-' || n.back() == '-') return bad_part_edge; // Domain labels may not start or end with a hyphen
    // if (!std::all_of(n.begin(), n.end(), is_valid_char)) return bad_char;   // checked outside
    return valid;
}

name_error validate_domain_name(const string& d, size_t max_size, size_t min_part, size_t max_part, bool strict_tld) {
    if (d.size() > max_size) return name_too_long;
    if (!std::all_of(d.begin(), d.end(), is_valid_char)) return bad_char;
    auto parts = split(d, '.');
    for (const auto& part: parts) {
        auto r = validate_part(part, min_part, max_part);
        if (r != valid) return r;
    }
    // Top-level domain names should not be all-numeric
    if (strict_tld) {
        auto tld = parts.back();
        if (std::all_of(tld.begin(), tld.end(), is_digit)) return all_numeric;
    }
    return valid;
}

void validate_domain_name(const domain_name& n) {
    auto r = validate_domain_name(n, domain_max_size, domain_min_part_size, domain_max_part_size, true);
    static const vector<string> err = {
        "",
        "Domain name is too long",
        "Domain label is too short",
        "Domain label is too long",
        "Domain label can't start or end with '-'",
        "Domain name contains bad symbol",
        "Top-level name is all-numeric"
    };
    eosio::check(r == valid, err[r].c_str());
}

void validate_username(const username& n) {
    auto r = validate_domain_name(n, username_max_size, username_min_part_size, username_max_part_size, false);
    static const vector<string> err = {
        "",
        "Username is too long",
        "Username part is too short",
        "Username part is too long",
        "Username part can't start or end with '-'",
        "Username contains bad symbol"
    };
    eosio::check(r == valid, err[r].c_str());
}


} // eosiosystem
