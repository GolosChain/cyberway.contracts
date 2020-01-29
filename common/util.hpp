#pragma once
#include "config.hpp"

namespace cyber {

template<typename T>
struct member_pointer_info;

template<typename C, typename V>
struct member_pointer_info<V C::*> {
    using value_type = V;
    using class_type = C;
};

static int64_t safe_prop(int64_t arg, int64_t numer, int64_t denom) {
    return !arg || !numer ? 0 : static_cast<int64_t>((static_cast<int128_t>(arg) * numer) / denom);
}

static int64_t safe_pct(int64_t arg, int64_t total) {
    return safe_prop(arg, total,  config::_100percent);
}

static int64_t mul_cut(int64_t a, int64_t b) {
    static constexpr int128_t max_ret128 = std::numeric_limits<int64_t>::max();
    auto ret128 = static_cast<int128_t>(a) * b;
    return static_cast<int64_t>(std::min(max_ret128, ret128));
}

template<typename T>
void reverse_bytes(T* data) {
    static auto constexpr length = sizeof(T);
    auto data_raw = reinterpret_cast<char*>(data);
    std::reverse(data_raw, data_raw + length);
}

//hex (taken from fc)
uint8_t from_hex( char c ) {
    if( c >= '0' && c <= '9' )
    return c - '0';
    if( c >= 'a' && c <= 'f' )
      return c - 'a' + 10;
    if( c >= 'A' && c <= 'F' )
      return c - 'A' + 10;
    eosio::check(false, "non hex character");
    return 0;
}

std::string to_hex( const char* d, uint32_t s ) 
{
    std::string r;
    r.reserve(s * 2);
    const static char* to_hex="0123456789abcdef";
    uint8_t* c = (uint8_t*)d;
    for( uint32_t i = 0; i < s; ++i ) {
        r += to_hex[(c[i]>>4)];
        r += to_hex[(c[i] &0x0f)];
    }
    return r;
}

size_t from_hex( const std::string& hex_str, char* out_data, size_t out_data_len ) {
    eosio::check(hex_str.size() == out_data_len * 2, "incorrect hex string size");
    std::string::const_iterator i = hex_str.begin();
    uint8_t* out_pos = (uint8_t*)out_data;
    uint8_t* out_end = out_pos + out_data_len;
    while( i != hex_str.end() && out_end != out_pos ) {
      *out_pos = from_hex( *i ) << 4;   
      ++i;
      if( i != hex_str.end() )  {
          *out_pos |= from_hex( *i );
          ++i;
      }
      ++out_pos;
    }
    return out_pos - (uint8_t*)out_data;
}
std::string to_hex( const std::vector<char>& data )
{
   if( data.size() )
      return to_hex( data.data(), data.size() );
   return "";
}

std::vector<char> bytes_from_hex(const std::string& hex_str) {
    std::vector<char> ret(hex_str.size() / 2);
    from_hex(hex_str, ret.data(), ret.size());
    return ret;
}

} // commun
