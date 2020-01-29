#pragma once
#include <eosio/eosio.hpp>
#include <eosio/crypto.hpp>
#include "arith_uint256.hpp"

namespace cyber {

eosio::checksum256 get_hash(const char* data, uint32_t length) { //bitcoin-style hash
    auto ret = eosio::sha256(data, length);
    auto bytes = ret.extract_as_byte_array();
    ret = eosio::sha256(reinterpret_cast<char*>(bytes.data()), bytes.size());
    auto ret_data = reinterpret_cast<char*>(ret.data());
    std::reverse(ret_data, ret_data + 32);
    return ret;
}

eosio::checksum256 get_hash(const std::vector<char>& data) {
    return get_hash(data.data(), data.size());
}

eosio::checksum256 get_hash(const std::string& arg) {
    auto bytes = bytes_from_hex(arg);
    return get_hash(bytes.data(), bytes.size());
}

eosio::checksum256 concat_hash(eosio::checksum256 lhs, eosio::checksum256 rhs) {
    auto bytes_lhs = lhs.extract_as_byte_array();
    auto bytes_rhs = rhs.extract_as_byte_array();
    auto lhs_raw = reinterpret_cast<char*>(bytes_lhs.data());
    auto rhs_raw = reinterpret_cast<char*>(bytes_rhs.data());
    std::reverse(lhs_raw, lhs_raw + 32);
    std::reverse(rhs_raw, rhs_raw + 32);
    std::vector<char> concated;
    concated.reserve(64);
    concated.insert(concated.end(), lhs_raw, lhs_raw + 32);
    concated.insert(concated.end(), rhs_raw, rhs_raw + 32);
    return get_hash(concated);
}
    
void swap_halves(eosio::checksum256& arg) {
    auto& arr = const_cast<std::array<eosio::checksum256::word_t, eosio::checksum256::num_words()>&>(arg.get_array());
    std::swap(arr[0], arr[1]);
}

arith_uint256 to_arith256(const eosio::checksum256& arg) {
    arith_uint256 ret = reinterpret_cast<const arith_uint256&>(arg);
    swap_halves(reinterpret_cast<eosio::checksum256&>(ret));
    return ret;
}

eosio::checksum256 to_hash256(const arith_uint256& arg) {
    eosio::checksum256 ret = reinterpret_cast<const eosio::checksum256&>(arg);
    swap_halves(ret);
    return ret;
}

eosio::checksum256 hex_to_hash(const std::string& hex_str) {
    eosio::checksum256 ret;
    eosio::check(hex_str.size() == 64, "invalid hash string size");
    from_hex(hex_str, reinterpret_cast<char*>(ret.data()), 32);
    swap_halves(ret);
    reverse_bytes(&ret);
    return ret;
}

eosio::checksum256 bytes_to_hash(const char* data) {
    eosio::checksum256 ret = *reinterpret_cast<const eosio::checksum256*>(data);
    swap_halves(ret);
    return ret;
}

}

