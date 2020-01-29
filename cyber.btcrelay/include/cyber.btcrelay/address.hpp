#pragma once
#include "config.hpp"
namespace cyber {

enum class pk_script_standard { P2PKH, P2SH, P2WPKH, P2WSH, UNKNOWN };

struct address_t {
    std::vector<uint8_t> hash;
    pk_script_standard standard = pk_script_standard::UNKNOWN;
    bool operator ==(const address_t& rhs)const {
        return standard != pk_script_standard::UNKNOWN &&
               standard == rhs.standard &&
               hash.size() == rhs.hash.size() &&
               !memcmp(hash.data(), rhs.hash.data(), hash.size());
    }
};

address_t hex_to_address (const std::string& address_hex) {
    //based on key_io.cpp: DecodeDestination
    std::vector<uint8_t> data;
    if (DecodeBase58Check(address_hex, data, 21) && data.size() == 21) {
        if (data[0] == config::base58_PKH_prefix) {
            return address_t { .hash = std::vector<uint8_t>(data.begin() + 1, data.end()), .standard = pk_script_standard::P2PKH };
        }
        else if (data[0] == config::base58_SH_prefix) {
            return address_t { .hash = std::vector<uint8_t>(data.begin() + 1, data.end()), .standard = pk_script_standard::P2SH };
        }
    }
    
    data.clear();
    auto bech = bech32::Decode(address_hex);
    if (bech.second.size() > 0 && bech.first == config::bech32_hrp) {
        // Bech32 decoding
        int version = bech.second[0]; // The first 5 bit symbol is the witness version (0-16)
        // The rest of the symbols are converted witness program bytes.
        data.reserve(((bech.second.size() - 1) * 5) / 8);
        
        //only version 0 is supported
        if (ConvertBits<5, 8, false>([&](unsigned char c) { data.push_back(c); }, bech.second.begin() + 1, bech.second.end()) && version == 0) {
            if (data.size() == 20) {
                return address_t { .hash = data, .standard = pk_script_standard::P2WPKH };
            }
            else if (data.size() == 32) {
                return address_t { .hash = data, .standard = pk_script_standard::P2WSH };
            }
        }
    }
    return address_t {};
}

constexpr uint8_t OP_0            = 0x00;
constexpr uint8_t OP_DUP          = 0x76;
constexpr uint8_t OP_EQUAL        = 0x87;
constexpr uint8_t OP_EQUALVERIFY  = 0x88;
constexpr uint8_t OP_HASH160      = 0xa9;
constexpr uint8_t OP_CHECKSIG     = 0xac;

address_t script_to_address (const uint8_t* data, size_t len) {
    if (     len == 25                     && 
            * data       == OP_DUP         && 
            *(data + 1)  == OP_HASH160     &&
            *(data + 2)  == 20             &&
            *(data + 23) == OP_EQUALVERIFY &&
            *(data + 24) == OP_CHECKSIG) {
        return address_t { .hash = std::vector<uint8_t>(data + 3, data + 23), .standard = pk_script_standard::P2PKH };
    }
    else if (len == 23                     &&
            * data       == OP_HASH160     && 
            *(data + 1)  == 20             &&
            *(data + 22) == OP_EQUAL) {
        return address_t { .hash = std::vector<uint8_t>(data + 2, data + 22), .standard = pk_script_standard::P2SH };
    }
    else if (len == 22                     &&
            * data       == OP_0           && 
            *(data + 1)  == 20) {
        return address_t { .hash = std::vector<uint8_t>(data + 2, data + 22), .standard = pk_script_standard::P2WPKH };
    }
    else if (len == 34                     &&
            * data       == OP_0           && 
            *(data + 1)  == 32) {
        return address_t { .hash = std::vector<uint8_t>(data + 2, data + 34), .standard = pk_script_standard::P2WSH };
    }
    return address_t {};
}

}

