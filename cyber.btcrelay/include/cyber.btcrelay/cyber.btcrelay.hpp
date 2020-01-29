//based on https://github.com/ethereum/btcrelay

#pragma once
#include <cmath>
#include <eosio/asset.hpp>
#include <eosio/singleton.hpp>
#include "hash.hpp"
#include "base58.hpp"
#include "bech32.hpp"
#include "address.hpp"

namespace cyber {
using eosio::name;
using eosio::asset;
using eosio::checksum256;

struct [[eosio::table]] block_header_arg {
    uint32_t version;
    std::string prev_hash;
    std::string merkle_root;
    uint32_t time;
    uint32_t bits;
    uint32_t nonce;
};

struct [[eosio::table]] block_header {
    uint32_t version;
    checksum256 prev_hash;
    checksum256 merkle_root;
    uint32_t time;
    uint32_t bits;
    uint32_t nonce;
    static const size_t raw_size = 80;
    std::vector<char> serialize()const {
        std::vector<char> ret(raw_size, 0);
        char* p = ret.data();
        *reinterpret_cast<uint32_t*>(p) = version;
        p += 4;
        *reinterpret_cast<checksum256*>(p) = prev_hash;
        swap_halves(*reinterpret_cast<checksum256*>(p));
        p += 32;
        *reinterpret_cast<checksum256*>(p) = merkle_root;
        swap_halves(*reinterpret_cast<checksum256*>(p));
        p += 32;
        *reinterpret_cast<uint32_t*>(p) = time;
        p += 4;
        *reinterpret_cast<uint32_t*>(p) = bits;
        p += 4;
        *reinterpret_cast<uint32_t*>(p) = nonce;
        return ret;
    }
    
    arith_uint256 target() const {
        arith_uint256 ret;
        ret.SetCompact(bits);
        return ret;
    };
};

block_header get_header(const block_header_arg& header) {
    block_header ret;
    ret.version = header.version;
    ret.prev_hash = hex_to_hash(header.prev_hash);
    ret.merkle_root =  hex_to_hash(header.merkle_root);
    ret.time = header.time;
    ret.bits = header.bits;
    ret.nonce = header.nonce;
    return ret;
}

block_header get_header(const std::vector<char>& data) {
    block_header ret;
    eosio::check(data.size() == block_header::raw_size, "incorrect header data size");
    const char* p = data.data();
    ret.version = *reinterpret_cast<const uint32_t*>(p);
    p += 4;
    ret.prev_hash = bytes_to_hash(p);
    p += 32;
    ret.merkle_root = bytes_to_hash(p);
    p += 32;
    ret.time = *reinterpret_cast<const uint32_t*>(p);
    p += 4;
    ret.bits = *reinterpret_cast<const uint32_t*>(p);
    p += 4;
    ret.nonce = *reinterpret_cast<const uint32_t*>(p);
    return ret;
}
    
class [[eosio::contract("cyber.btcrel")]] btcrelay : public eosio::contract {
    static uint64_t ancestor_depth(uint64_t anc) { return std::pow(config::ancestor_depth_base, anc); };
struct structures {

    struct [[eosio::table]] block {
        uint64_t id;
        checksum256 key;
        block_header header;
        uint64_t height;
        checksum256 chain_work_data = checksum256();
        std::vector<uint64_t> ancestors;
        uint64_t primary_key()const { return id; }
        checksum256 by_key()const { return key; }
    };
    
    struct [[eosio::table("mainchain")]] mainchain_info {
        uint64_t heaviest_block;
        checksum256 chain_work_data = checksum256();
    };
};

    using block_id_index = eosio::indexed_by<"blockid"_n, eosio::const_mem_fun<structures::block, uint64_t, &structures::block::primary_key> >;
    using block_key_index = eosio::indexed_by<"bykey"_n, eosio::const_mem_fun<structures::block, checksum256, &structures::block::by_key> >;
    using blocks = eosio::multi_index<"btcrel.block"_n, structures::block, block_id_index, block_key_index>;
    
    using mainchain_singleton = eosio::singleton<"mainchain"_n, structures::mainchain_info>;
    
    static uint32_t get_new_bits(uint32_t prev_bits, uint32_t start_time, uint32_t prev_time); //see CalculateNextWorkRequired
    
    static inline blocks::const_iterator get_block_itr(blocks& blocks_table, uint64_t height, uint64_t heaviest_block_id) {
        
        btcrelay::blocks::const_iterator ret = blocks_table.find(heaviest_block_id);
        eosio::check(ret != blocks_table.end(), "SYSTEM: heaviest block doesn't exist");
        size_t anc = config::ancestors_num - 1;
        while (ret->height > height) {
            while ((ret->height - height < ancestor_depth(anc)) && anc) {
                --anc;
            }
            ret = blocks_table.find(ret->ancestors[anc]);
            eosio::check(ret != blocks_table.end(), "SYSTEM: ancestor doesn't exist");
        }
        return ret;
    }
    
    static inline uint64_t parse_varint(const std::vector<uint8_t>& bytes, size_t* pos) {
        eosio::check(*pos + 1 < bytes.size(), "parse_varint: incorrect pos value");
        const uint8_t* data = bytes.data() + *pos;
        auto bits = *(data++);
        if (bits < 0xfd) {
            *pos += 1;
            return static_cast<uint64_t>(bits);
        }
        else if (bits == 0xfd) {
            *pos += 3;
            eosio::check(*pos < bytes.size(), "parse_varint: incorrect varint size");
            auto ret = *reinterpret_cast<const uint16_t*>(data);
            return static_cast<uint64_t>(ret);
        }
        else if (bits == 0xfe) {
            *pos += 5;
            eosio::check(*pos < bytes.size(), "parse_varint: incorrect varint size");
            auto ret = *reinterpret_cast<const uint32_t*>(data);
            return static_cast<uint64_t>(ret);
        }
        else {
            eosio::check(bits == 0xff, "incorrect varint");
            *pos += 9;
            eosio::check(*pos < bytes.size(), "parse_varint: incorrect varint size");
            auto ret = *reinterpret_cast<const uint64_t*>(data);
            return ret;
        }
    }
    void add_header(block_header header, name payer);

public:
    using contract::contract;
    [[eosio::action]] void init(block_header_arg header, uint64_t height);
    [[eosio::action]] void addheader(block_header_arg header, name payer);
    [[eosio::action]] void addheaderhex(std::string header_hex, name payer);
    [[eosio::action]] void verifytx(std::string tx_hex, uint32_t tx_index, std::vector<std::string> siblings_hex, std::string header_hash_hex, uint64_t min_confirmations_num);
    [[eosio::action]] void checkpayment(std::string tx_hex, std::string address_hex, asset min_quantity);
    [[eosio::action]] void checkaddress(std::string address_hex);
    
    static inline checksum256 get_merkle(const std::string& tx_hex, uint32_t tx_index, const std::vector<std::string>& siblings_hex) {
        checksum256 ret = get_hash(tx_hex);
        for (size_t i = 0; i < siblings_hex.size(); i++) {
            const auto& sib_hash = hex_to_hash(siblings_hex[i]);
            bool sib_on_left = tx_index % 2;
            checksum256 left  = sib_on_left ? sib_hash : ret;
            checksum256 right = sib_on_left ? ret      : sib_hash;
            ret = concat_hash(left, right);
            tx_index /= 2;
        }
        return ret;
    }
    
    static inline uint64_t get_confirmations_num(name relay_contract_account, const std::string& tx_hex, uint32_t tx_index, const std::vector<std::string>& siblings_hex, const std::string& header_hash_hex) {
        eosio::check(tx_hex.size() / 2 != 64, "64-byte transactions not supported"); //bitslog.com/2018/06/09/leaf-node-weakness-in-bitcoin-merkle-tree-design/
        
        auto mainchain = mainchain_singleton(relay_contract_account, relay_contract_account.value);
        eosio::check(mainchain.exists(), "relay not initialized");
        
        blocks blocks_table(relay_contract_account, relay_contract_account.value);
        auto blocks_idx = blocks_table.get_index<"bykey"_n>();
        const structures::block& block = blocks_idx.get(hex_to_hash(header_hash_hex), "block not found");
        auto heaviest_block_id = mainchain.get().heaviest_block;
        eosio::check(block.key == get_block_itr(blocks_table, block.height, heaviest_block_id)->key, "the block is not in the main chain");
        eosio::check(block.header.merkle_root == get_merkle(tx_hex, tx_index, siblings_hex), "failed to prove transaction existence in block");
        
        auto tip_height = blocks_table.get(heaviest_block_id, "SYSTEM: heaviest block not found").height;
        eosio::check(tip_height >= block.height, "SYSTEM: incorrect block height");
        return (tip_height - block.height) + 1;
    }
    
    static inline bool supported_address(const std::string& address_hex) {
        return hex_to_address(address_hex).standard != pk_script_standard::UNKNOWN;
    }
    
    static inline asset get_payment_quantity(const std::string& tx_hex, const std::string& address_hex) {
        //based on https://github.com/rainbreak/solidity-btc-parser
        
        std::vector<uint8_t> tx_bytes(tx_hex.size() / 2);
        from_hex(tx_hex, reinterpret_cast<char*>(tx_bytes.data()), tx_bytes.size());
        auto arg_address = hex_to_address(address_hex);
        
        eosio::check(arg_address.standard != pk_script_standard::UNKNOWN, "unknown address standard");
        
        size_t pos = 4; // skip version
        eosio::check(pos < tx_bytes.size(), "unexpected end of transaction data");
        
        bool is_segwit_tx = !tx_bytes[pos];
        if (is_segwit_tx) {
            pos++;
            eosio::check(tx_bytes[pos++] == 1, "incorrect segwit flag");
        }
        
        auto inputs_num = parse_varint(tx_bytes, &pos);
        
        for (uint64_t i = 0; i < inputs_num; i++) {
            pos += 36;  // skip outpoint
            eosio::check(pos < tx_bytes.size(), "unexpected end of transaction data");
            auto script_len = parse_varint(tx_bytes, &pos);
            pos += script_len + 4;  // skip sig_script, seq
            eosio::check(pos < tx_bytes.size(), "unexpected end of transaction data");
        }
        
        auto outputs_num = parse_varint(tx_bytes, &pos);
        for (uint64_t i = 0; i < outputs_num; i++) {
            eosio::check(pos + 8 < tx_bytes.size(), "unexpected end of transaction data");
            auto cur_amount = *reinterpret_cast<const uint64_t*>(tx_bytes.data() + pos);
            pos += 8;
            auto script_len = parse_varint(tx_bytes, &pos);
            auto cur_address = script_to_address(tx_bytes.data() + pos, script_len);
            
            if (cur_address == arg_address) {
                return asset(cur_amount, config::btc_symbol);
            }
            pos += script_len;
            eosio::check(pos < tx_bytes.size(), "unexpected end of transaction data");
        }
        eosio::check(false, "payment not found");
        return asset(0, config::btc_symbol);
    }
};
}
