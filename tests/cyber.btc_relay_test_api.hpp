#pragma once
#include "test_api_helper.hpp"
#include "../common/config.hpp"

using eosio::chain::symbol_code;
static const auto btc_symbol = eosio::chain::symbol(8, "BTC");

namespace eosio { namespace testing {
    
struct btc_block_header {
    uint32_t version;
    string prev_hash;
    string merkle_root;
    uint32_t time;
    uint32_t bits;
    uint32_t nonce;
};

struct cyber_btc_relay_api: base_contract_api {
public:
    cyber_btc_relay_api(golos_tester* tester, name code) : base_contract_api(tester, code){}
    
    action_result init(btc_block_header header, uint64_t height) {
        return push(N(init), cyber::config::btc_relay_name, 
            args()("header", header)("height", height));
    }
    action_result addheader(btc_block_header header, account_name payer) {
        return push(N(addheader), payer, args()("header", header)("payer", payer));
    }
    action_result addheaderhex(std::string header_hex, account_name payer) {
        return push(N(addheaderhex), payer, args()("header_hex", header_hex)("payer", payer));
    }
    action_result verifytx(std::string tx_hex, uint32_t tx_index, std::vector<std::string> siblings_hex, std::string header_hash_hex, uint64_t min_confirmations_num) {
        return push(N(verifytx), cyber::config::btc_relay_name, args()
            ("tx_hex", tx_hex)("tx_index", tx_index)("siblings_hex", siblings_hex)("header_hash_hex", header_hash_hex)("min_confirmations_num", min_confirmations_num));
    }
    
    action_result checkpayment(std::string tx_hex, std::string address_hex, asset min_quantity) {
        return push(N(checkpayment), cyber::config::btc_relay_name, args()
            ("tx_hex", tx_hex)("address_hex", address_hex)("min_quantity", min_quantity));
    }
    action_result checkaddress(std::string address_hex) {
        return push(N(checkaddress), cyber::config::btc_relay_name, args()("address_hex", address_hex));
    }
};

}} // eosio::testing

FC_REFLECT(eosio::testing::btc_block_header, (version)(prev_hash)(merkle_root)(time)(bits)(nonce))
