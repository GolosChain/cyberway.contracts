#pragma once
#include "test_api_helper.hpp"
#include "../common/config.hpp"

using eosio::chain::symbol_code;

namespace eosio { namespace testing {

struct cyber_box_api: base_contract_api {

public:
    cyber_box_api(golos_tester* tester, name code)
    :   base_contract_api(tester, code){}

    ////actions
    action_result create(name contract, name treasurer, name title, name signer = name()) {
        return push(N(create), signer ? signer : treasurer,
            args()("contract", contract)("treasurer", treasurer)("title", title));
    }
    action_result packup(name contract, name treasurer, name title, name signer = name()) {
        return push(N(packup), signer ? signer : contract,
            args()("contract", contract)("treasurer", treasurer)("title", title));
    }
    action_result unpack(name contract, name treasurer, name title, name owner, name signer) {
        return push(N(unpack), signer,
            args()("contract", contract)("treasurer", treasurer)("title", title)("owner", owner));
    }
    action_result burn(name contract, name treasurer, name title, name signer) {
        return push(N(burn), signer,
            args()("contract", contract)("treasurer", treasurer)("title", title));
    }
    action_result transfer(name contract, name treasurer, name title, name from, name to, std::string memo, name signer) {
        return push(N(transfer), signer,
            args()("contract", contract)("treasurer", treasurer)("title", title)("from", from)("to", to)("memo", memo));
    }
    
    variant get_box(name contract, name treasurer, name title) {
        auto all = _tester->get_all_chaindb_rows(_code, treasurer.value, N(box), false);
        for(auto& v : all) {
            if (v["contract"].as<name>() == contract && v["title"].as<name>() == title) {
                return v;
            }
        }
        return variant();
    }
};

}} // eosio::testing
