#pragma once
#include "test_api_helper.hpp"
#include "../common/config.hpp"
#include "../cyber.govern/include/cyber.govern/config.hpp"

namespace eosio { namespace testing {

struct cyber_govern_api: base_contract_api {
public:
    cyber_govern_api(golos_tester* tester, name code)
    :   base_contract_api(tester, code){}

    variant get_active_producers() const {
        std::vector<account_name> ret_vec;
        for (const auto& k : _tester->control->pending_block_state()->active_schedule.producers) {
            ret_vec.emplace_back(k.producer_name);
        }
        std::sort(ret_vec.begin(), ret_vec.end());
        variant ret;
        to_variant(ret_vec, ret);
        return ret;
    }

     ////tables
    
    int64_t get_balance(account_name account, bool confirmed = true) {
        auto s = get_struct(_code, N(producer), account.value, "producer_struct");
        auto r = !s.is_null() ? s[confirmed ? "amount" : "unconfirmed_amount"].as<int64_t>() : -1;
        return (!r) ? (-1) : r;
    }
    
    variant get_state()const {
        auto all = _tester->get_all_chaindb_rows(_code, _code.value, N(governstate), false);
        BOOST_REQUIRE(all.size() == 1);
        return all[0];
    }

    uint32_t get_block_num()const { return get_state()["block_num"].as<uint32_t>(); }
    uint32_t get_last_propose_block_num()const { return get_state()["last_propose_block_num"].as<uint32_t>(); }
    int64_t get_target_emission_per_block()const { return get_state()["target_emission_per_block"].as<int64_t>(); }

    static variant make_producers_group(std::vector<account_name> accounts) {
        std::sort(accounts.begin(), accounts.end());
        variant ret;
        to_variant(accounts, ret);
        return ret;
    }
    uint32_t get_block_offset()const {
         return _tester->control->head_block_num() - get_block_num();
    }
    
    uint32_t wait_for_proper_block(uint32_t interval, const std::string& s, uint32_t displ = 0, 
                                   std::map<account_name, uint32_t>* prod_blocks = nullptr, 
                                   const std::set<account_name>& disabled_producers = std::set<account_name>()) {
        auto prev_block = _tester->control->head_block_num();
        while((get_block_num() + displ) % interval != 0) {
            _tester->produce_block(fc::milliseconds(config::block_interval_ms), 0, disabled_producers);
            if (prod_blocks) {
                (*prod_blocks)[_tester->control->head_block_producer()]++;
            }
        }
        uint32_t ret = _tester->control->head_block_num() - prev_block;
        BOOST_TEST_MESSAGE("--- waited " << ret << " blocks for " << s << " (displ = " << displ << ")");
        return ret;
    }

    uint32_t wait_proposing(const std::set<account_name>& disabled_producers = std::set<account_name>()) {
        auto prev_block = _tester->control->head_block_num();
        while(get_block_num() != get_last_propose_block_num()) {
            _tester->produce_block(fc::milliseconds(config::block_interval_ms), 0, disabled_producers);
        }
        uint32_t ret = _tester->control->head_block_num() - prev_block;
        BOOST_TEST_MESSAGE("--- waited " << ret << " blocks");
        return ret;
    }
    
    uint32_t wait_reward(uint32_t displ = 0, std::map<account_name, uint32_t>* prod_blocks = nullptr, 
                         const std::set<account_name>& disabled_producers = std::set<account_name>()) {
        return wait_for_proper_block(cyber::config::reward_interval, "reward", displ, prod_blocks, disabled_producers);
    }
    
    signed_block_ptr wait_irreversible_block(const uint32_t lib, const std::set<account_name>& disabled_producers = std::set<account_name>()) {
        signed_block_ptr b;
        while (_tester->control->head_block_state()->dpos_irreversible_blocknum < lib) {
            b = _tester->produce_block(fc::milliseconds(config::block_interval_ms), 0, disabled_producers);
        }
        return b;
    }
    
    uint32_t wait_schedule_activation(bool change_version = true, const std::set<account_name>& disabled_producers = std::set<account_name>()) {
        auto blocks_for_update = wait_proposing(disabled_producers);
        auto prev_version = _tester->control->head_block_header().schedule_version;
        auto prev_block = _tester->control->head_block_num();
        auto prev_block_offset = get_block_offset();
        auto proposed_schedule_block_num = _tester->control->head_block_num() + 1; // see controller.cpp set_proposed_producers
        
        wait_irreversible_block(proposed_schedule_block_num, disabled_producers);
        wait_irreversible_block(_tester->control->head_block_num(), disabled_producers);
        BOOST_REQUIRE_EQUAL(_tester->control->head_block_header().schedule_version, prev_version);
        BOOST_REQUIRE_EQUAL(get_block_offset(), prev_block_offset);
        
        BOOST_REQUIRE_EQUAL(_tester->control->pending_block_state()->active_schedule.version, prev_version + static_cast<int>(change_version));
        auto ret = _tester->control->head_block_num() - prev_block;
        BOOST_TEST_MESSAGE("--- waited " << ret << " more blocks for schedule activation");
        ret += blocks_for_update;
        return ret;
    }
    
    action_result set_shift(int8_t shift) {
        std::vector<account_name> signers;
        std::vector<permission_level> perms;
        for (const auto& k : _tester->control->pending_block_state()->active_schedule.producers) {
            signers.emplace_back(k.producer_name);
            perms.emplace_back(permission_level{k.producer_name, config::active_name});
        }
        perms.emplace_back(permission_level{config::producers_account_name, config::active_name});
        return push_msig(N(setshift), perms, signers, args()("shift", shift));
    }
};

}} // eosio::testing
