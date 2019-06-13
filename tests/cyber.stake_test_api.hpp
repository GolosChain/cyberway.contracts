#pragma once
#include "test_api_helper.hpp"
#include "../common/config.hpp"
#include "../cyber.stake/include/cyber.stake/config.hpp"

using eosio::chain::symbol_code;

namespace eosio { namespace testing {

struct cyber_stake_api: base_contract_api {
    bool verbose;
    uint32_t billed_cpu_time_us = base_tester::DEFAULT_BILLED_CPU_TIME_US;
    uint64_t billed_ram_bytes = base_tester::DEFAULT_BILLED_RAM_BYTES;
public:
    cyber_stake_api(golos_tester* tester, name code, bool verbose_ = true)
    :   base_contract_api(tester, code), verbose(verbose_){}
    
    void set_verbose(bool verbose_) { verbose = verbose_; };

    ////actions
    action_result create(account_name issuer, symbol token_symbol,
            std::vector<uint8_t> max_proxies, int64_t payout_step_length, uint16_t payout_steps_num,
            int64_t min_own_staked_for_election = 0) {
        
        _tester->delegate_authority(issuer, {_code}, cyber::config::token_name, N(issue), cyber::config::reward_name);
        _tester->produce_block();
        _tester->delegate_authority(issuer, {_code}, cyber::config::token_name, N(transfer), cyber::config::reward_name);
        return push(N(create), issuer, args()
            ("token_symbol", token_symbol)
            ("max_proxies", max_proxies)
            ("payout_step_length", payout_step_length)
            ("payout_steps_num", payout_steps_num)
            ("min_own_staked_for_election", min_own_staked_for_election)
        );
    }
    
    action_result open(account_name owner, symbol_code token_code, account_name ram_payer = account_name(0)) {
        return ram_payer ? 
            push(N(open), ram_payer, args()("owner", owner)("token_code", token_code)("ram_payer", ram_payer)) : 
            push(N(open), owner,     args()("owner", owner)("token_code", token_code));
    }
    
    action_result enable(account_name issuer, symbol token_symbol) {
        return push(N(enable), issuer, args()
            ("token_symbol", token_symbol)
        );
    }
    
    action_result delegate(account_name grantor_name, account_name agent_name, asset quantity) {
        if (verbose) {
            BOOST_TEST_MESSAGE("--- " << grantor_name <<  " delegates " << quantity <<  " to " << agent_name);
        }
        return push(N(delegate), grantor_name, args()
            ("grantor_name", grantor_name)
            ("agent_name", agent_name)
            ("quantity", quantity)
        );
    }
    
    action_result setgrntterms(account_name grantor_name, account_name agent_name, symbol_code token_code,
        int16_t pct, int16_t break_fee = cyber::config::_100percent, int64_t break_min_own_staked = 0) {
        if (verbose) {
            BOOST_TEST_MESSAGE("--- " << grantor_name <<  " sets grant terms for " << agent_name);
        }
        return push(N(setgrntterms), grantor_name, args()
            ("grantor_name", grantor_name)
            ("agent_name", agent_name)
            ("token_code", token_code)
            ("pct", pct)
            ("break_fee", break_fee)
            ("break_min_own_staked", break_min_own_staked)        
        );
    }
    
    action_result recall(account_name grantor_name, account_name agent_name, symbol_code token_code, int16_t pct) {
        if (verbose) {
            BOOST_TEST_MESSAGE("--- " << grantor_name <<  " recalls " << pct 
                <<  "(" << token_code << ")" << " from " << agent_name);
        }
        return push(N(recall), grantor_name, args()
            ("grantor_name", grantor_name)
            ("agent_name", agent_name)
            ("token_code", token_code)
            ("pct", pct)
        );
    }
    
    action_result withdraw(account_name account, asset quantity) {
        if (verbose) {
            BOOST_TEST_MESSAGE("--- " << account <<  " withdraws " << quantity);
        }
        return push(N(withdraw), account, args()
            ("account", account)
            ("quantity", quantity)
        );
    }
    
    action_result cancelwd(account_name account, asset quantity) {
        if (verbose) {
            BOOST_TEST_MESSAGE("--- " << account <<  " cancels withdraw " << quantity);
        }
        return push(N(cancelwd), account, args()
            ("account", account)
            ("quantity", quantity)
        );
    }
    
    action_result claim(account_name account, symbol_code token_code) {
        if (verbose) {
            BOOST_TEST_MESSAGE("--- " << account <<  " claims " << symbol(token_code << 8).name());
        }
        return push(N(claim), account, args()
            ("account", account)
            ("token_code", token_code)
        );
    }
    
    action_result setproxylvl(account_name account, symbol_code token_code, uint8_t level, bool mssg = true) {
        if (mssg && verbose) {
            BOOST_TEST_MESSAGE("--- " << account <<  " sets proxy level");
        }
        return push(N(setproxylvl), account, args()
            ("account", account)
            ("token_code", token_code)
            ("level", level)
        );
    }
    action_result setproxyfee(account_name account, symbol_code token_code, int16_t fee) {
        return push(N(setproxyfee), account, args()
            ("account", account)
            ("token_code", token_code)
            ("fee", fee)
        );
    }
    action_result setminstaked(account_name account, symbol_code token_code, int64_t min_own_staked) {
        return push(N(setminstaked), account, args()
            ("account", account)
            ("token_code", token_code)
            ("min_own_staked", min_own_staked)
        );
    }

    action_result updatefunds(account_name account, symbol_code token_code) {
        return push(N(updatefunds), account, args()
            ("account", account)
            ("token_code", token_code)
        );
    }
    
    action_result reward(account_name issuer, account_name account, asset quantity) {
        return push(N(reward), issuer, args()
            ("rewards", std::vector<std::pair<account_name, int64_t> >{std::make_pair(account, quantity.get_amount())})
            ("sym", quantity.get_symbol())
        );
    }
    
    action_result register_candidate(account_name account, symbol_code token_code, bool need_to_open = true) {
        if (need_to_open) {
            auto ret = open(account, token_code);
            if(ret != base_tester::success())
                return ret;
        }
        auto ret = setproxylvl(account, token_code, 0);
        if(ret != base_tester::success())
            return ret;
         return push(N(setkey), account, args()
            ("account", account)
            ("token_code", token_code)
            ("signing_key", base_tester::get_public_key(account, "active"))
        );
    }

     ////tables
    variant get_agent(account_name account, symbol token_symbol) {
        auto all = _tester->get_all_chaindb_rows(name(), 0, N(stake.agent), false);
        for(auto& v : all) {
            auto o = mvo(v);
            if (v["account"].as<account_name>() == account && 
                v["token_code"].as<symbol_code>() == token_symbol.to_symbol_code()) 
            {
                o.erase("id");
                o.erase("signing_key");
                v = o;
                return v;
            }
        }
        return variant();
    }

    variant make_agent(
            account_name account, symbol token_symbol, 
            uint8_t proxy_level, 
            time_point_sec last_proxied_update,
            int64_t balance = 0,
            int64_t proxied = 0,
            int64_t shares_sum = 0,
            int64_t own_share = 0,
            int16_t fee = 0,
            int64_t min_own_staked = 0
        ) {
        return mvo()
            ("token_code", token_symbol.to_symbol_code())
            ("account", account)
            ("proxy_level", proxy_level)
            ("last_proxied_update", last_proxied_update)
            ("balance", balance)
            ("proxied", proxied)
            ("shares_sum", shares_sum)
            ("own_share", own_share)
            ("fee", fee)
            ("min_own_staked", min_own_staked);
    }
    
    int64_t get_total_votes(symbol_code token_code) {
        int64_t ret = 0;
        auto all = _tester->get_all_chaindb_rows(name(), 0, N(stake.cand), false);
        for(auto& v : all) {
            if (v["token_code"].as<symbol_code>() == token_code) {
                ret += v["votes"].as<int64_t>();
            }
        }
        return ret;
    }
    
    variant get_stats(symbol token_symbol) {
        auto all = _tester->get_all_chaindb_rows(name(), 0, N(stake.stat), false);
        for(auto& v : all) {
            auto o = mvo(v);
            if (v["token_code"].as<symbol_code>() == token_symbol.to_symbol_code()) 
            {
                o.erase("id");
                v = o;
                return v;
            }
        }
        return variant();
    }
    
    variant make_stats(symbol token_symbol, int64_t total_staked, int64_t total_votes, bool enabled = false, time_point_sec last_reward = time_point_sec()) {
        return mvo()
            ("token_code", token_symbol.to_symbol_code())
            ("total_staked", total_staked)
            ("total_votes", total_votes)
            ("last_reward", last_reward)
            ("enabled", enabled);
    }
};

}} // eosio::testing
