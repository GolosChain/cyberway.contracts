/**
 *  @file
 *  @copyright defined in eos/LICENSE.txt
 */
#pragma once

#include <eosiolib/asset.hpp>
#include <eosiolib/eosio.hpp>
#include <eosiolib/time.hpp>
#include "config.hpp"
#include <string>
#include <tuple>
#include <eosiolib/privileged.h>

#define table_owner name()

namespace cyber {

using eosio::name;
using eosio::asset;
using eosio::symbol;
using eosio::symbol_code;
using eosio::time_point_sec;
using eosio::public_key;
using std::string;

class [[eosio::contract("cyber.stake")]] stake : public eosio::contract {
struct structures {

    struct [[eosio::table]] agent {
        uint64_t id;
        symbol_code token_code;
        name account;
        
        uint8_t proxy_level;
        int64_t votes;
        time_point_sec last_proxied_update;
        int64_t balance = 0;// aka unproxied funds
        int64_t proxied = 0;// proxed funds
        int64_t shares_sum = 0;
        int64_t own_share = 0;
        int16_t fee = 0;
        int64_t min_own_staked = 0;
        public_key signing_key = {};
        
        uint64_t primary_key()const { return id; }
        using key_t = std::tuple<symbol_code, name>;
        key_t by_key()const { return std::make_tuple(token_code, account); }
        using votes_key_t = std::tuple<symbol_code, int64_t, name>;
        votes_key_t by_votes()const { return std::make_tuple(token_code, votes, account); }
        int64_t get_total_funds()const { return balance + proxied; }
        void set_balance(int64_t arg) {
            balance = arg;
            if (!proxy_level) {
                votes = balance;
            }
        };
     };
 
    struct [[eosio::table]] grant {
        uint64_t id;
        symbol_code token_code;
        name grantor_name;
        name agent_name;
        int16_t pct = 0;
        int64_t share = 0;
        int16_t break_fee = config::_100percent;
        int64_t break_min_own_staked = 0;
        
        uint64_t primary_key()const { return id; }
        using key_t = std::tuple<symbol_code, name, name>;
        key_t by_key()const { return std::make_tuple(token_code, grantor_name, agent_name); }
    };
    
    struct [[eosio::table]] param {
        uint64_t id;
        symbol token_symbol;
        std::vector<uint8_t> max_proxies;
        int64_t frame_length;
        int64_t payout_step_length;
        uint16_t payout_steps_num;
        int64_t min_own_staked_for_election = 0;
        uint64_t primary_key()const { return id; }
    };
 
    struct [[eosio::table]] payout {
        uint64_t id;
        symbol_code token_code;
        name account;
        int64_t balance;
        uint16_t steps_left;
        time_point_sec last_step;
        uint64_t primary_key()const { return id; }
        
        using by_account_t = std::tuple<symbol_code, name>;
        by_account_t by_account()const { return std::make_tuple(token_code, account); }
    };
    
    struct [[eosio::table]] stat {
        uint64_t id;
        symbol_code token_code;
        int64_t total_staked;
        bool enabled = false;
        uint64_t primary_key()const { return id; }
    }; 
};

    using agent_id_index = eosio::indexed_by<"agentid"_n, eosio::const_mem_fun<structures::agent, uint64_t, &structures::agent::primary_key> >;
    using agent_key_index = eosio::indexed_by<"bykey"_n, eosio::const_mem_fun<structures::agent, structures::agent::key_t, &structures::agent::by_key> >;
    using agent_votes_index = eosio::indexed_by<"byvotes"_n, eosio::const_mem_fun<structures::agent, structures::agent::votes_key_t, &structures::agent::by_votes> >;
    using agents = eosio::multi_index<"stake.agent"_n, structures::agent, agent_id_index, agent_key_index, agent_votes_index>;
    using agents_idx_t = decltype(agents(table_owner, table_owner.value).get_index<"bykey"_n>());
    
    using grant_id_index = eosio::indexed_by<"grantid"_n, eosio::const_mem_fun<structures::grant, uint64_t, &structures::grant::primary_key> >;
    using grant_key_index = eosio::indexed_by<"bykey"_n, eosio::const_mem_fun<structures::grant, structures::grant::key_t, &structures::grant::by_key> >;
    using grants = eosio::multi_index<"stake.grant"_n, structures::grant, grant_id_index, grant_key_index>;
    using grants_idx_t = decltype(grants(table_owner, table_owner.value).get_index<"bykey"_n>());
    
    using params = eosio::multi_index<"stake.param"_n, structures::param>;
    
    using stat_id_index = eosio::indexed_by<"statid"_n, eosio::const_mem_fun<structures::stat, uint64_t, &structures::stat::primary_key> >;

    using stats = eosio::multi_index<"stake.stat"_n, structures::stat, stat_id_index>;

    using payout_id_index = eosio::indexed_by<"payoutid"_n, eosio::const_mem_fun<structures::payout, uint64_t, &structures::payout::primary_key> >;
    using payout_acc_index = eosio::indexed_by<"payoutacc"_n, eosio::const_mem_fun<structures::payout, structures::payout::by_account_t, &structures::payout::by_account> >;
    using payouts = eosio::multi_index<"payout"_n, structures::payout, payout_id_index, payout_acc_index>;
    
    void update_stake_proxied(symbol_code token_code, name agent_name) {
        ::update_stake_proxied(token_code.raw(), agent_name.value, int64_t(1), static_cast<int>(true));
    }
    
    void send_scheduled_payout(payouts& payouts_table, name account, int64_t payout_step_length, symbol sym, bool claim_mode = false);
    void update_payout(name account, asset quantity, bool claim_mode = false);

    //return: share
    int64_t delegate_traversal(symbol_code token_code, agents_idx_t& agents_idx, grants_idx_t& grants_idx, name agent_name, int64_t amount, bool refill = false);
    
    agents_idx_t::const_iterator get_agent_itr(symbol_code token_code, agents_idx_t& agents_idx, name agent_name, int16_t proxy_level_for_emplaced = -1, agents* agents_table = nullptr, bool* emplaced = nullptr);
    void add_proxy(symbol_code token_code, grants& grants_table, const structures::agent& grantor_as_agent, const structures::agent& agent, 
        int16_t pct, int64_t share, int16_t break_fee = -1, int64_t break_min_own_staked = -1);

    void change_balance(name account, asset quantity);
    void update_stats(const structures::stat& stat_arg, name payer = name());
    
    static inline void check_staking(symbol_code token_code) {
        params params_table(table_owner, table_owner.value);
        params_table.get(token_code.raw(), "no staking for token");
    };
    
    template<typename Lambda>
    void modify_agent(name account, symbol_code token_code, Lambda f) {
        require_auth(account);
        agents agents_table(table_owner, table_owner.value);
        auto agents_idx = agents_table.get_index<"bykey"_n>();
        auto agent = get_agent_itr(token_code, agents_idx, account);
        agents_idx.modify(agent, name(), f);
    }
    static void check_grant_terms(const structures::agent& agent, int16_t break_fee, int64_t break_min_own_staked);

public:

    static inline std::vector<std::pair<name, public_key> > get_top(uint16_t n, symbol_code token_code) {
        check_staking(token_code);
        agents agents_table(table_owner, table_owner.value);
        auto agents_idx = agents_table.get_index<"byvotes"_n>();

        std::vector<std::pair<name, public_key> > ret;
        size_t i = 0;
        auto agent_itr = agents_idx.lower_bound(std::make_tuple(token_code, std::numeric_limits<int64_t>::max(), name()));
        while ((agent_itr != agents_idx.end()) && (agent_itr->token_code == token_code) && (agent_itr->votes >= 0) && (i < n)) {
            if (agent_itr->signing_key != public_key{}) {
                ret.emplace_back(std::make_pair(agent_itr->account, agent_itr->signing_key));
                ++i;
            }
            ++agent_itr;
        }
        return ret;
    }
    
    static inline int64_t get_votes_sum(symbol_code token_code) {
        check_staking(token_code);
        agents agents_table(table_owner, table_owner.value);
        auto agents_idx = agents_table.get_index<"byvotes"_n>();
        int64_t ret = 0;
        auto agent_itr = agents_idx.lower_bound(std::make_tuple(token_code, std::numeric_limits<int64_t>::max(), name()));
        while ((agent_itr != agents_idx.end()) && (agent_itr->token_code == token_code) && (agent_itr->votes > 0)) {
            ret += agent_itr->votes;
            ++agent_itr;
        }
        return ret;
    }

    using contract::contract;

    [[eosio::action]] void create(symbol token_symbol, std::vector<uint8_t> max_proxies, 
        int64_t frame_length, int64_t payout_step_length, uint16_t payout_steps_num,
        int64_t min_own_staked_for_election);
        
    [[eosio::action]] void enable(symbol token_symbol);

    [[eosio::action]] void delegate(name grantor_name, name agent_name, asset quantity);
    
    [[eosio::action]] void setgrntterms(name grantor_name, name agent_name, symbol_code token_code, 
        int16_t pct, int16_t break_fee, int64_t break_min_own_staked);
    [[eosio::action]] void recall     (name grantor_name, name agent_name, symbol_code token_code, int16_t pct);
    
    [[eosio::action]] void withdraw(name account, asset quantity);
    [[eosio::action]] void claim(name account, symbol_code token_code);
    [[eosio::action]] void cancelwd(name account, asset quantity);
 
    void on_transfer(name from, name to, asset quantity, std::string memo);

    [[eosio::action]] void setproxylvl(name account, symbol_code token_code, uint8_t level);
    [[eosio::action]] void setproxyfee(name account, symbol_code token_code, int16_t fee);
    [[eosio::action]] void setminstaked(name account, symbol_code token_code, int64_t min_own_staked);
    [[eosio::action]] void setkey(name account, symbol_code token_code, public_key signing_key);
    
    [[eosio::action]] void updatefunds(name account, symbol_code token_code);

    [[eosio::action]] void reward(name account, asset quantity);
};
} /// namespace cyber
