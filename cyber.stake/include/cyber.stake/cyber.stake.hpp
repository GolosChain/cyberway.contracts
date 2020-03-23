/**
 *  @file
 *  @copyright defined in eos/LICENSE.txt
 */
#pragma once

#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>
#include <eosio/time.hpp>
#include <eosio/singleton.hpp>
#include "config.hpp"
#include <string>
#include <tuple>
#include <eosio/privileged.hpp>
#include <common/util.hpp>
#include <cyber.token/cyber.token.hpp>
#include <common/dispatchers.hpp>

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

    struct candidate {
        uint64_t id;
        symbol_code token_code;
        name account;
        time_point_sec latest_pick;
        int64_t votes = 0;
        int64_t priority = std::numeric_limits<int64_t>::max();
        public_key signing_key = {};
        bool enabled = false;
        uint64_t primary_key()const { return id; }

        using key_t = std::tuple<symbol_code, name>;
        key_t by_key()const { return std::make_tuple(token_code, account); }
        using votes_key_t = std::tuple<symbol_code, bool, int64_t, name>;
        using prior_key_t = std::tuple<symbol_code, bool, int64_t, int64_t, name>;
        votes_key_t by_votes()const { return std::make_tuple(token_code, enabled, votes, account); }
        prior_key_t by_prior()const { return std::make_tuple(token_code, enabled, priority, votes, account); }

        void set_votes(int64_t arg, int64_t cur_supply);
        void pick(int64_t cur_supply);
        void set_key(public_key arg);
    private:
        void update_priority(int64_t cur_supply, bool can_increase);
    };

    struct agent {
        uint64_t id;
        symbol_code token_code;
        name account;

        uint8_t proxy_level;
        time_point_sec last_proxied_update;
        int64_t balance = 0;// aka unproxied funds
        int64_t proxied = 0;// proxed funds
        int64_t shares_sum = 0;
        int64_t own_share = 0;
        int16_t fee = 0;
        int64_t min_own_staked = 0;

        int64_t provided = 0;
        int64_t received = 0;

        uint64_t primary_key()const { return id; }
        using key_t = std::tuple<symbol_code, name>;
        key_t by_key()const { return std::make_tuple(token_code, account); }
        int64_t get_total_funds()const { return balance + proxied; }
        int64_t get_own_funds() const {
            auto total_funds = get_total_funds();
            eosio::check(total_funds >= 0, "SYSTEM: incorrect total_funds value");
            eosio::check(own_share >= 0, "SYSTEM: incorrect own_share value");
            eosio::check(shares_sum >= 0, "SYSTEM: incorrect shares_sum value");
            eosio::check((total_funds == 0) == (shares_sum == 0), "SYSTEM: incorrect total_funds or shares_sum");
            return total_funds ? safe_prop(total_funds, own_share, shares_sum) : 0;
        }
        int64_t get_effective_stake() const {
            auto own_funds = get_own_funds();
            eosio::check(provided <= own_funds, "SYSTEM: incorrect provided or own_funds");
            eosio::check(received >= 0, "SYSTEM: incorrect received");
            return (own_funds - provided) + received;
        }
        void check_own_staked(name privileged, int64_t min_own_staked_for_election) const {
            if (!has_auth(privileged)) {
                //there are accounts with inconsistent balance and min_own_staked values,
                //to test their deactivation we allow _self to set such values

                eosio::check(proxy_level || min_own_staked >= min_own_staked_for_election,
                    "min_own_staked can't be less than min_own_staked_for_election for users with an ultimate level");
                eosio::check(get_own_funds() >= min_own_staked, "own staked funds can't be less than min_own_staked");
            }
        }
    };

    struct auto_recall {
        uint64_t id;
        symbol_code token_code;
        name account;
        bool break_fee_enabled = false;
        bool break_min_stake_enabled = false;
        uint64_t primary_key()const { return id; }
        using key_t = std::tuple<symbol_code, name>;
        key_t by_key()const { return std::make_tuple(token_code, account); }
    };

    struct grant {
        uint64_t id;
        symbol_code token_code;
        name grantor_name;
        name recipient_name;
        int16_t pct = 0;
        int64_t share = 0;
        int16_t break_fee = config::_100percent;
        int64_t break_min_own_staked = 0;

        uint64_t primary_key()const { return id; }
        using key_t = std::tuple<symbol_code, name, name>;
        key_t by_key()const { return std::make_tuple(token_code, grantor_name, recipient_name); }
    };

    struct param {
        uint64_t id;
        symbol token_symbol;
        std::vector<uint8_t> max_proxies;
        int64_t depriving_window;
        int64_t min_own_staked_for_election = 0;
        uint64_t primary_key()const { return id; }
    };

    struct stat {
        uint64_t id;
        symbol_code token_code;
        int64_t total_staked;
        int64_t total_votes;
        time_point_sec last_reward;
        bool enabled = false;
        uint64_t primary_key()const { return id; }
    };

    struct provision_struct {
        uint64_t id;
        symbol_code token_code;
        name grantor_name;
        name recipient_name;
        int64_t amount = 0;

        uint64_t primary_key()const { return id; }
        using key_t = std::tuple<symbol_code, name, name>;
        key_t by_key()const { return std::make_tuple(token_code, grantor_name, recipient_name); }
    };

    struct prov_payout_struct {
        uint64_t id;
        symbol_code token_code;
        name grantor_name;
        name recipient_name;
        int64_t amount;
        time_point_sec date;

        uint64_t primary_key()const { return id; }
        using key_t = std::tuple<symbol_code, name, name>;
        key_t by_key()const { return std::make_tuple(token_code, grantor_name, recipient_name); }
    };

    struct suspense {
        uint64_t id;
        symbol_code token_code;
        name account;
        name action_name;
        time_point_sec expiration_time;
        uint64_t primary_key()const { return id; }
        using key_t = std::tuple<symbol_code, name, name>;
        key_t by_key()const { return std::make_tuple(token_code, account, action_name); }
    };

    struct losses {
        time_point_sec time;
        symbol_code token_code;
        int64_t total;
    };
};

    using agent_id_index = eosio::indexed_by<"agentid"_n, eosio::const_mem_fun<structures::agent, uint64_t, &structures::agent::primary_key> >;
    using agent_key_index = eosio::indexed_by<"bykey"_n, eosio::const_mem_fun<structures::agent, structures::agent::key_t, &structures::agent::by_key> >;
    using agents = eosio::multi_index<"stake.agent"_n, structures::agent, agent_id_index, agent_key_index>;
    using agents_idx_t = decltype(agents(table_owner, table_owner.value).get_index<"bykey"_n>());

    using autorc_id_index = eosio::indexed_by<"autorcid"_n, eosio::const_mem_fun<structures::auto_recall, uint64_t, &structures::auto_recall::primary_key> >;
    using autorc_key_index = eosio::indexed_by<"bykey"_n, eosio::const_mem_fun<structures::auto_recall, structures::auto_recall::key_t, &structures::auto_recall::by_key> >;
    using autorcs = eosio::multi_index<"stake.autorc"_n, structures::auto_recall, autorc_id_index, autorc_key_index>;

    using candidate_id_index = eosio::indexed_by<"candidateid"_n, eosio::const_mem_fun<structures::candidate, uint64_t, &structures::candidate::primary_key> >;
    using candidate_key_index = eosio::indexed_by<"bykey"_n, eosio::const_mem_fun<structures::candidate, structures::candidate::key_t, &structures::candidate::by_key> >;
    using candidate_votes_index = eosio::indexed_by<"byvotes"_n, eosio::const_mem_fun<structures::candidate, structures::candidate::votes_key_t, &structures::candidate::by_votes> >;
    using candidate_prior_index = eosio::indexed_by<"byprior"_n, eosio::const_mem_fun<structures::candidate, structures::candidate::prior_key_t, &structures::candidate::by_prior> >;
    using candidates = eosio::multi_index<"stake.cand"_n, structures::candidate, candidate_id_index, candidate_key_index, candidate_votes_index, candidate_prior_index>;
    using candidates_idx_t = decltype(candidates(table_owner, table_owner.value).get_index<"bykey"_n>());

    using grant_id_index = eosio::indexed_by<"grantid"_n, eosio::const_mem_fun<structures::grant, uint64_t, &structures::grant::primary_key> >;
    using grant_key_index = eosio::indexed_by<"bykey"_n, eosio::const_mem_fun<structures::grant, structures::grant::key_t, &structures::grant::by_key> >;
    using grants = eosio::multi_index<"stake.grant"_n, structures::grant, grant_id_index, grant_key_index>;
    using grants_idx_t = decltype(grants(table_owner, table_owner.value).get_index<"bykey"_n>());

    using params = eosio::multi_index<"stake.param"_n, structures::param>;

    using stat_id_index = eosio::indexed_by<"statid"_n, eosio::const_mem_fun<structures::stat, uint64_t, &structures::stat::primary_key> >;

    using stats = eosio::multi_index<"stake.stat"_n, structures::stat, stat_id_index>;

    using prov_key_index [[using eosio: order("token_code"), order("grantor_name"), order("recipient_name")]] =
        eosio::indexed_by<"bykey"_n, eosio::const_mem_fun<structures::provision_struct, structures::provision_struct::key_t, &structures::provision_struct::by_key> >;
    using provs [[eosio::order("id")]] =
        eosio::multi_index<"provision"_n, structures::provision_struct, prov_key_index>;

    using prov_payout_acc_index [[using eosio: order("token_code"), order("grantor_name"), order("recipient_name")]] =
        eosio::indexed_by<"bykey"_n, eosio::const_mem_fun<structures::prov_payout_struct, structures::prov_payout_struct::key_t, &structures::prov_payout_struct::by_key> >;
    using prov_payouts [[eosio::order("id")]] =
        eosio::multi_index<"provpayout"_n, structures::prov_payout_struct, prov_payout_acc_index>;

    using susp_key_index [[using eosio: order("token_code"), order("account"), order("action_name")]] =
        eosio::indexed_by<"bykey"_n, eosio::const_mem_fun<structures::suspense, structures::suspense::key_t, &structures::suspense::by_key> >;
    using susps [[eosio::order("id")]] =
        eosio::multi_index<"suspense"_n, structures::suspense, susp_key_index>;
    using susps_idx_t = decltype(susps(_self, _self.value).get_index<"bykey"_n>());

    using losses_singleton [[eosio::order("id","asc")]] = eosio::singleton<"losses"_n, structures::losses>;

    void update_stake_proxied(symbol_code token_code, name agent_name) {
        eosio::update_stake_proxied(token_code, agent_name, true);
    }

    //return: share
    int64_t delegate_traversal(symbol_code token_code, agents_idx_t& agents_idx, grants_idx_t& grants_idx, name agent_name, int64_t amount, std::map<name, int64_t>& votes_changes, bool refill = false);

    agents_idx_t::const_iterator get_agent_itr(symbol_code token_code, agents_idx_t& agents_idx, name agent_name);
    void emplace_agent(name account, agents& agents_table, const structures::param& param, name ram_payer);
    void add_proxy(symbol_code token_code, grants& grants_table, const structures::agent& grantor_as_agent, const structures::agent& agent,
        int16_t pct, int64_t share, int16_t break_fee = -1, int64_t break_min_own_staked = -1);

    void change_balance(name account, asset quantity);

    static inline void staking_exists(symbol_code token_code) {
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
        params params_table(table_owner, table_owner.value);
        agent->check_own_staked(_self, params_table.get(token_code.raw(), "no staking for token").min_own_staked_for_election);
    }

    template<typename Lambda>
    void modify_stat(symbol_code token_code, Lambda f) {
        stats stats_table(table_owner, table_owner.value);
        auto stat = stats_table.find(token_code.raw());
        eosio::check(stat != stats_table.end(), "stat doesn't exist");
        stats_table.modify(stat, name(), f);
    }

    static void check_grant_terms(const structures::agent& agent, int16_t break_fee, int64_t break_min_own_staked);
    void set_votes(symbol_code token_code, const std::map<name, int64_t>& votes_changes);

    void update_provided(name grantor_name, name recipient_name, asset quantity);

    void check_suspense(susps& susps_table, susps_idx_t& susps_idx, symbol_code token_code, name account, name action_name);
    void set_suspense(name ram_payer, susps& susps_table, susps_idx_t& susps_idx, symbol_code token_code, name account, name action_name, int delay);

public:

    struct elected_t {
        name account;
        int64_t votes = 0;
        public_key signing_key = {};
    };

    static inline uint8_t get_max_level(symbol_code token_code) {
        params params_table(table_owner, table_owner.value);
        return params_table.get(token_code.raw(), "no staking for token").max_proxies.size();
    }

    static inline std::vector<elected_t> get_top(symbol_code token_code, uint16_t elected_num, uint16_t reserve_num) {
        staking_exists(token_code);

        candidates candidates_table(table_owner, table_owner.value);
        std::vector<elected_t> ret;
        static constexpr auto maxval = std::numeric_limits<int64_t>::max();

        {
            auto cands_idx = candidates_table.get_index<"byvotes"_n>();
            size_t i = 0;
            auto cands_itr = cands_idx.lower_bound(std::make_tuple(token_code, true, maxval, name()));
            while ((cands_itr != cands_idx.end()) && (cands_itr->token_code == token_code) && (i < elected_num)) {
                if (cands_itr->signing_key != public_key{}) {
                    ret.emplace_back(elected_t{cands_itr->account, cands_itr->votes, cands_itr->signing_key});
                    ++i;
                }
                ++cands_itr;
            }
        }

        int64_t elected = ret.size();
        auto min_votes_of_elected = elected ? ret.back().votes : maxval;

        {
            auto cands_idx = candidates_table.get_index<"byprior"_n>();
            size_t i = 0;
            auto cands_itr = cands_idx.lower_bound(std::make_tuple(token_code, true, 0, maxval, name()));
            while ((cands_itr != cands_idx.end()) && (cands_itr->token_code == token_code) && (i < reserve_num)) {
                bool new_one = true;
                if (cands_itr->votes > min_votes_of_elected) {
                    new_one = false;
                }
                else if (cands_itr->votes == min_votes_of_elected) {
                    int64_t cur_elected_i = elected - 1;
                    while ((cur_elected_i >= 0) && (ret[cur_elected_i].votes == cands_itr->votes)) {
                        if (ret[cur_elected_i].account == cands_itr->account) {
                            new_one = false;
                            break;
                        }
                        --cur_elected_i;
                    }
                }

                if (new_one) {
                    if (cands_itr->signing_key != public_key{}) {
                        ret.emplace_back(elected_t{cands_itr->account, cands_itr->votes, cands_itr->signing_key});
                        ++i;
                    }
                }
                ++cands_itr;
            }
        }

        return ret;
    }

    static inline int64_t get_votes_sum(symbol_code token_code, size_t limit = 0) {
        staking_exists(token_code);
        stats stats_table(table_owner, table_owner.value);
        if (!limit) {
            return stats_table.get(token_code.raw(), "stat doesn't exist").total_votes;
        }
        candidates candidates_table(table_owner, table_owner.value);
        auto cands_idx = candidates_table.get_index<"byvotes"_n>();
        int64_t ret = 0;
        size_t i = 0;
        auto cands_itr = cands_idx.lower_bound(std::make_tuple(token_code, true, std::numeric_limits<int64_t>::max(), name()));
        while ((cands_itr != cands_idx.end()) && (cands_itr->token_code == token_code) && (i < limit)) {
            ++i;
            ++cands_itr;
            ret += cands_itr->votes;
        }
        return ret;
    }

    static inline bool candidate_exists(name account, symbol_code token_code) {
        staking_exists(token_code);

        candidates candidates_table(table_owner, table_owner.value);
        auto cands_idx = candidates_table.get_index<"bykey"_n>();
        return cands_idx.find(std::make_tuple(token_code, account)) != cands_idx.end();
    }

    using contract::contract;

    [[eosio::action]] void create(symbol token_symbol, std::vector<uint8_t> max_proxies, int64_t depriving_window,
        int64_t min_own_staked_for_election);

    [[eosio::action]] void enable(symbol_code token_code);

    static inline bool enabled(symbol_code token_code) {
        staking_exists(token_code);
        stats stats_table(table_owner, table_owner.value);
        return stats_table.get(token_code.raw(), "stat doesn't exist").enabled;
    }

    [[eosio::action]] void open(name owner, symbol_code token_code, std::optional<name> ram_payer);

    [[eosio::action]] void delegatevote(name grantor_name, name recipient_name, asset quantity);

    [[eosio::action]] void setgrntterms(name grantor_name, name recipient_name, symbol_code token_code,
        int16_t pct, int16_t break_fee, int64_t break_min_own_staked);
    [[eosio::action]] void recallvote(name grantor_name, name recipient_name, symbol_code token_code, int16_t pct);

    [[eosio::action]] void withdraw(name account, asset quantity);

    ON_TRANSFER(CYBER_TOKEN, on_transfer) void on_transfer(name from, name to, asset quantity, std::string memo);

    [[eosio::action]] void setproxylvl(name account, symbol_code token_code, uint8_t level);
    [[eosio::action]] void setproxyfee(name account, symbol_code token_code, int16_t fee);
    [[eosio::action]] void setminstaked(name account, symbol_code token_code, int64_t min_own_staked);
    [[eosio::action]] void setkey(name account, symbol_code token_code, std::optional<public_key> signing_key);

    [[eosio::action]] void updatefunds(name account, symbol_code token_code);
    [[eosio::action]] void suspendcand(name account, symbol_code token_code);

    [[eosio::action]] void reward(std::vector<std::pair<name, int64_t> > rewards, symbol sym);

    [[eosio::action]] void pick(symbol_code token_code, std::vector<name> accounts);

    [[eosio::action]] void returnlosses();

    static inline int64_t get_effective_stake(name account, symbol_code token_code) {
        agents agents_table(table_owner, table_owner.value);
        auto agents_idx = agents_table.get_index<"bykey"_n>();
        return agents_idx.get(std::make_tuple(token_code, account),
            ("agent " + account.to_string() + " doesn't exist").c_str()).get_effective_stake();
    }

    [[eosio::action]] void delegateuse(name grantor_name, name recipient_name, asset quantity);
    [[eosio::action]] void recalluse(name grantor_name, name recipient_name, asset quantity);

    [[eosio::action]] void claim(name grantor_name, name recipient_name, symbol_code token_code);

    [[eosio::action]] void setautorc(name account, symbol_code token_code, bool break_fee_enabled, bool break_min_stake_enabled);
    [[eosio::action]] void setautorcmode(symbol_code token_code, bool enabled);

    [[eosio::action]] void setinfo(name account, symbol_code token_code, string url, eosio::binary_extension<string> info);
};
} /// namespace cyber
