#include <cyber.govern/cyber.govern.hpp>
#include <eosiolib/privileged.hpp> 
#include <cyber.stake/cyber.stake.hpp>
#include <cyber.token/cyber.token.hpp>
#include <common/util.hpp>

using namespace cyber::config;

namespace cyber {

void govern::onblock(name producer) {
    require_auth(_self);
    
    auto state = state_singleton(_self, _self.value);
    auto s = state.get_or_default(structures::state_info { .last_schedule_increase = time_point_sec(now()) });
    
    s.block_num++;
    
    int64_t block_reward = 0;
    if (producer != config::internal_name) {
        auto supply     = eosio::token::get_supply    (config::token_name, system_token.code()).amount;
        auto max_supply = eosio::token::get_max_supply(config::token_name, system_token.code()).amount;
        eosio_assert(max_supply >= supply, "SYSTEM: incorrect supply");
        
        if ((s.block_num % config::update_emission_per_block_interval == 0) || !s.target_emission_per_block) {
            s.target_emission_per_block = get_target_emission_per_block(supply);
        }
        auto cur_block_emission = std::min(max_supply - supply, s.target_emission_per_block);
        block_reward = safe_pct(cur_block_emission, config::block_reward_pct);
        s.funds += cur_block_emission - block_reward;
    }
        
    balances balances_table(_self, _self.value);
    
    if (producer != config::internal_name && s.block_num != 1) {
        auto b = balances_table.find(producer.value);
        if (b != balances_table.end()) {
            balances_table.modify(b, name(), [&](auto& b) { b.amount += block_reward; } );
        }
        else {
            balances_table.emplace(_self, [&](auto& b) { b = structures::balance {
                .account = producer,
                .amount = block_reward
            };});
        }
    }
    
    if (s.block_num % config::reward_interval == 0) {
        reward_producers(balances_table, s);
        reward_workers(s);
    }
    
    if ((s.block_num >= s.last_producers_num * schedule_period_factor + s.last_propose_block_num) || !s.last_propose_block_num) {
        propose_producers(s);
    }

    state.set(s, _self);
}

void govern::reward_workers(structures::state_info& s) {
    if (s.funds) {
        INLINE_ACTION_SENDER(eosio::token, issue)(config::token_name, {config::issuer_name, config::active_name}, 
            {config::worker_name, asset(s.funds, system_token), ""});
        s.funds = 0;
    }
}

void govern::reward_producers(balances& balances_table, structures::state_info& s) {
    std::map<name, int64_t> rewards;
    for (auto i = balances_table.begin(); i != balances_table.end();) {
        if (i->amount) {
            rewards[i->account] += i->amount;
        }
        i = balances_table.erase(i);
    }
    
    auto top = stake::get_top(system_token.code(), s.required_producers_num + rewarded_for_votes_limit_displ, 0, false);
    
    auto actual_elected_num = top.size();
    int64_t votes_sum = 0;
    for (const auto& t : top) {
        votes_sum += t.votes;
    }

    if (votes_sum) {
        auto reward_of_elected = safe_pct(s.funds, config::_100percent - config::workers_reward_pct);
        auto change = reward_of_elected;
        for (size_t i = 0; i < actual_elected_num; i++) {
            auto cur_reward = safe_prop(reward_of_elected, top[i].votes, votes_sum);
            if (cur_reward) {
                rewards[top[i].account] += cur_reward;
                change -= cur_reward;
            }
        }
        if (change) {
            rewards[top[s.block_num % actual_elected_num].account] += change;
        }
        s.funds -= reward_of_elected;
    }
    
    if (rewards.size()) {
        INLINE_ACTION_SENDER(cyber::stake, reward)(config::stake_name, {config::issuer_name, config::active_name},
            {std::vector<std::pair<name, int64_t> >(rewards.begin(), rewards.end()), system_token});
    }
}

void govern::propose_producers(structures::state_info& s) {

    if ((s.required_producers_num < max_producers_num) && (now() - s.last_schedule_increase.sec_since_epoch() >= schedule_increase_min_delay)) {
        auto votes_total = stake::get_votes_sum(system_token.code());
        auto votes_top   = stake::get_votes_sum(system_token.code(), s.required_producers_num - active_reserve_producers_num);
        
        if (votes_top < safe_pct(votes_total, schedule_increase_blocking_votes_pct)) {
            s.required_producers_num += 1;
            s.last_schedule_increase = time_point_sec(now());
        }
    }
    
    auto new_producers = stake::get_top(system_token.code(), s.required_producers_num - active_reserve_producers_num, active_reserve_producers_num);
    auto new_producers_num = new_producers.size();
    if (new_producers_num < s.last_producers_num) {
        return;
    }
    
    std::vector<std::pair<name, public_key> > schedule;
    schedule.reserve(new_producers_num);
    for (const auto& t : new_producers) {
        schedule.emplace_back(std::make_pair(t.account, t.signing_key));
    }
    auto packed_schedule = pack(schedule);
    if (set_proposed_producers(packed_schedule.data(),  packed_schedule.size()) < 0) {
        return;
    }
    s.last_producers_num = new_producers_num;
    s.last_propose_block_num = s.block_num;
    std::vector<name> accounts;
    accounts.reserve(new_producers_num);
    for (const auto& t : new_producers) {
        accounts.emplace_back(t.account);
    }
    
    INLINE_ACTION_SENDER(cyber::stake, pick)(config::stake_name, {config::issuer_name, config::active_name},
        {system_token.code(), accounts});
}

int64_t govern::get_target_emission_per_block(int64_t supply) const {
    auto votes_sum = cyber::stake::get_votes_sum(system_token.code());
    eosio_assert(votes_sum <= supply, "SYSTEM: incorrect votes_sum val");
    auto not_involved_pct = static_cast<decltype(config::_100percent)>(safe_prop(config::_100percent, supply - votes_sum, supply));
    auto arg = std::min(std::max(not_involved_pct, config::emission_min_arg), config::emission_max_arg);
    arg -= config::emission_min_arg;
    arg = safe_prop(config::_100percent, arg, config::emission_max_arg - config::emission_min_arg);
    auto emission_per_year_pct = (((arg * config::emission_factor) / config::_100percent) + config::emission_addition);  
    int64_t emission_per_year = safe_pct(emission_per_year_pct, supply);
    return emission_per_year / config::blocks_per_year;
}

}

EOSIO_DISPATCH( cyber::govern, (onblock))
