#include <cyber.stake/cyber.stake.hpp>
#include <cyber.token/cyber.token.hpp>
#include <cyber.govern/cyber.govern.hpp>
#include <eosio/privileged.hpp>
#include <common/util.hpp>
#include <eosio/event.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/container/flat_set.hpp>

using namespace cyber::config;

namespace cyber {

void govern::onblock(name producer, eosio::binary_extension<uint32_t> schedule_version) {
    require_auth(_self);
    
    auto state = state_singleton(_self, _self.value);
    auto s = state.get_or_default(structures::state_info { .last_schedule_increase = eosio::current_time_point() });

    s.block_num++;

    int64_t block_reward = 0;
    if (producer != config::internal_name) {
        auto supply     = eosio::token::get_supply    (config::token_name, system_token.code()).amount;
        auto max_supply = eosio::token::get_max_supply(config::token_name, system_token.code()).amount;
        eosio::check(max_supply >= supply, "SYSTEM: incorrect supply");
        
        if ((s.block_num % config::update_emission_per_block_interval == 0) || !s.target_emission_per_block) {
            s.target_emission_per_block = get_target_emission_per_block(supply);
        }
        auto cur_block_emission = std::min(max_supply - supply, s.target_emission_per_block);
        block_reward = safe_pct(cur_block_emission, config::block_reward_pct);
        s.funds += cur_block_emission - block_reward;
    }

    producers producers_table(_self, _self.value);

    if (producer != config::internal_name && s.block_num != 1) {
        auto utr = producers_table.find(producer.value);
        if (utr != producers_table.end()) {
            producers_table.modify(utr, eosio::same_payer, [&](auto& u) {
                u.amount += block_reward + u.unconfirmed_amount;
                u.unconfirmed_amount = 0;
                u.omission_resets = 0;
                u.omission_count = 0;
                u.is_oblidged = false;
                u.last_time = eosio::current_time_point();
            });
        } else if (block_reward > 0) {
            producers_table.emplace(_self, [&](auto& u) {
                u.account = producer;
                u.amount = block_reward;
                u.is_oblidged = false;
                u.last_time = eosio::current_time_point();
            });
        }
    }
    
    if (s.block_num % config::reward_interval == 0) {
        reward_producers(producers_table, s);
        reward_workers(s);
    }
    
    if ((s.block_num >= s.last_producers_num * schedule_period_factor + s.last_propose_block_num) || !s.last_propose_block_num) {
        propose_producers(s);
    }

    // the schedule version temporarily has the binary extension type only for the upgrade phase
    if (schedule_version.has_value()) {
        if (s.schedule_version.has_value() && s.schedule_version.value() != schedule_version.value()) {
            promote_producers(producers_table);
            remove_old_producers(producers_table);
        }
        s.schedule_version.emplace(schedule_version.value());
    } else {
        s.schedule_version.emplace(0);
    }

    state.set(std::move(s), _self);
}

void govern::reward_workers(structures::state_info& s) {
    if (s.funds) {
        INLINE_ACTION_SENDER(eosio::token, issue)(config::token_name, {config::issuer_name, config::active_name}, 
            {config::worker_name, asset(s.funds, system_token), ""});
        s.funds = 0;
    }
}

void govern::burn_reward(const eosio::name& account, const int64_t& amount) const {
    if (amount > 0) {
        auto data = structures::balance_struct{account, amount};
        eosio::event(_self, "burnreward"_n, data).send();
    }
}

void govern::reward_producers(producers& producers_table, structures::state_info& s) {
    static constexpr auto token_code = system_token.code();
    std::vector<std::pair<eosio::name, int64_t>> unconfirmed_rewards;
    std::vector<std::pair<eosio::name, int64_t>> rewards;

    unconfirmed_rewards.reserve(config::max_producers_num + 16);
    rewards.reserve(config::max_producers_num + 16);

    // the temporary decision only for the upgrade phase,
    //   the balances table can be removed after migrating to the producers table
    boost::container::flat_map<eosio::name, int64_t> old_rewards;
    balances balances_table(_self, _self.value);

    old_rewards.reserve(config::max_producers_num + 16);
    for (auto itr = balances_table.begin(); itr != balances_table.end();) {
        if (itr->amount) {
            old_rewards.emplace(itr->account, itr->amount);
        }
        itr = balances_table.erase(itr);
    }

    auto get_old_reward = [&](const eosio::name& account) -> int64_t {
        int64_t amount = 0;
        auto itr = old_rewards.find(account);
        if (old_rewards.end() != itr) {
            amount = itr->second;
            old_rewards.erase(itr);
        }
        return amount;
    };
    // end of the temporary decision

    auto top = stake::get_top(system_token.code(), s.required_producers_num + rewarded_for_votes_limit_displ, 0);
    int64_t votes_sum = 0;
    for (const auto& t : top) {
        votes_sum += t.votes;
    }

    auto reward_of_elected = safe_pct(s.funds, config::_100percent - config::workers_reward_pct);
    if (votes_sum && reward_of_elected) {
        s.funds -= reward_of_elected;

        auto change = reward_of_elected;
        for (const auto& t : top) {
            auto cur_reward = safe_prop(reward_of_elected, t.votes, votes_sum);
            if (cur_reward) {
                unconfirmed_rewards.emplace_back(t.account, cur_reward);
                change -= cur_reward;
            } else {
                break;
            }
        }

        if (change) {
            if (!unconfirmed_rewards.empty()) {
                auto idx = s.block_num % unconfirmed_rewards.size();
                unconfirmed_rewards[idx].second += change;
            } else {
                auto idx = s.block_num % top.size();
                unconfirmed_rewards.emplace_back(top[idx].account, change);
            }
        }

        for (auto& r: unconfirmed_rewards) {
            auto btr = producers_table.find(r.first.value);
            int64_t amount = get_old_reward(r.first);

            if (btr != producers_table.end()) {
                producers_table.modify(btr, name(), [&](auto& b) {
                    amount += b.amount;
                    b.amount = 0;
                    b.unconfirmed_amount += r.second;
                });
            } else {
                producers_table.emplace(_self, [&](auto& b) {
                    b.is_oblidged = false;
                    b.account = r.first;
                    b.unconfirmed_amount = r.second;
                });
            }

            if (amount > 0) {
                rewards.emplace_back(r.first, amount);
            }
        }
    }

    auto balances_idx = producers_table.get_index<"bybalance"_n>();
    for (auto itr = balances_idx.begin(); itr != balances_idx.end() && itr->amount; ++itr) {
        rewards.emplace_back(itr->account, itr->amount + get_old_reward(itr->account));
        balances_idx.modify(itr, eosio::same_payer, [&](auto& u){
            u.amount = 0;
        });
    }

    for (const auto& r: old_rewards) {
        rewards.emplace_back(r.first, r.second);
    }

    if (rewards.size()) {
        INLINE_ACTION_SENDER(cyber::stake, reward)(config::stake_name, {config::issuer_name, config::active_name},
            {rewards, system_token});
    }
}

void govern::propose_producers(structures::state_info& s) {
    s.last_propose_block_num = s.block_num;

    if (!s.last_resize_step.has_value()) {
        s.last_resize_step.emplace(eosio::current_time_point());
    }
    if (!s.resize_shift.has_value()) {
        s.resize_shift.emplace(1);
    }

    if ((eosio::current_time_point() - s.last_resize_step.value()).to_seconds() >= schedule_resize_min_delay) {
        s.required_producers_num += s.resize_shift.value();
        s.required_producers_num = std::min(std::max(s.required_producers_num, min_producers_num), max_producers_num);
        
        s.last_resize_step.emplace(eosio::current_time_point());
    }

    auto new_producers = stake::get_top(system_token.code(), s.required_producers_num - active_reserve_producers_num, active_reserve_producers_num);
    auto new_producers_num = new_producers.size();
    
    auto min_new_producers_num = s.last_producers_num;
    if (s.resize_shift.value() < 0) {
        min_new_producers_num -= std::min<decltype(min_new_producers_num)>(min_new_producers_num, std::abs(s.resize_shift.value()));
    }
    if (new_producers_num < min_new_producers_num) {
        return;
    }
    
    std::vector<eosio::producer_key> schedule;
    schedule.reserve(new_producers_num + 16);
    for (const auto& t : new_producers) {
        schedule.emplace_back(eosio::producer_key{t.account, t.signing_key});
    }
    if (!eosio::set_proposed_producers(schedule)) {
        return;
    }
    s.last_producers_num = new_producers_num;
    std::vector<name> accounts;
    accounts.reserve(new_producers_num + 16);
    for (const auto& t : new_producers) {
        accounts.emplace_back(t.account);
    }
    
    INLINE_ACTION_SENDER(cyber::stake, pick)(config::stake_name, {config::issuer_name, config::active_name},
        {system_token.code(), accounts});
}

int64_t govern::get_target_emission_per_block(int64_t supply) const {
    auto votes_sum = cyber::stake::get_votes_sum(system_token.code());
    eosio::check(votes_sum <= supply, "SYSTEM: incorrect votes_sum val");
    auto not_involved_pct = static_cast<decltype(config::_100percent)>(safe_prop(config::_100percent, supply - votes_sum, supply));
    auto arg = std::min(std::max(not_involved_pct, config::emission_min_arg), config::emission_max_arg);
    arg -= config::emission_min_arg;
    arg = safe_prop(config::_100percent, arg, config::emission_max_arg - config::emission_min_arg);
    auto emission_per_year_pct = (((arg * config::emission_factor) / config::_100percent) + config::emission_addition);  
    int64_t emission_per_year = safe_pct(emission_per_year_pct, supply);
    return emission_per_year / config::blocks_per_year;
}

void govern::setshift(int8_t shift) {
    eosio::check(schedule_size_shift_min <= shift && shift <= schedule_size_shift_max, "incorrect shift");
    require_auth(producers_name);
    auto state = state_singleton(_self, _self.value);
    auto s = state.get(); // no default values, because it was created on the first block, errors can happens only in tests
    eosio::check(shift != s.resize_shift.value(), "the shift has not changed");
    s.resize_shift.emplace(shift);
    state.set(std::move(s), _self);
}

void govern::promote_producers(producers& producers_table) {
    static constexpr auto token_code = system_token.code();
    auto obliged_idx = producers_table.get_index<"byoblidged"_n>();
    boost::container::flat_set<eosio::name> active_producers;

    active_producers.reserve(config::max_producers_num + 16);
    for (const auto& acc: eosio::get_active_producers()) {
        active_producers.insert(acc);
    }
    for (auto itr = obliged_idx.begin(); itr != obliged_idx.end() && itr->is_oblidged; ) {
        bool should_erase = false;
        if (!cyber::stake::candidate_exists(itr->account, token_code)) {
            should_erase = true;
        } else if (itr->omission_resets >= config::resets_limit) {
            INLINE_ACTION_SENDER(cyber::stake, setproxylvl)(config::stake_name, {config::issuer_name, config::active_name},
                {itr->account, token_code, stake::get_max_level(token_code)}); // agent cannot disappear
            should_erase = true;
        }

        auto atr = active_producers.find(itr->account);
        if (should_erase) {
            if (active_producers.end() != atr) {
                active_producers.erase(atr);
            }
            burn_reward(itr->account, itr->amount + itr->unconfirmed_amount);
            itr = obliged_idx.erase(itr);
            continue;
        }

        burn_reward(itr->account, itr->unconfirmed_amount);

        obliged_idx.modify(itr, eosio::same_payer, [&](auto& o){
            if (active_producers.end() != atr) {
                active_producers.erase(atr);
            } else {
                o.is_oblidged = false;
            }

            o.unconfirmed_amount = 0;
            o.omission_count += 1;

            if (o.omission_count >= config::omission_limit) {
                INLINE_ACTION_SENDER(cyber::stake, setkey)(config::stake_name, {config::issuer_name, config::active_name},
                    {o.account, token_code, public_key{}});

                o.omission_count = 0;
                o.omission_resets += 1;
            }
        });
        ++itr;
    }

    for (const auto& acc : active_producers) {
        auto itr = producers_table.find(acc.value);
        if (producers_table.end() == itr) {
            producers_table.emplace(_self, [&](auto& p) {
                p.account = acc;
                p.is_oblidged = true;
                p.last_time = eosio::current_time_point();
            });
        } else if (!itr->is_oblidged) {
            producers_table.modify(itr, eosio::same_payer, [&](auto& p) {
                p.is_oblidged = true;
            });
        }
    }
}

void govern::remove_old_producers(producers& producers_table) {
    static constexpr auto token_code = system_token.code();
    auto last_time_idx = producers_table.get_index<"bytime"_n>();
    auto itr = last_time_idx.begin();
    if (last_time_idx.end() == itr) {
        return;
    }
    if (!cyber::stake::candidate_exists(itr->account, token_code)) {
        burn_reward(itr->account, itr->unconfirmed_amount + itr->amount);
        last_time_idx.erase(itr);
    } else {
        last_time_idx.modify(itr, eosio::same_payer, [&](auto& p){
           p.last_time = eosio::current_time_point();
        });
    }
}

}
