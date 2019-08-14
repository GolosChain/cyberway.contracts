/**
 *  @file
 *  @copyright defined in eos/LICENSE.txt
 */
#undef CHAINDB_ANOTHER_CONTRACT_PROTECT
#define CHAINDB_ANOTHER_CONTRACT_PROTECT(_CHECK, _MSG)

#include <eosio/check.hpp>
#include <eosio/system.hpp>
#include <algorithm>
#include <cyber.stake/cyber.stake.hpp>
#include <cyber.token/cyber.token.hpp>
#include <common/dispatchers.hpp>
#include <common/parameter_ops.hpp>

namespace cyber {
        
void stake::set_votes(symbol_code token_code, const std::map<name, int64_t>& votes_changes) {
    int64_t votes_changes_sum = 0; 
    for (const auto& v : votes_changes) { 
        votes_changes_sum += v.second; 
    } 

    stats stats_table(table_owner, table_owner.value); 
    auto stat = stats_table.find(token_code.raw()); 
    eosio::check(stat != stats_table.end(), "stat doesn't exist");
    stats_table.modify(stat, name(), [votes_changes_sum](auto& s) { s.total_votes += votes_changes_sum; });
    
    auto cur_supply = eosio::token::get_supply(config::token_name, token_code).amount;
    candidates candidates_table(table_owner, table_owner.value);
    auto cands_idx = candidates_table.get_index<"bykey"_n>();
    for (const auto& v : votes_changes) {
        auto cand = cands_idx.find(std::make_tuple(token_code, v.first));
        eosio::check(cand != cands_idx.end(), ("candidate " + v.first.to_string() + " doesn't exist").c_str());
        cands_idx.modify(cand, name(), [&](auto& a) { a.set_votes(a.votes + v.second, cur_supply); });
    }
}

void stake::structures::candidate::update_priority(int64_t cur_supply, bool can_increase) {
    if (!votes) {
        priority = std::numeric_limits<int64_t>::max();
    }
    else {
        static constexpr int128_t int64_max = std::numeric_limits<int64_t>::max();
        auto priority128 = std::min(static_cast<int128_t>(cur_supply) * config::priority_precision / votes, int64_max);
        priority128 += int128_t(latest_pick.sec_since_epoch()) * config::priority_precision;
        auto new_priority = static_cast<int64_t>(std::min(priority128, int64_max));
        if (can_increase || (new_priority < priority)) {
            priority = new_priority;
        }
    }
}

void stake::structures::candidate::set_votes(int64_t arg, int64_t cur_supply) {
    votes = arg;
    update_priority(cur_supply, false);
}

void stake::structures::candidate::pick(int64_t cur_supply) {
    latest_pick = eosio::current_time_point();
    update_priority(cur_supply, true);
}

void stake::structures::candidate::set_key(public_key arg) {
    signing_key = arg;
    enabled = arg != public_key{};
}

int64_t stake::delegate_traversal(symbol_code token_code, stake::agents_idx_t& agents_idx, stake::grants_idx_t& grants_idx, name agent_name, int64_t amount, std::map<name, int64_t>& votes_changes, bool refill) {
    
    auto agent = get_agent_itr(token_code, agents_idx, agent_name);
    auto total_funds = agent->get_total_funds();
    auto own_funds = agent->get_own_funds();
    eosio::check((own_funds >= agent->min_own_staked) || refill, "insufficient agent funds");
    if(amount == 0)
        return 0;
    auto remaining_amount = amount;
    auto grant_itr = grants_idx.lower_bound(
        std::make_tuple(token_code, agent_name, name()));
    while ((grant_itr != grants_idx.end()) && (grant_itr->token_code   == token_code) && (grant_itr->grantor_name == agent_name)) {
        auto to_delegate = safe_pct(amount, grant_itr->pct);
        remaining_amount -= to_delegate;
        eosio::check(remaining_amount >= 0, "SYSTEM: incorrect remaining_amount");
        auto delegated = delegate_traversal(token_code, agents_idx, grants_idx, grant_itr->recipient_name, to_delegate, votes_changes, true);
        grants_idx.modify(grant_itr, name(), [&](auto& g) { g.share += delegated; });
        ++grant_itr;
    }
    eosio::check(remaining_amount <= amount, "SYSTEM: incorrect remaining_amount");
    
    auto ret = total_funds && agent->shares_sum ? safe_prop(agent->shares_sum, amount, total_funds) : amount;
    eosio::check(std::numeric_limits<int64_t>::max() - agent->shares_sum >= ret, "shares_sum overflow");

    agents_idx.modify(agent, name(), [&](auto& a) {
        a.balance += remaining_amount;
        a.proxied += amount - remaining_amount;
        a.shares_sum += ret;
    });
    if (!agent->proxy_level) {
        votes_changes[agent->account] += remaining_amount;
    }
    
    return ret;
}

void stake::add_proxy(symbol_code token_code, grants& grants_table, const structures::agent& grantor_as_agent, const structures::agent& agent, 
        int16_t pct, int64_t share, int16_t break_fee, int64_t break_min_own_staked) {

    auto now = eosio::current_time_point();
    eosio::check(agent.last_proxied_update == now,
        ("SYSTEM: outdated last_proxied_update val: last update = " +
        std::to_string(agent.last_proxied_update.sec_since_epoch()) +
        ", now = " + std::to_string(now.sec_since_epoch())).c_str());
    eosio::check(grantor_as_agent.proxy_level > agent.proxy_level,
        ("incorrect proxy levels: grantor " + std::to_string(grantor_as_agent.proxy_level) + 
        ", agent " + std::to_string(agent.proxy_level)).c_str());
    grants_table.emplace(grantor_as_agent.account, [&]( auto &item ) { item = structures::grant {
        .id = grants_table.available_primary_key(),
        .token_code = token_code,
        .grantor_name = grantor_as_agent.account,
        .recipient_name = agent.account,
        .pct = pct,
        .share = share,
        .break_fee = break_fee < 0 ? agent.fee : break_fee,
        .break_min_own_staked = break_min_own_staked < 0 ? agent.min_own_staked : break_min_own_staked
    };});
}
 
void stake::delegatevote(name grantor_name, name recipient_name, asset quantity) {
    require_auth(grantor_name);
    eosio::check(quantity.amount > 0, "quantity must be positive");
    params params_table(table_owner, table_owner.value);
     auto token_code = quantity.symbol.code();
    const auto& param = params_table.get(token_code.raw(), "no staking for token");
    
    update_stake_proxied(token_code, recipient_name);
     
    agents agents_table(table_owner, table_owner.value);
    auto agents_idx = agents_table.get_index<"bykey"_n>();
    
    auto grantor_as_agent = get_agent_itr(token_code, agents_idx, grantor_name);
    eosio::check(quantity.amount <= grantor_as_agent->balance, "insufficient funds");
    auto agent = get_agent_itr(token_code, agents_idx, recipient_name);
    grants grants_table(table_owner, table_owner.value);
    auto grants_idx = grants_table.get_index<"bykey"_n>();
    std::map<name, int64_t> votes_changes;
    auto delegated = delegate_traversal(token_code, agents_idx, grants_idx, recipient_name, quantity.amount, votes_changes);
    set_votes(token_code, votes_changes);
    uint8_t proxies_num = 0;
    auto grant_itr = grants_idx.lower_bound(std::make_tuple(token_code, grantor_name, name()));
    while ((grant_itr != grants_idx.end()) && (grant_itr->token_code   == token_code) && (grant_itr->grantor_name == grantor_name)) {
        ++proxies_num;
        if (grant_itr->recipient_name == recipient_name) {
            grants_idx.modify(grant_itr, name(), [&](auto& g) { g.share += delegated; });
            delegated = 0;
        }
        ++grant_itr;
    }
    
    if (delegated) {
        eosio::check(proxies_num < param.max_proxies[grantor_as_agent->proxy_level - 1], "proxy cannot be added");
        add_proxy(token_code, grants_table, *grantor_as_agent, *agent, 0, delegated);
    }

    agents_idx.modify(grantor_as_agent, name(), [&](auto& a) {
        a.balance -= quantity.amount;
        a.proxied += quantity.amount;
    });
}

void stake::recallvote(name grantor_name, name recipient_name, symbol_code token_code, int16_t pct) {
    require_auth(grantor_name);
    eosio::recall_stake_proxied(token_code, grantor_name, recipient_name, pct);
}

void stake::check_grant_terms(const structures::agent& agent, int16_t break_fee, int64_t break_min_own_staked) {
    eosio::check(break_fee < 0 || agent.fee <= break_fee, "break_fee can't be less than current agent fee");
    eosio::check(break_min_own_staked <= agent.min_own_staked, "break_min_own_staked can't be greater than current min_own_staked value");
}

void stake::setgrntterms(name grantor_name, name recipient_name, symbol_code token_code, int16_t pct, int16_t break_fee, int64_t break_min_own_staked) {
    eosio::check(0 <= pct && pct <= config::_100percent, "pct must be between 0% and 100% (0-10000)");
    eosio::check(0 <= break_fee && break_fee <= config::_100percent, "break_fee must be between 0% and 100% (0-10000)");
    eosio::check(0 <= break_min_own_staked, "break_min_own_staked can't be negative");
    
    require_auth(grantor_name);
    params params_table(table_owner, table_owner.value);
    const auto& param = params_table.get(token_code.raw(), "no staking for token");

    agents agents_table(table_owner, table_owner.value);
    auto agents_idx = agents_table.get_index<"bykey"_n>();
    grants grants_table(table_owner, table_owner.value);
    auto grants_idx = grants_table.get_index<"bykey"_n>();

    int16_t pct_sum = 0;
    bool changed = false;
    bool agent_found = false;
    uint8_t proxies_num = 0;
    auto grant_itr = grants_idx.lower_bound(std::make_tuple(token_code, grantor_name, name()));
    while ((grant_itr != grants_idx.end()) && (grant_itr->token_code == token_code) && (grant_itr->grantor_name == grantor_name)) {
         ++proxies_num;
        if (grant_itr->recipient_name == recipient_name) {
            check_grant_terms(*get_agent_itr(token_code, agents_idx, recipient_name), break_fee, break_min_own_staked);
            changed = changed
                || grant_itr->pct != pct
                || grant_itr->break_fee != break_fee
                || grant_itr->break_min_own_staked != break_min_own_staked;
            agent_found = true;
            if(pct || grant_itr->share) {
                grants_idx.modify(grant_itr, name(), [&](auto& g) {
                    g.pct = pct;
                    g.break_fee = break_fee;
                    g.break_min_own_staked = break_min_own_staked;
                });
                pct_sum += pct;
                ++grant_itr;
            }
            else
                grant_itr = grants_idx.erase(grant_itr);
        }
        else {
            pct_sum += grant_itr->pct;
            ++grant_itr;
        }
        eosio::check(pct_sum <= config::_100percent, "too high pct value\n");
    }
    if (!agent_found && pct) {
        auto grantor_as_agent = get_agent_itr(token_code, agents_idx, grantor_name);
        eosio::check(proxies_num < param.max_proxies[grantor_as_agent->proxy_level - 1], "proxy cannot be added");
        update_stake_proxied(token_code, recipient_name);
        auto agent = get_agent_itr(token_code, agents_idx, recipient_name);
        check_grant_terms(*agent, break_fee, break_min_own_staked);
        
        add_proxy(token_code, grants_table, *grantor_as_agent, *agent, pct, 0, break_fee, break_min_own_staked);
        changed = true;
    }
    
    eosio::check(changed, "grant terms has not been changed");
}

void stake::on_transfer(name from, name to, asset quantity, std::string memo) {
    if (_self != to || memo == config::reward_memo)
        return;
    name account = memo.empty() ? from : name(memo);
    auto token_code = quantity.symbol.code();
    params params_table(table_owner, table_owner.value);
    const auto& param = params_table.get(token_code.raw(), "no staking for token");
    
    agents agents_table(table_owner, table_owner.value);
    auto agents_idx = agents_table.get_index<"bykey"_n>();
    auto agent = agents_idx.find(std::make_tuple(token_code, account));
    if (agent == agents_idx.end()) {
        emplace_agent(account, agents_table, param, from);
        agent = agents_idx.find(std::make_tuple(token_code, account));
    }
    update_stake_proxied(token_code, account);

    grants grants_table(table_owner, table_owner.value);
    auto grants_idx = grants_table.get_index<"bykey"_n>();
    std::map<name, int64_t> votes_changes;
    auto share = delegate_traversal(token_code, agents_idx, grants_idx, account, quantity.amount, votes_changes, true);
    set_votes(token_code, votes_changes);
    agents_idx.modify(agent, name(), [&](auto& a) { a.own_share += share; });
    modify_stat(token_code, [&](auto& s) { s.total_staked += quantity.amount; });
}

void stake::withdraw(name account, asset quantity) {
    require_auth(account); 
    eosio::check(quantity.amount > 0, "must withdraw positive quantity");
       
    auto token_code = quantity.symbol.code();
    params params_table(table_owner, table_owner.value);
    const auto& param = params_table.get(token_code.raw(), "no staking for token");
    
    update_stake_proxied(token_code, account);
     
    agents agents_table(table_owner, table_owner.value);
    auto agents_idx = agents_table.get_index<"bykey"_n>();
    auto agent = get_agent_itr(token_code, agents_idx, account);

    auto total_funds = agent->get_total_funds();
    
    eosio::check(quantity.amount <= agent->balance, "insufficient funds");

    eosio::check(total_funds > 0, "no funds to withdrawal");
    auto own_funds = safe_prop(total_funds, agent->own_share, agent->shares_sum);
    eosio::check(own_funds - quantity.amount >= agent->min_own_staked, "insufficient agent funds");
    eosio::check(own_funds - agent->provided >= quantity.amount, "insufficient agent funds due to providing");

    int64_t shares_diff = safe_prop(agent->shares_sum, quantity.amount, total_funds);
    eosio::check(shares_diff <= agent->own_share, "SYSTEM: incorrect shares_to_withdraw val");
    
    agents_idx.modify(agent, name(), [&](auto& a) {
        a.balance -= quantity.amount;
        a.shares_sum -= shares_diff;
        a.own_share -= shares_diff;
    });
    
    if (!agent->proxy_level) {
        set_votes(token_code, std::map<name, int64_t>{{account, -quantity.amount}});
    }
    modify_stat(token_code, [&](auto& s) { s.total_staked += -quantity.amount; });
    
    require_recipient(eosio::token::get_issuer(config::token_name, quantity.symbol.code()));
    
    INLINE_ACTION_SENDER(eosio::token, transfer)(config::token_name, {_self, config::active_name},
        {_self, account, quantity, "unstaked tokens"});
}

void stake::setproxyfee(name account, symbol_code token_code, int16_t fee) {
    eosio::check(0 <= fee && fee <= config::_100percent, "fee must be between 0% and 100% (0-10000)");
    staking_exists(token_code);
    modify_agent(account, token_code, [fee](auto& a) { a.fee = fee; } );
}

void stake::setminstaked(name account, symbol_code token_code, int64_t min_own_staked) {
    eosio::check(0 <= min_own_staked, "min_own_staked can't be negative");
    params params_table(table_owner, table_owner.value);
    auto min_own_staked_for_election = params_table.get(token_code.raw(), "no staking for token").min_own_staked_for_election;
    modify_agent(account, token_code, [min_own_staked, min_own_staked_for_election](auto& a) {
        eosio::check(a.proxy_level || min_own_staked >= min_own_staked_for_election, 
            "min_own_staked can't be less than min_own_staked_for_election for users with an ultimate level");
        a.min_own_staked = min_own_staked;
    });
}

void stake::setkey(name account, symbol_code token_code, public_key signing_key) {
    staking_exists(token_code);

    params params_table(table_owner, table_owner.value);
    auto min_own_staked_for_election = params_table.get(token_code.raw(), "no staking for token").min_own_staked_for_election;

    agents agents_table(table_owner, table_owner.value);
    auto agents_idx = agents_table.get_index<"bykey"_n>();
    auto agent = get_agent_itr(token_code, agents_idx, account);
    eosio::check(agent->proxy_level || agent->min_own_staked >= min_own_staked_for_election, 
        "min_own_staked can't be less than min_own_staked_for_election for users with an ultimate level");

    modify_candidate(account, token_code, [signing_key](auto& a) { 
        a.signing_key = signing_key;
        a.enabled = signing_key != public_key{};
    });
}

void stake::setproxylvl(name account, symbol_code token_code, uint8_t level) {
    require_auth(account);
    params params_table(table_owner, table_owner.value);
    const auto& param = params_table.get(token_code.raw(), "no staking for token");
    
    eosio::check(level <= param.max_proxies.size(), "level too high");
    agents agents_table(table_owner, table_owner.value);
    auto agents_idx = agents_table.get_index<"bykey"_n>();
    auto agent = get_agent_itr(token_code, agents_idx, account);
    eosio::check(level || agent->min_own_staked >= param.min_own_staked_for_election,
            "min_own_staked can't be less than min_own_staked_for_election for users with an ultimate level");
    eosio::check(level != agent->proxy_level, "proxy level has not been changed");
    grants grants_table(table_owner, table_owner.value);
    auto grants_idx = grants_table.get_index<"bykey"_n>();
    uint8_t proxies_num = 0;
    auto grant_itr = grants_idx.lower_bound(std::make_tuple(token_code, account, name()));
    while ((grant_itr != grants_idx.end()) && (grant_itr->token_code   == token_code) && (grant_itr->grantor_name == account)) { 
         ++proxies_num;
         ++grant_itr;
    }
    eosio::check(level || !proxies_num, "can't set an ultimate level because the user has a proxy");
    eosio::check(!level || proxies_num <= param.max_proxies[level - 1], "can't set proxy level, user has too many proxies");
    
    candidates candidates_table(table_owner, table_owner.value);
    auto cands_idx = candidates_table.get_index<"bykey"_n>();
    if (!agent->proxy_level && level) {
        cands_idx.erase(cands_idx.find(std::make_tuple(token_code, account)));
        
        stats stats_table(table_owner, table_owner.value);
        auto stat = stats_table.find(token_code.raw());
        eosio::check(stat != stats_table.end(), "stat doesn't exist");
        stats_table.modify(stat, name(), [&](auto& s) { s.total_votes -= agent->balance; });
    }
    else if (agent->proxy_level && !level) {
        candidates_table.emplace(account, [&](auto& a) {
            a = {
                .id = candidates_table.available_primary_key(),
                .token_code = token_code,
                .account = account,
                .latest_pick = eosio::current_time_point()
            };
        });
        set_votes(token_code, std::map<name, int64_t>{{account, agent->balance}});
    }

    agents_idx.modify(agent, name(), [&](auto& a) {
        a.proxy_level = level;
    });
} 
 
void stake::create(symbol token_symbol, std::vector<uint8_t> max_proxies, int64_t depriving_window, int64_t min_own_staked_for_election)
{
    auto token_code = token_symbol.code();
    eosio::check(max_proxies.size(), "no proxy levels are specified");
    eosio::check(max_proxies.size() < std::numeric_limits<uint8_t>::max(), "too many proxy levels");
    if (max_proxies.size() > 1)
        for (size_t i = 1; i < max_proxies.size(); i++) {
            eosio::check(max_proxies[i - 1] >= max_proxies[i], "incorrect proxy levels");
        }
    eosio::check(depriving_window > 0, "incorrect depriving_window");
    eosio::check(min_own_staked_for_election >= 0, "incorrect min_own_staked_for_election");
    auto issuer = eosio::token::get_issuer(config::token_name, token_code);
    require_auth(issuer);
    params params_table(table_owner, table_owner.value);
    eosio::check(params_table.find(token_code.raw()) == params_table.end(), "already exists");
    
    params_table.emplace(issuer, [&](auto& p) { p = {
        .id = token_code.raw(),
        .token_symbol = token_symbol,
        .max_proxies = max_proxies,
        .depriving_window = depriving_window,
        .min_own_staked_for_election = min_own_staked_for_election
    };});
        
    stats stats_table(table_owner, table_owner.value);
    eosio::check(stats_table.find(token_code.raw()) == stats_table.end(), "SYSTEM: already exists");
    stats_table.emplace(issuer, [&](auto& s) { s = {
        .id = token_code.raw(),
        .token_code = token_code,
        .total_staked = 0,
        .total_votes = 0
    };});    
}

void stake::enable(symbol token_symbol) {
    auto token_code = token_symbol.code();
    auto issuer = eosio::token::get_issuer(config::token_name, token_code);
    require_auth(issuer);
    modify_stat(token_code, [&](auto& s) {
        eosio::check(!s.enabled, "already enabled");
        s.enabled = true;
    });
}

void stake::open(name owner, symbol_code token_code, std::optional<name> ram_payer = std::nullopt) {
    
    auto actual_ram_payer = ram_payer.value_or(owner);
    require_auth(actual_ram_payer);
    
    params params_table(table_owner, table_owner.value);
    const auto& param = params_table.get(token_code.raw(), "no staking for token");
    agents agents_table(table_owner, table_owner.value);
    auto agents_idx = agents_table.get_index<"bykey"_n>();
    eosio::check(agents_idx.find(std::make_tuple(token_code, owner)) == agents_idx.end(), "agent already exists");
    emplace_agent(owner, agents_table, param, actual_ram_payer);
}

stake::agents_idx_t::const_iterator stake::get_agent_itr(symbol_code token_code, stake::agents_idx_t& agents_idx, name agent_name) {
    auto ret = agents_idx.find(std::make_tuple(token_code, agent_name));
    eosio::check(ret != agents_idx.end(), ("agent " + agent_name.to_string() + " doesn't exist").c_str());
    return ret;
}

void stake::emplace_agent(name account, agents& agents_table, const structures::param& param, name ram_payer) {
    eosio::check(is_account(account), "account does not exist");
    agents_table.emplace(ram_payer, [&](auto& a) { a = {
        .id = agents_table.available_primary_key(),
        .token_code = param.token_symbol.code(),
        .account = account,
        .proxy_level = static_cast<uint8_t>(param.max_proxies.size()),
        .last_proxied_update = eosio::current_time_point()
    };});
}

void stake::updatefunds(name account, symbol_code token_code) {
    //require_auth(anyone);
    params params_table(table_owner, table_owner.value);
    const auto& param = params_table.get(token_code.raw(), "no staking for token");
    update_stake_proxied(token_code, account);
}

void stake::reward(std::vector<std::pair<name, int64_t> > rewards, symbol sym) {
    eosio::check(rewards.size(), "no rewards");
    auto token_code = sym.code();
    auto issuer = eosio::token::get_issuer(config::token_name, token_code);
    require_auth(issuer);
    params params_table(table_owner, table_owner.value);
    const auto& param = params_table.get(token_code.raw(), "no staking for token");
    agents agents_table(table_owner, table_owner.value);
    auto agents_idx = agents_table.get_index<"bykey"_n>();
    
    std::map<name, int64_t> votes_changes;
    
    int64_t rewards_sum = 0;
    for (const auto& r : rewards) {
        eosio::check(r.second > 0, "amount must be positive");
        rewards_sum += r.second; // do we need an overflow check here?
        auto agent = get_agent_itr(token_code, agents_idx, r.first);
        int64_t balance_diff = 0;
        if (agent->get_total_funds()) {
            agents_idx.modify(agent, name(), [&](auto& a) {
                auto fee_amount = safe_pct(a.fee, r.second);
                auto net_amount = r.second - fee_amount;
                a.balance += net_amount;
                
                auto total_funds = a.get_total_funds();
                auto fee_share = total_funds && a.shares_sum ? safe_prop(a.shares_sum, fee_amount, total_funds) : fee_amount;
                a.balance += fee_amount;
                a.shares_sum += fee_share;
                a.own_share  += fee_share; 
                
                if (!a.proxy_level) {
                    votes_changes[r.first] += net_amount + fee_amount;
                }
            });
        }
        else {
            agents_idx.modify(agent, name(), [&](auto& a) {
                a.balance = r.second;
                a.shares_sum = r.second;
                a.own_share = r.second;
                if (!a.proxy_level) {
                    votes_changes[r.first] += r.second;
                }
            });
        }
    }
    
    asset quantity(rewards_sum, sym);
    
    modify_stat(token_code, [&](auto& s) {
        s.total_staked += quantity.amount;
        s.last_reward = eosio::current_time_point();
    });
    
    set_votes(token_code, votes_changes);
    
    INLINE_ACTION_SENDER(eosio::token, issue)(config::token_name, {issuer, config::active_name}, {_self, quantity, config::reward_memo});
}

void stake::pick(symbol_code token_code, std::vector<name> accounts) {
    require_auth(eosio::token::get_issuer(config::token_name, token_code));
    auto cur_supply = eosio::token::get_supply(config::token_name, token_code).amount;
    candidates candidates_table(table_owner, table_owner.value);
    auto cands_idx = candidates_table.get_index<"bykey"_n>();
    for (auto& account : accounts) {
        auto cand = cands_idx.find(std::make_tuple(token_code, account));
        eosio::check(cand != cands_idx.end(), ("candidate " + account.to_string() + " doesn't exist").c_str());
        cands_idx.modify(cand, name(), [cur_supply](auto& a) { a.pick(cur_supply); });
    }
}

void stake::update_provided(name grantor_name, name recipient_name, asset quantity) {
    
    require_auth(grantor_name);
    eosio::check(grantor_name != recipient_name, "can't delegate to yourself");
    auto token_code = quantity.symbol.code();
    params params_table(table_owner, table_owner.value);
    const auto& param = params_table.get(token_code.raw(), "no staking for token");
    update_stake_proxied(token_code, grantor_name);
    
    agents agents_table(table_owner, table_owner.value);
    auto agents_idx = agents_table.get_index<"bykey"_n>();
    auto grantor = get_agent_itr(token_code, agents_idx, grantor_name);
    auto recipient = get_agent_itr(token_code, agents_idx, recipient_name);
    
    auto prov_key = std::make_tuple(token_code, grantor_name, recipient_name);
    
    provs provs_table(_self, _self.value);
    auto provs_index = provs_table.get_index<"bykey"_n>();
    auto prov_itr = provs_index.find(prov_key);
    
    prov_payouts payouts_table(_self, _self.value);
    auto payouts_index = payouts_table.get_index<"bykey"_n>();
    auto payout_itr = payouts_index.find(prov_key);
    
    if (quantity.amount > 0) {
        int64_t to_provide = quantity.amount;
        
        if (payout_itr != payouts_index.end()) {
            auto payout_diff = std::min(quantity.amount, payout_itr->amount);
            to_provide -= payout_diff;
            if (payout_itr->amount > payout_diff) {
                payouts_index.modify(payout_itr, name(), [&](auto& p) { p.amount -= payout_diff; });
            }
            else {
                payouts_index.erase(payout_itr);
            }
        }
        
        int64_t available = grantor->get_own_funds() - grantor->provided;
        eosio::check(available > 0, "SYSTEM: incorrect available");
        eosio::check(to_provide <= available, "not enough staked tokens");
        
        if (prov_itr != provs_index.end()) {
            provs_index.modify(prov_itr, name(), [&](auto& p) { p.amount += quantity.amount; });
        }
        else {
            provs_table.emplace(grantor_name, [&]( auto &item ) { item = structures::provision {
                .id = provs_table.available_primary_key(),
                .token_code = token_code,
                .grantor_name = grantor_name,
                .recipient_name = recipient_name,
                .amount = quantity.amount
            };});
        }
        
        agents_idx.modify(grantor, name(), [&](auto& a) { a.provided += to_provide; });
        agents_idx.modify(recipient, name(), [&](auto& a) { a.received += quantity.amount; });
        require_recipient(eosio::token::get_issuer(config::token_name, quantity.symbol.code()));
    }
    else {
        auto to_deprive = -quantity.amount;
        eosio::check(prov_itr != provs_index.end(), "no tokens delegated");
        eosio::check(prov_itr->amount >= to_deprive, "not enough delegated tokens");
        
        if (payout_itr != payouts_index.end()) {
            payouts_index.modify(payout_itr, name(), [&](auto& p) {
                p.amount += to_deprive;
                p.date = eosio::current_time_point() + eosio::seconds(param.depriving_window);
            });
        }
        else {
            payouts_table.emplace(grantor_name, [&]( auto &item ) { item = structures::prov_payout {
                .id = provs_table.available_primary_key(),
                .token_code = token_code,
                .grantor_name = grantor_name,
                .recipient_name = recipient_name,
                .amount = to_deprive,
                .date = eosio::current_time_point() + eosio::seconds(param.depriving_window)
            };});
        }
        
        if (prov_itr->amount > to_deprive) {
            provs_index.modify(prov_itr, name(), [&](auto& p) { p.amount -= to_deprive; });
        }
        else {
            provs_index.erase(prov_itr);
        }
        
        agents_idx.modify(recipient, name(), [&](auto& a) { a.received -= to_deprive; });
    }
    eosio::check(grantor->provided >= 0, "SYSTEM: incorrect provided");
    eosio::check(recipient->received >= 0, "SYSTEM: incorrect received");
}

void stake::delegateuse(name grantor_name, name recipient_name, asset quantity) {
    eosio::check(quantity.amount > 0, "must delegate positive quantity");
    update_provided(grantor_name, recipient_name, quantity);
}

void stake::recalluse(name grantor_name, name recipient_name, asset quantity) {
    eosio::check(quantity.amount > 0, "must recall positive quantity");
    quantity.amount = -quantity.amount;
    update_provided(grantor_name, recipient_name, quantity);
}

void stake::claim(name grantor_name, name recipient_name, symbol_code token_code) {
    
    require_auth(grantor_name);
    
    agents agents_table(table_owner, table_owner.value);
    auto agents_idx = agents_table.get_index<"bykey"_n>();
    auto grantor = get_agent_itr(token_code, agents_idx, grantor_name);
    
    prov_payouts payouts_table(_self, _self.value);
    auto payouts_index = payouts_table.get_index<"bykey"_n>();
    auto payout_itr = payouts_index.find(std::make_tuple(token_code, grantor_name, recipient_name));
    
    eosio::check(payout_itr != payouts_index.end() && payout_itr->date <= eosio::current_time_point(), "nothing to claim");
    eosio::check(payout_itr->amount <= grantor->provided, "SYSTEM: incorrect provided");
    
    agents_idx.modify(grantor, name(), [&](auto& a) { a.provided -= payout_itr->amount; });
    payouts_index.erase(payout_itr);
    
}

} /// namespace cyber

DISPATCH_WITH_TRANSFER(cyber::stake, cyber::config::token_name, on_transfer,
    (create)(enable)(open)(delegatevote)(setgrntterms)(recallvote)(withdraw)
    (setproxylvl)(setproxyfee)(setminstaked)(setkey)
    (updatefunds)(reward)(pick)
    (delegateuse)(recalluse)(claim)
)
