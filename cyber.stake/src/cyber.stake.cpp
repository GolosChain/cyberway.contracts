/**
 *  @file
 *  @copyright defined in eos/LICENSE.txt
 */
#undef CHAINDB_ANOTHER_CONTRACT_PROTECT
#define CHAINDB_ANOTHER_CONTRACT_PROTECT(_CHECK, _MSG)
   
#include <algorithm>
#include <cyber.stake/cyber.stake.hpp>
#include <cyber.token/cyber.token.hpp>
#include <common/dispatchers.hpp>
#include <common/parameter_ops.hpp>
#include <common/util.hpp>

namespace cyber {
    
int64_t stake::delegate_traversal(symbol_code token_code, stake::agents_idx_t& agents_idx, stake::grants_idx_t& grants_idx, name agent_name, int64_t amount, bool refill) {
    
    auto agent = get_agent_itr(token_code, agents_idx, agent_name);
    auto total_funds = agent->get_total_funds();
    eosio_assert((total_funds == 0) == (agent->shares_sum == 0), "SYSTEM: incorrect total_funds or shares_sum");
    auto own_funds = total_funds && agent->shares_sum ? safe_prop(total_funds, agent->own_share, agent->shares_sum) : 0;
    eosio_assert((own_funds >= agent->min_own_staked) || refill, "insufficient agent funds");
    if(amount == 0)
        return 0;

    auto remaining_amount = amount;
    auto grant_itr = grants_idx.lower_bound(
        std::make_tuple(token_code, agent_name, name()));
    while ((grant_itr != grants_idx.end()) && (grant_itr->token_code   == token_code) && (grant_itr->grantor_name == agent_name)) {
        auto to_delegate = safe_pct(amount, grant_itr->pct);
        remaining_amount -= to_delegate;
        eosio_assert(remaining_amount >= 0, "SYSTEM: incorrect remaining_amount");
        auto delegated = delegate_traversal(token_code, agents_idx, grants_idx, grant_itr->agent_name, to_delegate, true);
        grants_idx.modify(grant_itr, name(), [&](auto& g) {
            g.share += delegated;
            g.granted += to_delegate;
        });
        ++grant_itr;
    }
    eosio_assert(remaining_amount <= amount, "SYSTEM: incorrect remaining_amount");
    
    auto ret = total_funds && agent->shares_sum ? safe_prop(agent->shares_sum, amount, total_funds) : amount;
    
    agents_idx.modify(agent, name(), [&](auto& a) {
        a.balance += remaining_amount;
        a.proxied += amount - remaining_amount;
        a.shares_sum += ret;
    });
    
    return ret;
}

void stake::add_proxy(symbol_code token_code, grants& grants_table, const structures::agent& grantor_as_agent, const structures::agent& agent, 
        int16_t pct, int64_t share, int64_t granted, int16_t break_fee, int64_t break_min_own_staked) {

    auto now = ::now();
    eosio_assert(agent.last_proxied_update == time_point_sec(now), 
        ("SYSTEM: outdated last_proxied_update val: last update = " + 
        std::to_string(agent.last_proxied_update.sec_since_epoch()) + 
        ", now = " + std::to_string(now)).c_str());
    eosio_assert(grantor_as_agent.proxy_level > agent.proxy_level, 
        ("incorrect proxy levels: grantor " + std::to_string(grantor_as_agent.proxy_level) + 
        ", agent " + std::to_string(agent.proxy_level)).c_str());
    grants_table.emplace(grantor_as_agent.account, [&]( auto &item ) { item = structures::grant {
        .id = grants_table.available_primary_key(),
        .token_code = token_code,
        .grantor_name = grantor_as_agent.account,
        .agent_name = agent.account,
        .pct = pct,
        .share = share,
        .granted = granted,
        .break_fee = break_fee < 0 ? agent.fee : break_fee,
        .break_min_own_staked = break_min_own_staked < 0 ? agent.min_own_staked : break_min_own_staked
    };});
}
 
void stake::delegate(name grantor_name, name agent_name, asset quantity) {
    require_auth(grantor_name);
    eosio_assert(quantity.amount > 0, "quantity must be positive");
    params params_table(table_owner, table_owner.value);
     auto token_code = quantity.symbol.code();
    const auto& param = params_table.get(token_code.raw(), "no staking for token");
    
    update_stake_proxied(token_code, agent_name, param.frame_length, true);
    
    agents agents_table(table_owner, table_owner.value);
    auto agents_idx = agents_table.get_index<"bykey"_n>();
    
    auto grantor_as_agent = get_agent_itr(token_code, agents_idx, grantor_name);   
    eosio_assert(quantity.amount <= grantor_as_agent->balance, "insufficient balance");
    auto agent = get_agent_itr(token_code, agents_idx, agent_name);
    grants grants_table(table_owner, table_owner.value);
    auto grants_idx = grants_table.get_index<"bykey"_n>();
    
    auto delegated = delegate_traversal(token_code, agents_idx, grants_idx, agent_name, quantity.amount);
    uint8_t proxies_num = 0;
    auto grant_itr = grants_idx.lower_bound(std::make_tuple(token_code, grantor_name, name()));
    while ((grant_itr != grants_idx.end()) && (grant_itr->token_code   == token_code) && (grant_itr->grantor_name == grantor_name)) {
        ++proxies_num;
        if (grant_itr->agent_name == agent_name) {
            grants_idx.modify(grant_itr, name(), [&](auto& g) {
                g.share += delegated;
                g.granted += quantity.amount; 
            });
            delegated = 0;
        }
        ++grant_itr;
    }
    
    if (delegated) {
        eosio_assert(proxies_num < param.max_proxies[grantor_as_agent->proxy_level - 1], "proxy cannot be added");
        add_proxy(token_code, grants_table, *grantor_as_agent, *agent, 0, delegated, quantity.amount);
    }
    
    agents_idx.modify(grantor_as_agent, name(), [&](auto& a) {
        a.balance -= quantity.amount;
        a.proxied += quantity.amount;
    });
}

void stake::recall(name grantor_name, name agent_name, symbol_code token_code, int16_t pct) {
    ::recall_stake_proxied(token_code.raw(), grantor_name.value, agent_name.value, pct);
}

void stake::check_grant_terms(const structures::agent& agent, int16_t break_fee, int64_t break_min_own_staked) {
    eosio_assert(break_fee < 0 || agent.fee <= break_fee, "break_fee can't be less than current agent fee");
    eosio_assert(break_min_own_staked <= agent.min_own_staked, "break_min_own_staked can't be greater than current min_own_staked value");
}

void stake::setgrntterms(name grantor_name, name agent_name, symbol_code token_code, int16_t pct, int16_t break_fee, int64_t break_min_own_staked) {
    eosio_assert(0 <= pct && pct <= config::_100percent, "pct must be between 0% and 100% (0-10000)");
    eosio_assert(0 <= break_fee && break_fee <= config::_100percent, "break_fee must be between 0% and 100% (0-10000)");
    eosio_assert(0 <= break_min_own_staked, "break_min_own_staked can't be negative");
    
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
        if (grant_itr->agent_name == agent_name) {
            check_grant_terms(*get_agent_itr(token_code, agents_idx, agent_name), break_fee, break_min_own_staked);
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
        eosio_assert(pct_sum <= config::_100percent, "too high pct value\n");
    }
    if (!agent_found && pct) {
        auto grantor_as_agent = get_agent_itr(token_code, agents_idx, grantor_name, param.max_proxies.size(), &agents_table);
        eosio_assert(proxies_num < param.max_proxies[grantor_as_agent->proxy_level - 1], "proxy cannot be added");
        auto agent = get_agent_itr(token_code, agents_idx, agent_name);
        check_grant_terms(*agent, break_fee, break_min_own_staked);
        update_stake_proxied(token_code, agent_name, param.frame_length, true);
    
        add_proxy(token_code, grants_table, *grantor_as_agent, *agent, pct, 0, 0, break_fee, break_min_own_staked);
        changed = true;
    }
    
    eosio_assert(changed, "grant terms has not been changed");
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
    auto agent = get_agent_itr(token_code, agents_idx, account, param.max_proxies.size(), &agents_table);
    
    update_stake_proxied(token_code, account, param.frame_length, false);

    grants grants_table(table_owner, table_owner.value);
    auto grants_idx = grants_table.get_index<"bykey"_n>();
    
    auto share = delegate_traversal(token_code, agents_idx, grants_idx, account, quantity.amount);
    agents_idx.modify(agent, name(), [&](auto& a) { a.own_share += share; });
    update_stats(structures::stat {
        .id = 0,
        .token_code = token_code,
        .total_staked = quantity.amount
    }, from);
}

void stake::claim(name account, symbol_code token_code) {
    update_payout(account, asset(0, symbol(token_code, 0)), true);
}

void stake::withdraw(name account, asset quantity) {
    eosio_assert(quantity.amount > 0, "must withdraw positive quantity");
    update_payout(account, quantity);
}

void stake::cancelwd(name account, asset quantity) {
    eosio_assert(quantity.amount >= 0, "quantity can't be negative");
    quantity.amount = -quantity.amount;
    update_payout(account, quantity);
}

void stake::update_payout(name account, asset quantity, bool claim_mode) {
    require_auth(account); 
    auto token_code = quantity.symbol.code();
    params params_table(table_owner, table_owner.value);
    const auto& param = params_table.get(token_code.raw(), "no staking for token");
    payouts payouts_table(_self, _self.value);
    send_scheduled_payout(payouts_table, account, param.payout_step_lenght, param.token_symbol);
    
    if(claim_mode)
        return;
    
    update_stake_proxied(token_code, account, param.frame_length, false);
     
    agents agents_table(table_owner, table_owner.value);
    auto agents_idx = agents_table.get_index<"bykey"_n>();
    auto agent = get_agent_itr(token_code, agents_idx, account);

    grants grants_table(table_owner, table_owner.value);
    auto grants_idx = grants_table.get_index<"bykey"_n>();
    
    auto total_funds = agent->get_total_funds();
    eosio_assert((total_funds == 0) == (agent->shares_sum == 0), "SYSTEM: incorrect total_funds or shares_sum");
    
    int64_t balance_diff = 0;
    int64_t shares_diff = 0;
    if (quantity.amount > 0) {
        eosio_assert(quantity.amount <= agent->balance, "insufficient funds");

        eosio_assert(total_funds > 0, "no funds to withdrawal");
        auto own_funds = safe_prop(total_funds, agent->own_share, agent->shares_sum);
        eosio_assert(own_funds - quantity.amount >= agent->min_own_staked, "insufficient agent funds");

        balance_diff = -quantity.amount;
        shares_diff = -safe_prop(agent->shares_sum, quantity.amount, total_funds);
        eosio_assert(-shares_diff <= agent->own_share, "SYSTEM: incorrect shares_to_withdraw val");
        
        payouts_table.emplace(account, [&]( auto &item ) { item = structures::payout {
            .id = payouts_table.available_primary_key(),
            .token_code = token_code,
            .account = account,
            .balance = quantity.amount,
            .steps_left = param.payout_steps_num,
            .last_step = time_point_sec(::now())
        };});
    }
    else {
        quantity.amount = -quantity.amount;
        auto acc_index = payouts_table.get_index<"payoutacc"_n>();
        auto payout_lb_itr = acc_index.lower_bound(std::make_tuple(token_code, account));

        int64_t amount_sum = 0;
        auto payout_itr = payout_lb_itr;
        while ((payout_itr != acc_index.end()) && (payout_itr->token_code == token_code) && (payout_itr->account == account)) {
            amount_sum += payout_itr->balance;
        }
        eosio_assert(amount_sum >= quantity.amount, "insufficient funds");
        
        while ((payout_itr != acc_index.end()) && (payout_itr->token_code == token_code) && (payout_itr->account == account)) {
            auto cur_amount = quantity.amount ? safe_prop(payout_itr->balance, quantity.amount, amount_sum) : payout_itr->balance;
            balance_diff += cur_amount;
            if (cur_amount < payout_itr->balance) {
                acc_index.modify(payout_itr, name(), [&](auto& p) { p.balance -= cur_amount; });
                ++payout_itr;
            }
            else
                payout_itr = acc_index.erase(payout_itr);
        }
        //TODO:? due to rounding, balance_diff usually will be less than requested. should we do something about it?
        shares_diff = total_funds ? safe_prop(agent->shares_sum, balance_diff, total_funds) : balance_diff;
    }
    
    agents_idx.modify(agent, name(), [&](auto& a) {
        a.balance += balance_diff;
        a.shares_sum += shares_diff;
        a.own_share += shares_diff;
    });
    
    update_stats(structures::stat {
        .id = 0,
        .token_code = token_code,
        .total_staked = balance_diff
    });
}
 
void stake::update_stats(const structures::stat& stat_arg, name payer) {
    stats stats_table(table_owner, table_owner.value);
    auto stat = stats_table.find(stat_arg.token_code.raw());

    if (stat == stats_table.end() && payer != name()) {
        eosio_assert(stat_arg.total_staked >= 0, "SYSTEM: incorrect total_staked");
        stats_table.emplace(payer, [&](auto& s) { s = stat_arg; s.id = stat_arg.token_code.raw(); });
    }
    else if (stat != stats_table.end()) {
        stats_table.modify(stat, name(), [&](auto& s) {
            s.total_staked += stat_arg.total_staked;
            s.enabled = s.enabled || stat_arg.enabled;
        });
    }
    else {
        eosio_assert(false, "stats doesn't exist");
    }
}

void stake::send_scheduled_payout(payouts& payouts_table, name account, int64_t payout_step_lenght, symbol sym) {
    const int64_t now = ::now();
    eosio_assert(payout_step_lenght > 0, "SYSTEM: incorrect payout_step_lenght val");
    
    auto acc_index = payouts_table.get_index<"payoutacc"_n>();
    auto payout_itr = acc_index.lower_bound(std::make_tuple(sym.code(), account)); 
    int64_t amount = 0;
    while ((payout_itr != acc_index.end()) && (payout_itr->token_code == sym.code()) && (payout_itr->account == account)) {
        auto seconds_passed = now - payout_itr->last_step.utc_seconds;
        eosio_assert(seconds_passed >= 0, "SYSTEM: incorrect seconds_passed val");
        auto steps_passed = std::min(seconds_passed / payout_step_lenght, static_cast<int64_t>(payout_itr->steps_left));
        if (steps_passed) {
            if(steps_passed != payout_itr->steps_left) {
                auto cur_amount = safe_prop(payout_itr->balance, steps_passed, payout_itr->steps_left);
                acc_index.modify(payout_itr, name(), [&](auto& p) {
                    p.balance -= cur_amount;
                    p.steps_left -= steps_passed;
                    p.last_step = time_point_sec(p.last_step.utc_seconds + (steps_passed * payout_step_lenght));
                });
                ++payout_itr;
            }
            else {
                amount += payout_itr->balance;
                payout_itr = acc_index.erase(payout_itr);
            }
        }
        else
            ++payout_itr;
    }
    if(amount) {
        INLINE_ACTION_SENDER(eosio::token, transfer)(config::token_name, {_self, config::active_name},
            {_self, account, asset(amount, sym), "unstaked tokens"});
    }
}

void stake::setproxyfee(name account, symbol_code token_code, int16_t fee) {
    eosio_assert(0 <= fee && fee <= config::_100percent, "fee must be between 0% and 100% (0-10000)");
    modify_agent(account, token_code, [fee](auto& a) { a.fee = fee; } );
}

void stake::setminstaked(name account, symbol_code token_code, int64_t min_own_staked) {
    eosio_assert(0 <= min_own_staked, "min_own_staked can't be negative");
    modify_agent(account, token_code, [min_own_staked](auto& a) { a.min_own_staked = min_own_staked; } );
}

void stake::setkey(name account, symbol_code token_code, public_key signing_key) {
    modify_agent(account, token_code, [signing_key](auto& a) { a.signing_key = signing_key; } );
}

void stake::setproxylvl(name account, symbol_code token_code, uint8_t level) {
    require_auth(account);
    params params_table(table_owner, table_owner.value);
    const auto& param = params_table.get(token_code.raw(), "no staking for token");
    
    eosio::print("setproxylvl for ", account, " ", int(level), "\n");
    eosio_assert(level <= param.max_proxies.size(), "level too high");
    agents agents_table(table_owner, table_owner.value);
    auto agents_idx = agents_table.get_index<"bykey"_n>();
    bool emplaced = false;
    auto agent = get_agent_itr(token_code, agents_idx, account, level, &agents_table, &emplaced);
    eosio_assert(emplaced || (level != agent->proxy_level), "proxy level has not been changed");
    grants grants_table(table_owner, table_owner.value);
    auto grants_idx = grants_table.get_index<"bykey"_n>();
    uint8_t proxies_num = 0;
    auto grant_itr = grants_idx.lower_bound(std::make_tuple(token_code, account, name()));
    while ((grant_itr != grants_idx.end()) && (grant_itr->token_code   == token_code) && (grant_itr->grantor_name == account)) { 
         ++proxies_num;
         ++grant_itr;
    }
    eosio_assert(level || !proxies_num, "can't set an ultimate level because the user has a proxy");
    eosio_assert(!level || proxies_num <= param.max_proxies[level - 1], "can't set proxy level, user has too many proxies");

    if(!emplaced) {
        agents_idx.modify(agent, name(), [&](auto& a) { a.proxy_level = level; a.ultimate = !level; });
    }
} 
 
void stake::create(symbol token_symbol, std::vector<uint8_t> max_proxies, int64_t frame_length, int64_t payout_step_lenght, uint16_t payout_steps_num)
{
    eosio::print("create stake for ", token_symbol.code(), "\n");
    eosio_assert(max_proxies.size(), "no proxy levels are specified");
    eosio_assert(max_proxies.size() < std::numeric_limits<uint8_t>::max(), "too many proxy levels");
    if (max_proxies.size() > 1)
        for (size_t i = 1; i < max_proxies.size(); i++) {
            eosio_assert(max_proxies[i - 1] >= max_proxies[i], "incorrect proxy levels");
        }
    auto issuer = eosio::token::get_issuer(config::token_name, token_symbol.code());
    require_auth(issuer);
    params params_table(table_owner, table_owner.value);
    eosio_assert(params_table.find(token_symbol.code().raw()) == params_table.end(), "already exists");
    
    params_table.emplace(issuer, [&](auto& p) { p = {
        .id = token_symbol.code().raw(),
        .token_symbol = token_symbol,
        .max_proxies = max_proxies,
        .frame_length = frame_length,
        .payout_step_lenght = payout_step_lenght,
        .payout_steps_num = payout_steps_num
        };});
}

void stake::enable(symbol token_symbol) {
    auto token_code = token_symbol.code();
    auto issuer = eosio::token::get_issuer(config::token_name, token_code);
    require_auth(issuer);
    params params_table(table_owner, table_owner.value);
    params_table.get(token_code.raw(), "no staking for token");
    update_stats(structures::stat {
        .id = 0,
        .token_code = token_code,
        .total_staked = 0,
        .enabled = true
    }, issuer);
}

stake::agents_idx_t::const_iterator stake::get_agent_itr(symbol_code token_code, stake::agents_idx_t& agents_idx, name agent_name, int16_t proxy_level_for_emplaced, agents* agents_table, bool* emplaced) {
    auto key = std::make_tuple(token_code, agent_name);
    auto agent = agents_idx.find(key);
    
    if (emplaced)
        *emplaced = false;

    if(proxy_level_for_emplaced < 0) {
        eosio_assert(agent != agents_idx.end(), ("agent " + agent_name.to_string() + " doesn't exist").c_str());
    }
    else if(agent == agents_idx.end()) {

        eosio_assert(static_cast<bool>(agents_table), "SYSTEM: agents_table can't be null");
        (*agents_table).emplace(agent_name, [&](auto& a) { a = {
            .id = agents_table->available_primary_key(),
            .token_code = token_code,
            .account = agent_name,
            .proxy_level = static_cast<uint8_t>(proxy_level_for_emplaced),
            .ultimate = !proxy_level_for_emplaced,
            .last_proxied_update = time_point_sec(::now())
        };});
        
        agent = agents_idx.find(key);
        if (emplaced)
            *emplaced = true;
    }
    return agent;
}

void stake::updatefunds(name account, symbol_code token_code) {
    //require_auth(anyone);
    params params_table(table_owner, table_owner.value);
    const auto& param = params_table.get(token_code.raw(), "no staking for token");
    update_stake_proxied(token_code, account, param.frame_length, false);
}

void stake::change_balance(name account, asset quantity) {
    eosio_assert(quantity.is_valid(), "invalid quantity");
    auto token_code = quantity.symbol.code();
    auto issuer = eosio::token::get_issuer(config::token_name, token_code);
    require_auth(issuer);
    params params_table(table_owner, table_owner.value);
    const auto& param = params_table.get(token_code.raw(), "no staking for token");

    agents agents_table(table_owner, table_owner.value);
    auto agents_idx = agents_table.get_index<"bykey"_n>();
    auto agent = get_agent_itr(token_code, agents_idx, account);
    
    auto actual_amount = std::max(quantity.amount, -agent->balance);
    if (agent->get_total_funds()) {
        agents_idx.modify(agent, name(), [&](auto& a) { a.balance += actual_amount; });
    }
    else {
        auto share = std::abs(actual_amount);
        agents_idx.modify(agent, name(), [&](auto& a) {
            a.balance = actual_amount;
            a.shares_sum = share;
            a.own_share = share;
        });
    }
    update_stats(structures::stat {
        .id = 0,
        .token_code = token_code,
        .total_staked = actual_amount
    }, issuer);
    
    if (quantity.amount < 0 && actual_amount) {
        quantity.amount = -actual_amount;
        INLINE_ACTION_SENDER(eosio::token, transfer)(config::token_name, {_self, config::active_name},
            {_self, issuer, quantity, ""});
        INLINE_ACTION_SENDER(eosio::token, retire)(config::token_name, {issuer, config::amerce_name}, {quantity, ""});
    }
    else if (quantity.amount > 0) {
        //we don't need actual_amount in this case
        INLINE_ACTION_SENDER(eosio::token, issue)(config::token_name, {issuer, config::reward_name}, {issuer, quantity, ""});
        INLINE_ACTION_SENDER(eosio::token, transfer)(config::token_name, {issuer, config::reward_name},
            {issuer, _self, quantity, config::reward_memo}); 
    }
}

void stake::amerce(name account, asset quantity) {
    eosio_assert(quantity.amount > 0, "quantity must be positive");
    eosio::print("stake::amerce: account = ", account, ", quantity = ", quantity, "\n");
    quantity.amount = -quantity.amount;
    change_balance(account, quantity);
}

void stake::reward(name account, asset quantity) {
    eosio_assert(quantity.amount > 0, "quantity must be positive");
    eosio::print("stake::reward: account = ", account, ", quantity = ", quantity, "\n");
    change_balance(account, quantity);
}

} /// namespace cyber

DISPATCH_WITH_TRANSFER(cyber::stake, cyber::config::token_name, on_transfer,
    (create)(enable)(delegate)(setgrntterms)(recall)(withdraw)(claim)(cancelwd)
    (setproxylvl)(setproxyfee)(setminstaked)(setkey)
    (updatefunds)(amerce)(reward)
)
