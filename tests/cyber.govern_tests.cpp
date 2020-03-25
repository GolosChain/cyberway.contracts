#include "golos_tester.hpp"
#include "cyber.token_test_api.hpp"
#include "cyber.stake_test_api.hpp"
#include "cyber.govern_test_api.hpp"
#include "contracts.hpp"
#include "../cyber.stake/include/cyber.stake/config.hpp"
#include "../cyber.bios/include/cyber.bios/config.hpp"
#include <eosio/chain/block_header_state.hpp>
#include <eosio/chain/int_arithmetic.hpp>
#include <eosio/chain/random.hpp>

namespace cfg = cyber::config;
using eosio::chain::config::stake_account_name;
using eosio::chain::config::govern_account_name;
using namespace eosio::testing;
using namespace eosio::chain;
using namespace eosio::chain::int_arithmetic;
using namespace fc; 
static const auto _token = cfg::system_token;

class cyber_govern_tester : public golos_tester {
protected:
    cyber_token_api token;
    cyber_stake_api stake;
    cyber_govern_api govern;

    time_point_sec head_block_time() { return time_point_sec(control->head_block_time().time_since_epoch().to_seconds()); };
 
public: 
    cyber_govern_tester()
        : golos_tester(govern_account_name, false)
        , token({this, cfg::token_name, cfg::system_token})
        , stake({this, stake_account_name})
        , govern({this, govern_account_name})
    { 
        create_accounts({_alice, _bob, _carol, _whale,
            cfg::token_name, cfg::worker_name});
        produce_block();
        install_contract(stake_account_name, contracts::stake_wasm(), contracts::stake_abi());
        install_contract(cfg::token_name, contracts::token_wasm(), contracts::token_abi());
        
    }
    
    const account_name _issuer = cfg::issuer_name;
    const account_name _alice = N(alice);
    const account_name _bob = N(bob);
    const account_name _carol = N(carol);
    const account_name _whale = N(whale);
    
    void deploy_sys_contracts(int64_t max_supply_amount = -1) {
        if (max_supply_amount < 0) {
            max_supply_amount = 10000000000;
        }
        BOOST_TEST_MESSAGE("--- creating token and stake"); 
        BOOST_CHECK_EQUAL(success(), token.create(_issuer, asset(max_supply_amount, token._symbol)));
        BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, 
            std::vector<uint8_t>{30, 10, 3, 1}, 30 * 24 * 60 * 60));
            
        BOOST_TEST_MESSAGE("--- installing governance contract");
        install_contract(govern_account_name, contracts::govern_wasm(), contracts::govern_abi());
        BOOST_TEST_MESSAGE("--- installing bios contract");
        //sys token and stake must already exist at this moment
        install_contract(config::system_account_name, contracts::bios_wasm(), contracts::bios_abi());
        produce_block();
        BOOST_TEST_MESSAGE("    ...done");
    }
    
    int64_t get_emission_per_block(double rate) {
        return (token.get_stats()["supply"].as<asset>().get_amount() * rate) / cfg::blocks_per_year;
    }
    
    const std::map<account_name, int64_t> get_rewards_of_elected(int64_t emission_per_block, uint32_t cur_block, const std::map<account_name, uint32_t>& prod_blocks) {
        uint32_t total_blocks = 0;
        for (auto& prod : prod_blocks) {
            total_blocks += prod.second;
        }
        size_t i = 0;
        int64_t total_reward = ((emission_per_block - (emission_per_block * cfg::block_reward_pct) / cfg::_100percent) * total_blocks) * 
            (cfg::_100percent - cfg::workers_reward_pct) / cfg::_100percent;
        std::map<account_name, int64_t> ret;
        for (auto& prod : prod_blocks) {
            ret[prod.first] += total_reward / prod_blocks.size();
            if(cur_block % prod_blocks.size() == i) {
                ret[prod.first] += total_reward % prod_blocks.size();
            }
            i++;
        }
        return ret;
    }
    
    int64_t get_rewards_of_workers(int64_t emission_per_block, uint32_t cur_block, const std::map<account_name, uint32_t>& prod_blocks) {
        uint32_t total_blocks = 0;
        
        for (auto& prod : prod_blocks) {
            total_blocks += prod.second;
        }
        int64_t funds = (emission_per_block * (cfg::_100percent - cfg::block_reward_pct) / cfg::_100percent) * total_blocks;
        int64_t reward_of_elected = funds * (cfg::_100percent - cfg::workers_reward_pct) / cfg::_100percent;
        return funds - reward_of_elected;
    }

    const int64_t get_reward_for_blocks(int64_t emission_per_block, uint32_t blocks) {
        int64_t reward_for_block = (emission_per_block * cfg::block_reward_pct) / cfg::_100percent;
        return blocks * reward_for_block;
    }
    
    void emission_test(int64_t supply_amount, int64_t granted_amount, const std::string& agent_name, double rate, int64_t max_supply_amount = -1) {
        deploy_sys_contracts(max_supply_amount);
        BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _whale, asset(supply_amount, token._symbol), ""));
        BOOST_CHECK_EQUAL(success(), stake.register_candidate(_alice, token._symbol.to_symbol_code()));
        if (granted_amount) {
            BOOST_CHECK_EQUAL(success(), token.transfer(_whale, stake_account_name, asset(granted_amount, token._symbol), agent_name));
        }
        govern.wait_schedule_activation();
         
        //cyber is still a producer
        BOOST_CHECK_EQUAL(govern.get_target_emission_per_block(), 0);
        produce_block();
        auto emission = get_emission_per_block(rate);
        BOOST_CHECK_EQUAL(govern.get_target_emission_per_block(), emission);
        auto alice_balance = govern.get_balance(_alice);
        BOOST_CHECK_EQUAL(alice_balance == -1 ? 0 : alice_balance,
            supply_amount != max_supply_amount ? safe_pct<int64_t>(cfg::block_reward_pct, emission) : 0);
        produce_block();
    }
    
    std::vector<account_name> reg_candidates(size_t num, int64_t amount_start, int64_t amount_step = 0) {
        std::vector<account_name> ret;
        for (int u = 0; u < num; u++) {
            ret.emplace_back(user_name(u));
        }
        create_accounts(ret);
        for (int u = 0; u < num; u++) {
            auto user = user_name(u);
            auto quantity = asset(amount_start + (amount_step * u), token._symbol);
            BOOST_CHECK_EQUAL(success(), token.issue(_issuer, user, quantity, ""));
            BOOST_CHECK_EQUAL(success(), stake.register_candidate(user, token._symbol.to_symbol_code()));
            BOOST_CHECK_EQUAL(success(), token.transfer(user, stake_account_name, quantity));
        }
        return ret;
    }

    struct errors: contract_error_messages {
        const string temp_unavailable = amsg("action is temporarily unavailable");
        const string incorrect_shift = amsg("incorrect shift");
        const string shift_not_changed = amsg("the shift has not changed");
        const string cand_is_active = amsg("candidate is active");
    } err;
};  

BOOST_AUTO_TEST_SUITE(cyber_govern_tests)

BOOST_FIXTURE_TEST_CASE(rewards_test, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("Rewards test");
    int64_t init_supply = 1000000000000;
    deploy_sys_contracts(init_supply * 2);
    int64_t init_amount = 1;
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _whale, asset(init_supply, token._symbol), ""));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_bob, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), token.transfer(_whale, stake_account_name, asset(init_amount, token._symbol), "alice"));
    BOOST_CHECK_EQUAL(success(), token.transfer(_whale, stake_account_name, asset(init_amount, token._symbol), "bob"));
    produce_block();
    BOOST_CHECK_EQUAL(success(), stake.updatefunds(_bob, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.updatefunds(_alice, token._symbol.to_symbol_code()));
    govern.wait_schedule_activation();
    auto blocks_num = govern.wait_reward();
    std::map<account_name, uint32_t> prod_blocks;
    prod_blocks[_alice] = blocks_num / 2;
    prod_blocks[_bob] = blocks_num / 2;
    if (blocks_num % 2) {
        prod_blocks[control->head_block_producer()]++;
    }
    auto emission_per_block = get_emission_per_block(double(cfg::emission_addition + cfg::emission_factor) / cfg::_100percent);
    auto rewards_of_elected = get_rewards_of_elected(emission_per_block, govern.get_block_num(), prod_blocks);
    BOOST_CHECK_CLOSE_FRACTION(double(token.get_account(cfg::worker_name)["balance"].as<asset>().get_amount()), 
        double(get_rewards_of_workers(emission_per_block, govern.get_block_num(), prod_blocks)), 0.0001);
    auto last_prod = control->head_block_producer();
    auto prev_prod = last_prod == _alice ? _bob : _alice;
    
    BOOST_CHECK_EQUAL(govern.get_balance(last_prod), -1);
    BOOST_CHECK_EQUAL(govern.get_balance(prev_prod), -1);
    BOOST_CHECK_EQUAL(govern.get_balance(last_prod, false), rewards_of_elected[last_prod]);
    BOOST_CHECK_EQUAL(govern.get_balance(prev_prod, false), rewards_of_elected[prev_prod]);
    
    BOOST_CHECK_EQUAL(stake.get_agent(last_prod, token._symbol)["balance"].as<int64_t>(),
        init_amount + get_reward_for_blocks(emission_per_block, prod_blocks[last_prod]));
    BOOST_CHECK_EQUAL(stake.get_agent(prev_prod, token._symbol)["balance"].as<int64_t>(),
        init_amount + get_reward_for_blocks(emission_per_block, prod_blocks[prev_prod]));
    
    auto balance_a = stake.get_agent(_alice, token._symbol)["balance"].as<int64_t>();
    auto balance_b = stake.get_agent(_bob,   token._symbol)["balance"].as<int64_t>();
    
    last_prod = control->head_block_producer();
    prev_prod = last_prod == _alice ? _bob : _alice;
    auto unconfirmed_balance_last = govern.get_balance(last_prod, false);
    auto unconfirmed_balance_prev = govern.get_balance(prev_prod, false);
    
    auto block_before_missed = govern.get_block_num();
    blocks_num = 20;
    for (auto i = 0; i < blocks_num; i++) {
        if (control->pending_block_state()->header.producer == last_prod) {
            produce_block(fc::microseconds(eosio::chain::config::block_interval_us * 2));
        }
        else {
            produce_block();
        }
    }
    produce_block();
    
    //despite the fact that last_prod missed a lot of blocks, his unconfirmed balance does not burn out,
    //because lib does not move, so the active schedule does not change
    BOOST_CHECK_EQUAL(govern.get_balance(last_prod), get_reward_for_blocks(emission_per_block, 1) + unconfirmed_balance_last);
    BOOST_CHECK_EQUAL(govern.get_balance(prev_prod), get_reward_for_blocks(emission_per_block, blocks_num) + unconfirmed_balance_prev);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["balance"].as<int64_t>(), balance_a);
    BOOST_CHECK_EQUAL(stake.get_agent(_bob,   token._symbol)["balance"].as<int64_t>(), balance_b);
    
    auto gov_balance_a = govern.get_balance(_alice);
    auto gov_balance_b = govern.get_balance(_bob);
    
    prod_blocks.clear();
    blocks_num = govern.wait_reward(0, &prod_blocks);
    for (auto& b : prod_blocks) {
        BOOST_TEST_MESSAGE("--- " << b.first << " produced " << b.second << " blocks");
    }
    
    last_prod = control->head_block_producer();
    prev_prod = last_prod == _alice ? _bob : _alice;
    
    auto balance_last = last_prod == _alice ? balance_a : balance_b;
    auto balance_prev = prev_prod == _alice ? balance_a : balance_b;
    auto gov_balance_last = last_prod == _alice ? gov_balance_a : gov_balance_b;
    auto gov_balance_prev = prev_prod == _alice ? gov_balance_a : gov_balance_b;
    
    BOOST_CHECK_EQUAL(stake.get_agent(last_prod, token._symbol)["balance"].as<int64_t>(),
        balance_last + gov_balance_last + get_reward_for_blocks(emission_per_block, prod_blocks[last_prod]));
    
    BOOST_CHECK_EQUAL(stake.get_agent(prev_prod, token._symbol)["balance"].as<int64_t>(),
        balance_prev + gov_balance_prev + get_reward_for_blocks(emission_per_block, prod_blocks[prev_prod]));
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(no_rewards_test, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("No rewards test");
    int64_t init_supply = 1000000000000;
    deploy_sys_contracts(init_supply * 2);
    int64_t init_amount = 1;
    
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _whale, asset(init_supply, token._symbol), ""));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_bob,   token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_carol, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_whale, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), token.transfer(_whale, stake_account_name, asset(init_amount, token._symbol), "alice"));
    BOOST_CHECK_EQUAL(success(), token.transfer(_whale, stake_account_name, asset(init_amount, token._symbol), "bob"));
    BOOST_CHECK_EQUAL(success(), token.transfer(_whale, stake_account_name, asset(init_amount, token._symbol), "carol"));
    BOOST_CHECK_EQUAL(success(), token.transfer(_whale, stake_account_name, asset(init_amount, token._symbol), ""));
    produce_block();
    
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["balance"].as<int64_t>(), init_amount);
    BOOST_CHECK_EQUAL(stake.get_agent(_bob,   token._symbol)["balance"].as<int64_t>(), init_amount);
    BOOST_CHECK_EQUAL(stake.get_agent(_carol, token._symbol)["balance"].as<int64_t>(), init_amount);
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["balance"].as<int64_t>(), init_amount);
    
    govern.wait_schedule_activation();
    std::map<account_name, uint32_t> prod_blocks;
    auto blocks_num = govern.wait_reward(0, &prod_blocks, {_bob});
    BOOST_CHECK(stake.get_agent(_alice, token._symbol)["balance"].as<int64_t>() > init_amount);
    BOOST_CHECK_EQUAL(stake.get_agent(_bob,   token._symbol)["balance"].as<int64_t>(), init_amount);
    BOOST_CHECK(stake.get_agent(_carol, token._symbol)["balance"].as<int64_t>() > init_amount);
    BOOST_CHECK(stake.get_agent(_whale, token._symbol)["balance"].as<int64_t>() > init_amount);
    BOOST_CHECK_EQUAL(stake.get_candidate(_bob, token._symbol)["signing_key"].as<public_key_type>(), public_key_type());
    
    BOOST_CHECK_GT(govern.get_balance(_alice, false), 0);
    BOOST_CHECK_EQUAL(govern.get_balance(_bob, false), -1);
    BOOST_CHECK_GT(govern.get_balance(_carol, false), 0);
    BOOST_CHECK_GT(govern.get_balance(_whale, false), 0);
    
    BOOST_CHECK_EQUAL(govern.get_balance(_alice), -1);
    BOOST_CHECK_EQUAL(govern.get_balance(_bob), -1);
    BOOST_CHECK_EQUAL(govern.get_balance(_carol), -1);
    BOOST_CHECK_EQUAL(govern.get_balance(_whale), -1);
    
    govern.wait_schedule_activation(false, {_bob});
    BOOST_CHECK_EQUAL(stake.get_candidate(_bob, token._symbol)["signing_key"].as<public_key_type>(), public_key_type());
    produce_block(fc::seconds(cfg::key_recovery_delay), 0, {_bob});
    BOOST_CHECK_EQUAL(success(), stake.setkey(_bob, token._symbol.to_symbol_code(), false));
    BOOST_CHECK_EQUAL(stake.get_candidate(_bob, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_bob, "active"));
    govern.wait_schedule_activation(true, {_bob});
    
    BOOST_CHECK_EQUAL(govern.get_balance(_alice, false), -1);
    BOOST_CHECK_EQUAL(govern.get_balance(_bob,   false), -1);
    BOOST_CHECK_EQUAL(govern.get_balance(_carol, false), -1);
    BOOST_CHECK_EQUAL(govern.get_balance(_whale, false), -1);
    
    BOOST_CHECK(govern.get_balance(_alice) > 0);
    BOOST_CHECK_EQUAL(govern.get_balance(_bob), -1);
    BOOST_CHECK(govern.get_balance(_carol) > 0);
    BOOST_CHECK(govern.get_balance(_whale) > 0);
    
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE(reset_key)
BOOST_FIXTURE_TEST_CASE(recovery_delay, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("reset_key/recovery_delay");
    deploy_sys_contracts();
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_bob,   token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_carol, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_whale, token._symbol.to_symbol_code()));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(stake.get_candidate(_alice, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_alice, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_bob,   token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_bob, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_carol, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_carol, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_whale, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_whale, "active"));
    for (size_t i = 0; i < 2222; i++) {
        produce_block(fc::milliseconds(config::block_interval_ms), 0, {_bob});
    }
    BOOST_CHECK_EQUAL(stake.get_candidate(_bob, token._symbol)["signing_key"].as<public_key_type>(), public_key_type());
    BOOST_CHECK_EQUAL(err.temp_unavailable, stake.setkey(_bob, token._symbol.to_symbol_code(), false));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_bob, token._symbol.to_symbol_code(), 1));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_bob, token._symbol.to_symbol_code(), 0));
    BOOST_CHECK_EQUAL(err.temp_unavailable, stake.setkey(_bob, token._symbol.to_symbol_code(), false));
    produce_block();
    produce_block(fc::seconds(cfg::key_recovery_delay) - fc::milliseconds(config::block_interval_ms));
    BOOST_CHECK_EQUAL(success(), stake.setkey(_bob, token._symbol.to_symbol_code(), false));
    BOOST_CHECK_EQUAL(stake.get_candidate(_bob, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_bob, "active"));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_bob, token._symbol.to_symbol_code(), 1));
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(lib_stopped, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("reset_key/lib_stopped");
    deploy_sys_contracts();
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_bob,   token._symbol.to_symbol_code()));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(stake.get_candidate(_alice, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_alice, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_bob,   token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_bob, "active"));
    for (size_t i = 0; i < 2222; i++) {
        produce_block(fc::milliseconds(config::block_interval_ms), 0, {_bob});
    }
    BOOST_CHECK_EQUAL(stake.get_candidate(_alice, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_alice, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_bob,   token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_bob, "active"));
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(lib_moved, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("reset_key/lib_moved");
    deploy_sys_contracts();
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_bob,   token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_carol, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_whale, token._symbol.to_symbol_code()));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(stake.get_candidate(_alice, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_alice, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_bob,   token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_bob, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_carol, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_carol, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_whale, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_whale, "active"));
    for (size_t i = 0; i < 2222; i++) {
        produce_block(fc::milliseconds(config::block_interval_ms), 0, {_bob});
    }
    BOOST_CHECK_EQUAL(stake.get_candidate(_alice, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_alice, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_bob,   token._symbol)["signing_key"].as<public_key_type>(), public_key_type());
    BOOST_CHECK_EQUAL(stake.get_candidate(_carol, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_carol, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_whale, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_whale, "active"));
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(lib_resumed, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("reset_key/lib_resumed");
    deploy_sys_contracts();
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_bob,   token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_carol, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_whale, token._symbol.to_symbol_code()));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(stake.get_candidate(_alice, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_alice, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_bob,   token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_bob, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_carol, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_carol, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_whale, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_whale, "active"));
    for (size_t i = 0; i < 2222; i++) {
        produce_block(fc::milliseconds(config::block_interval_ms), 0, {_alice, _bob});
    }
    BOOST_CHECK_EQUAL(stake.get_candidate(_alice, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_alice, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_bob,   token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_bob, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_carol, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_carol, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_whale, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_whale, "active"));
    for (size_t i = 0; i < 2222; i++) {
        produce_block(fc::milliseconds(config::block_interval_ms), 0, {_bob});
    }
    BOOST_CHECK_EQUAL(stake.get_candidate(_alice, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_alice, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_bob,   token._symbol)["signing_key"].as<public_key_type>(), public_key_type());
    BOOST_CHECK_EQUAL(stake.get_candidate(_carol, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_carol, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_whale, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_whale, "active"));
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(producer_replacement, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("reset_key/producer_replacement");
    deploy_sys_contracts();
    auto cur_producers = reg_candidates(cfg::min_producers_num, 1000);
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group({cfg::internal_name}));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group(cur_producers));
    auto pre_sched_version = control->pending_block_state()->active_schedule.version;
    
    while ((control->pending_block_state()->active_schedule.version - pre_sched_version) < cfg::omission_limit - 1) {
        govern.wait_schedule_activation(true, {cur_producers[0]});
    }
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group(cur_producers));
    for (size_t p = 0; p < cur_producers.size(); p++) {
        BOOST_CHECK_EQUAL(stake.get_candidate(cur_producers[p], token._symbol)["signing_key"].as<public_key_type>(), get_public_key(cur_producers[p], "active"));
    }
    govern.wait_schedule_activation(true, {cur_producers[0]});
    produce_block(); // producer key resetting happens on the second block of the schedule round
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group(cur_producers));
    BOOST_CHECK_EQUAL(stake.get_candidate(cur_producers[0], token._symbol)["signing_key"].as<public_key_type>(), public_key_type());
    for (size_t p = 1; p < cur_producers.size(); p++) {
        BOOST_CHECK_EQUAL(stake.get_candidate(cur_producers[p], token._symbol)["signing_key"].as<public_key_type>(), get_public_key(cur_producers[p], "active"));
    }
    
    govern.wait_schedule_activation(false, {cur_producers[0]});
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group(cur_producers));
    
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_alice, token._symbol.to_symbol_code()));
    govern.wait_schedule_activation(true, {cur_producers[0]});
    cur_producers[0] = _alice;
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group(cur_producers));
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(unreg_sleeping_producer, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("reset_key/unreg_sleeping_producer");
    deploy_sys_contracts();
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_bob,   token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_carol, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.setkey(_alice, token._symbol.to_symbol_code(), true));
    BOOST_CHECK_EQUAL(success(), stake.setkey(_bob,   token._symbol.to_symbol_code(), true));
    BOOST_CHECK_EQUAL(success(), stake.setkey(_carol, token._symbol.to_symbol_code(), true));
    
    auto cur_producers = reg_candidates(cfg::min_producers_num, 1000);
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group({cfg::internal_name}));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group(cur_producers));
    
    auto pre_sched_version = control->pending_block_state()->active_schedule.version;
    
    while ((control->pending_block_state()->active_schedule.version - pre_sched_version) < cfg::omission_limit - 1) {
        govern.wait_schedule_activation(true, {cur_producers[0], cur_producers[1], cur_producers[2]});
    }
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(cur_producers[0], token._symbol.to_symbol_code(), 1));
    BOOST_CHECK_EQUAL(success(), stake.setkey(cur_producers[1], token._symbol.to_symbol_code(), true));
    
    BOOST_CHECK(stake.get_candidate(cur_producers[0], token._symbol).is_null());
    BOOST_CHECK_EQUAL(stake.get_candidate(cur_producers[1], token._symbol)["signing_key"].as<public_key_type>(), public_key_type());
    for (size_t p = 2; p < cur_producers.size(); p++) {
        BOOST_CHECK_EQUAL(stake.get_candidate(cur_producers[p], token._symbol)["signing_key"].as<public_key_type>(), get_public_key(cur_producers[p], "active"));
    }
    govern.wait_schedule_activation(false, {cur_producers[0], cur_producers[1], cur_producers[2]});
    BOOST_CHECK_EQUAL(success(), stake.setkey(_alice, token._symbol.to_symbol_code(), false));
    BOOST_CHECK_EQUAL(success(), stake.setkey(_bob,   token._symbol.to_symbol_code(), false));
    govern.wait_schedule_activation(true, {cur_producers[0], cur_producers[1], cur_producers[2]});
    
    BOOST_CHECK_EQUAL(success(), stake.setkey(_carol, token._symbol.to_symbol_code(), false));
    //3 times because we don't know in which order the keys will be reset
    govern.wait_schedule_activation(true, {cur_producers[0], cur_producers[1], cur_producers[2]});
    govern.wait_schedule_activation(true, {cur_producers[0], cur_producers[1], cur_producers[2]});
    govern.wait_schedule_activation(true, {cur_producers[0], cur_producers[1], cur_producers[2]});
    BOOST_CHECK_EQUAL(stake.get_candidate(cur_producers[2], token._symbol)["signing_key"].as<public_key_type>(), public_key_type());
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END() // reset_key

BOOST_AUTO_TEST_SUITE(reset_level)
BOOST_FIXTURE_TEST_CASE(suspendcand, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("reset_level/suspendcand");
    
    deploy_sys_contracts();
    auto cur_producers = reg_candidates(cfg::min_producers_num, 1000);
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_alice, token._symbol.to_symbol_code()));
    
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group({cfg::internal_name}));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group(cur_producers));
    BOOST_CHECK_EQUAL(success(), stake.setkey(cur_producers[0], token._symbol.to_symbol_code(), true));
    produce_block();
    produce_block(fc::seconds(cfg::max_no_pick_period) - fc::milliseconds(config::block_interval_ms));
    govern.wait_schedule_activation();
    auto suspended = cur_producers[0];
    cur_producers[0] = _alice;
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group(cur_producers));
    
    BOOST_CHECK_EQUAL(success(), stake.suspendcand(suspended, token._symbol.to_symbol_code()));
    for (size_t p = 0; p < cur_producers.size(); p++) {
        BOOST_CHECK_EQUAL(err.cand_is_active, stake.suspendcand(cur_producers[p], token._symbol.to_symbol_code()));
    }
    BOOST_CHECK_EQUAL(stake.get_agent(suspended, token._symbol)["proxy_level"], 4);
    
    BOOST_CHECK_EQUAL(err.temp_unavailable, stake.setproxylvl(suspended, token._symbol.to_symbol_code(), 1));
    produce_block();
    produce_block(fc::seconds(cfg::proxylvl_recovery_delay) - fc::milliseconds(config::block_interval_ms));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(suspended, token._symbol.to_symbol_code(), 1));
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(resets_limit, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("reset_level/resets_limit");
    deploy_sys_contracts();
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_bob,   token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_carol, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_whale, token._symbol.to_symbol_code()));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(stake.get_candidate(_alice, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_alice, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_bob,   token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_bob, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_carol, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_carol, "active"));
    BOOST_CHECK_EQUAL(stake.get_candidate(_whale, token._symbol)["signing_key"].as<public_key_type>(), get_public_key(_whale, "active"));
    for (size_t r = 0; r < cfg::resets_limit; r++) {
        BOOST_TEST_MESSAGE("--- reset " << r);
        for (size_t i = 0; i < 2222; i++) {
            produce_block(fc::milliseconds(config::block_interval_ms), 0, {_bob});
        }
        BOOST_CHECK_EQUAL(stake.get_candidate(_bob, token._symbol)["signing_key"].as<public_key_type>(), public_key_type());
        BOOST_CHECK_EQUAL(stake.get_agent(_bob, token._symbol)["proxy_level"], 0);
        produce_block(fc::milliseconds(config::block_interval_ms), 0, {_bob});
        produce_block(fc::seconds(cfg::key_recovery_delay) - fc::milliseconds(config::block_interval_ms), 0, {_bob});
        BOOST_CHECK_EQUAL(success(), stake.setkey(_bob, token._symbol.to_symbol_code(), false));
    }
    for (size_t i = 0; i < 2222; i++) {
        produce_block(fc::milliseconds(config::block_interval_ms), 0, {_bob});
    }
    BOOST_CHECK(stake.get_candidate(_bob, token._symbol).is_null());
    BOOST_CHECK_EQUAL(stake.get_agent(_bob, token._symbol)["proxy_level"], 4);
    
} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END() // reset_level

BOOST_AUTO_TEST_SUITE(emission)
BOOST_FIXTURE_TEST_CASE(no_staked_test, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("emission/no_staked_test");
    emission_test(cfg::blocks_per_year * 100, 0, "", double(cfg::emission_addition + cfg::emission_factor) / cfg::_100percent);
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(no_votes_test, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("emission/no_votes_test");
    emission_test(cfg::blocks_per_year * 100, cfg::blocks_per_year * 100, "bob", double(cfg::emission_addition + cfg::emission_factor) / cfg::_100percent);
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(not_enough_votes_test, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("emission/not_enough_votes_test");
    emission_test(cfg::blocks_per_year * 100, safe_pct<int64_t>(cfg::emission_min_arg / 2, cfg::blocks_per_year * 100), "alice", 
        double(cfg::emission_addition + cfg::emission_factor) / cfg::_100percent);
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(still_not_enough_votes_test, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("emission/still_not_enough_votes_test");
    emission_test(cfg::blocks_per_year * 100, safe_pct<int64_t>(cfg::emission_min_arg, cfg::blocks_per_year * 100), "alice", 
        double(cfg::emission_addition + cfg::emission_factor) / cfg::_100percent);
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(half_supply_test, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("emission/half_supply_test");
    emission_test(cfg::blocks_per_year * 100, cfg::blocks_per_year * 50, "alice", 
        double(cfg::emission_addition + cfg::emission_factor / 2) / cfg::_100percent);
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(a_lot_of_votes_test, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("emission/a_lot_of_votes_test");
    emission_test(cfg::blocks_per_year * 100, safe_pct<int64_t>(cfg::emission_max_arg, cfg::blocks_per_year * 100), "alice", 
        double(cfg::emission_addition) / cfg::_100percent);
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(all_voted_test, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("emission/all_voted_test");
    emission_test(cfg::blocks_per_year * 100, cfg::blocks_per_year * 100, "alice", 
        double(cfg::emission_addition) / cfg::_100percent);
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(max_supply_test, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("emission/max_supply_test");
    emission_test(cfg::blocks_per_year * 100, cfg::blocks_per_year * 100, "alice", 
        double(cfg::emission_addition) / cfg::_100percent, cfg::blocks_per_year * 100);
} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END() // emission

BOOST_AUTO_TEST_SUITE(election)

BOOST_FIXTURE_TEST_CASE(set_producers_test, cyber_govern_tester) try {
    
    BOOST_TEST_MESSAGE("election/set_producers_test");
    deploy_sys_contracts();
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _whale, asset(100500, token._symbol), ""));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_bob, token._symbol.to_symbol_code()));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group({_bob}));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_alice, token._symbol.to_symbol_code()));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group({_bob, _alice}));
    
    std::vector<account_name> crowd_of_bps;
    for (int u = cfg::min_producers_num - 2; u >= 0; u--) {
        auto user = user_name(u);
        crowd_of_bps.emplace_back(user);
        create_accounts({user});
        BOOST_CHECK_EQUAL(success(), stake.register_candidate(user, token._symbol.to_symbol_code()));
        int64_t amount = u ? (u + 1) * 1000 : 2;
        BOOST_CHECK_EQUAL(success(), token.issue(_issuer, user, asset(amount, token._symbol), ""));
        BOOST_CHECK_EQUAL(success(), token.transfer(user, stake_account_name, asset(amount, token._symbol)));
    }
    auto crowd_and_alice = crowd_of_bps;
    crowd_and_alice.emplace_back(_alice);
    auto crowd_and_bob = crowd_of_bps;
    crowd_and_bob.emplace_back(_bob);
    
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group(crowd_and_alice));
   
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _carol, asset(3, token._symbol), ""));
    BOOST_CHECK_EQUAL(success(), token.transfer(_carol, stake_account_name, asset(1, token._symbol)));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_carol, token._symbol.to_symbol_code(), 1));
    
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_carol, _bob, asset(1, token._symbol)));
    
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group(crowd_and_bob));
    
    BOOST_CHECK_EQUAL(success(), token.transfer(_carol, stake_account_name, asset(2, token._symbol)));
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_carol, _alice, asset(2, token._symbol)));
    
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group(crowd_and_alice));
    
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_whale, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), token.transfer(_whale, stake_account_name, asset(100500, token._symbol)));
    
    crowd_of_bps.back() = _whale;
    crowd_and_alice = crowd_of_bps;
    crowd_and_alice.emplace_back(_alice);
    crowd_and_bob = crowd_of_bps;
    crowd_and_bob.emplace_back(_bob);
    auto crowd_and_user = crowd_of_bps;
    crowd_and_user.emplace_back(user_name(0));
    
    //start with alice because crowd contained user before an activation of whale
    for (int i = 0; i < 3; i++) {
        govern.wait_schedule_activation();
        BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group(crowd_and_alice));
        govern.wait_schedule_activation();
        BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group(crowd_and_user));

    }
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _bob, asset(1, token._symbol), ""));
    BOOST_CHECK_EQUAL(success(), token.transfer(_bob, stake_account_name, asset(1, token._symbol)));
    for (int i = 0; i < 2; i++) {
        govern.wait_schedule_activation();
        BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group(crowd_and_bob));
        govern.wait_schedule_activation();
        BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group(crowd_and_alice));
        govern.wait_schedule_activation();
        BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group(crowd_and_user));
    }
    
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(no_key_test, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("election/no_key_test");
    deploy_sys_contracts();
    BOOST_CHECK_EQUAL(success(), stake.open(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 0));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_bob, token._symbol.to_symbol_code()));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group({_bob}));
    
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(unreg_producer_no_spare_test, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("election/unreg_producer_no_spare_test");
    deploy_sys_contracts();
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_bob, token._symbol.to_symbol_code()));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group({_bob, _alice}));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 1));
    produce_blocks(100);
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group({_bob, _alice}));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_carol, token._symbol.to_symbol_code()));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group({_bob, _carol}));
    
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(unreg_producer_test, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("election/unreg_producer_test");
    deploy_sys_contracts();
    
    for (int u = 0; u < cfg::min_producers_num + 1; u++) {
        auto user = user_name(u);
        create_accounts({user});
        BOOST_CHECK_EQUAL(success(), token.issue(_issuer, user, asset((u + 1) * 1000, token._symbol), ""));
    }
    
    std::vector<account_name> cur_pbs;
    for (int u = 0; u < cfg::min_producers_num + 1; u++) {
        auto user = user_name(u);
        BOOST_CHECK_EQUAL(success(), stake.register_candidate(user, token._symbol.to_symbol_code()));
        BOOST_CHECK_EQUAL(success(), token.transfer(user, stake_account_name, asset((u + 1) * 1000, token._symbol)));
        if (u) {
            cur_pbs.emplace_back(user_name(u));
        }
    }
    
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group(cur_pbs));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(user_name(cfg::min_producers_num), token._symbol.to_symbol_code(), 1));
    govern.wait_schedule_activation();
    cur_pbs.back() = user_name(0);
    BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group(cur_pbs));
    
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(reserve_freq_test, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("election/reserve_freq_test");
    deploy_sys_contracts();
    std::vector<int64_t> stakes;
    for (auto u = 0; u < cfg::min_producers_num - 1; u++) {
        stakes.push_back(5001);
    }
    for (auto i = 0; i < 2; i++) {
        for (auto s = 1000; s <= 5000; s+=1000) {
            stakes.push_back(s);
        }
    }
    
    for (auto s = 10; s <= 100; s+=10) {
        stakes.push_back(s);
    }
    
    for (auto u = 0; u < stakes.size(); u++) {
        auto user = user_name(u);
        create_accounts({user});
        BOOST_CHECK_EQUAL(success(), token.issue(_issuer, user, asset(stakes[u], token._symbol), ""));
    }
    for (auto u = 0; u < stakes.size(); u++) {
        auto user = user_name(u);
        BOOST_CHECK_EQUAL(success(), stake.register_candidate(user, token._symbol.to_symbol_code()));
        BOOST_CHECK_EQUAL(success(), token.transfer(user, stake_account_name, asset(stakes[u], token._symbol)));
    }
    std::map<account_name, int64_t> blocks;
    for (auto b = 0; b < 10000; b++) {
        blocks[produce_block()->producer]++;
        if (b % 1000 == 0) {
            BOOST_TEST_MESSAGE("--- block " << b);
        }
    }
    
    for (auto u = 0; u < stakes.size(); u++) {
        BOOST_TEST_MESSAGE("--- user with " << stakes[u] << " votes produced " << blocks[user_name(u)] << " blocks");
    }
} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END() // election

BOOST_AUTO_TEST_SUITE(schedule_size)
BOOST_FIXTURE_TEST_CASE(not_enough_producers_test, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("schedule_size/not_enough_producers_test");
    deploy_sys_contracts();
    
    std::vector<account_name> cur_pbs;
    for (int u = 0; u < cfg::min_producers_num + 1; u++) {
        auto user = user_name(u);
        create_accounts({user});
        BOOST_CHECK_EQUAL(success(), stake.register_candidate(user, token._symbol.to_symbol_code()));
        if (u != cfg::min_producers_num) {
            cur_pbs.emplace_back(user_name(u));
        }
        govern.wait_schedule_activation();
        BOOST_CHECK_EQUAL(govern.get_active_producers(), govern.make_producers_group(cur_pbs));
    }

} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(set_shift_test, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("schedule_size/set_shift_test");
    deploy_sys_contracts();
    
    reg_candidates(cfg::min_producers_num + 2, 1000);
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers().size(), cfg::min_producers_num);
    
    produce_block(fc::seconds(cfg::schedule_resize_min_delay));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers().size(), cfg::min_producers_num + 1);
    
    BOOST_CHECK_EQUAL(err.incorrect_shift, govern.set_shift(-2));
    BOOST_CHECK_EQUAL(err.incorrect_shift, govern.set_shift(2));
    BOOST_CHECK_EQUAL(err.shift_not_changed, govern.set_shift(1));
    BOOST_CHECK_EQUAL(success(), govern.set_shift(0));
    
    produce_block(fc::seconds(cfg::schedule_resize_min_delay));
    govern.wait_schedule_activation();
    produce_block(fc::seconds(cfg::schedule_resize_min_delay));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers().size(), cfg::min_producers_num + 1);
    
    BOOST_CHECK_EQUAL(success(), govern.set_shift(-1));
    produce_block(fc::seconds(cfg::schedule_resize_min_delay));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers().size(), cfg::min_producers_num);
    produce_block(fc::seconds(cfg::schedule_resize_min_delay));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers().size(), cfg::min_producers_num);
    
    BOOST_CHECK_EQUAL(success(), govern.set_shift(1));
    
    produce_block(fc::seconds(cfg::schedule_resize_min_delay));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers().size(), cfg::min_producers_num + 1);
    produce_block(fc::seconds(cfg::schedule_resize_min_delay));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers().size(), cfg::min_producers_num + 2);
    produce_block(fc::seconds(cfg::schedule_resize_min_delay));
    govern.wait_schedule_activation();
    produce_block(fc::seconds(cfg::schedule_resize_min_delay));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers().size(), cfg::min_producers_num + 2);
    produce_block(fc::seconds(cfg::schedule_resize_min_delay));
    govern.wait_schedule_activation();
    produce_block(fc::seconds(cfg::schedule_resize_min_delay));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers().size(), cfg::min_producers_num + 2);
    
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.register_candidate(_bob, token._symbol.to_symbol_code()));
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers().size(), cfg::min_producers_num + 4);

    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(waiting_test, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("schedule_size/waiting_test");
    deploy_sys_contracts();
    int64_t votes_per_user = 1000;
    double overlay = 0.3;
    
    int u = 0;
    for (; u < cfg::min_producers_num; u++) {
        auto user = user_name(u);
        create_accounts({user});
        BOOST_CHECK_EQUAL(success(), stake.register_candidate(user, token._symbol.to_symbol_code()));
        BOOST_CHECK_EQUAL(success(), token.issue(_issuer, user, asset(votes_per_user, token._symbol), ""));
        BOOST_CHECK_EQUAL(success(), token.transfer(user, stake_account_name, asset(votes_per_user, token._symbol)));
    }
    int64_t cur_pbs_num = cfg::min_producers_num;
    int64_t cur_active_bps_num = cfg::min_producers_num;
    
    govern.wait_schedule_activation();
    BOOST_CHECK_EQUAL(govern.get_active_producers().size(), cur_active_bps_num);
    
    for (int i = cur_active_bps_num; i < cfg::max_producers_num + 2; i++) {
        BOOST_TEST_MESSAGE("-- waiting for the next increase (" << cur_active_bps_num + 1 << ")");
        produce_block(fc::seconds((1.0 - overlay) * cfg::schedule_resize_min_delay));
        
        int64_t bps_target_num = (static_cast<eosio::chain::int128_t>(cur_active_bps_num) * cfg::_100percent / cfg::schedule_increase_blocking_votes_pct) + 1;
        for (int j = cur_pbs_num; j < bps_target_num; j++) {
            auto user = user_name(u++);
            create_accounts({user});
            BOOST_CHECK_EQUAL(success(), stake.register_candidate(user, token._symbol.to_symbol_code()));
            BOOST_CHECK_EQUAL(success(), token.issue(_issuer, user, asset(votes_per_user, token._symbol), ""));
            BOOST_CHECK_EQUAL(success(), token.transfer(user, stake_account_name, asset(votes_per_user, token._symbol)));
        }
        BOOST_TEST_MESSAGE("-- bps_target_num = " << bps_target_num);
        cur_pbs_num = bps_target_num;
        govern.wait_schedule_activation();
        
        BOOST_CHECK_EQUAL(govern.get_active_producers().size(), cur_active_bps_num);
        produce_block(fc::seconds(overlay * 2.0 * cfg::schedule_resize_min_delay));
        govern.wait_schedule_activation();
        if (cur_active_bps_num < cfg::max_producers_num) {
            cur_active_bps_num++;
        }
        BOOST_CHECK_EQUAL(govern.get_active_producers().size(), cur_active_bps_num);
    }
    
} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END() // schedule_size

BOOST_AUTO_TEST_SUITE_END() // cyber_govern_tests

BOOST_AUTO_TEST_SUITE(cyber_govern_tests_ext, * boost::unit_test::disabled())
BOOST_FIXTURE_TEST_CASE(shuffle_test, cyber_govern_tester) try {
    BOOST_TEST_MESSAGE("shuffle_test");
    int max_step_num = 2000;

    struct series_counter {
        int val = 0;
        int max_val = 0;
        int last_step_num = -1;
        void step(int num) {
            BOOST_REQUIRE(num > last_step_num);
            val = (num == last_step_num + 1) ? val + 1 : 1;
            max_val = std::max(max_val, val);
            last_step_num = num;
        }
    };
    
    using series_key = std::tuple<int, int, int>;
    
    for (size_t vec_size = 21; vec_size <= 101; vec_size++) {
        std::vector<int> vec(vec_size);
        std::iota(vec.begin(), vec.end(), 0);
        std::map<series_key, series_counter> series;
        
        auto do_steps = [&](int num) {
            for (size_t i = 0; i < vec_size; i++) {
                series[series_key(vec[i], vec[(i + 1) % vec_size], vec[(i + 2) % vec_size])].step(num);
            }
        };
        
        do_steps(0);
        for (int step_num = 1; step_num <= max_step_num; step_num++) {
            shuffle(vec, step_num * vec_size);
            do_steps(step_num);
        }
        int max_series = 0;
        for (const auto& s : series) {
            max_series = std::max(max_series, s.second.max_val);
        }
        BOOST_CHECK(max_series <= 3);
        BOOST_TEST_MESSAGE("--- vec_size = " << vec_size << ", max_series = " << max_series);
    }
    
} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END()
