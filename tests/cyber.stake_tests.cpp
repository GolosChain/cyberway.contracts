#include "golos_tester.hpp"
#include "cyber.token_test_api.hpp"
#include "cyber.stake_test_api.hpp"
#include "cyber.govern_test_api.hpp"
#include "cyber.bios_test_api.hpp"
#include "contracts.hpp"
#include "../cyber.bios/include/cyber.bios/config.hpp"
#include <eosio/chain/block_header_state.hpp>

namespace cfg = cyber::config;
using eosio::chain::config::stake_account_name;
using eosio::chain::config::govern_account_name;
using namespace eosio::testing;
using namespace eosio::chain;
using namespace eosio::chain::int_arithmetic;
using namespace fc; 
static const auto _token = cfg::system_token;

class cyber_stake_tester : public golos_tester {
protected:
    cyber_token_api token;
    cyber_stake_api stake;
    cyber_govern_api govern;
    cyber_bios_api bios;

    time_point_sec head_block_time() { return time_point_sec(control->head_block_time().time_since_epoch().to_seconds()); };
 
public: 
    cyber_stake_tester()
        : golos_tester(stake_account_name, false)
        , token({this, cfg::token_name, cfg::system_token})
        , stake({this, _code})
        , govern({this, govern_account_name})
        , bios({this, config::system_account_name})
    { 
        create_accounts({_alice, _bob, _carol, _whale,
            cfg::token_name, cfg::worker_name});
        produce_block();
        install_contract(_code, contracts::stake_wasm(), contracts::stake_abi());
        install_contract(cfg::token_name, contracts::token_wasm(), contracts::token_abi());
    }
    
    const account_name _issuer = cfg::issuer_name;
    const account_name _alice = N(alice);
    const account_name _bob = N(bob);
    const account_name _carol = N(carol);
    const account_name _whale = N(whale);
    
    void deploy_sys_contracts() {
        BOOST_TEST_MESSAGE("--- creating token and stake"); 
        BOOST_CHECK_EQUAL(success(), token.create(_issuer, asset(std::numeric_limits<int64_t>::max() / 10, token._symbol)));
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
    
    void create_agent(account_name acc, int64_t stake_amount, size_t level, size_t max_proxy_level) {
        create_accounts({acc});
        if (stake_amount) {
            BOOST_CHECK_EQUAL(success(), token.issue(_issuer, acc, token.from_amount(stake_amount), ""));
            BOOST_CHECK_EQUAL(success(), token.transfer(acc, _code, token.from_amount(stake_amount)));
        }
        else {
            BOOST_CHECK_EQUAL(success(), stake.open(acc, token._symbol.to_symbol_code()));
        }
        if (level != max_proxy_level || !stake_amount) {
            BOOST_CHECK_EQUAL(success(), stake.setproxylvl(acc, token._symbol.to_symbol_code(), level));
        }
    }
    
    std::vector<account_name> create_agents(std::vector<int64_t> stake_amounts) {
        std::vector<account_name> agents;
        agents.reserve(stake_amounts.size());
        auto u = 0;
        for (size_t level = 0; level < stake_amounts.size(); level++) {
            auto cur_user = user_name(++u);
            agents.emplace_back(cur_user);
            create_agent(cur_user, stake_amounts[level], level, stake_amounts.size() - 1);
        }
        return agents;
    }
    
    std::vector<std::vector<account_name> > create_agents(size_t max_proxy_level, uint8_t agents_on_level, std::vector<int64_t> stake_amounts) {
        std::vector<std::vector<account_name> > agents(max_proxy_level + 1);
        auto u = 0;
        for (size_t level = 0; level <= max_proxy_level; level++) {
            
            for (size_t i = 0; i < agents_on_level; i++) {
                auto cur_user = user_name(++u);
                agents[level].emplace_back(cur_user);
                create_agent(cur_user, stake_amounts[level], level, max_proxy_level);
            }
        }
        return agents;
    }
    std::vector<std::vector<account_name> > create_agents(size_t max_proxy_level, uint8_t agents_on_level, int64_t stake_amount) {
        return create_agents(max_proxy_level, agents_on_level, std::vector<int64_t>(max_proxy_level + 1, stake_amount));
    }

    const int64_t get_reward_for_blocks(int64_t emission_per_block, uint32_t blocks) {
        int64_t reward_for_block = (emission_per_block * cfg::block_reward_pct) / cfg::_100percent;
        return blocks * reward_for_block;
    }

    struct errors: contract_error_messages {
        const string incorrect_proxy_levels(uint8_t g, uint8_t a) {
            return amsg("incorrect proxy levels: grantor " + std::to_string(g) + ", agent " + std::to_string(a));
        };
        static string no_agent() {
            return "agent doesn't exist";
        }
        const string agent_exists() {
            return amsg(std::string("agent already exists"));
        }
        const string no_funds() {
            return amsg(std::string("insufficient funds"));
        }
        const string not_enough_staked() {
            return amsg(std::string("not enough staked tokens"));
        }
        const string not_enough_delegated() {
            return amsg(std::string("not enough delegated tokens"));
        }
        const string no_funds_due_to_usage() {
            return amsg(std::string("no staked tokens available due to resource usage"));
        }
        const string no_agent_funds() {
            return amsg(std::string("insufficient agent funds"));
        }
        const string must_withdraw_positive() {
            return amsg(std::string("must withdraw positive quantity"));
        }
        const string can_not_be_negative() {
            return amsg(std::string("quantity can't be negative"));
        }
        const string min_staked_can_not_be_negative() {
            return amsg(std::string("min_own_staked can't be negative"));
        }
        const string nothing_to_claim() {
            return amsg(std::string("nothing to claim"));
        }
        const string nothing_to_cancel() {
            return amsg(std::string("nothing to cancel"));
        }
        const string min_for_election_violated() {
            return amsg(std::string("min_own_staked can't be less than min_own_staked_for_election for users with an ultimate level"));
        }
        const string level_too_high() {
            return amsg(std::string("level too high"));
        }
        const string level_no_change() {
            return amsg(std::string("proxy level has not been changed"));
        }
        const string proxy_cannot_be_added() {
            return amsg(std::string("proxy cannot be added"));
        }
        const string has_a_proxy() {
            return amsg(std::string("can't set an ultimate level because the user has a proxy"));
        }
        const string too_many_proxies() {
            return amsg(std::string("can't set proxy level, user has too many proxies"));
        }
        
        static bool is_insufficient_staked_mssg(const std::string& arg) {
            return arg.find("has insufficient staked tokens") != std::string::npos;
        }
        static bool is_insufficient_ram_mssg(const std::string& arg) {
            return arg.find(" for use ram.") != std::string::npos;
        }
        static bool is_costs_too_much_mssg(const std::string& arg) {
            return arg.find("transaction costs too much") != std::string::npos;
        }
        static bool is_system_err_mssg(const std::string& arg) {
            return arg.find("SYSTEM") != std::string::npos;
        }
        static bool is_transaction_cpu_limit_err_mssg(const std::string& arg) {
            return arg.find("is greater than the maximum billable CPU time for the transaction") != std::string::npos;
        }
        static bool is_transaction_storage_limit_err_mssg(const std::string& arg) {
            return arg.find("transaction resource(3) usage is too high") != std::string::npos;
        }
        static bool is_block_cpu_limit_err_mssg(const std::string& arg) {
            return arg.find("is greater than the billable CPU time left in the block") != std::string::npos;
        }
        static bool is_block_res_limit_err_mssg(const std::string& arg) {
            return arg.find("Block has insufficient resources") != std::string::npos;
        }
    } err;
};

BOOST_AUTO_TEST_SUITE(cyber_stake_tests)
BOOST_FIXTURE_TEST_CASE(basic_tests, cyber_stake_tester) try {
    BOOST_TEST_MESSAGE("Basic stake tests");

    std::vector<uint8_t> max_proxies = {30, 10, 3, 1};
    int64_t frame_length = 30;
    asset stake_a(100, token._symbol);
    asset stake_a2(400, token._symbol);
    asset stake_b(10, token._symbol);
    asset stake_c(1000, token._symbol);
    double pct_b = 0.5;
    double pct_c = 0.2;
    int16_t fee_c = 5555; 
    asset supply = stake_a + stake_a2 + stake_b + stake_c;
    BOOST_CHECK_EQUAL(success(), token.create(_issuer, asset(1000000, token._symbol)));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _alice, stake_a + stake_a2, ""));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _bob,   stake_b, ""));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _carol, stake_c, ""));
 
    BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, max_proxies, 30 * 24 * 60 * 60));
    BOOST_CHECK_EQUAL(success(), stake.open(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.open(_bob, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.open(_carol, token._symbol.to_symbol_code()));

    BOOST_TEST_MESSAGE("--- alice stakes " << stake_a); 
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _code, stake_a));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_carol, token._symbol.to_symbol_code(), 0));
    BOOST_CHECK_EQUAL(success(), stake.setgrntterms(_bob, _carol, token._symbol.to_symbol_code(), pct_c * cfg::_100percent, 0));
    BOOST_CHECK_EQUAL(err.incorrect_proxy_levels(4, 4), 
        stake.setgrntterms(_alice, _bob, token._symbol.to_symbol_code(), pct_b * cfg::_100percent));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_bob, token._symbol.to_symbol_code(), 1));
  
    BOOST_CHECK_EQUAL(success(), stake.setgrntterms(_alice, _bob, token._symbol.to_symbol_code(), pct_b * cfg::_100percent));

    produce_block();
    auto t = head_block_time();
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol),
        stake.make_agent(_alice, token._symbol, max_proxies.size(), t, stake_a.get_amount(),
        0, stake_a.get_amount(), stake_a.get_amount()));
    
    BOOST_CHECK_EQUAL(stake.get_agent(_bob, token._symbol),
        stake.make_agent(_bob, token._symbol, 1, t));

    BOOST_CHECK_EQUAL(stake.get_agent(_carol, token._symbol),
        stake.make_agent(_carol, token._symbol, 0, t));

    BOOST_CHECK_EQUAL(success(), token.transfer(_bob, _code, stake_b));
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _code, stake_a2));
    BOOST_CHECK_EQUAL(success(), token.transfer(_carol, _code, stake_c));
    int64_t total_staked = stake_a.get_amount() + stake_a2.get_amount() + stake_b.get_amount() + stake_c.get_amount();
    BOOST_CHECK_EQUAL(stake.get_stats(token._symbol), stake.make_stats(token._symbol, total_staked, stake.get_total_votes(token._symbol.to_symbol_code())));
    produce_block();
    t = head_block_time();
    double own_a = stake_a.get_amount() + stake_a2.get_amount();
    double own_b = stake_b.get_amount();
    double own_c = stake_c.get_amount();
    double balance_a = stake_a.get_amount() + ((1.0 - pct_b) * stake_a2.get_amount());
    double balance_b = ((stake_a2.get_amount() * pct_b) + stake_b.get_amount()) * (1.0 - pct_c);
    double balance_c = ((stake_a2.get_amount() * pct_b) + stake_b.get_amount()) * pct_c + stake_c.get_amount();
    double total_a = stake_a.get_amount() + stake_a2.get_amount();
    double total_b = stake_b.get_amount() + (total_a - balance_a);
    double total_c = balance_c;
 
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["balance"], balance_a);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["proxied"], total_a - balance_a);
    BOOST_CHECK_EQUAL(stake.get_agent(_bob, token._symbol),
        stake.make_agent(_bob, token._symbol, 1, t, balance_b, total_b - balance_b, total_b, own_b));
    BOOST_CHECK_EQUAL(stake.get_agent(_carol, token._symbol),
        stake.make_agent(_carol, token._symbol, 0, t, balance_c, total_c - balance_c, total_c, own_c));
     
    auto t1 = time_point_sec(t.sec_since_epoch() + frame_length);
    auto blocks_num = ((t1.sec_since_epoch() - head_block_time().sec_since_epoch()) * 1000) / cfg::block_interval_ms - 1;
    BOOST_TEST_MESSAGE("--- produce " << blocks_num << " blocks");
    produce_blocks(blocks_num);
    BOOST_CHECK_EQUAL(success(), stake.updatefunds(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol),
        stake.make_agent(_alice, token._symbol, max_proxies.size(), t1, balance_a, total_a - balance_a, total_a, own_a));
    BOOST_CHECK_EQUAL(stake.get_agent(_bob, token._symbol),
        stake.make_agent(_bob, token._symbol, 1, t1, balance_b, total_b - balance_b, total_b, own_b));
    BOOST_CHECK_EQUAL(stake.get_agent(_carol, token._symbol),
        stake.make_agent(_carol, token._symbol, 0, t1, balance_c, 0, total_c, own_c));
    BOOST_TEST_MESSAGE("--- carol sets fee");
    BOOST_CHECK_EQUAL(success(), stake.setproxyfee(_carol, token._symbol.to_symbol_code(), fee_c));
    t1 = time_point_sec(t1.sec_since_epoch() + frame_length);
    blocks_num = ((t1.sec_since_epoch() - head_block_time().sec_since_epoch()) * 1000) / cfg::block_interval_ms - 1;
    BOOST_TEST_MESSAGE("--- produce " << blocks_num << " blocks");
    produce_blocks(blocks_num);

    BOOST_CHECK_EQUAL(success(), stake.updatefunds(_bob, token._symbol.to_symbol_code()));
    
    balance_c -= (total_b - balance_b);
    total_c = balance_c;
    balance_b = total_b;
    BOOST_CHECK_EQUAL(stake.get_agent(_bob, token._symbol),
        stake.make_agent(_bob, token._symbol, 1, t1, balance_b, total_b - balance_b, total_b, own_b));
    BOOST_CHECK_EQUAL(stake.get_agent(_carol, token._symbol),
        stake.make_agent(_carol, token._symbol, 0, t1, balance_c, 0, total_c, own_c, fee_c));
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(increase_proxy_level_test, cyber_stake_tester) try {
    BOOST_TEST_MESSAGE("Increase proxy level test");
    
    std::vector<uint8_t> max_proxies = {30, 10, 3, 1};
    int64_t frame_length = 30;
    double pct_a = 0.4;
    double pct_b = 0.5;
    double pct_c = 0.2;
    asset staked(10000000, token._symbol);
    BOOST_CHECK_EQUAL(success(), token.create(_issuer, asset(1000000000, token._symbol)));
    BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, max_proxies, 30 * 24 * 60 * 60));
    BOOST_CHECK_EQUAL(success(), stake.open(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.open(_bob, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.open(_carol, token._symbol.to_symbol_code()));

    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _carol, staked, ""));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _alice, staked, ""));

    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 0));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_bob,   token._symbol.to_symbol_code(), 1));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_carol, token._symbol.to_symbol_code(), 2));
    BOOST_CHECK_EQUAL(success(), stake.setgrntterms(_bob, _alice, token._symbol.to_symbol_code(), pct_b * cfg::_100percent));
    BOOST_CHECK_EQUAL(success(), stake.setgrntterms(_carol, _bob, token._symbol.to_symbol_code(), pct_c * cfg::_100percent));
    BOOST_TEST_MESSAGE("--- carol stakes " << staked);
    BOOST_CHECK_EQUAL(success(), token.transfer(_carol, _code, staked));
    BOOST_TEST_MESSAGE("--- alice stakes " << staked);
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _code, staked));

    produce_block();
    auto t = head_block_time();
    auto balance_a = ((pct_b * pct_c) + 1.0) * staked.get_amount();
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol),
        stake.make_agent(_alice, token._symbol, 0, t, balance_a, 0, balance_a, staked.get_amount()));
    BOOST_TEST_MESSAGE("--- alice changes level");
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 4));
    produce_block();
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol),
        stake.make_agent(_alice, token._symbol, 4, t, balance_a, 0, balance_a, staked.get_amount()));
    
    BOOST_TEST_MESSAGE("--- alice delegates");
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_alice, _carol, asset(staked.get_amount() * pct_a, token._symbol)));
    produce_block();
    t = head_block_time();
    balance_a = (1.0 - pct_a) * staked.get_amount();
    auto proxied_a = staked.get_amount() - balance_a;
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol),
        stake.make_agent(_alice, token._symbol, 4, t, balance_a, proxied_a, staked.get_amount(), staked.get_amount()));
        
    auto total_c = proxied_a + staked.get_amount();
    auto balance_c = total_c * (1.0 - pct_c);
    auto proxied_c = total_c * pct_c;
    BOOST_CHECK_EQUAL(stake.get_agent(_carol, token._symbol),
        stake.make_agent(_carol, token._symbol, 2, t, balance_c, proxied_c, total_c, staked.get_amount()));

    auto total_b = proxied_c;
    auto balance_b = total_b;
    auto proxied_b = 0;
    BOOST_CHECK_EQUAL(stake.get_agent(_bob, token._symbol),
        stake.make_agent(_bob, token._symbol, 1, t, balance_b, proxied_b, balance_b, 0));
    BOOST_CHECK_EQUAL(success(), stake.recallvote(_alice, _carol, token._symbol.to_symbol_code(), cfg::_100percent));
    produce_block();

} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(open_test, cyber_stake_tester) try {
    asset stake_u(100, token._symbol);
    BOOST_CHECK_EQUAL(success(), token.create(_issuer, asset(10000000000, token._symbol)));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _alice, stake_u , ""));
    BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, {1}, 30 * 24 * 60 * 60));
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _code, stake_u));
    BOOST_CHECK_EQUAL(err.agent_exists(), stake.open(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.open(_bob, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.enable(_issuer, token._symbol));
    BOOST_CHECK_EQUAL("explicitly_billed_exception", stake.open(_carol, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(err.no_agent(), stake.delegatevote(_alice, _carol, stake_u));
    BOOST_CHECK_EQUAL(success(), stake.open(_carol, token._symbol.to_symbol_code(), _alice));
    produce_block();
    BOOST_CHECK_EQUAL(err.agent_exists(), stake.open(_carol, token._symbol.to_symbol_code(), _alice));
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE(bandwidth)
BOOST_FIXTURE_TEST_CASE(basic_tests, cyber_stake_tester) try {
    
    BOOST_TEST_MESSAGE("Basic bw tests");
    install_contract(config::system_account_name, contracts::bios_wasm(), contracts::bios_abi());
    produce_block();
    double ram_using_prop = 0.0000001;
    double ram_capacity = config::default_max_virtual_limits[resource_limits::RAM] * config::default_account_usage_windows[resource_limits::RAM] / config::block_interval_ms;
    stake.set_billed(100, ram_capacity * ram_using_prop);
    token.set_billed(100, ram_capacity * ram_using_prop);

    std::vector<uint8_t> max_proxies = {30, 10, 3, 1};
    int64_t frame_length = 30;
    asset stake_u(50000, token._symbol);
    asset stake_w(50000 / ram_using_prop, token._symbol);
    asset reward_c(50000 * 2, token._symbol);
    BOOST_CHECK_EQUAL(success(), token.create(_issuer, asset(1000000000000, token._symbol)));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _alice, stake_u , ""));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _bob,   stake_u, ""));
    BOOST_CHECK_EQUAL(success(), token.open(_carol, token._symbol, _carol)); // resource usage
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _issuer, stake_w, ""));
 
    BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, max_proxies, 30 * 24 * 60 * 60));
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _code, stake_u));
    BOOST_CHECK_EQUAL(success(), token.transfer(_bob, _code, stake_u));
    BOOST_CHECK_EQUAL(success(), stake.open(_carol, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.enable(_issuer, token._symbol));

    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 1));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_bob, token._symbol.to_symbol_code(), 1));
    
    BOOST_CHECK(err.is_insufficient_staked_mssg(stake.setproxylvl(_carol, token._symbol.to_symbol_code(), 0)));
    produce_block();
    
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _alice,   stake_u, ""));
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _code, stake_u, "carol"));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_carol, token._symbol.to_symbol_code(), 0));
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_alice, _carol, stake_u));
    auto blocks_num = (frame_length * 1000) / cfg::block_interval_ms;
    produce_blocks(blocks_num);
    
    BOOST_CHECK_EQUAL(success(), stake.reward(_issuer, _carol, reward_c));
    BOOST_CHECK_EQUAL(success(), token.transfer(_issuer, _code, stake_w, "whale"));
    BOOST_CHECK(err.is_insufficient_staked_mssg(stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 2)));
    BOOST_CHECK(err.is_insufficient_staked_mssg(stake.setproxylvl(_bob, token._symbol.to_symbol_code(), 3)));
    produce_block();
    auto params = bios.get_params();
    const auto& prev_min = params.min_virtual_limits;
    const auto& prev_max = params.max_virtual_limits;
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_whale, token._symbol.to_symbol_code(), 1));
    BOOST_CHECK_EQUAL(success(), bios.set_limits({prev_min[0], prev_min[1], 1, prev_min[3]}, cyber_bios_api::MIN_VIRT));
    BOOST_CHECK_EQUAL(success(), bios.set_limits({prev_max[0], prev_max[1], 2, prev_max[3]}, cyber_bios_api::MAX_VIRT));
    produce_block();
    BOOST_CHECK(err.is_insufficient_staked_mssg(stake.setproxylvl(_whale, token._symbol.to_symbol_code(), 2)));
    BOOST_CHECK_EQUAL(success(), bios.set_limits(prev_max, cyber_bios_api::MAX_VIRT));
    BOOST_CHECK_EQUAL(success(), bios.set_limits(prev_min, cyber_bios_api::MIN_VIRT));
    produce_block();
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_whale, token._symbol.to_symbol_code(), 2));
    produce_block();

} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(sys_transaction_usage_test, cyber_stake_tester) try {
    deploy_sys_contracts();
    stake.set_verbose(false);
    asset stake_u(1000, token._symbol);
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _alice, stake_u, ""));
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _code, stake_u));
    stake.set_billed(5000, 1024);
    bios.set_billed(3000, 1024);
    BOOST_CHECK_EQUAL(success(), stake.enable(_issuer, token._symbol));
    produce_block();
    BOOST_CHECK_EQUAL(success(), bios.set_limits({8000, 10000, 10000, 0}, cyber_bios_api::TRANSACTION));
    BOOST_CHECK_EQUAL(success(), bios.set_limits({12000, 100000, 100000, 1}, cyber_bios_api::BLOCK));
    BOOST_CHECK_EQUAL(success(), bios.set_min_transaction_cpu_usage(3000));
    produce_block();
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 1));
    err.is_block_cpu_limit_err_mssg(stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 2));
    produce_block();
    BOOST_CHECK_EQUAL(success(), bios.set_min_transaction_cpu_usage(2000));
    produce_block();
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 2));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 1));
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(hard_limits_tests, cyber_stake_tester) try {
    deploy_sys_contracts();
    stake.set_verbose(false);
    asset stake_u(1000, token._symbol);
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _alice, stake_u, ""));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _bob, stake_u, ""));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _carol, stake_u, ""));
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _code, stake_u));
    BOOST_CHECK_EQUAL(success(), token.transfer(_bob, _code, stake_u));
    BOOST_CHECK_EQUAL(success(), token.transfer(_carol, _code, stake_u));
    BOOST_CHECK_EQUAL(success(), bios.set_min_transaction_cpu_usage(500));
    stake.set_billed(1501, 1024);
    bios.set_billed(500, 1);
    BOOST_CHECK_EQUAL(success(), stake.enable(_issuer, token._symbol));
    produce_block();
    BOOST_CHECK_EQUAL(success(), bios.set_limits({1500, 10000, 10000, 10000}, cyber_bios_api::TRANSACTION));
    BOOST_CHECK_EQUAL(success(), bios.set_limits({2500, 100000, 100000, 20000}, cyber_bios_api::BLOCK));
    produce_block();
    
    err.is_transaction_cpu_limit_err_mssg(stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 2));
    stake.set_billed(1500, 1024);
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 2));

    err.is_block_cpu_limit_err_mssg(stake.setproxylvl(_bob, token._symbol.to_symbol_code(), 2));
    stake.set_billed(500, 1024);
    uint64_t prev_storage_used = bios.get_pending_usage()[3];
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_bob, token._symbol.to_symbol_code(), 0));
    uint64_t storage_used = bios.get_pending_usage()[3] - prev_storage_used;
    err.is_block_cpu_limit_err_mssg(stake.setproxylvl(_carol, token._symbol.to_symbol_code(), 2));
    produce_block();
    BOOST_CHECK_EQUAL(success(), bios.set_limits({1500, 10000, 10000, storage_used}, cyber_bios_api::TRANSACTION));
    BOOST_CHECK_EQUAL(success(), bios.set_limits({2500, 100000, 100000, storage_used + 1}, cyber_bios_api::BLOCK));
    produce_block();
    
    auto pending_usage = bios.get_pending_usage()[3];
    BOOST_CHECK(err.is_transaction_storage_limit_err_mssg(stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 0)));
    
    pending_usage = bios.get_pending_usage()[3];
    BOOST_CHECK(err.is_transaction_storage_limit_err_mssg(stake.setproxylvl(_carol, token._symbol.to_symbol_code(), 0)));
    pending_usage = bios.get_pending_usage()[3];
    
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_bob, token._symbol.to_symbol_code(), 1));
    pending_usage = bios.get_pending_usage()[3];
    BOOST_CHECK(err.is_transaction_storage_limit_err_mssg(stake.setproxylvl(_carol, token._symbol.to_symbol_code(), 0)));
    pending_usage = bios.get_pending_usage()[3];
    
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(virt_limit_test, cyber_stake_tester) try {
    BOOST_TEST_MESSAGE("virt_limit_test");
    deploy_sys_contracts();
    stake.set_verbose(false);
    asset stake_u(1000, token._symbol);
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _alice, stake_u, ""));
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _code, stake_u));
    stake.set_billed(config::default_max_transaction_usage[resource_limits::CPU], 1024);
    bios.set_billed(3000, 1024);
    auto cur_virt_lim = bios.get_virtual_limits()[0];
    BOOST_CHECK_EQUAL(cur_virt_lim, config::default_max_virtual_limits[resource_limits::CPU]);
    size_t i = 0;
    BOOST_TEST_MESSAGE("--- limit decreasing");
    while (cur_virt_lim > config::default_min_virtual_limits[resource_limits::CPU]) {
        
        BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 1 + (i % 2)));
        produce_block();
        auto prev_virt_lim = cur_virt_lim;
        cur_virt_lim = bios.get_virtual_limits()[0];
        if (i % 100 == 0) {
            BOOST_TEST_MESSAGE("--- i = " << i << ", cur_virt_lim = " << cur_virt_lim << ", prev_virt_lim = " << prev_virt_lim);
        }
        BOOST_CHECK(i < 3 || cur_virt_lim < prev_virt_lim);
        ++i;
    }
    i = 0;
    BOOST_TEST_MESSAGE("--- limit increasing");
    while (cur_virt_lim < config::default_max_virtual_limits[resource_limits::CPU]) {
        produce_block();
        auto prev_virt_lim = cur_virt_lim;
        cur_virt_lim = bios.get_virtual_limits()[0];
        if (i % 100 == 0) {
            BOOST_TEST_MESSAGE("--- i = " << i << ", cur_virt_lim = " << cur_virt_lim << ", prev_virt_lim = " << prev_virt_lim);
        }
        BOOST_CHECK(i < 33 || cur_virt_lim > prev_virt_lim);
        ++i;
    }

} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(rush_test, cyber_stake_tester) try {
    BOOST_TEST_MESSAGE("rush_test");
    deploy_sys_contracts();
    stake.set_verbose(false);
    
    asset stake_c(10000000000, token._symbol);
    asset stake_u(10000, token._symbol);
    asset supply = stake_c;
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _carol, stake_c, ""));
    BOOST_CHECK_EQUAL(success(), stake.open(_carol, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), token.transfer(_carol, _code, stake_c));
    BOOST_CHECK_EQUAL(success(), stake.enable(_issuer, token._symbol));
    
    produce_block();
    std::vector<int> rush(eosio::chain::resource_limits::resources_num);
    auto u = 0;
    stake.set_billed(200, 2048);

    for (u = 0; u < std::pow(2, rush.size()); u++) {
        auto user = user_name(u);
        create_accounts({user});
        BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _carol, stake_u, ""));
        BOOST_CHECK_EQUAL(success(), token.transfer(_carol, _code, stake_u, user.to_string()));
        produce_block();
        supply += stake_u;
    }
    
    produce_block();
    u = 0;
    for (rush[0] = 0; rush[0] <= 1; rush[0]++) {
    for (rush[1] = 0; rush[1] <= 1; rush[1]++) {
    for (rush[2] = 0; rush[2] <= 1; rush[2]++) {
    for (rush[3] = 0; rush[3] <= 1; rush[3]++) {
        std::vector<int64_t> avg_used(eosio::chain::resource_limits::resources_num);
        std::vector<uint64_t> virt_lim(eosio::chain::resource_limits::resources_num);
        auto user = user_name(u++);
        for (auto i = 0; i < eosio::chain::resource_limits::resources_num; i++) {
            avg_used[i] = rush[i] ? config::default_max_block_usage[i] : 0;
            virt_lim[i] = rush[i] ? config::default_min_virtual_limits[i] : config::default_max_virtual_limits[i];
            
        }
        bios.set_global_usage(avg_used);
        bios.set_virtual_limits(virt_lim);
        produce_block();
        auto pre_usage = bios.get_pending_usage();
        BOOST_CHECK_EQUAL(success(), stake.register_candidate(user, token._symbol.to_symbol_code(), false));
        auto cost = bios.get_cost(pre_usage, bios.get_pending_usage());
        auto prop = double(cost) / double(supply.get_amount());
        BOOST_TEST_MESSAGE("rush mask = " << rush[0] << rush[1] << rush[2] << rush[3] <<
            ", cost = " << cost << ", prop = " << prop);
        produce_block();
    }}}}
    produce_block();
    
} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END() // bandwidth

BOOST_AUTO_TEST_SUITE(unstaking)

BOOST_FIXTURE_TEST_CASE(general_test, cyber_stake_tester) try {
    BOOST_TEST_MESSAGE("unstaking/general_test");
    install_contract(config::system_account_name, contracts::bios_wasm(), contracts::bios_abi());
    int64_t stake_amount = 50000000;
    BOOST_CHECK_EQUAL(success(), token.create(_issuer, token.from_amount(stake_amount * 1001)));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _alice, token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _whale, token.from_amount(stake_amount * 1000), ""));
    BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, {30, 10, 3, 1}, 30 * 24 * 60 * 60));
    BOOST_CHECK_EQUAL(err.no_agent(), stake.withdraw(_alice, token.from_amount(stake_amount)));
    
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _code, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), token.transfer(_whale, _code, token.from_amount(stake_amount * 1000)));
    BOOST_CHECK_EQUAL(success(), stake.enable(_issuer, token._symbol));
    produce_block();

    BOOST_CHECK_EQUAL(err.no_funds(), stake.withdraw(_alice, token.from_amount(stake_amount + 1)));
    BOOST_CHECK_EQUAL(err.must_withdraw_positive(), stake.withdraw(_alice, token.from_amount(-1)));
    BOOST_CHECK_EQUAL(err.must_withdraw_positive(), stake.withdraw(_alice, token.from_amount(0)));
    BOOST_CHECK_EQUAL(success(), stake.withdraw(_alice, token.from_amount(stake_amount / 2)));
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["balance"], stake_amount / 2);
    produce_block();
    BOOST_CHECK_EQUAL(err.no_funds(), stake.withdraw(_alice, token.from_amount((stake_amount / 2) + 1)));
    BOOST_CHECK_EQUAL(err.no_funds_due_to_usage(), stake.withdraw(_alice, token.from_amount(stake_amount / 2)));
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["balance"], stake_amount / 2);
    
    produce_block();
    
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(proxy_test, cyber_stake_tester) try {
    BOOST_TEST_MESSAGE("unstaking/proxy_test");
    install_contract(config::system_account_name, contracts::bios_wasm(), contracts::bios_abi());
    int64_t stake_amount = 5000;
    BOOST_CHECK_EQUAL(success(), token.create(_issuer, token.from_amount(100500)));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _alice, token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _bob,   token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _carol, token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, {30, 10, 3, 1}, 100500));
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _code, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), token.transfer(_bob,   _code, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), token.transfer(_carol, _code, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 2));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_bob,   token._symbol.to_symbol_code(), 3));
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_carol, _bob, token.from_amount(stake_amount / 2)));
    BOOST_CHECK_EQUAL(err.no_funds(), stake.withdraw(_carol, token.from_amount(stake_amount / 2 + 1)));
    BOOST_CHECK_EQUAL(success(), stake.withdraw(_carol, token.from_amount(stake_amount / 2)));
    BOOST_CHECK_EQUAL(success(), token.transfer(_carol, _code, token.from_amount(stake_amount / 2)));
    produce_block();
    
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_carol, _bob, token.from_amount(stake_amount / 2)));
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_bob, _alice, token.from_amount(stake_amount - 1)));
    BOOST_CHECK_EQUAL(err.no_funds(), stake.withdraw(_bob, token.from_amount(stake_amount + 2)));
    BOOST_CHECK_EQUAL(err.no_agent_funds(), stake.withdraw(_bob, token.from_amount(stake_amount + 1)));
    BOOST_CHECK_EQUAL(success(), stake.withdraw(_bob, token.from_amount(stake_amount / 2)));
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["balance"],   stake_amount * 2 - 1);
    BOOST_CHECK_EQUAL(stake.get_agent(_bob,   token._symbol)["balance"],   stake_amount / 2 + 1);
    BOOST_CHECK_EQUAL(stake.get_agent(_bob,   token._symbol)["proxied"],   stake_amount - 1);
    BOOST_CHECK_EQUAL(stake.get_agent(_bob,   token._symbol)["own_share"], stake_amount / 2);
    
    BOOST_CHECK_EQUAL(success(), stake.recallvote(_carol, _bob,   token._symbol.to_symbol_code(), cfg::_100percent));
    BOOST_CHECK_EQUAL(success(), stake.recallvote(_bob,   _alice, token._symbol.to_symbol_code(), cfg::_100percent));
    produce_block();
    
    BOOST_CHECK_EQUAL(success(), token.transfer(_bob, _code, token.from_amount(stake_amount / 2)));
    BOOST_CHECK_CLOSE_FRACTION(double(stake_amount), double(stake.get_agent(_alice, token._symbol)["balance"].as<int64_t>()), 0.001);
    BOOST_CHECK_CLOSE_FRACTION(double(stake_amount), double(stake.get_agent(_bob,   token._symbol)["balance"].as<int64_t>()), 0.001);
    BOOST_CHECK_CLOSE_FRACTION(double(stake_amount), double(stake.get_agent(_carol, token._symbol)["balance"].as<int64_t>()), 0.001);

    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END() // unstaking

BOOST_AUTO_TEST_SUITE(providing)
BOOST_FIXTURE_TEST_CASE(basic_test, cyber_stake_tester) try {
    BOOST_TEST_MESSAGE("providing/basic_test");
    install_contract(config::system_account_name, contracts::bios_wasm(), contracts::bios_abi());
    BOOST_CHECK_EQUAL(success(), bios.set_min_transaction_cpu_usage(500));
    stake.set_billed(1500, 1024);
    bios.set_billed(500, 1);
    int64_t stake_amount = 50000000000;
    size_t blocks_before_payout = 4;
    
    BOOST_CHECK_EQUAL(success(), token.create(_issuer, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _whale, token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, {30, 10, 3, 1}, blocks_before_payout * cyber::config::block_interval_ms / 1000));
    
    BOOST_CHECK_EQUAL(success(), token.transfer(_whale, _code, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), stake.open(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.enable(_issuer, token._symbol));
    
    auto res_balance = bios.get_account_balance(_alice);
    int64_t prov_step_0 = 50;
    BOOST_TEST_MESSAGE("alice's resource balance = " << res_balance);
    BOOST_CHECK_EQUAL(res_balance, 0);
    BOOST_CHECK_EQUAL(success(), stake.delegateuse(_whale, _alice, token.from_amount(prov_step_0)));
    res_balance = bios.get_account_balance(_alice);
    BOOST_TEST_MESSAGE("alice's resource balance = " << res_balance);
    BOOST_CHECK_GT(prov_step_0, res_balance);
    int64_t prov_step_1 = 30;
    BOOST_CHECK_EQUAL(success(), stake.delegateuse(_whale, _alice, token.from_amount(prov_step_1)));
    auto new_res_balance = bios.get_account_balance(_alice);
    BOOST_CHECK_EQUAL(new_res_balance - res_balance, prov_step_1);
    res_balance = new_res_balance;
    BOOST_TEST_MESSAGE("alice's resource balance = " << res_balance);
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 3));
    BOOST_TEST_MESSAGE("alice's resource balance = " << bios.get_account_balance(_alice));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 2));
    BOOST_TEST_MESSAGE("alice's resource balance = " << bios.get_account_balance(_alice));
    BOOST_CHECK_EQUAL("explicitly_billed_exception", stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 1));
    BOOST_TEST_MESSAGE("alice's resource balance = " << bios.get_account_balance(_alice));
    
    produce_block();
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["provided"], prov_step_0 + prov_step_1);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["received"], prov_step_0 + prov_step_1);
    BOOST_CHECK_EQUAL(success(), stake.recalluse(_whale, _alice, token.from_amount(prov_step_0)));
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["provided"], prov_step_0 + prov_step_1);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["received"], prov_step_1);
    BOOST_CHECK_EQUAL(success(), stake.recalluse(_whale, _alice, token.from_amount(prov_step_1)));
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["provided"], prov_step_0 + prov_step_1);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["received"], 0);
    produce_blocks(blocks_before_payout - 1);
    BOOST_CHECK_EQUAL(err.nothing_to_claim(), stake.claim(_whale, _alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["provided"], prov_step_0 + prov_step_1);
    produce_block();
    BOOST_CHECK_EQUAL(success(), stake.claim(_whale, _alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["provided"], 0);
    produce_block();
    BOOST_CHECK_EQUAL(err.nothing_to_claim(), stake.claim(_whale, _alice, token._symbol.to_symbol_code()));
    produce_block();

} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(limits, cyber_stake_tester) try {
    BOOST_TEST_MESSAGE("providing/limits");
    install_contract(config::system_account_name, contracts::bios_wasm(), contracts::bios_abi());
    BOOST_CHECK_EQUAL(success(), bios.set_min_transaction_cpu_usage(500));
    int64_t stake_amount = 50000000000;
    int64_t delta = 5;
    
    token.set_billed(1024, 1024);
    stake.set_billed(1500, 1024);
    bios.set_billed(500, 1);
    
    BOOST_CHECK_EQUAL(success(), token.create(_issuer, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _whale, token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, {30, 10, 3, 1}, 42));
    
    BOOST_CHECK_EQUAL(success(), token.transfer(_whale, _code, token.from_amount(stake_amount)));
    
    BOOST_CHECK_EQUAL(success(), stake.open(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.open(_bob, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.enable(_issuer, token._symbol));
    produce_block();
    auto initial_res_cost = stake_amount - bios.get_account_balance(_whale);
    BOOST_TEST_MESSAGE("initial cost = " << initial_res_cost);
    auto res_balance = bios.get_account_balance(_whale);
    BOOST_CHECK_EQUAL(success(), stake.delegateuse(_whale, _alice, token.from_amount(stake_amount / 2)));
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["provided"], stake_amount / 2);
    auto price = res_balance - (stake_amount / 2 + bios.get_account_balance(_whale));
    BOOST_TEST_MESSAGE("price of delegateuse action = " << price);
    BOOST_CHECK_EQUAL(err.not_enough_staked(), stake.delegateuse(_whale, _bob, token.from_amount(stake_amount / 2 + 1)));
    auto required_stake = price * 2 + initial_res_cost;
    BOOST_CHECK(err.is_insufficient_staked_mssg(stake.delegateuse(_whale, _bob, token.from_amount(stake_amount / 2))));
    BOOST_CHECK(err.is_insufficient_staked_mssg(stake.delegateuse(_whale, _bob, token.from_amount(stake_amount / 2 - required_stake + delta))));
    BOOST_CHECK_EQUAL(success(), stake.delegateuse(_whale, _bob, token.from_amount(stake_amount / 2 - required_stake - delta)));
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["provided"], stake_amount - required_stake - delta);
    BOOST_CHECK_EQUAL("explicitly_billed_exception", stake.recalluse(_whale, _alice, token.from_amount(stake_amount / 2)));
    produce_blocks(777);
    BOOST_CHECK_EQUAL(success(), stake.recalluse(_whale, _alice, token.from_amount(stake_amount / 2)));
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(recall, cyber_stake_tester) try {
    BOOST_TEST_MESSAGE("providing/recall");
    install_contract(config::system_account_name, contracts::bios_wasm(), contracts::bios_abi());
    BOOST_CHECK_EQUAL(success(), bios.set_min_transaction_cpu_usage(500));
    int64_t stake_amount = 50000000000;
    int64_t to_provide = 10000;
    
    BOOST_CHECK_EQUAL(success(), token.create(_issuer, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _whale, token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, {30, 10, 3, 1}, 1));
    BOOST_CHECK_EQUAL(success(), token.transfer(_whale, _code, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), stake.open(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.enable(_issuer, token._symbol));
    
    BOOST_CHECK_EQUAL(success(), stake.delegateuse(_whale, _alice, token.from_amount(to_provide)));
    BOOST_CHECK_EQUAL(err.not_enough_delegated(), stake.recalluse(_whale, _alice, token.from_amount(to_provide + 1)));
    BOOST_CHECK_EQUAL(success(), stake.recalluse(_whale, _alice, token.from_amount(to_provide)));
    produce_block();
    BOOST_CHECK_EQUAL(success(), stake.delegateuse(_whale, _alice, token.from_amount(to_provide)));
    
    BOOST_CHECK_EQUAL(success(), stake.recalluse(_whale, _alice, token.from_amount(to_provide - 2)));
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["provided"], to_provide);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["received"], 2);
    BOOST_CHECK_EQUAL(stake.get_payout(token._symbol.to_symbol_code(), _whale, _alice), to_provide - 2);
    BOOST_CHECK_EQUAL(stake.get_prov(token._symbol.to_symbol_code(), _whale, _alice), 2);
    
    BOOST_CHECK_EQUAL(success(), stake.recalluse(_whale, _alice, token.from_amount(1)));
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["provided"], to_provide);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["received"], 1);
    BOOST_CHECK_EQUAL(stake.get_payout(token._symbol.to_symbol_code(), _whale, _alice), to_provide - 1);
    BOOST_CHECK_EQUAL(stake.get_prov(token._symbol.to_symbol_code(), _whale, _alice), 1);
    
    produce_block();
    BOOST_CHECK_EQUAL(success(), stake.claim(_whale, _alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["provided"], 1);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["received"], 1);
    BOOST_CHECK_EQUAL(stake.get_payout(token._symbol.to_symbol_code(), _whale, _alice), 0);
    BOOST_CHECK_EQUAL(stake.get_prov(token._symbol.to_symbol_code(), _whale, _alice), 1);
    
    produce_block();
    BOOST_CHECK_EQUAL(success(), stake.recalluse(_whale, _alice, token.from_amount(1)));
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["provided"], 1);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["received"], 0);
    BOOST_CHECK_EQUAL(stake.get_payout(token._symbol.to_symbol_code(), _whale, _alice), 1);
    BOOST_CHECK_EQUAL(stake.get_prov(token._symbol.to_symbol_code(), _whale, _alice), 0);
    BOOST_CHECK_EQUAL(err.nothing_to_claim(), stake.claim(_whale, _alice, token._symbol.to_symbol_code()));
    
    produce_block();
    BOOST_CHECK_EQUAL(success(), stake.claim(_whale, _alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["provided"], 0);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["received"], 0);
    BOOST_CHECK_EQUAL(stake.get_payout(token._symbol.to_symbol_code(), _whale, _alice), 0);
    BOOST_CHECK_EQUAL(stake.get_prov(token._symbol.to_symbol_code(), _whale, _alice), 0);
    
    produce_block();

} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(delegate_out_of_payout, cyber_stake_tester) try {
    BOOST_TEST_MESSAGE("providing/delegate_out_of_payout");
    
    install_contract(config::system_account_name, contracts::bios_wasm(), contracts::bios_abi());
    BOOST_CHECK_EQUAL(success(), bios.set_min_transaction_cpu_usage(500));
    int64_t stake_amount = 50000000000;
    int64_t to_provide = 10000;
    
    BOOST_CHECK_EQUAL(success(), token.create(_issuer, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _whale, token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, {30, 10, 3, 1}, 1));
    BOOST_CHECK_EQUAL(success(), token.transfer(_whale, _code, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), stake.open(_alice, token._symbol.to_symbol_code()));
    
    BOOST_CHECK_EQUAL(success(), stake.delegateuse(_whale, _alice, token.from_amount(to_provide)));
        
    BOOST_CHECK_EQUAL(success(), stake.recalluse(_whale, _alice, token.from_amount(10)));
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["provided"], to_provide);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["received"], to_provide - 10);
    BOOST_CHECK_EQUAL(stake.get_payout(token._symbol.to_symbol_code(), _whale, _alice), 10);
    BOOST_CHECK_EQUAL(stake.get_prov(token._symbol.to_symbol_code(), _whale, _alice), to_provide - 10);
    
    BOOST_CHECK_EQUAL(success(), stake.delegateuse(_whale, _alice, token.from_amount(3)));
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["provided"], to_provide);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["received"], to_provide - 7);
    BOOST_CHECK_EQUAL(stake.get_payout(token._symbol.to_symbol_code(), _whale, _alice), 7);
    BOOST_CHECK_EQUAL(stake.get_prov(token._symbol.to_symbol_code(), _whale, _alice), to_provide - 7);
    
    BOOST_CHECK_EQUAL(success(), stake.delegateuse(_whale, _alice, token.from_amount(8)));
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["provided"], to_provide + 1);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["received"], to_provide + 1);
    BOOST_CHECK_EQUAL(stake.get_payout(token._symbol.to_symbol_code(), _whale, _alice), 0);
    BOOST_CHECK_EQUAL(stake.get_prov(token._symbol.to_symbol_code(), _whale, _alice), to_provide + 1);
    
    BOOST_CHECK_EQUAL(success(), stake.recalluse(_whale, _alice, token.from_amount(to_provide)));
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["provided"], to_provide + 1);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["received"], 1);
    BOOST_CHECK_EQUAL(stake.get_payout(token._symbol.to_symbol_code(), _whale, _alice), to_provide);
    BOOST_CHECK_EQUAL(stake.get_prov(token._symbol.to_symbol_code(), _whale, _alice), 1);
    
    //bw is disabled in this test
    BOOST_CHECK_EQUAL(err.not_enough_staked(), stake.delegateuse(_whale, _alice, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), stake.delegateuse(_whale, _alice, token.from_amount(stake_amount - 1)));
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["provided"], stake_amount);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["received"], stake_amount);
    BOOST_CHECK_EQUAL(stake.get_payout(token._symbol.to_symbol_code(), _whale, _alice), 0);
    BOOST_CHECK_EQUAL(stake.get_prov(token._symbol.to_symbol_code(), _whale, _alice), stake_amount);
    
} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END() // providing

BOOST_AUTO_TEST_SUITE(agent_updates)

BOOST_FIXTURE_TEST_CASE(proxy_level_test, cyber_stake_tester) try {
    BOOST_TEST_MESSAGE("agent_updates/proxy_level_test");
    int64_t stake_amount = 5000;
    BOOST_CHECK_EQUAL(success(), token.create(_issuer, token.from_amount(100500)));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _alice, token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _bob,   token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _carol, token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, {30, 3, 2, 1}, 100500));
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _code, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), token.transfer(_bob,   _code, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), token.transfer(_carol, _code, token.from_amount(stake_amount)));

    BOOST_CHECK_EQUAL(err.level_too_high(),  stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 5));
    BOOST_CHECK_EQUAL(err.level_no_change(), stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 4));
    
    BOOST_CHECK_EQUAL(success(),  stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 2));
    BOOST_CHECK_EQUAL(success(),  stake.setproxylvl(_bob,   token._symbol.to_symbol_code(), 3));

    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_bob,   _alice, token.from_amount(stake_amount)));
    //level: 4    3    2    1    0
    //            b -> a
    BOOST_CHECK_EQUAL(stake.get_agent(_alice,   token._symbol)["balance"], stake_amount * 2);
    BOOST_CHECK_EQUAL(stake.get_agent(_bob,     token._symbol)["balance"], 0);
    BOOST_CHECK_EQUAL(stake.get_agent(_bob,     token._symbol)["proxied"], stake_amount);
    
    BOOST_CHECK_EQUAL(success(),  stake.setproxylvl(_bob,   token._symbol.to_symbol_code(), 1));
    
    BOOST_CHECK_EQUAL(stake.get_agent(_alice,   token._symbol)["balance"], stake_amount * 2);
    BOOST_CHECK_EQUAL(err.no_funds(), stake.delegatevote(_alice, _bob,   token.from_amount(stake_amount * 2)));
    
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_alice, _bob,   token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_carol, _bob,   token.from_amount(stake_amount)));
    //level: 4    3    2    1    0
    //                 a -> b
    //       c--------------^     
    BOOST_CHECK_EQUAL(stake.get_agent(_bob,     token._symbol)["balance"], stake_amount * 3);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice,   token._symbol)["balance"], 0);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice,   token._symbol)["proxied"], stake_amount);
    BOOST_CHECK_EQUAL(stake.get_agent(_carol,   token._symbol)["balance"], 0);
    BOOST_CHECK_EQUAL(stake.get_agent(_carol,   token._symbol)["proxied"], stake_amount);
    produce_block();
    
    BOOST_CHECK_EQUAL(success(),  stake.setproxylvl(_bob,   token._symbol.to_symbol_code(), 3));
    //level: 4    3    2    1    0
    //            b    a
    //       c----^     
    
    produce_block();
    BOOST_CHECK_EQUAL(success(), stake.updatefunds(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.updatefunds(_carol, token._symbol.to_symbol_code()));

    BOOST_CHECK_EQUAL(stake.get_agent(_bob,     token._symbol)["balance"], stake_amount * 2);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice,   token._symbol)["balance"], stake_amount);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice,   token._symbol)["proxied"], 0);
    BOOST_CHECK_EQUAL(stake.get_agent(_carol,   token._symbol)["proxied"], stake_amount);
    
    BOOST_CHECK_EQUAL(success(), stake.recallvote(_carol, _bob, token._symbol.to_symbol_code(), cfg::_100percent / 2));
    BOOST_CHECK_EQUAL(stake.get_agent(_carol,   token._symbol)["balance"], stake_amount / 2);
    BOOST_CHECK_EQUAL(stake.get_agent(_carol,   token._symbol)["proxied"], stake_amount / 2);
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_carol, _bob, token.from_amount(stake_amount / 2)));
    BOOST_CHECK_EQUAL(stake.get_agent(_carol,   token._symbol)["balance"], 0);
    BOOST_CHECK_EQUAL(stake.get_agent(_carol,   token._symbol)["proxied"], stake_amount);
    produce_block();
    
    BOOST_CHECK_EQUAL(success(), stake.recallvote(_carol, _bob, token._symbol.to_symbol_code(), cfg::_100percent / 2));
    BOOST_CHECK_EQUAL(stake.get_agent(_carol,   token._symbol)["balance"], stake_amount / 2);
    BOOST_CHECK_EQUAL(stake.get_agent(_carol,   token._symbol)["proxied"], stake_amount / 2);
    BOOST_CHECK_EQUAL(err.proxy_cannot_be_added(), stake.delegatevote(_carol, _alice, token.from_amount(stake_amount / 2)));
    
    BOOST_CHECK_EQUAL(success(),  stake.setproxylvl(_bob,   token._symbol.to_symbol_code(), 1));
    produce_blocks(2);
    BOOST_CHECK_EQUAL(success(), stake.updatefunds(_carol, token._symbol.to_symbol_code()));
    //bob-carol edge still exists
    BOOST_CHECK_EQUAL(stake.get_agent(_carol,   token._symbol)["proxied"], stake_amount / 2);
    
    BOOST_CHECK_EQUAL(success(),  stake.setproxylvl(_carol,   token._symbol.to_symbol_code(), 3));
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_carol, _alice, token.from_amount(stake_amount / 2)));
    //level: 4    3    2    1    0
    //                 a    b
    //            c----^----^
    BOOST_CHECK_EQUAL(stake.get_agent(_bob,     token._symbol)["balance"], stake_amount + stake_amount / 2);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice,   token._symbol)["balance"], stake_amount + stake_amount / 2);
    BOOST_CHECK_EQUAL(stake.get_agent(_carol,   token._symbol)["balance"], 0);
    BOOST_CHECK_EQUAL(stake.get_agent(_carol,   token._symbol)["proxied"], stake_amount);
    
    BOOST_CHECK_EQUAL(err.has_a_proxy(),      stake.setproxylvl(_carol,   token._symbol.to_symbol_code(), 0));
    BOOST_CHECK_EQUAL(err.too_many_proxies(), stake.setproxylvl(_carol,   token._symbol.to_symbol_code(), 4));
    
    BOOST_CHECK_EQUAL(success(),  stake.setproxylvl(_alice,   token._symbol.to_symbol_code(), 1));
    BOOST_CHECK_EQUAL(success(),  stake.setproxylvl(_carol,   token._symbol.to_symbol_code(), 2));
    produce_blocks(2);
    BOOST_CHECK_EQUAL(success(), stake.updatefunds(_carol, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(),  stake.setproxylvl(_carol,   token._symbol.to_symbol_code(), 3));
    produce_blocks(2);
    BOOST_CHECK_EQUAL(success(), stake.updatefunds(_carol, token._symbol.to_symbol_code()));
    //level: 4    3    2    1    0
    //            c ------> ab
    BOOST_CHECK_EQUAL(stake.get_agent(_bob,     token._symbol)["balance"], stake_amount + stake_amount / 2);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice,   token._symbol)["balance"], stake_amount + stake_amount / 2);
    BOOST_CHECK_EQUAL(stake.get_agent(_carol,   token._symbol)["balance"], 0);
    BOOST_CHECK_EQUAL(stake.get_agent(_carol,   token._symbol)["proxied"], stake_amount);
    produce_block();
} FC_LOG_AND_RETHROW()


BOOST_FIXTURE_TEST_CASE(fee_parallel_test, cyber_stake_tester) try {
    BOOST_TEST_MESSAGE("agent_updates/fee_parallel_test");
    int64_t stake_amount = 5000;
    int64_t reward_amount = stake_amount * 96; // x100 for balance
    BOOST_CHECK_EQUAL(success(), token.create(_issuer, token.from_amount(1234567890)));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _alice, token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _bob,   token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _carol, token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _whale, token.from_amount(stake_amount), ""));
    
    BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, {30, 3, 2, 1}, 100500));
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _code, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), token.transfer(_bob,   _code, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), token.transfer(_carol, _code, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), token.transfer(_whale, _code, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_whale, token._symbol.to_symbol_code(), 3));
    BOOST_CHECK_EQUAL(success(), stake.setproxyfee(_whale, token._symbol.to_symbol_code(), 1000));
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_alice, _whale, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_bob,   _whale, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_carol, _whale, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), stake.setgrntterms(_bob,   _whale, token._symbol.to_symbol_code(), 0, 2000));
    BOOST_CHECK_EQUAL(success(), stake.setgrntterms(_carol, _whale, token._symbol.to_symbol_code(), 0, 3000));
    
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["balance"],   stake_amount * 4);
    BOOST_CHECK_EQUAL(success(), stake.reward(_issuer, _whale, token.from_amount(reward_amount)));
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["balance"],   stake_amount * 4 + reward_amount);
    
    BOOST_CHECK_EQUAL(success(), stake.setproxyfee(_whale, token._symbol.to_symbol_code(), 2500));
    produce_block();
    BOOST_CHECK_EQUAL(success(), stake.updatefunds(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.updatefunds(_bob,   token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.updatefunds(_carol, token._symbol.to_symbol_code()));
    
    auto acc_reward = reward_amount / 4;
    auto fee_paid = safe_pct<int64_t>(1000, acc_reward);
        
    BOOST_CHECK_CLOSE_FRACTION(double(stake.get_agent(_alice, token._symbol)["balance"].as<int64_t>()), 
        double(stake_amount + acc_reward - fee_paid), 0.0001);
    BOOST_CHECK_CLOSE_FRACTION(double(stake.get_agent(_bob,   token._symbol)["balance"].as<int64_t>()), 
        double(stake_amount + acc_reward - fee_paid), 0.0001);
    BOOST_CHECK_EQUAL(stake.get_agent(_carol, token._symbol)["balance"], 0);
    BOOST_CHECK_EQUAL(success(), stake.recallvote(_carol, _whale, token._symbol.to_symbol_code(), cfg::_100percent));
    BOOST_CHECK_CLOSE_FRACTION(double(stake.get_agent(_carol, token._symbol)["balance"].as<int64_t>()), 
        double(stake_amount + acc_reward - fee_paid), 0.0001);
    BOOST_CHECK_CLOSE_FRACTION(double(stake.get_agent(_whale, token._symbol)["balance"].as<int64_t>()), 
        double(stake_amount + acc_reward + (fee_paid * 3)), 0.0001);
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(fee_series_test, cyber_stake_tester) try {
    BOOST_TEST_MESSAGE("agent_updates/fee_series_test");
    int64_t stake_amount = 5000;
    int64_t reward_amount = stake_amount * 98; // x100 for balance
    int16_t fee_pct_b = 1000;
    int16_t fee_pct_c = 2500;
    BOOST_CHECK_EQUAL(success(), token.create(_issuer, token.from_amount(1234567890)));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _alice, token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _bob,   token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _carol, token.from_amount(stake_amount), ""));
    
    BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, {30, 3, 2, 1}, 100500));
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _code, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), token.transfer(_bob,   _code, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), token.transfer(_carol, _code, token.from_amount(stake_amount)));

    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_bob,   token._symbol.to_symbol_code(), 3));
    BOOST_CHECK_EQUAL(success(), stake.setproxyfee(_bob,   token._symbol.to_symbol_code(), fee_pct_b));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_carol, token._symbol.to_symbol_code(), 2));
    BOOST_CHECK_EQUAL(success(), stake.setproxyfee(_carol, token._symbol.to_symbol_code(), fee_pct_c));
    
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_alice, _bob,   token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_bob,   _carol, token.from_amount(stake_amount))); // half
    
    BOOST_CHECK_EQUAL(success(), stake.reward(_issuer, _carol, token.from_amount(reward_amount)));
    
    int64_t balance_a = 0;
    int64_t balance_b = stake_amount;
    int64_t balance_c = stake_amount * 2 + reward_amount;
    
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["balance"],   balance_a);
    BOOST_CHECK_EQUAL(stake.get_agent(_bob,   token._symbol)["balance"],   balance_b);
    BOOST_CHECK_EQUAL(stake.get_agent(_carol, token._symbol)["balance"],   balance_c);
    
    BOOST_CHECK_EQUAL(success(), stake.setproxyfee(_bob, token._symbol.to_symbol_code(), fee_pct_b + 1));
    produce_block();
    BOOST_CHECK_EQUAL(success(), stake.updatefunds(_alice, token._symbol.to_symbol_code()));

    int64_t fee_received_c = safe_pct<int64_t>(fee_pct_c, reward_amount / 2);
    
    int64_t recalled_b = (stake_amount + reward_amount / 2 - fee_received_c) / 2;
    int64_t proxied_b = recalled_b;
    int64_t reward_received_b = reward_amount / 2 - fee_received_c;
    int64_t reward_received_a = reward_received_b / 2;
    
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["balance"], stake_amount + reward_received_a);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["proxied"], 0);
    BOOST_CHECK_EQUAL(stake.get_agent(_bob,   token._symbol)["balance"], stake_amount / 2);
    BOOST_CHECK_EQUAL(stake.get_agent(_bob,   token._symbol)["proxied"], proxied_b);
    BOOST_CHECK_EQUAL(stake.get_agent(_carol, token._symbol)["balance"], stake_amount + reward_amount / 2 + fee_received_c + proxied_b);
    BOOST_CHECK_EQUAL(stake.get_agent(_carol, token._symbol)["proxied"], 0);
    
    BOOST_CHECK_EQUAL(
        stake.get_agent(_alice, token._symbol)["balance"] + 
        stake.get_agent(_bob,   token._symbol)["balance"] + 
        stake.get_agent(_carol, token._symbol)["balance"], 
        stake_amount * 3 + reward_amount);
    produce_block();
    
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(no_fee_test, cyber_stake_tester) try {
    BOOST_TEST_MESSAGE("agent_updates/no_fee_test");
    int64_t stake_amount = 5000;
    BOOST_CHECK_EQUAL(success(), token.create(_issuer, token.from_amount(1234567890)));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _alice, token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _bob,   token.from_amount(stake_amount), ""));
    
    BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, {30, 3, 2, 1}, 100500));
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _code, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), token.transfer(_bob,   _code, token.from_amount(stake_amount)));
    
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_bob, token._symbol.to_symbol_code(), 3));
    BOOST_CHECK_EQUAL(success(), stake.setproxyfee(_bob, token._symbol.to_symbol_code(), 1000));
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_alice, _bob, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["balance"], 0);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["proxied"], stake_amount);
    BOOST_CHECK_EQUAL(stake.get_agent(_bob,   token._symbol)["balance"], stake_amount * 2);
    BOOST_CHECK_EQUAL(success(), stake.setproxyfee(_bob, token._symbol.to_symbol_code(), 2000));
    produce_block();
    
    BOOST_CHECK_EQUAL(success(), stake.updatefunds(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["balance"], stake_amount);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice, token._symbol)["proxied"], 0);
    BOOST_CHECK_EQUAL(stake.get_agent(_bob,   token._symbol)["balance"], stake_amount);
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(min_staked_test, cyber_stake_tester) try {
    BOOST_TEST_MESSAGE("agent_updates/min_staked_test");
    int64_t initial_min_staked = 10;
    int64_t min_for_election = 1000;
    int64_t stake_amount = 5000;
    BOOST_CHECK_EQUAL(success(), token.create(_issuer, token.from_amount(100500)));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _alice, token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _bob,   token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _carol, token.from_amount(stake_amount), ""));
    BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, {30, 10, 3, 1}, 100500, min_for_election));
    int64_t alice_stake = min_for_election - 1;
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _code, token.from_amount(alice_stake)));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 2));
    
    BOOST_CHECK_EQUAL(err.min_staked_can_not_be_negative(), stake.setminstaked(_alice, token._symbol.to_symbol_code(), -1));
    BOOST_CHECK_EQUAL(success(), stake.setminstaked(_alice, token._symbol.to_symbol_code(), initial_min_staked));
    BOOST_CHECK_EQUAL(success(), token.transfer(_bob,   _code, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), token.transfer(_carol, _code, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_bob,   _alice, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_carol, _alice, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(stake.get_agent(_bob,   token._symbol)["proxied"], stake_amount);
    BOOST_CHECK_EQUAL(stake.get_agent(_carol, token._symbol)["proxied"], stake_amount);
    BOOST_CHECK_EQUAL(success(), stake.setgrntterms(_carol, _alice, token._symbol.to_symbol_code(), cfg::_100percent));
    BOOST_CHECK_EQUAL(success(), stake.setminstaked(_alice, token._symbol.to_symbol_code(), initial_min_staked - 1));
    produce_block();
    
    BOOST_CHECK_EQUAL(success(), stake.updatefunds(_bob, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.updatefunds(_carol, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(stake.get_agent(_bob,   token._symbol)["proxied"], 0);
    BOOST_CHECK_EQUAL(stake.get_agent(_bob,   token._symbol)["balance"], stake_amount);
    BOOST_CHECK_EQUAL(stake.get_agent(_carol, token._symbol)["proxied"], stake_amount);
    BOOST_CHECK_EQUAL(err.min_for_election_violated(), stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 0));
    BOOST_CHECK_EQUAL(success(), stake.setminstaked(_alice, token._symbol.to_symbol_code(), min_for_election));
    BOOST_CHECK_EQUAL(err.no_agent_funds(), stake.delegatevote(_bob, _alice, token.from_amount(stake_amount)));
    
    BOOST_CHECK_EQUAL(stake.get_agent(_alice,   token._symbol)["balance"], stake_amount + alice_stake);
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_carol, token._symbol.to_symbol_code(), 3));
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_bob, _carol, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(stake.get_agent(_carol, token._symbol)["proxied"], stake_amount * 2);
    BOOST_CHECK_EQUAL(stake.get_agent(_alice,   token._symbol)["balance"], stake_amount * 2 + alice_stake);
    BOOST_CHECK_EQUAL(success(), stake.recallvote(_bob, _carol, token._symbol.to_symbol_code(), cfg::_100percent));
    BOOST_CHECK_EQUAL(stake.get_agent(_alice,   token._symbol)["balance"], stake_amount + alice_stake);
     
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _code, token.from_amount(1)));
    BOOST_CHECK_EQUAL(success(), stake.delegatevote(_bob, _alice, token.from_amount(stake_amount)));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 0));
    BOOST_CHECK_EQUAL(err.min_for_election_violated(), stake.setminstaked(_alice, token._symbol.to_symbol_code(), min_for_election - 1));
    
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END() // agent_updates

BOOST_AUTO_TEST_SUITE(delegation)

BOOST_FIXTURE_TEST_CASE(_3x3_test, cyber_stake_tester) try {
    BOOST_TEST_MESSAGE("delegation/_3x3_test");
    size_t max_proxy_level = 2;
    uint8_t agents_on_level = 3;
    int64_t stake_amount = 65610000;
    std::vector<int64_t> stake_amounts(max_proxy_level + 1, 0);
    stake_amounts.back() = stake_amount;
    
    BOOST_CHECK_EQUAL(success(), token.create(_issuer, token.from_amount(1000 * stake_amount * (max_proxy_level + 1) * agents_on_level)));
    BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, {agents_on_level, agents_on_level}, 1));
    auto agents = create_agents(max_proxy_level, agents_on_level, stake_amounts);
    
    int64_t fee = 6500;
    for (auto& acc : agents[0]) {
        BOOST_CHECK_EQUAL(success(), stake.setproxyfee(acc, token._symbol.to_symbol_code(), fee));
        fee += 1000;
    }
    
    for (size_t grantor_level = max_proxy_level; grantor_level >= 1; grantor_level--) {
        BOOST_TEST_MESSAGE("delegate for grantor_level = " << grantor_level);
        for (size_t g = 0; g < agents_on_level; g++) {
            for (size_t a = 0; a < agents_on_level; a++) {
                BOOST_CHECK_EQUAL(success(), stake.delegatevote(agents[grantor_level][g], agents[grantor_level - 1][a], token.from_amount(stake_amount / agents_on_level)));
            }
        }
    }
    
    auto grantor_level = max_proxy_level;
    int64_t reward_amount = stake_amount;
    
    for (size_t a = 0; a < agents_on_level; a++) {
        BOOST_CHECK_EQUAL(success(), stake.reward(_issuer, agents[0][a], token.from_amount(reward_amount)));
    }
    
    for (size_t g = 0; g < agents_on_level; g++) {
        for (size_t a = 0; a < agents_on_level; a++) {
            BOOST_CHECK_EQUAL(success(), stake.recallvote(agents[grantor_level][g], agents[grantor_level - 1][a], token._symbol.to_symbol_code(), cfg::_100percent));
        }
        BOOST_CHECK_EQUAL(success(), stake.updatefunds(agents[grantor_level][g], token._symbol.to_symbol_code()));
        BOOST_CHECK_EQUAL(stake.get_agent(agents[grantor_level][0], token._symbol)["proxied"], 0);
        BOOST_CHECK_EQUAL(stake.get_agent(agents[grantor_level][0], token._symbol)["balance"], stake_amount + (reward_amount / 4));

    }

    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(fuzz_test, cyber_stake_tester) try {
    BOOST_TEST_MESSAGE("delegation/fuzz_test");
    size_t max_proxy_level = 3;
    uint8_t agents_on_level = 5;
    int64_t stake_amount = 50000;
    auto total_staked = 0;
    
    BOOST_CHECK_EQUAL(success(), token.create(_issuer, token.from_amount(1000 * stake_amount * (max_proxy_level + 1) * agents_on_level)));
    BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, {agents_on_level, agents_on_level, agents_on_level, agents_on_level}, 1));
    auto agents = create_agents(max_proxy_level, agents_on_level, stake_amount);
    std::srand(0);
    total_staked += stake_amount * (max_proxy_level + 1) * agents_on_level;
    stake.set_verbose(false);
    for (size_t step = 0; step < 1000; step++) {
        //BOOST_TEST_MESSAGE("step = " << step);
        if (std::rand() % 100 == 0) {
            auto q = token.from_amount(1 + std::rand() % (stake_amount - 1));
            total_staked += q.get_amount();
            BOOST_CHECK_EQUAL(success(), stake.reward(_issuer, agents[0][std::rand() % agents_on_level], q));
        }
        if (std::rand() % 30 == 0) {
            BOOST_CHECK_EQUAL(success(), stake.setproxyfee(
                agents[std::rand() % max_proxy_level][std::rand() % agents_on_level], 
                token._symbol.to_symbol_code(), 
                std::rand() % (cfg::_100percent + 1)));
        } 
        auto grantor_level = std::rand() % max_proxy_level + 1;
        auto grantor = agents[grantor_level][std::rand() % agents_on_level];
        auto agent = agents[grantor_level - 1][std::rand() % agents_on_level];
        
        produce_block();
        BOOST_CHECK_EQUAL(success(), stake.updatefunds(grantor, token._symbol.to_symbol_code()));
        BOOST_CHECK_EQUAL(success(), stake.updatefunds(agent, token._symbol.to_symbol_code()));
        produce_block();
        
        double grantor_balance_pre = stake.get_agent(grantor, token._symbol)["balance"].as<int64_t>();
        double grantor_proxied_pre = stake.get_agent(grantor, token._symbol)["proxied"].as<int64_t>();
        double agent_total_pre = stake.get_agent(agent, token._symbol)["balance"].as<int64_t>() 
                + stake.get_agent(agent, token._symbol)["proxied"].as<int64_t>();
                
        //BOOST_TEST_MESSAGE("grantor balance = " << stake.get_agent(grantor, token._symbol)["balance"].as<int64_t>());
        //BOOST_TEST_MESSAGE("grantor proxied = " << stake.get_agent(grantor, token._symbol)["proxied"].as<int64_t>());
        //BOOST_TEST_MESSAGE("agent balance = " << stake.get_agent(agent, token._symbol)["balance"].as<int64_t>());
        //BOOST_TEST_MESSAGE("agent proxied = " << stake.get_agent(agent, token._symbol)["proxied"].as<int64_t>());
             
        auto q = token.from_amount(std::min<double>(grantor_balance_pre, 1 + std::rand() % (stake_amount - 1)));
        bool can_delegate = grantor_balance_pre && q.get_amount() <= grantor_balance_pre;
        bool can_recall = false;
        if (can_delegate) {
            BOOST_CHECK_EQUAL(success(), stake.delegatevote(grantor, agent, q));
        }
        else {
            auto res = stake.recallvote(grantor, agent, token._symbol.to_symbol_code(), std::min(std::rand() % 11000, 10000));
            if(success() != res) {
                //BOOST_REQUIRE_MESSAGE(!err.is_system_err_mssg(res), res);
            }
            else {
                can_recall = true;
            }
        }

        produce_block();
        BOOST_CHECK_EQUAL(success(), stake.updatefunds(grantor, token._symbol.to_symbol_code()));
        BOOST_CHECK_EQUAL(success(), stake.updatefunds(agent, token._symbol.to_symbol_code()));
        
        double grantor_balance_res = stake.get_agent(grantor, token._symbol)["balance"].as<int64_t>();
        double grantor_proxied_res = stake.get_agent(grantor, token._symbol)["proxied"].as<int64_t>();
        double agent_total_res = stake.get_agent(agent, token._symbol)["balance"].as<int64_t>() 
            + stake.get_agent(agent, token._symbol)["proxied"].as<int64_t>();
            
        //BOOST_TEST_MESSAGE("grantor balance = " << stake.get_agent(grantor, token._symbol)["balance"].as<int64_t>());
        //BOOST_TEST_MESSAGE("grantor proxied = " << stake.get_agent(grantor, token._symbol)["proxied"].as<int64_t>());
        //BOOST_TEST_MESSAGE("agent balance = " << stake.get_agent(agent, token._symbol)["balance"].as<int64_t>());
        //BOOST_TEST_MESSAGE("agent proxied = " << stake.get_agent(agent, token._symbol)["proxied"].as<int64_t>());
        
        if (can_delegate) {
            BOOST_CHECK_SMALL(double(grantor_balance_pre - grantor_balance_res - q.get_amount()), 2.0);
            BOOST_CHECK_SMALL(double(grantor_proxied_res - grantor_proxied_pre - q.get_amount()), 2.0);
            BOOST_CHECK_SMALL(double(agent_total_res - agent_total_pre - q.get_amount()), 2.0);
        }
        else if (can_recall) {
            auto fee_amount = (grantor_proxied_pre - grantor_proxied_res) - (grantor_balance_res - grantor_balance_pre);
            BOOST_CHECK(fee_amount >= 0);
        }
        
        auto actual_total_staked = 0;
        if (std::rand() % 10 == 0) {
            produce_block();
            BOOST_TEST_MESSAGE("--- balance check, step = " << step);
            for (auto& level : agents) {
                for (auto acc : level) {
                    BOOST_CHECK_EQUAL(success(), stake.updatefunds(acc, token._symbol.to_symbol_code()));
                }
            }
            //BOOST_TEST_MESSAGE("--- funds updated");
            for (auto& level : agents) {
                for (auto acc : level) {
                    actual_total_staked += stake.get_agent(acc, token._symbol)["balance"].as<int64_t>();
                }
            }
            BOOST_CHECK_EQUAL(actual_total_staked, total_staked);
            //BOOST_TEST_MESSAGE("---      ========= done");
        }
    }
    
    produce_block();
} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END() // delegation

BOOST_AUTO_TEST_SUITE_END() // cyber_stake_tests

BOOST_AUTO_TEST_SUITE(cyber_stake_tests_ext, * boost::unit_test::disabled()) 
BOOST_FIXTURE_TEST_CASE(recursive_update_test, cyber_stake_tester) try {
    BOOST_TEST_MESSAGE("Recursive update test");
    
    std::vector<uint8_t> max_proxies = {50, 20, 5, 1};
    int64_t frame_length = 30;
    asset staked(10000000, token._symbol);
    double reward_factor = 0.1;
    
    BOOST_CHECK_EQUAL(success(), token.create(_issuer, asset(1000000000, token._symbol)));
    BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, max_proxies, 30 * 24 * 60 * 60));

    uint8_t level = 0;
    size_t u = 0;
    account_name user;
    std::vector<account_name> prev_level_accs;
    std::vector<account_name> bp_accs;
    while (level <= max_proxies.size()) {
        std::vector<account_name> cur_level_accs;
        for (size_t i = 0; i < max_proxies[std::min(static_cast<size_t>(level), max_proxies.size() - 1)]; i++) {
            user = user_name(u++);
            cur_level_accs.emplace_back(user);
            create_accounts({user});
            BOOST_CHECK_EQUAL(success(), token.issue(_issuer, user, staked, ""));
            BOOST_CHECK_EQUAL(success(), stake.open(user, token._symbol.to_symbol_code()));
            if (level != max_proxies.size()) {
                BOOST_CHECK_EQUAL(success(), stake.setproxylvl(user, token._symbol.to_symbol_code(), level));
            }
            for (auto proxy : prev_level_accs) {
                int16_t pct = (1.0 / prev_level_accs.size()) * cfg::_100percent;
                BOOST_TEST_MESSAGE("--- setgrntterms pct: " << pct << " " << user << " -> " << proxy);
                BOOST_CHECK_EQUAL(success(), stake.setgrntterms(user, proxy, token._symbol.to_symbol_code(), pct));
            }
            BOOST_CHECK_EQUAL(success(), token.transfer(user, _code, staked));
            if(u % 20 == 0)
                produce_block();
        }
        prev_level_accs = cur_level_accs;
        if(!level)
            bp_accs = cur_level_accs;
        cur_level_accs.clear();
        ++level;
    }
    auto total_amount = staked.get_amount() * u; 
    auto bp_amount = total_amount / bp_accs.size();
    BOOST_TEST_MESSAGE("--- total_amount = " << total_amount);
    BOOST_TEST_MESSAGE("--- bp_amount = " << bp_amount);
    for (auto bp : bp_accs) {
        BOOST_CHECK_EQUAL(success(), stake.reward(_issuer, bp, asset(bp_amount * reward_factor, token._symbol)));
    }
    
    produce_block();
    auto t = head_block_time();
    BOOST_CHECK_EQUAL(stake.get_agent(user, token._symbol),
        stake.make_agent(user, token._symbol, max_proxies.size(), t, 0,
        staked.get_amount(), staked.get_amount(), staked.get_amount()));
    
    produce_blocks(frame_length * 1000 / cfg::block_interval_ms);
    BOOST_CHECK_EQUAL(success(), stake.updatefunds(user, token._symbol.to_symbol_code()));
    produce_block();
    t = head_block_time();
    BOOST_CHECK_EQUAL(stake.get_agent(user, token._symbol),
        stake.make_agent(user, token._symbol, max_proxies.size(), t, 0,
        staked.get_amount() * (1.0 + reward_factor), staked.get_amount(), staked.get_amount()));

    produce_block();
} FC_LOG_AND_RETHROW()
BOOST_AUTO_TEST_SUITE_END()
