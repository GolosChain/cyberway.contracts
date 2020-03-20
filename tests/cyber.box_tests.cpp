#include "golos_tester.hpp"
#include "cyber.token_test_api.hpp"
#include "cyber.stake_test_api.hpp"
#include "cyber.box_test_api.hpp"
#include "contracts.hpp"

namespace cfg = cyber::config;
using eosio::chain::config::stake_account_name;
using cfg::box_name;
using namespace eosio::testing;
using namespace eosio::chain;
using namespace eosio::chain::int_arithmetic;
using namespace fc;

class cyber_box_tester : public golos_tester {
protected:
    cyber_token_api token;
    cyber_stake_api stake;
    cyber_box_api   box;

public:
    cyber_box_tester()
        : golos_tester(box_name, false)
        , token({this, cfg::token_name, cfg::system_token})
        , stake({this, stake_account_name})
        , box({this, _code})
    {
        create_accounts({_alice, _bob, _carol, _whale, cfg::token_name, box_name});
        produce_block();
        install_contract(cfg::token_name, contracts::token_wasm(), contracts::token_abi());
        install_contract(stake_account_name, contracts::stake_wasm(), contracts::stake_abi());
        install_contract(box_name, contracts::box_wasm(), contracts::box_abi());
    }

    const account_name _issuer = cyber::config::internal_name;
    const account_name _alice = N(alice);
    const account_name _bob = N(bob);
    const account_name _carol = N(carol);
    const account_name _whale = N(whale);

    struct errors: contract_error_messages {
        const string no_staking = amsg("no staking for token");
        const string no_box = amsg("box does not exist");
        const string box_already_exists  = amsg("such a box already exists");
        const string not_empty  = amsg("the box is not empty");
        const string not_enough = amsg("not enough staked tokens");
        
        const string non_unique = amsg("non-unique title");
        
        const string empty_transfer = amsg("cannot transfer an empty box");
        const string empty_unpack = amsg("cannot unpack an empty box");
        const string self_transfer  = amsg("cannot transfer to self");
        const string no_to_acc = amsg("to account does not exist");
        
        const string no_balance = amsg("owner balance does not exist");
        const string not_owner = amsg("only the owner can do it");
        const string owner_not_specified = amsg("owner not specified");
        const string incorrect_owner = amsg("incorrect owner");
        
        string missing_authority(name acc) { return "missing authority of " + std::string(acc); };

    } err;
};

BOOST_AUTO_TEST_SUITE(cyber_box_tests)
BOOST_FIXTURE_TEST_CASE(stake_in_box_tests, cyber_box_tester) try {
    BOOST_TEST_MESSAGE("stake_in_box_tests");
    
    std::map<name, int64_t> votes;
    votes[_alice] = 0;
    votes[_bob  ] = 0;
    votes[_carol] = 0;
    int64_t balance = 7;
    int64_t provided = 87654321;
    auto staked = balance;
    int64_t cur_vote = 25;
    int64_t vote_step = 10000;
    
    auto alice_box = balance;
    auto bob_box   = cur_vote / 10;
    auto carol_box = (vote_step * cur_vote) + cur_vote - bob_box;
    auto whale_box = 7654321;
    
    for (auto& v : votes) {
        v.second = cur_vote;
        staked += cur_vote;
        cur_vote *= vote_step;
    }
    
    BOOST_CHECK_EQUAL(success(), token.create(_issuer, asset(std::numeric_limits<int64_t>::max() / 10, token._symbol)));
    
    BOOST_CHECK_EQUAL(err.no_staking, stake.constrain(_whale, N(whalebox), asset(whale_box, token._symbol)));
    
    BOOST_CHECK_EQUAL(success(), stake.create(_issuer, token._symbol, std::vector<uint8_t>{3}, 30 * 24 * 60 * 60));
    
    BOOST_CHECK_EQUAL(success(), stake.open(_alice, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.open(_bob,   token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.open(_carol, token._symbol.to_symbol_code()));
    BOOST_CHECK_EQUAL(success(), stake.open(_whale, token._symbol.to_symbol_code()));
    
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_alice, token._symbol.to_symbol_code(), 0));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_bob,   token._symbol.to_symbol_code(), 0));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(_carol, token._symbol.to_symbol_code(), 0));
    
    BOOST_CHECK_EQUAL(success(), token.issue(_issuer, _whale, asset(staked, token._symbol), ""));
    
    BOOST_CHECK_EQUAL(err.not_enough, stake.constrain(_whale, N(whalebox), asset(staked, token._symbol)));
    produce_block();
    BOOST_CHECK_EQUAL(success(), token.transfer(_whale, stake_account_name, asset(staked, token._symbol)));
    BOOST_CHECK_EQUAL(err.no_box, stake.constrain(_whale, N(whalebox), asset(staked, token._symbol)));
    
    BOOST_CHECK_EQUAL(success(), box.create(stake_account_name, _whale, N(whalebox)));
    produce_block();
    
    BOOST_CHECK_EQUAL(err.box_already_exists, box.create(stake_account_name, _whale, N(whalebox)));
    BOOST_CHECK_EQUAL(success(), stake.constrain(_whale, N(whalebox), asset(staked, token._symbol)));
    BOOST_CHECK_EQUAL(err.not_enough, stake.constrain(_whale, N(whalebox), asset(1, token._symbol)));
    BOOST_CHECK_EQUAL(err.not_empty, box.packup(stake_account_name, _whale, N(whalebox)));
    produce_block();
    BOOST_CHECK_EQUAL(err.box_already_exists, box.create(stake_account_name, _whale, N(whalebox)));
    
    BOOST_CHECK_EQUAL(err.no_box, box.burn(stake_account_name, _whale, N(whalefox), _whale));
    BOOST_CHECK_EQUAL(err.no_box, box.unpack(stake_account_name, _whale, N(whalefox), _whale, _whale));
    
    BOOST_CHECK_EQUAL(err.missing_authority(_whale), box.unpack(stake_account_name, _whale, N(whalebox), _whale, _alice));
    BOOST_CHECK_EQUAL(err.incorrect_owner, box.unpack(stake_account_name, _whale, N(whalebox), _alice, _whale));
    BOOST_CHECK_EQUAL(success(), box.unpack(stake_account_name, _whale, N(whalebox), _whale, _whale));
    
    produce_block();
    BOOST_CHECK_EQUAL(success(), stake.delegateuse(_whale, _alice, token.from_amount(provided)));
    BOOST_CHECK_EQUAL(err.not_enough, stake.constrain(_whale, N(whalebox), asset(staked, token._symbol)));
    BOOST_CHECK_EQUAL(err.not_enough, stake.constrain(_whale, N(whalebox), asset(staked - provided + 1, token._symbol)));
    BOOST_CHECK_EQUAL(err.no_box, stake.constrain(_whale, N(whalebox), asset(staked - provided, token._symbol)));
    
    for (const auto& v : votes) {
        BOOST_CHECK_EQUAL(success(), stake.delegatevote(_whale, v.first, asset(v.second, token._symbol)));
    }
    
    BOOST_CHECK_EQUAL(err.no_box, box.transfer(stake_account_name, _whale, N(alicebox), _whale, _alice, "", _whale));
    
    BOOST_CHECK_EQUAL(success(), box.create(stake_account_name, _whale, N(alicebox)));
    BOOST_CHECK_EQUAL(success(), box.create(stake_account_name, _whale, N(bobbox)));
    BOOST_CHECK_EQUAL(success(), box.create(stake_account_name, _whale, N(carolbox)));
    BOOST_CHECK_EQUAL(success(), box.create(stake_account_name, _whale, N(whalebox)));
    
    BOOST_CHECK_EQUAL(err.empty_transfer, box.transfer(stake_account_name, _whale, N(alicebox), _whale, _alice, "", _whale));
    BOOST_CHECK_EQUAL(err.empty_unpack, box.unpack(stake_account_name, _whale, N(alicebox), _whale, _whale));
    
    BOOST_CHECK_EQUAL(success(), stake.constrain(_whale, N(alicebox), asset(alice_box, token._symbol)));
    BOOST_CHECK_EQUAL(success(), stake.constrain(_whale, N(bobbox),   asset(bob_box,   token._symbol)));
    BOOST_CHECK_EQUAL(success(), stake.constrain(_whale, N(carolbox), asset(carol_box, token._symbol)));
    BOOST_CHECK_EQUAL(success(), stake.constrain(_whale, N(whalebox), asset(whale_box, token._symbol)));
    
    produce_block();
    BOOST_CHECK_EQUAL(err.non_unique, stake.constrain(_whale, N(alicebox), asset(alice_box, token._symbol)));
    
    BOOST_CHECK_EQUAL(err.no_to_acc, box.transfer(stake_account_name, _whale, N(alicebox), _whale, N(leprechaun), "", _whale));
    
    BOOST_CHECK_EQUAL(success(), box.transfer(stake_account_name, _whale, N(alicebox), _whale, _bob, "give it to alice", _whale));
    
    BOOST_CHECK_EQUAL(err.missing_authority(_bob), box.transfer(stake_account_name, _whale, N(alicebox), _bob, _alice, "", _whale));
    BOOST_CHECK_EQUAL(err.not_owner, box.transfer(stake_account_name, _whale, N(alicebox), _whale, _alice, "", _whale));

    BOOST_CHECK_EQUAL(success(), box.transfer(stake_account_name, _whale, N(alicebox), _bob, _alice, "", _bob));
    
    BOOST_CHECK_EQUAL(success(), box.transfer(stake_account_name, _whale, N(bobbox),   _whale, _bob, "", _whale));
    BOOST_CHECK_EQUAL(success(), box.transfer(stake_account_name, _whale, N(carolbox), _whale, _carol, "", _whale));
    BOOST_CHECK_EQUAL(err.self_transfer, box.transfer(stake_account_name, _whale, N(whalebox), _whale, _whale, "", _whale));
    
    BOOST_CHECK_EQUAL(err.missing_authority(_alice), box.unpack(stake_account_name, _whale, N(alicebox), _alice, _whale));
    
    BOOST_CHECK_EQUAL(err.no_balance, box.unpack(stake_account_name, _whale, N(alicebox), _alice, _alice));
    
    BOOST_CHECK_EQUAL(success(), token.open(_alice, token._symbol, _alice));
    BOOST_CHECK_EQUAL(success(), token.open(_bob,   token._symbol, _bob));
    BOOST_CHECK_EQUAL(success(), token.open(_carol, token._symbol, _carol));
    
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["balance"], balance);
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["proxied"], staked - balance);
    
    BOOST_CHECK_EQUAL(success(), box.unpack(stake_account_name, _whale, N(alicebox), _alice, _alice));
    
    BOOST_CHECK_EQUAL(alice_box, token.get_account(_alice)["balance"].as<asset>().get_amount());
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["balance"], 0);
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["proxied"], staked - alice_box);
    
    BOOST_CHECK_EQUAL(success(), box.unpack(stake_account_name, _whale, N(bobbox), _bob, _bob));
    BOOST_CHECK_EQUAL(bob_box, token.get_account(_bob)["balance"].as<asset>().get_amount());
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["balance"], 0);
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["proxied"], staked - alice_box - bob_box);
    
    BOOST_CHECK_EQUAL(err.owner_not_specified, box.unpack(stake_account_name, _whale, N(whalebox), name(), _whale));
    BOOST_CHECK_EQUAL(success(), box.unpack(stake_account_name, _whale, N(whalebox), _whale, _whale));
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["balance"], 0);
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["proxied"], staked - alice_box - bob_box);
    
    BOOST_CHECK_EQUAL(err.no_balance, box.burn(stake_account_name, _whale, N(carolbox), _carol));
    BOOST_CHECK_EQUAL(success(), token.open(cfg::null_name, token._symbol, _carol));
    BOOST_CHECK_EQUAL(success(), box.burn(stake_account_name, _whale, N(carolbox), _carol));
    BOOST_CHECK_EQUAL(0, token.get_account(_carol)["balance"].as<asset>().get_amount());
    BOOST_CHECK_EQUAL(carol_box, token.get_account(cfg::null_name)["balance"].as<asset>().get_amount());
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["balance"], 0);
    BOOST_CHECK_EQUAL(stake.get_agent(_whale, token._symbol)["proxied"], staked - alice_box - bob_box - carol_box);

} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END()
