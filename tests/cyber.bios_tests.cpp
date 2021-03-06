#include "golos_tester.hpp"
#include "cyber.token_test_api.hpp"
#include "cyber.stake_test_api.hpp"
#include "cyber.govern_test_api.hpp"
#include "test_api_helper.hpp"
#include "contracts.hpp"
#include "../cyber.bios/include/cyber.bios/config.hpp"


namespace cfg = cyber::config;
using namespace eosio::testing;
using namespace eosio::chain;
using eosio::chain::config::govern_account_name;
using namespace fc;
static const auto _token = cfg::system_token;

class cyber_bios_tester : public golos_tester {
protected:
    cyber_token_api token;
    cyber_stake_api stake;
    cyber_govern_api govern;

public:
   cyber_bios_tester()
       : golos_tester(config::system_account_name, false)
       , token({this, config::token_account_name, _token})
       , stake({this, config::stake_account_name})
       , govern({this, config::govern_account_name})
   {
       create_accounts({cfg::token_name, cfg::names_name});
       produce_block();

       install_contract(config::stake_account_name, contracts::stake_wasm(), contracts::stake_abi());
       install_contract(config::token_account_name, contracts::token_wasm(), contracts::token_abi());

       deploy_sys_contracts();
   }

   void deploy_sys_contracts(int64_t max_supply_amount = -1) {
       if (max_supply_amount < 0) {
           max_supply_amount = 10000000000000;
       }

       BOOST_TEST_MESSAGE("--- creating token and stake");
       BOOST_CHECK_EQUAL(success(), token.create(config::system_account_name, asset(max_supply_amount, token._symbol)));
       BOOST_CHECK_EQUAL(success(), token.issue(config::system_account_name, config::system_account_name, token.from_amount(10000000000000), ""));
       BOOST_CHECK_EQUAL(success(), token.open(cfg::names_name, token._symbol, cfg::names_name));
       BOOST_CHECK_EQUAL(success(), stake.create(config::system_account_name, token._symbol,
           std::vector<uint8_t>{30, 10, 3, 1}, 30 * 24 * 60 * 60));

       BOOST_TEST_MESSAGE("--- installing governance contract");
       install_contract(govern_account_name, contracts::govern_wasm(), contracts::govern_abi());
       BOOST_TEST_MESSAGE("--- installing bios contract");
       //sys token and stake must already exist at this moment
       install_contract(config::system_account_name, contracts::bios_wasm(), contracts::bios_abi());
       produce_block();
       BOOST_TEST_MESSAGE("    ...done");
   }

   action_result bidname(account_name bidder, account_name newname, asset bid) {
       return push_action(_code, N(bidname), bidder, mvo()
                          ("bidder", bidder)
                          ("newname", newname)
                          ("bid", bid));
   }

   action_result bidrefund(account_name bidder, account_name refunder = account_name()) {
       if (!refunder) {
          refunder = bidder;
       }
       return push_action(_code, N(bidrefund), refunder, mvo()
                          ("bidder", bidder));
   }

   action_result checkwin(account_name checker) {
       return push_action(_code, N(checkwin), checker, mvo());
   }

   void create_accounts_with_resources( vector<account_name> accounts, account_name creator = config::system_account_name ) {
      for( auto a : accounts ) {
         create_account_with_resources( a, creator );
      }
   }

   transaction_trace_ptr create_account_with_resources( account_name a, account_name creator, uint32_t ram_bytes = 8000, asset net = asset(100000, _token), asset cpu = asset(100000, _token) ) {
      signed_transaction trx;
      set_transaction_headers(trx);

      authority owner_auth =  authority( get_public_key( a, "owner" ) );
      trx.actions.emplace_back( vector<permission_level>{{creator,config::active_name}},
                                newaccount{
                                   .creator  = creator,
                                   .name     = a,
                                   .owner    = owner_auth,
                                   .active   = authority( get_public_key( a, "active" ) )
                                });

      set_transaction_headers(trx);
      trx.sign( get_private_key( creator, "active" ), control->get_chain_id()  );
      return push_transaction( trx );
   }
};

BOOST_AUTO_TEST_SUITE(cyber_bios_tests)

BOOST_FIXTURE_TEST_CASE( buyname, cyber_bios_tester ) try {
   BOOST_TEST_MESSAGE("Testing generic buying name");

   create_accounts({ N(dan), N(sam) });

   BOOST_CHECK_EQUAL(success(), token.open(N(dan), token._symbol, N(dan)));
   BOOST_CHECK_EQUAL(success(), token.open(N(sam), token._symbol, N(sam)));

   BOOST_CHECK_EQUAL(success(), token.transfer(config::system_account_name, N(dan), token.from_amount(1000000), ""));
   BOOST_CHECK_EQUAL(success(), token.transfer(config::system_account_name, N(sam), token.from_amount(1000000), ""));

   BOOST_CHECK_EQUAL(success(), stake.open(config::system_account_name, _token.to_symbol_code(), config::system_account_name));
   BOOST_CHECK_EQUAL(success(), stake.open(N(dan), _token.to_symbol_code(), N(dan)));
   BOOST_CHECK_EQUAL(success(), stake.open(N(sam), _token.to_symbol_code(), N(sam)));

   BOOST_CHECK_EQUAL(success(), token.transfer(config::system_account_name, config::stake_account_name, token.from_amount(160000000)));
   BOOST_CHECK_EQUAL(success(), token.transfer(N(dan), config::stake_account_name, token.from_amount(10000)));
   BOOST_CHECK_EQUAL(success(), token.transfer(N(sam), config::stake_account_name, token.from_amount(10000)));

   BOOST_CHECK_EQUAL(success(), stake.setproxylvl(config::system_account_name, token._symbol.to_symbol_code(), 1));
   BOOST_CHECK_EQUAL(success(), stake.setproxylvl(N(dan), token._symbol.to_symbol_code(), 0));
   BOOST_CHECK_EQUAL(success(), stake.setproxylvl(N(sam), token._symbol.to_symbol_code(), 0));

   BOOST_CHECK_EQUAL(success(), stake.delegatevote(config::system_account_name, N(dan), token.from_amount(10000000)));
   BOOST_CHECK_EQUAL(success(), stake.delegatevote(config::system_account_name, N(sam), token.from_amount(10000000)));

   produce_block();
   produce_block(fc::days(14));

   BOOST_REQUIRE_EXCEPTION( create_accounts_with_resources( { N(fail) }, N(dan) ),
                            eosio_assert_message_exception, eosio_assert_message_is( "no active bid for name" ) );


   const asset names_balance = token.get_account(config::names_account_name).get_object()["balance"].as<asset>();
   const asset dan_balance = token.get_account(N(dan)).get_object()["balance"].as<asset>();
   BOOST_REQUIRE_EQUAL( success(), bidname( N(dan), N(nofail), token.from_amount(10000) ) );
   BOOST_REQUIRE_EQUAL(dan_balance - token.from_amount(10000), token.get_account(N(dan)).get_object()["balance"].as<asset>());
   BOOST_REQUIRE_EQUAL(names_balance + token.from_amount(10000), token.get_account(config::names_account_name).get_object()["balance"].as<asset>());

   BOOST_REQUIRE_EQUAL( "assertion failure with message: must increase bid by 10%", bidname( N(sam), N(nofail), token.from_amount(10000) )); // didn't increase bid by 10%
   BOOST_REQUIRE_EQUAL( success(), bidname( N(sam), N(nofail), token.from_amount(20000) )); // didn't increase bid by 10%
   produce_block();
   produce_block( fc::days(1) );
   BOOST_REQUIRE_EQUAL( success(), checkwin(N(sam)));

   BOOST_REQUIRE_EXCEPTION( create_accounts_with_resources( { N(nofail) }, N(dan) ),
                            eosio_assert_message_exception, eosio_assert_message_is( "only highest bidder can claim" ) );
   create_accounts_with_resources( { N(nofail) }, N(sam) );
   BOOST_REQUIRE_EQUAL( success(), token.transfer(config::system_account_name, N(nofail), token.from_amount(10000000)));

   BOOST_TEST_MESSAGE("Testing creating subname accounts");
   create_accounts_with_resources( { N(nofail.sub) }, N(nofail) );
   BOOST_REQUIRE_EXCEPTION( create_accounts_with_resources( { N(fail.test) }, N(dan) ),
                            eosio_assert_message_exception, eosio_assert_message_is( "only prefix may create this account" ) );

   create_accounts_with_resources( { N(nofail.s.s) }, N(nofail) );
   //create_accounts_with_resources( { N(nofail.890123) }, N(nofail) );
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( bid_refunding, cyber_bios_tester ) try {
   BOOST_TEST_MESSAGE("Testing refunding bid");

   create_accounts({ N(alice), N(bob), N(carl) });

   BOOST_CHECK_EQUAL(success(), token.open(N(alice), token._symbol, N(alice)));
   BOOST_CHECK_EQUAL(success(), token.open(N(bob), token._symbol, N(bob)));
   BOOST_CHECK_EQUAL(success(), token.open(N(carl), token._symbol, N(carl)));

   BOOST_CHECK_EQUAL(success(), token.transfer(config::system_account_name, N(alice), token.from_amount(100000), ""));
   BOOST_CHECK_EQUAL(success(), token.transfer(config::system_account_name, N(bob), token.from_amount(100000), ""));
   BOOST_CHECK_EQUAL(success(), token.transfer(config::system_account_name, N(carl), token.from_amount(100000), ""));

   const asset names_balance = token.get_account(config::names_account_name).get_object()["balance"].as<asset>();
   const asset alice_balance = token.get_account(N(alice)).get_object()["balance"].as<asset>();

   BOOST_TEST_MESSAGE("-- Checking cannot refund without outbidding");

   BOOST_REQUIRE_EQUAL( success(), bidname(N(alice), N(nofail), token.from_amount(10000)) );
   produce_block();
   BOOST_REQUIRE_EQUAL( wasm_assert_msg("Nothing to refund"), bidrefund(N(alice)) );

   BOOST_TEST_MESSAGE("-- Checking normal refund");

   BOOST_REQUIRE_EQUAL( success(), bidname(N(bob), N(nofail), token.from_amount(20000)) );
   produce_block();
   BOOST_REQUIRE_EQUAL( success(), bidrefund(N(alice)) );
   produce_block();

   BOOST_REQUIRE_EQUAL(names_balance + token.from_amount(20000), token.get_account(config::names_account_name).get_object()["balance"].as<asset>());
   BOOST_REQUIRE_EQUAL(alice_balance, token.get_account(N(alice)).get_object()["balance"].as<asset>());

   BOOST_TEST_MESSAGE("-- Checking cannot refund twice");

   BOOST_REQUIRE_EQUAL( wasm_assert_msg("Nothing to refund"), bidrefund(N(alice)) );

   BOOST_TEST_MESSAGE("-- Checking another person can refund outbidded bid");
   BOOST_TEST_MESSAGE("-- Checking can refund accumulated bid");

   BOOST_REQUIRE_EQUAL( success(), bidname(N(carl), N(nofail), token.from_amount(30000)) );
   produce_block();
   BOOST_REQUIRE_EQUAL( success(), bidname(N(alice), N(nofail), token.from_amount(40000)) );
   produce_block();
   BOOST_REQUIRE_EQUAL( success(), bidname(N(carl), N(nofail), token.from_amount(50000)) );
   produce_block();
   BOOST_REQUIRE_EQUAL( success(), bidname(N(alice), N(nofail), token.from_amount(60000)) );
   produce_block();
   BOOST_REQUIRE_EQUAL( success(), bidrefund(N(alice), N(carl)) );
   produce_block();

   BOOST_TEST_MESSAGE("-- Checking refunding checks winner");

   produce_block( fc::days(1) );
   BOOST_REQUIRE_EQUAL( success(), bidrefund(N(carl)) );
   produce_block();
   create_accounts_with_resources({ N(nofail) }, N(alice));
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( bid_invalid_names, cyber_bios_tester ) try {
   BOOST_TEST_MESSAGE("Testing bidding invalid names");

   create_accounts( { N(dan) } );

   BOOST_REQUIRE_EQUAL( wasm_assert_msg( "you can only bid on top-level prefix" ),
                        bidname( N(dan), N(abcdefg.123456), token.from_amount(10000) ) );

   BOOST_REQUIRE_EQUAL( wasm_assert_msg( "the empty name is not a valid account name to bid on" ),
                        bidname( N(dan), N(), token.from_amount(1) ) );

   BOOST_REQUIRE_EQUAL( wasm_assert_msg( "13 character names are not valid account names to bid on" ),
                        bidname( N(dan), N(abcdefgh12345), token.from_amount(1) ) );

   BOOST_REQUIRE_EQUAL( wasm_assert_msg( "accounts with 12 character names without dots can be created without bidding required" ),
                        bidname( N(dan), N(abcdefg12345), token.from_amount(1) ) );

   BOOST_TEST_MESSAGE("Testing creating 12-character account without bidding");

   create_accounts_with_resources({ N(abcdefg12345) }, N(dan));

   BOOST_TEST_MESSAGE("Testing creating 12-character account with dot without bidding (failure)");

   BOOST_REQUIRE_EXCEPTION(create_accounts_with_resources({ N(abcde.g12345) }, N(dan)),
                            eosio_assert_message_exception, eosio_assert_message_is( "only prefix may create this account" ) );

} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( multiple_namebids, cyber_bios_tester ) try {
   BOOST_TEST_MESSAGE("Testing interaction of multiple bids and multiple auctions");

   const std::string not_closed_message("auction for name is not closed yet");

   std::vector<account_name> accounts = { N(alice), N(bob), N(carl), N(david), N(eve) };
   create_accounts_with_resources( accounts );
   for ( const auto& a: accounts ) {
       BOOST_CHECK_EQUAL(success(), token.open(a, token._symbol, a));
       BOOST_CHECK_EQUAL(success(), token.transfer( config::system_account_name, a, token.from_amount( 100000000 ) ));
       BOOST_REQUIRE_EQUAL( token.from_amount( 100000000 ), token.get_account(a).get_object()["balance"].as<asset>() );
   }
   create_accounts_with_resources( { N(producer) } );
   BOOST_CHECK_EQUAL(success(), stake.open(config::system_account_name, _token.to_symbol_code(), config::system_account_name));
   BOOST_CHECK_EQUAL(success(), stake.open(N(producer), _token.to_symbol_code(), N(producer)));
   BOOST_CHECK_EQUAL(success(), stake.open(N(bob), _token.to_symbol_code(), N(bob)));
   BOOST_CHECK_EQUAL(success(), stake.open(N(carl), _token.to_symbol_code(), N(carl)));

   BOOST_CHECK_EQUAL(success(), stake.setproxylvl(config::system_account_name, token._symbol.to_symbol_code(), 1));
   BOOST_CHECK_EQUAL(success(), stake.setproxylvl(N(producer), token._symbol.to_symbol_code(), 1));
   BOOST_CHECK_EQUAL(success(), stake.setproxylvl(N(bob),  token._symbol.to_symbol_code(), 0));
   BOOST_CHECK_EQUAL(success(), stake.setproxylvl(N(carl), token._symbol.to_symbol_code(), 0));

   produce_block();

   BOOST_CHECK_EQUAL(success(), token.transfer(config::system_account_name, config::stake_account_name, token.from_amount(300000000)));
   BOOST_CHECK_EQUAL(success(), token.transfer(N(bob),  config::stake_account_name, token.from_amount(10000)));
   BOOST_CHECK_EQUAL(success(), token.transfer(N(carl), config::stake_account_name, token.from_amount(10000)));
   BOOST_CHECK_EQUAL(success(), stake.delegatevote(config::system_account_name, N(bob),  token.from_amount(10000000)));
   BOOST_CHECK_EQUAL(success(), stake.delegatevote(config::system_account_name, N(carl), token.from_amount(10000000)));

   // start bids
   BOOST_CHECK_EQUAL(success(), bidname( N(bob), N(prefa), token.from_amount( 10003 )));
   BOOST_REQUIRE_EQUAL( token.from_amount( 99979997 ), token.get_account(N(bob)).get_object()["balance"].as<asset>() );
   BOOST_CHECK_EQUAL(success(), bidname( N(bob),  N(prefb), token.from_amount( 10000 )));
   BOOST_CHECK_EQUAL(success(), bidname( N(bob),  N(prefc), token.from_amount( 10000 )));
   BOOST_REQUIRE_EQUAL( token.from_amount( 99959997 ), token.get_account(N(bob)).get_object()["balance"].as<asset>() );

   BOOST_CHECK_EQUAL(success(), bidname( N(carl), N(prefd), token.from_amount(10000) ));
   BOOST_CHECK_EQUAL(success(), bidname( N(carl), N(prefe), token.from_amount(10000) ));
   BOOST_REQUIRE_EQUAL( token.from_amount( 99970000 ), token.get_account(N(carl)).get_object()["balance"].as<asset>() );

   BOOST_REQUIRE_EQUAL( error("assertion failure with message: account is already highest bidder"),
                        bidname( N(bob), N(prefb), token.from_amount(11001) ) );
   BOOST_REQUIRE_EQUAL( error("assertion failure with message: must increase bid by 10%"),
                        bidname( N(alice), N(prefb), token.from_amount(10999) ) );
   BOOST_REQUIRE_EQUAL( token.from_amount( 99959997 ), token.get_account(N(bob)).get_object()["balance"].as<asset>() );
   BOOST_REQUIRE_EQUAL( token.from_amount( 100000000 ), token.get_account(N(alice)).get_object()["balance"].as<asset>() );

   // alice outbids bob on prefb
   {
      const asset initial_names_balance = token.get_account(config::names_account_name).get_object()["balance"].as<asset>();
      BOOST_REQUIRE_EQUAL( success(), bidname( "alice", "prefb", token.from_amount(11001) ) );
      BOOST_REQUIRE_EQUAL( token.from_amount( 99959997 ), token.get_account("bob").get_object()["balance"].as<asset>() );
      BOOST_REQUIRE_EQUAL( token.from_amount( 99988999 ), token.get_account("alice").get_object()["balance"].as<asset>() );
      BOOST_REQUIRE_EQUAL( initial_names_balance + token.from_amount(11001), token.get_account(config::names_account_name).get_object()["balance"].as<asset>() );
   }

   // david outbids carl on prefd
   {
      BOOST_REQUIRE_EQUAL( token.from_amount( 99970000 ), token.get_account("carl").get_object()["balance"].as<asset>() );
      BOOST_REQUIRE_EQUAL( token.from_amount( 100000000 ), token.get_account("david").get_object()["balance"].as<asset>() );
      BOOST_REQUIRE_EQUAL( success(), bidname( "david", "prefd", token.from_amount(19900) ));
      BOOST_REQUIRE_EQUAL( token.from_amount( 99970000 ), token.get_account("carl").get_object()["balance"].as<asset>() ); // FIXME ERROR
      BOOST_REQUIRE_EQUAL( token.from_amount( 99980100 ), token.get_account("david").get_object()["balance"].as<asset>() );
   }

   // eve outbids carl on prefe
   {
      BOOST_REQUIRE_EQUAL( success(), bidname( "eve", "prefe", token.from_amount(17200) ) );
   }

   produce_block();
   produce_block( fc::hours(20) );
   BOOST_REQUIRE_EQUAL( success(), checkwin("david"));
   BOOST_REQUIRE_EXCEPTION( create_account_with_resources( N(prefd), N(david) ), fc::exception,  fc_assert_exception_message_is( "auction for name is not closed yet" ));
   BOOST_CHECK_EQUAL(success(), stake.delegatevote(config::system_account_name, N(bob),  token.from_amount(100000000)));

   produce_blocks(10);
   produce_block( fc::hours(2) );
   produce_blocks(10);
   BOOST_REQUIRE_EQUAL( success(), checkwin("david"));

   BOOST_REQUIRE_EXCEPTION( create_account_with_resources( N(prefd), N(david) ), fc::exception, fc_assert_exception_message_is( not_closed_message ) );
   BOOST_REQUIRE_EXCEPTION( create_account_with_resources( N(prefa), N(bob) ), fc::exception, fc_assert_exception_message_is( not_closed_message ) );
   BOOST_REQUIRE_EXCEPTION( create_account_with_resources( N(prefb), N(alice) ), fc::exception, fc_assert_exception_message_is( not_closed_message ) );
   BOOST_REQUIRE_EXCEPTION( create_account_with_resources( N(prefc), N(bob) ), fc::exception, fc_assert_exception_message_is( not_closed_message ) );
   BOOST_REQUIRE_EXCEPTION( create_account_with_resources( N(prefe), N(eve) ), fc::exception, fc_assert_exception_message_is( not_closed_message ) );
   BOOST_REQUIRE_EXCEPTION( create_account_with_resources( N(prefg), N(alice) ), fc::exception, fc_assert_exception_message_is( "no active bid for name" ) );

   produce_block();
   produce_block( fc::days(2) );
   BOOST_REQUIRE_EQUAL( success(), checkwin("david"));

   create_account_with_resources( N(prefd), N(david) );
   BOOST_REQUIRE_EQUAL( success(), bidname( N(eve), N(prefb), token.from_amount(21880) ) );

   produce_blocks(2);
   produce_block( fc::hours(22) );
   BOOST_REQUIRE_EQUAL( success(), checkwin("eve"));

   BOOST_REQUIRE_EXCEPTION( create_account_with_resources( N(prefb), N(eve) ), fc::exception, fc_assert_exception_message_is( not_closed_message ) );

   produce_blocks(2);
   produce_block( fc::hours(2) );
   // bidname calls checkwin for eve
   BOOST_REQUIRE_EQUAL( success(), bidname( "carl", "prefe", token.from_amount(20980) ) );

   BOOST_REQUIRE_EXCEPTION( create_account_with_resources( N(prefb), N(alice) ), eosio_assert_message_exception, eosio_assert_message_is( "only highest bidder can claim" ) );
   BOOST_REQUIRE_EXCEPTION( create_account_with_resources( N(prefb), N(carl) ), eosio_assert_message_exception, eosio_assert_message_is( "only highest bidder can claim" ) );
   create_account_with_resources( N(prefb), N(eve) );
   BOOST_REQUIRE_EXCEPTION( create_account_with_resources( N(prefe), N(carl) ), fc::exception, fc_assert_exception_message_is( not_closed_message ) );

   produce_block();
   produce_block( fc::hours(24) );
   BOOST_REQUIRE_EQUAL( success(), checkwin("carl"));

   create_account_with_resources( N(prefe), N(carl) );
   BOOST_REQUIRE_EXCEPTION( create_account_with_resources( N(prefe.xyz), N(carl) ), fc::exception, fc_assert_exception_message_is("only prefix may create this account") );
   BOOST_CHECK_EQUAL(success(), token.transfer( config::system_account_name, N(prefe), token.from_amount(100000000) ));
   create_account_with_resources( N(prefe.xyz), N(prefe) );

   BOOST_REQUIRE_EXCEPTION( create_account_with_resources( N(prefa), N(bob) ), fc::exception, fc_assert_exception_message_is( not_closed_message ) );
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( namebid_pending_winner, cyber_bios_tester ) try {
    BOOST_TEST_MESSAGE("Testing creating account by pending winner");

    std::vector<account_name> accounts = { N(alice1111111), N(bob111111111) };
    create_accounts_with_resources( accounts );
    for ( const auto& a: accounts ) {
        BOOST_CHECK_EQUAL(success(), token.open(a, token._symbol, a));
        BOOST_CHECK_EQUAL(success(), token.transfer( config::system_account_name, a, token.from_amount( 100000000 ) ));
        BOOST_REQUIRE_EQUAL( token.from_amount( 100000000 ), token.get_account(a).get_object()["balance"].as<asset>() );
    }
    create_accounts_with_resources( { N(producer) } );
    BOOST_CHECK_EQUAL(success(), stake.open(config::system_account_name, _token.to_symbol_code(), config::system_account_name));
    BOOST_CHECK_EQUAL(success(), stake.open(N(producer), _token.to_symbol_code(), N(producer)));

    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(config::system_account_name, token._symbol.to_symbol_code(), 1));
    BOOST_CHECK_EQUAL(success(), stake.setproxylvl(N(producer), token._symbol.to_symbol_code(), 1));

    produce_block();
    produce_block( fc::days(14) );

   BOOST_REQUIRE_EQUAL( success(), token.transfer( config::system_account_name, N(alice1111111), token.from_amount( 100000000 ) ));
   BOOST_REQUIRE_EQUAL( success(), token.transfer( config::system_account_name, N(bob111111111), token.from_amount( 100000000 ) ));

   BOOST_REQUIRE_EQUAL( success(), bidname( N(alice1111111), N(prefa), token.from_amount( 500000 ) ));
   BOOST_REQUIRE_EQUAL( success(), bidname( N(bob111111111), N(prefb), token.from_amount( 300000 ) ));
   produce_block();
   produce_block( fc::hours(100) ); //should close "perfa"
   produce_block( fc::hours(100) ); //should close "perfb"
   BOOST_REQUIRE_EQUAL( success(), checkwin("alice1111111"));
   produce_block();
   produce_block( fc::hours(24) );
   BOOST_REQUIRE_EQUAL( success(), checkwin("bob111111111"));
   produce_block();
   produce_block( fc::hours(24) );
   BOOST_REQUIRE_EQUAL( success(), checkwin("bob111111111")); // case with calling it again

   create_account_with_resources( N(prefb), N(bob111111111) );
} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END()
