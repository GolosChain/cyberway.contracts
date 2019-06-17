#include <boost/test/unit_test.hpp>
#include <eosio/testing/tester.hpp>
#include <eosio/chain/abi_serializer.hpp>
#include "contracts.hpp"

#include "Runtime/Runtime.h"

#include <fc/variant_object.hpp>

using namespace eosio::testing;
using namespace eosio;
using namespace eosio::chain;
using namespace eosio::testing;
using namespace fc;
using namespace std;

using mvo = fc::mutable_variant_object;

struct recipient {
    name    to;
    asset   quantity;
    string  memo;
};
FC_REFLECT(recipient, (to)(quantity)(memo))

class cyber_token_tester : public tester {
public:

   cyber_token_tester() {
      produce_blocks( 2 );

      create_accounts( { N(alice), N(bob), N(carol), N(cyber.token) } );
      produce_blocks( 2 );

      set_code( N(cyber.token), contracts::token_wasm() );
      set_abi( N(cyber.token), contracts::token_abi().data() );

      produce_blocks();

      const auto& accnt = control->chaindb().get<account_object>( N(cyber.token) );
      abi_def abi;
      BOOST_REQUIRE_EQUAL(abi_serializer::to_abi(accnt.abi, abi), true);
      abi_ser.set_abi(abi, abi_serializer_max_time);


      big_memo = std::string(max_memo_size, '0');
      super_big_memo = std::string(max_memo_size + 1, '1');
   }

   action_result push_action( const account_name& signer, const action_name &name, const variant_object &data ) {
      string action_type_name = abi_ser.get_action_type(name);

      action act;
      act.account = N(cyber.token);
      act.name    = name;
      act.data    = abi_ser.variant_to_binary( action_type_name, data,abi_serializer_max_time );

      return base_tester::push_action( std::move(act), uint64_t(signer));
   }

   fc::variant get_stats( const string& symbolname )
   {
      auto symb = eosio::chain::symbol::from_string(symbolname);
      auto symbol_code = symb.to_symbol_code().value;
      vector<char> data = get_row_by_account( N(cyber.token), symbol_code, N(stat), symbol_code );
      return data.empty() ? fc::variant() : abi_ser.binary_to_variant( "currency_stats", data, abi_serializer_max_time );
   }

   fc::variant get_account( account_name acc, const string& symbolname)
   {
      auto symb = eosio::chain::symbol::from_string(symbolname);
      auto symbol_code = symb.to_symbol_code().value;
      vector<char> data = get_row_by_account( N(cyber.token), acc, N(accounts), symbol_code );
      return data.empty() ? fc::variant() : abi_ser.binary_to_variant( "account", data, abi_serializer_max_time );
   }

   action_result create( account_name issuer,
                asset        maximum_supply ) {

      return push_action( N(cyber.token), N(create), mvo()
           ( "issuer", issuer)
           ( "maximum_supply", maximum_supply)
      );
   }

   action_result issue( account_name issuer, account_name to, asset quantity, string memo ) {
      return push_action( issuer, N(issue), mvo()
           ( "to", to)
           ( "quantity", quantity)
           ( "memo", memo)
      );
   }

   action_result retire( account_name issuer, asset quantity, string memo ) {
      return push_action( issuer, N(retire), mvo()
           ( "quantity", quantity)
           ( "memo", memo)
      );

   }

   action_result transfer( account_name from,
                  account_name to,
                  asset        quantity,
                  string       memo ) {
      return push_action( from, N(transfer), mvo()
           ( "from", from)
           ( "to", to)
           ( "quantity", quantity)
           ( "memo", memo)
      );
   }

   action_result bulk_transfer( account_name from, std::vector<recipient> recipients ) {
      return push_action( from, N(bulktransfer), mvo()
           ( "from", from)
           ( "recipients", recipients)
      );
   }

   action_result bulk_payment( account_name from, std::vector<recipient> recipients ) {
       return push_action( from, N(bulkpayment), mvo()
              ( "from", from)
              ( "recipients", recipients)
       );
    }

   action_result payment( account_name from,
                  account_name to,
                  asset        quantity,
                  string       memo ) {
      return push_action( from, N(payment), mvo()
           ( "from", from)
           ( "to", to)
           ( "quantity", quantity)
           ( "memo", memo)
      );
   }

   action_result open( account_name owner,
                       const string& symbolname,
                       account_name ram_payer    ) {
      return push_action( ram_payer, N(open), mvo()
           ( "owner", owner )
           ( "symbol", symbolname )
           ( "ram_payer", ram_payer )
      );
   }

   action_result close( account_name owner,
                        const string& symbolname ) {
      return push_action( owner, N(close), mvo()
           ( "owner", owner )
           ( "symbol", "0,CERO" )
      );
   }

   action_result claim( account_name owner,
                        asset quantity ) {
      return push_action( owner, N(claim), mvo()
           ( "owner", owner )
           ( "quantity", quantity )
      );
   }

   abi_serializer abi_ser;
   std::string big_memo;
   std::string super_big_memo;

   const size_t max_memo_size = 384;
};

BOOST_AUTO_TEST_SUITE(cyber_token_tests)

BOOST_FIXTURE_TEST_CASE( create_tests, cyber_token_tester ) try {

   auto token = create( N(alice), asset::from_string("1000.000 TKN"));
   auto stats = get_stats("3,TKN");
   REQUIRE_MATCHING_OBJECT( stats, mvo()
      ("supply", "0.000 TKN")
      ("max_supply", "1000.000 TKN")
      ("issuer", "alice")
   );
   produce_blocks(1);

} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( create_negative_max_supply, cyber_token_tester ) try {

   BOOST_REQUIRE_EQUAL( wasm_assert_msg( "max-supply must be positive" ),
      create( N(alice), asset::from_string("-1000.000 TKN"))
   );

} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( symbol_already_exists, cyber_token_tester ) try {

   auto token = create( N(alice), asset::from_string("100 TKN"));
   auto stats = get_stats("0,TKN");
   REQUIRE_MATCHING_OBJECT( stats, mvo()
      ("supply", "0 TKN")
      ("max_supply", "100 TKN")
      ("issuer", "alice")
   );
   produce_blocks(1);

   BOOST_REQUIRE_EQUAL( wasm_assert_msg( "token with symbol already exists" ),
                        create( N(alice), asset::from_string("100 TKN"))
   );

} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( create_max_supply, cyber_token_tester ) try {

   auto token = create( N(alice), asset::from_string("4611686018427387903 TKN"));
   auto stats = get_stats("0,TKN");
   REQUIRE_MATCHING_OBJECT( stats, mvo()
      ("supply", "0 TKN")
      ("max_supply", "4611686018427387903 TKN")
      ("issuer", "alice")
   );
   produce_blocks(1);

   asset max(10, symbol(SY(0, NKT)));
   share_type amount = 4611686018427387904;
   static_assert(sizeof(share_type) <= sizeof(asset), "asset changed so test is no longer valid");
   static_assert(std::is_trivially_copyable<asset>::value, "asset is not trivially copyable");
   memcpy(&max, &amount, sizeof(share_type)); // hack in an invalid amount

   BOOST_CHECK_EXCEPTION( create( N(alice), max) , asset_type_exception, [](const asset_type_exception& e) {
      return expect_assert_message(e, "magnitude of asset amount must be less than 2^62");
   });


} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( create_max_decimals, cyber_token_tester ) try {

   auto token = create( N(alice), asset::from_string("1.000000000000000000 TKN"));
   auto stats = get_stats("18,TKN");
   REQUIRE_MATCHING_OBJECT( stats, mvo()
      ("supply", "0.000000000000000000 TKN")
      ("max_supply", "1.000000000000000000 TKN")
      ("issuer", "alice")
   );
   produce_blocks(1);

   asset max(10, symbol(SY(0, NKT)));
   //1.0000000000000000000 => 0x8ac7230489e80000L
   share_type amount = 0x8ac7230489e80000L;
   static_assert(sizeof(share_type) <= sizeof(asset), "asset changed so test is no longer valid");
   static_assert(std::is_trivially_copyable<asset>::value, "asset is not trivially copyable");
   memcpy(&max, &amount, sizeof(share_type)); // hack in an invalid amount

   BOOST_CHECK_EXCEPTION( create( N(alice), max) , asset_type_exception, [](const asset_type_exception& e) {
      return expect_assert_message(e, "magnitude of asset amount must be less than 2^62");
   });

} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( issue_tests, cyber_token_tester ) try {

   auto token = create( N(alice), asset::from_string("1000.000 TKN"));
   produce_blocks(1);

   issue( N(alice), N(alice), asset::from_string("500.000 TKN"), "hola" );

   auto stats = get_stats("3,TKN");
   REQUIRE_MATCHING_OBJECT( stats, mvo()
      ("supply", "500.000 TKN")
      ("max_supply", "1000.000 TKN")
      ("issuer", "alice")
   );

   auto alice_balance = get_account(N(alice), "3,TKN");
   REQUIRE_MATCHING_OBJECT( alice_balance, mvo()
      ("balance", "500.000 TKN")
      ("payments", "0.000 TKN")
   );

   BOOST_REQUIRE_EQUAL( wasm_assert_msg( "quantity exceeds available supply" ),
      issue( N(alice), N(alice), asset::from_string("500.001 TKN"), "hola" )
   );

   BOOST_REQUIRE_EQUAL( wasm_assert_msg( "must issue positive quantity" ),
      issue( N(alice), N(alice), asset::from_string("-1.000 TKN"), "hola" )
   );

   BOOST_REQUIRE_EQUAL( success(),
      issue( N(alice), N(alice), asset::from_string("1.000 TKN"), "hola" )
   );

   BOOST_REQUIRE_EQUAL( success(),
      issue( N(alice), N(alice), asset::from_string("1.000 TKN"), big_memo )
   );

   BOOST_REQUIRE_EQUAL( wasm_assert_msg( "memo has more than 384 bytes" ),
      issue( N(alice), N(alice), asset::from_string("1.000 TKN"), super_big_memo )
   );

} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( retire_tests, cyber_token_tester ) try {

   auto token = create( N(alice), asset::from_string("1000.000 TKN"));
   produce_blocks(1);

   BOOST_REQUIRE_EQUAL( success(), issue( N(alice), N(alice), asset::from_string("500.000 TKN"), "hola" ) );

   auto stats = get_stats("3,TKN");
   REQUIRE_MATCHING_OBJECT( stats, mvo()
      ("supply", "500.000 TKN")
      ("max_supply", "1000.000 TKN")
      ("issuer", "alice")
   );

   auto alice_balance = get_account(N(alice), "3,TKN");
   REQUIRE_MATCHING_OBJECT( alice_balance, mvo()
      ("balance", "500.000 TKN")
      ("payments", "0.000 TKN")
   );

   BOOST_REQUIRE_EQUAL( success(), retire( N(alice), asset::from_string("200.000 TKN"), "hola" ) );
   stats = get_stats("3,TKN");
   REQUIRE_MATCHING_OBJECT( stats, mvo()
      ("supply", "300.000 TKN")
      ("max_supply", "1000.000 TKN")
      ("issuer", "alice")
   );
   alice_balance = get_account(N(alice), "3,TKN");
   REQUIRE_MATCHING_OBJECT( alice_balance, mvo()
      ("balance", "300.000 TKN")
      ("payments", "0.000 TKN")
   );

   //should fail to retire more than current supply
   BOOST_REQUIRE_EQUAL( wasm_assert_msg("overdrawn balance"), retire( N(alice), asset::from_string("500.000 TKN"), "hola" ) );

   BOOST_REQUIRE_EQUAL( wasm_assert_msg( "memo has more than 384 bytes" ),
      transfer( N(alice), N(bob), asset::from_string("100.000 TKN"), super_big_memo )
   );
   BOOST_REQUIRE_EQUAL( success(), transfer( N(alice), N(bob), asset::from_string("100.000 TKN"), big_memo ) );

   BOOST_REQUIRE_EQUAL( success(), transfer( N(alice), N(bob), asset::from_string("100.000 TKN"), "hola" ) );
   //should fail to retire since tokens are not on the issuer's balance
   BOOST_REQUIRE_EQUAL( wasm_assert_msg("overdrawn balance"), retire( N(alice), asset::from_string("300.000 TKN"), "hola" ) );
   //transfer tokens back
   BOOST_REQUIRE_EQUAL( success(), transfer( N(bob), N(alice), asset::from_string("200.000 TKN"), "hola" ) );

   BOOST_REQUIRE_EQUAL( wasm_assert_msg( "memo has more than 384 bytes" ),
       retire( N(alice), asset::from_string("100.000 TKN"), super_big_memo )
   );
   BOOST_REQUIRE_EQUAL( success(), retire( N(alice), asset::from_string("100.000 TKN"), big_memo ) );

   BOOST_REQUIRE_EQUAL( success(), retire( N(alice), asset::from_string("200.000 TKN"), "hola" ) );
   stats = get_stats("3,TKN");
   REQUIRE_MATCHING_OBJECT( stats, mvo()
      ("supply", "0.000 TKN")
      ("max_supply", "1000.000 TKN")
      ("issuer", "alice")
   );
   alice_balance = get_account(N(alice), "3,TKN");
   REQUIRE_MATCHING_OBJECT( alice_balance, mvo()
      ("balance", "0.000 TKN")
      ("payments", "0.000 TKN")
   );

   //trying to retire tokens with zero supply
   BOOST_REQUIRE_EQUAL( wasm_assert_msg("overdrawn balance"), retire( N(alice), asset::from_string("1.000 TKN"), "hola" ) );

} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( transfer_tests, cyber_token_tester ) try {

   auto token = create( N(alice), asset::from_string("1000 CERO"));
   produce_blocks(1);

   issue( N(alice), N(alice), asset::from_string("1000 CERO"), "hola" );

   auto stats = get_stats("0,CERO");
   REQUIRE_MATCHING_OBJECT( stats, mvo()
      ("supply", "1000 CERO")
      ("max_supply", "1000 CERO")
      ("issuer", "alice")
   );

   auto alice_balance = get_account(N(alice), "0,CERO");
   REQUIRE_MATCHING_OBJECT( alice_balance, mvo()
      ("balance", "1000 CERO")
      ("payments", "0 CERO")
   );

   transfer( N(alice), N(bob), asset::from_string("300 CERO"), "hola" );

   alice_balance = get_account(N(alice), "0,CERO");
   REQUIRE_MATCHING_OBJECT( alice_balance, mvo()
      ("balance", "700 CERO")
      ("payments", "0 CERO")
   );

   auto bob_balance = get_account(N(bob), "0,CERO");
   REQUIRE_MATCHING_OBJECT( bob_balance, mvo()
      ("balance", "300 CERO")
      ("payments", "0 CERO")
   );

   BOOST_REQUIRE_EQUAL( wasm_assert_msg( "overdrawn balance" ),
      transfer( N(alice), N(bob), asset::from_string("701 CERO"), "hola" )
   );

   BOOST_REQUIRE_EQUAL( wasm_assert_msg( "must transfer positive quantity" ),
      transfer( N(alice), N(bob), asset::from_string("-1000 CERO"), "hola" )
   );


} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( bulk_transfer_tests, cyber_token_tester ) try {

   auto token = create( N(alice), asset::from_string("1000 CERO"));
   produce_blocks(1);

   issue( N(alice), N(alice), asset::from_string("1000 CERO"), "hola" );

   auto stats = get_stats("0,CERO");
   REQUIRE_MATCHING_OBJECT( stats, mvo()
      ("supply", "1000 CERO")
      ("max_supply", "1000 CERO")
      ("issuer", "alice")
   );

   auto alice_balance = get_account(N(alice), "0,CERO");
   REQUIRE_MATCHING_OBJECT( alice_balance, mvo()
      ("balance", "1000 CERO")
      ("payments", "0 CERO")
   );

   BOOST_REQUIRE_EQUAL(wasm_assert_msg("recipients must not be empty"), bulk_transfer( N(alice), {}));
   BOOST_REQUIRE_EQUAL(success(), bulk_transfer( N(alice), {{N(bob), asset::from_string("300 CERO"), "hola"},
                                                            {N(carol), asset::from_string("200 CERO"), "hola"}} ));

   BOOST_REQUIRE_EQUAL(wasm_assert_msg("transfer of different tokens is prohibited"), bulk_transfer( N(alice), {{N(bob), asset::from_string("300 CERO"), "hola"},
                                                                                                                {N(carol), asset::from_string("200 ZERO"), "hola"}} ));

   alice_balance = get_account(N(alice), "0,CERO");
   REQUIRE_MATCHING_OBJECT( alice_balance, mvo()
      ("balance", "500 CERO")
      ("payments", "0 CERO")
   );

   auto bob_balance = get_account(N(bob), "0,CERO");
   REQUIRE_MATCHING_OBJECT( bob_balance, mvo()
      ("balance", "300 CERO")
      ("payments", "0 CERO")
   );

   auto carol_balance = get_account(N(carol), "0,CERO");
   REQUIRE_MATCHING_OBJECT( carol_balance, mvo()
      ("balance", "200 CERO")
      ("payments", "0 CERO")
   );

   bulk_transfer( N(alice), {{N(bob), asset::from_string("100 CERO"), "hola"},
                             {N(bob), asset::from_string("100 CERO"), "hola"}} );

   alice_balance = get_account(N(alice), "0,CERO");
   REQUIRE_MATCHING_OBJECT( alice_balance, mvo()
      ("balance", "300 CERO")
      ("payments", "0 CERO")
   );

   bob_balance = get_account(N(bob), "0,CERO");
   REQUIRE_MATCHING_OBJECT( bob_balance, mvo()
      ("balance", "500 CERO")
      ("payments", "0 CERO")
   );

} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( transfer_not_notification_tests, cyber_token_tester ) try {

   auto token = create( N(alice), asset::from_string("1000 CERO"));
   produce_blocks(1);

   issue( N(alice), N(alice), asset::from_string("1000 CERO"), "hola" );

   auto stats = get_stats("0,CERO");
   REQUIRE_MATCHING_OBJECT( stats, mvo()
      ("supply", "1000 CERO")
      ("max_supply", "1000 CERO")
      ("issuer", "alice")
   );

   auto alice_balance = get_account(N(alice), "0,CERO");
   REQUIRE_MATCHING_OBJECT( alice_balance, mvo()
      ("balance", "1000 CERO")
      ("payments", "0 CERO")
   );

   payment( N(alice), N(bob), asset::from_string("300 CERO"), "hola" );

   alice_balance = get_account(N(alice), "0,CERO");
   REQUIRE_MATCHING_OBJECT( alice_balance, mvo()
      ("balance", "700 CERO")
      ("payments", "0 CERO")
   );

   auto bob_balance = get_account(N(bob), "0,CERO");
   REQUIRE_MATCHING_OBJECT( bob_balance, mvo()
      ("balance", "0 CERO")
      ("payments", "300 CERO")
   );
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( bulk_transfer_not_notification_tests, cyber_token_tester ) try {

    auto token = create( N(alice), asset::from_string("1000 CERO"));
    produce_blocks(1);

    issue( N(alice), N(alice), asset::from_string("1000 CERO"), "hola" );

    auto stats = get_stats("0,CERO");
    REQUIRE_MATCHING_OBJECT( stats, mvo()
       ("supply", "1000 CERO")
       ("max_supply", "1000 CERO")
       ("issuer", "alice")
    );

    auto alice_balance = get_account(N(alice), "0,CERO");
    REQUIRE_MATCHING_OBJECT( alice_balance, mvo()
       ("balance", "1000 CERO")
       ("payments", "0 CERO")
    );

    BOOST_REQUIRE_EQUAL(wasm_assert_msg("recipients must not be empty"), bulk_payment( N(alice), {}));
    BOOST_REQUIRE_EQUAL( success(), bulk_payment( N(alice), {{N(bob), asset::from_string("300 CERO"), "hola"},
                                                            {N(carol), asset::from_string("200 CERO"), "hola"}} )); 
    BOOST_REQUIRE_EQUAL(wasm_assert_msg("payment of different tokens is prohibited"), bulk_payment( N(alice), {{N(bob), asset::from_string("300 CERO"), "hola"},
                                                                                                               {N(carol), asset::from_string("200 ZERO"), "hola"}} ));

    alice_balance = get_account(N(alice), "0,CERO");
    REQUIRE_MATCHING_OBJECT( alice_balance, mvo()
       ("balance", "500 CERO")
       ("payments", "0 CERO")
    );

    auto bob_balance = get_account(N(bob), "0,CERO");
    REQUIRE_MATCHING_OBJECT( bob_balance, mvo()
       ("balance", "0 CERO")
       ("payments", "300 CERO")
    );

    auto carol_balance = get_account(N(carol), "0,CERO");
    REQUIRE_MATCHING_OBJECT( carol_balance, mvo()
       ("balance", "0 CERO")
       ("payments", "200 CERO")
    );

    BOOST_REQUIRE_EQUAL( success(), bulk_payment( N(alice), {{N(bob), asset::from_string("100 CERO"), "hola"},
                                                             {N(bob), asset::from_string("100 CERO"), "hola"}} ));

    alice_balance = get_account(N(alice), "0,CERO");
    REQUIRE_MATCHING_OBJECT( alice_balance, mvo()
       ("balance", "300 CERO")
       ("payments", "0 CERO")
    );

    bob_balance = get_account(N(bob), "0,CERO");
    REQUIRE_MATCHING_OBJECT( bob_balance, mvo()
       ("balance", "0 CERO")
       ("payments", "500 CERO")
    );

} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( open_tests, cyber_token_tester ) try {

   auto token = create( N(alice), asset::from_string("1000 CERO"));

   auto alice_balance = get_account(N(alice), "0,CERO");
   BOOST_REQUIRE_EQUAL(true, alice_balance.is_null() );

   BOOST_REQUIRE_EQUAL( success(), issue( N(alice), N(alice), asset::from_string("1000 CERO"), "issue" ) );

   alice_balance = get_account(N(alice), "0,CERO");
   REQUIRE_MATCHING_OBJECT( alice_balance, mvo()
      ("balance", "1000 CERO")
      ("payments", "0 CERO")
   );

   auto bob_balance = get_account(N(bob), "0,CERO");
   BOOST_REQUIRE_EQUAL(true, bob_balance.is_null() );

   BOOST_REQUIRE_EQUAL( wasm_assert_msg( "owner account does not exist" ), open( N(bobdilan), "0,CERO", N(alice) ) );
   BOOST_REQUIRE_EQUAL( success(), open( N(bob), "0,CERO", N(alice) ) );

   bob_balance = get_account(N(bob), "0,CERO");
   REQUIRE_MATCHING_OBJECT( bob_balance, mvo()
      ("balance", "0 CERO")
      ("payments", "0 CERO")
   );

   BOOST_REQUIRE_EQUAL( success(), transfer( N(alice), N(bob), asset::from_string("200 CERO"), "hola" ) );

   bob_balance = get_account(N(bob), "0,CERO");
   REQUIRE_MATCHING_OBJECT( bob_balance, mvo()
      ("balance", "200 CERO")
      ("payments", "0 CERO")
   );

   BOOST_REQUIRE_EQUAL( wasm_assert_msg( "symbol does not exist" ),
                        open( N(carol), "0,INVALID", N(alice) ) );

   BOOST_REQUIRE_EQUAL( wasm_assert_msg( "symbol precision mismatch" ),
                        open( N(carol), "1,CERO", N(alice) ) );

} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( close_tests, cyber_token_tester ) try {

   auto token = create( N(alice), asset::from_string("1000 CERO"));

   auto alice_balance = get_account(N(alice), "0,CERO");
   BOOST_REQUIRE_EQUAL(true, alice_balance.is_null() );

   BOOST_REQUIRE_EQUAL( success(), issue( N(alice), N(alice), asset::from_string("1000 CERO"), "hola" ) );

   alice_balance = get_account(N(alice), "0,CERO");
   REQUIRE_MATCHING_OBJECT( alice_balance, mvo()
      ("balance", "1000 CERO")
      ("payments", "0 CERO")
   );

   BOOST_REQUIRE_EQUAL( success(), transfer( N(alice), N(bob), asset::from_string("1000 CERO"), "hola" ) );

   alice_balance = get_account(N(alice), "0,CERO");
   REQUIRE_MATCHING_OBJECT( alice_balance, mvo()
      ("balance", "0 CERO")
      ("payments", "0 CERO")
   );

   BOOST_REQUIRE_EQUAL( success(), close( N(alice), "0,CERO" ) );
   alice_balance = get_account(N(alice), "0,CERO");
   BOOST_REQUIRE_EQUAL(true, alice_balance.is_null() );

} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( claim_tests, cyber_token_tester ) try {

    auto token = create( N(alice), asset::from_string("1000 CERO"));
    produce_blocks(1);

    issue( N(alice), N(alice), asset::from_string("1000 CERO"), "hola" );

    auto stats = get_stats("0,CERO");
    REQUIRE_MATCHING_OBJECT( stats, mvo()
       ("supply", "1000 CERO")
       ("max_supply", "1000 CERO")
       ("issuer", "alice")
    );

    auto alice_balance = get_account(N(alice), "0,CERO");
    REQUIRE_MATCHING_OBJECT( alice_balance, mvo()
       ("balance", "1000 CERO")
       ("payments", "0 CERO")
    );

    payment( N(alice), N(bob), asset::from_string("300 CERO"), "hola" );

    alice_balance = get_account(N(alice), "0,CERO");
    REQUIRE_MATCHING_OBJECT( alice_balance, mvo()
       ("balance", "700 CERO")
       ("payments", "0 CERO")
    );

    auto bob_balance = get_account(N(bob), "0,CERO");
    REQUIRE_MATCHING_OBJECT( bob_balance, mvo()
       ("balance", "0 CERO")
       ("payments", "300 CERO")
    );

    claim( N(bob),  asset::from_string("300 CERO") );

    bob_balance = get_account(N(bob), "0,CERO");
    REQUIRE_MATCHING_OBJECT( bob_balance, mvo()
       ("balance", "300 CERO")
       ("payments", "0 CERO")
    );

    BOOST_REQUIRE_EQUAL( wasm_assert_msg( "must transfer positive quantity" ),
                         claim( N(bob),  asset::from_string("0 CERO") )
    );

    BOOST_REQUIRE_EQUAL( wasm_assert_msg( "not found object account" ),
                         claim( N(carol),  asset::from_string("10 CERO") )
    );

    BOOST_REQUIRE_EQUAL( wasm_assert_msg( "insufficient funds" ),
                         claim( N(bob),  asset::from_string("10 CERO") )
    );

} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END()
