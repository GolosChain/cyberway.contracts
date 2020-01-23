#include <boost/test/unit_test.hpp>
#include <eosio/testing/tester.hpp>
#include <eosio/chain/abi_serializer.hpp>
#include <eosio/chain/wast_to_wasm.hpp>

#include <Runtime/Runtime.h>

#include <fc/variant_object.hpp>
#include "contracts.hpp"
#include "test_symbol.hpp"

using namespace eosio::testing;
using namespace eosio;
using namespace eosio::chain;
using namespace eosio::testing;
using namespace fc;

using mvo = fc::mutable_variant_object;

class cyber_msig_tester : public tester {
public:
   cyber_msig_tester() {
      create_accounts({config::ram_account_name, config::ramfee_account_name,
         N(alice), N(bob), N(carol)});
      produce_block();

      const auto sys_priv_key = get_private_key(config::system_account_name, name{config::active_name}.to_string());
      set_code(config::msig_account_name, contracts::msig_wasm(), &sys_priv_key);
      set_abi(config::msig_account_name, contracts::msig_abi().data(), &sys_priv_key);

      produce_blocks();
      const auto& accnt = control->chaindb().get<account_object>(config::msig_account_name);
      abi_def abi;
      BOOST_REQUIRE_EQUAL(abi_serializer::to_abi(accnt.abi, abi), true);
      abi_ser.set_abi(abi, abi_serializer_max_time);
   }

   transaction_trace_ptr create_account_with_resources( account_name a, account_name creator, asset ramfunds, bool multisig,
                                                        asset net = core_sym::from_string("10.0000"), asset cpu = core_sym::from_string("10.0000") ) {
      signed_transaction trx;
      set_transaction_headers(trx);

      authority owner_auth;
      if (multisig) {
         // multisig between account's owner key and creators active permission
         owner_auth = authority(2, {key_weight{get_public_key( a, "owner" ), 1}}, {permission_level_weight{{creator, config::active_name}, 1}});
      } else {
         owner_auth =  authority( get_public_key( a, "owner" ) );
      }

      trx.actions.emplace_back( vector<permission_level>{{creator,config::active_name}},
                                newaccount{
                                   .creator  = creator,
                                   .name     = a,
                                   .owner    = owner_auth,
                                   .active   = authority( get_public_key( a, "active" ) )
                                });

      trx.actions.emplace_back( get_action(config::system_account_name, N(buyram), vector<permission_level>{{creator,config::active_name}},
                                            mvo()
                                            ("payer", creator)
                                            ("receiver", a)
                                            ("quant", ramfunds) )
                              );

      trx.actions.emplace_back( get_action(config::system_account_name, N(delegatebw), vector<permission_level>{{creator,config::active_name}},
                                            mvo()
                                            ("from", creator)
                                            ("receiver", a)
                                            ("stake_net_quantity", net )
                                            ("stake_cpu_quantity", cpu )
                                            ("transfer", 0 )
                                          )
                                );

      set_transaction_headers(trx);
      trx.sign( get_private_key( creator, "active" ), control->get_chain_id()  );
      return push_transaction( trx );
   }
   void create_currency( name contract, name manager, asset maxsupply ) {
      auto act =  mutable_variant_object()
         ("issuer",       manager )
         ("maximum_supply", maxsupply );

      base_tester::push_action(contract, N(create), contract, act );
   }
   void issue( name to, const asset& amount, name manager = config::system_account_name ) {
      base_tester::push_action(config::token_account_name, N(issue), manager, mutable_variant_object()
                                ("to",      to )
                                ("quantity", amount )
                                ("memo", "")
                                );
   }
   void transfer( name from, name to, const string& amount, name manager = config::system_account_name ) {
      base_tester::push_action(config::token_account_name, N(transfer), manager, mutable_variant_object()
                                ("from",    from)
                                ("to",      to )
                                ("quantity", asset::from_string(amount) )
                                ("memo", "")
                                );
   }
   asset get_balance( const account_name& act ) {
      return tester::get_currency_balance(config::token_account_name, symbol(CORE_SYM), act);
   }

   transaction_trace_ptr push_action( const account_name& signer, const action_name& name, const variant_object& data, bool auth = true ) {
      vector<account_name> accounts;
      if( auth )
         accounts.push_back( signer );
      auto trace = base_tester::push_action(config::msig_account_name, name, accounts, data );
      produce_block();
      BOOST_REQUIRE_EQUAL( true, chain_has_transaction(trace->id) );
      return trace;

      /*
         string action_type_name = abi_ser.get_action_type(name);

         action act;
         act.account = config::msig_account_name;
         act.name = name;
         act.data = abi_ser.variant_to_binary( action_type_name, data, abi_serializer_max_time );
         //std::cout << "test:\n" << fc::to_hex(act.data.data(), act.data.size()) << " size = " << act.data.size() << std::endl;

         return base_tester::push_action( std::move(act), auth ? uint64_t(signer) : 0 );
      */
   }

   transaction reqauth( account_name from, const vector<permission_level>& auths, const fc::microseconds& max_serialization_time );
   transaction reqauth_delayed(account_name from, const vector<permission_level>& auths, const uint32_t delay);

   abi_serializer abi_ser;
};

transaction cyber_msig_tester::reqauth( account_name from, const vector<permission_level>& auths, const fc::microseconds& max_serialization_time ) {
   fc::variants v;
   for ( auto& level : auths ) {
      v.push_back(fc::mutable_variant_object()
                  ("actor", level.actor)
                  ("permission", level.permission)
      );
   }
   variant pretty_trx = fc::mutable_variant_object()
      ("expiration", "2020-01-01T00:30")
      ("ref_block_num", 2)
      ("ref_block_prefix", 3)
      ("max_net_usage_words", 0)
      ("max_cpu_usage_ms", 0)
      ("max_ram_kbytes", 0)
      ("max_storage_kbytes", 0)
      ("delay_sec", 0)
      ("actions", fc::variants({
            fc::mutable_variant_object()
               ("account", name(config::system_account_name))
               ("name", "reqauth")
               ("authorization", v)
               ("data", fc::mutable_variant_object() ("from", from) )
               })
      );
   transaction trx;
   abi_serializer::from_variant(pretty_trx, trx, get_resolver(), max_serialization_time);
   return trx;
}

transaction cyber_msig_tester::reqauth_delayed(account_name from, const vector<permission_level>& auths, const uint32_t delay) {
   fc::variants v;
   for ( auto& level : auths ) {
      v.push_back(fc::mutable_variant_object()
                  ("actor", level.actor)
                  ("permission", level.permission)
      );
   }
   variant pretty_trx = fc::mutable_variant_object()
      ("expiration", "2020-01-01T00:30")
      ("ref_block_num", 0)
      ("ref_block_prefix", 0)
      ("max_net_usage_words", 0)
      ("max_cpu_usage_ms", 0)
      ("max_ram_kbytes", 0)
      ("max_storage_kbytes", 0)
      ("delay_sec", delay)
      ("actions", fc::variants({
            fc::mutable_variant_object()
               ("account", name(config::system_account_name))
               ("name", "reqauth")
               ("authorization", v)
               ("data", fc::mutable_variant_object() ("from", from) )
               })
      );
   transaction trx;
   abi_serializer::from_variant(pretty_trx, trx, get_resolver(), abi_serializer_max_time);
   return trx;
}

BOOST_AUTO_TEST_SUITE(cyber_msig_tests)

BOOST_FIXTURE_TEST_CASE( propose_approve_execute, cyber_msig_tester ) try {
   auto trx = reqauth("alice", {permission_level{N(alice), config::active_name}}, abi_serializer_max_time );

   push_action( N(alice), N(propose), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("trx",           trx)
                  ("requested", vector<permission_level>{{ N(alice), config::active_name }})
   );

   //fail to execute before approval
   BOOST_REQUIRE_EXCEPTION( push_action( N(alice), N(exec), mvo()
                                          ("proposer",      "alice")
                                          ("proposal_name", "first")
                                          ("executer",      "alice")
                            ),
                            eosio_assert_message_exception,
                            eosio_assert_message_is("transaction authorization failed")
   );

   //approve and execute
   push_action( N(alice), N(approve), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("level",         permission_level{ N(alice), config::active_name })
   );

   transaction_trace_ptr trace;
   control->applied_transaction.connect([&]( const transaction_trace_ptr& t) { if (t->scheduled) { trace = t; } } );
   push_action( N(alice), N(exec), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("executer",      "alice")
   );

   BOOST_REQUIRE( bool(trace) );
   BOOST_REQUIRE_EQUAL( 1, trace->action_traces.size() );
   BOOST_REQUIRE_EQUAL( transaction_receipt::executed, trace->receipt->status );
} FC_LOG_AND_RETHROW()


BOOST_FIXTURE_TEST_CASE( propose_approve_unapprove, cyber_msig_tester ) try {
   auto trx = reqauth("alice", {permission_level{N(alice), config::active_name}}, abi_serializer_max_time );

   push_action( N(alice), N(propose), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("trx",           trx)
                  ("requested", vector<permission_level>{{ N(alice), config::active_name }})
   );

   push_action( N(alice), N(approve), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("level",         permission_level{ N(alice), config::active_name })
   );

   push_action( N(alice), N(unapprove), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("level",         permission_level{ N(alice), config::active_name })
   );

   BOOST_REQUIRE_EXCEPTION( push_action( N(alice), N(exec), mvo()
                                          ("proposer",      "alice")
                                          ("proposal_name", "first")
                                          ("executer",      "alice")
                            ),
                            eosio_assert_message_exception,
                            eosio_assert_message_is("transaction authorization failed")
   );

} FC_LOG_AND_RETHROW()


BOOST_FIXTURE_TEST_CASE( propose_approve_by_two, cyber_msig_tester ) try {
   auto trx = reqauth("alice", vector<permission_level>{ { N(alice), config::active_name }, { N(bob), config::active_name } }, abi_serializer_max_time );
   push_action( N(alice), N(propose), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("trx",           trx)
                  ("requested", vector<permission_level>{ { N(alice), config::active_name }, { N(bob), config::active_name } })
   );

   //approve by alice
   push_action( N(alice), N(approve), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("level",         permission_level{ N(alice), config::active_name })
   );

   //fail because approval by bob is missing

   BOOST_REQUIRE_EXCEPTION( push_action( N(alice), N(exec), mvo()
                                          ("proposer",      "alice")
                                          ("proposal_name", "first")
                                          ("executer",      "alice")
                            ),
                            eosio_assert_message_exception,
                            eosio_assert_message_is("transaction authorization failed")
   );

   //approve by bob and execute
   push_action( N(bob), N(approve), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("level",         permission_level{ N(bob), config::active_name })
   );

   transaction_trace_ptr trace;
   control->applied_transaction.connect([&]( const transaction_trace_ptr& t) { if (t->scheduled) { trace = t; } } );

   push_action( N(alice), N(exec), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("executer",      "alice")
   );

   BOOST_REQUIRE( bool(trace) );
   BOOST_REQUIRE_EQUAL( 1, trace->action_traces.size() );
   BOOST_REQUIRE_EQUAL( transaction_receipt::executed, trace->receipt->status );
} FC_LOG_AND_RETHROW()


BOOST_FIXTURE_TEST_CASE( propose_with_wrong_requested_auth, cyber_msig_tester ) try {
   auto trx = reqauth("alice", vector<permission_level>{ { N(alice), config::active_name },  { N(bob), config::active_name } }, abi_serializer_max_time );
   //try with not enough requested auth
   BOOST_REQUIRE_EXCEPTION( push_action( N(alice), N(propose), mvo()
                                             ("proposer",      "alice")
                                             ("proposal_name", "third")
                                             ("trx",           trx)
                                             ("requested", vector<permission_level>{ { N(alice), config::active_name } } )
                            ),
                            eosio_assert_message_exception,
                            eosio_assert_message_is("transaction authorization failed")
   );

} FC_LOG_AND_RETHROW()


BOOST_FIXTURE_TEST_CASE( big_transaction, cyber_msig_tester ) try {
   return; // TODO: fix for CyberWay
   vector<permission_level> perm = { { N(alice), config::active_name }, { N(bob), config::active_name } };
   auto wasm = contracts::util::exchange_wasm();

   variant pretty_trx = fc::mutable_variant_object()
      ("expiration", "2020-01-01T00:30")
      ("ref_block_num", 2)
      ("ref_block_prefix", 3)
      ("max_net_usage_words", 0)
      ("max_cpu_usage_ms", 0)
      ("max_ram_kbytes", 0)
      ("max_storage_kbytes", 0)
      ("delay_sec", 0)
      ("actions", fc::variants({
            fc::mutable_variant_object()
               ("account", name(config::system_account_name))
               ("name", "setcode")
               ("authorization", perm)
               ("data", fc::mutable_variant_object()
                ("account", "alice")
                ("vmtype", 0)
                ("vmversion", 0)
                ("code", bytes( wasm.begin(), wasm.end() ))
               )
               })
      );

   transaction trx;
   abi_serializer::from_variant(pretty_trx, trx, get_resolver(), abi_serializer_max_time);

   push_action( N(alice), N(propose), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("trx",           trx)
                  ("requested", perm)
   );

   //approve by alice
   push_action( N(alice), N(approve), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("level",         permission_level{ N(alice), config::active_name })
   );
   //approve by bob and execute
   push_action( N(bob), N(approve), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("level",         permission_level{ N(bob), config::active_name })
   );

   transaction_trace_ptr trace;
   control->applied_transaction.connect([&]( const transaction_trace_ptr& t) { if (t->scheduled) { trace = t; } } );

   push_action( N(alice), N(exec), mvo()
      ("proposer",      "alice")
                                                       ("proposal_name", "first")
      ("executer",      "alice"));

   // TODO: Cyberway exchange_wasm is compiled for EOS
   return;

   BOOST_REQUIRE( bool(trace) );
   BOOST_REQUIRE_EQUAL( 1, trace->action_traces.size() );
   BOOST_REQUIRE_EQUAL( transaction_receipt::executed, trace->receipt->status );
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( propose_approve_invalidate, cyber_msig_tester ) try {
   auto trx = reqauth("alice", {permission_level{N(alice), config::active_name}}, abi_serializer_max_time );

   push_action( N(alice), N(propose), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("trx",           trx)
                  ("requested", vector<permission_level>{{ N(alice), config::active_name }})
   );

   //fail to execute before approval
   BOOST_REQUIRE_EXCEPTION( push_action( N(alice), N(exec), mvo()
                                          ("proposer",      "alice")
                                          ("proposal_name", "first")
                                          ("executer",      "alice")
                            ),
                            eosio_assert_message_exception,
                            eosio_assert_message_is("transaction authorization failed")
   );

   //approve
   push_action( N(alice), N(approve), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("level",         permission_level{ N(alice), config::active_name })
   );

   //invalidate
   push_action( N(alice), N(invalidate), mvo()
                  ("account",      "alice")
   );

   //fail to execute after invalidation
   BOOST_REQUIRE_EXCEPTION( push_action( N(alice), N(exec), mvo()
                                          ("proposer",      "alice")
                                          ("proposal_name", "first")
                                          ("executer",      "alice")
                            ),
                            eosio_assert_message_exception,
                            eosio_assert_message_is("transaction authorization failed")
   );
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( propose_invalidate_approve, cyber_msig_tester ) try {
   auto trx = reqauth("alice", {permission_level{N(alice), config::active_name}}, abi_serializer_max_time );

   push_action( N(alice), N(propose), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("trx",           trx)
                  ("requested", vector<permission_level>{{ N(alice), config::active_name }})
   );

   //fail to execute before approval
   BOOST_REQUIRE_EXCEPTION( push_action( N(alice), N(exec), mvo()
                                          ("proposer",      "alice")
                                          ("proposal_name", "first")
                                          ("executer",      "alice")
                            ),
                            eosio_assert_message_exception,
                            eosio_assert_message_is("transaction authorization failed")
   );

   //invalidate
   push_action( N(alice), N(invalidate), mvo()
                  ("account",      "alice")
   );

   //approve
   push_action( N(alice), N(approve), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("level",         permission_level{ N(alice), config::active_name })
   );

   //successfully execute
   transaction_trace_ptr trace;
   control->applied_transaction.connect([&]( const transaction_trace_ptr& t) { if (t->scheduled) { trace = t; } } );

   push_action( N(bob), N(exec), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("executer",      "bob")
   );

   BOOST_REQUIRE( bool(trace) );
   BOOST_REQUIRE_EQUAL( 1, trace->action_traces.size() );
   BOOST_REQUIRE_EQUAL( transaction_receipt::executed, trace->receipt->status );
} FC_LOG_AND_RETHROW()


BOOST_FIXTURE_TEST_CASE( approve_with_hash, cyber_msig_tester ) try {
   auto trx = reqauth("alice", {permission_level{N(alice), config::active_name}}, abi_serializer_max_time );
   auto trx_hash = fc::sha256::hash( trx );
   auto not_trx_hash = fc::sha256::hash( trx_hash );

   push_action( N(alice), N(propose), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("trx",           trx)
                  ("requested", vector<permission_level>{{ N(alice), config::active_name }})
   );

   //fail to approve with incorrect hash
   BOOST_REQUIRE_EXCEPTION( push_action( N(alice), N(approve), mvo()
                                          ("proposer",      "alice")
                                          ("proposal_name", "first")
                                          ("level",         permission_level{ N(alice), config::active_name })
                                          ("proposal_hash", not_trx_hash)
                            ),
                            eosio::chain::crypto_api_exception,
                            fc_exception_message_is("hash mismatch")
   );

   //approve and execute
   push_action( N(alice), N(approve), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("level",         permission_level{ N(alice), config::active_name })
                  ("proposal_hash", trx_hash)
   );

   transaction_trace_ptr trace;
   control->applied_transaction.connect([&]( const transaction_trace_ptr& t) { if (t->scheduled) { trace = t; } } );
   push_action( N(alice), N(exec), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("executer",      "alice")
   );

   BOOST_REQUIRE( bool(trace) );
   BOOST_REQUIRE_EQUAL( 1, trace->action_traces.size() );
   BOOST_REQUIRE_EQUAL( transaction_receipt::executed, trace->receipt->status );
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE( switch_proposal_and_fail_approve_with_hash, cyber_msig_tester ) try {
   auto trx1 = reqauth("alice", {permission_level{N(alice), config::active_name}}, abi_serializer_max_time );
   auto trx1_hash = fc::sha256::hash( trx1 );

   push_action( N(alice), N(propose), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("trx",           trx1)
                  ("requested", vector<permission_level>{{ N(alice), config::active_name }})
   );

   auto trx2 = reqauth("alice",
                       { permission_level{N(alice), config::active_name},
                         permission_level{N(alice), config::owner_name}  },
                       abi_serializer_max_time );

   push_action( N(alice), N(cancel), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("canceler",       "alice")
   );

   push_action( N(alice), N(propose), mvo()
                  ("proposer",      "alice")
                  ("proposal_name", "first")
                  ("trx",           trx2)
                  ("requested", vector<permission_level>{ { N(alice), config::active_name },
                                                          { N(alice), config::owner_name } })
   );

   //fail to approve with hash meant for old proposal
   BOOST_REQUIRE_EXCEPTION( push_action( N(alice), N(approve), mvo()
                                          ("proposer",      "alice")
                                          ("proposal_name", "first")
                                          ("level",         permission_level{ N(alice), config::active_name })
                                          ("proposal_hash", trx1_hash)
                            ),
                            eosio::chain::crypto_api_exception,
                            fc_exception_message_is("hash mismatch")
   );
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(propose_with_description, cyber_msig_tester) try {
   auto trx = reqauth("alice", {permission_level{N(alice), config::active_name}}, abi_serializer_max_time);
   const name p_name = N(description);
   push_action(N(alice), N(propose), mvo()
      ("proposer", "alice")
      ("proposal_name", p_name)
      ("trx", trx)
      ("requested", vector<permission_level>{{ N(alice), config::active_name }})
      ("description", "Propose to Hello world!")
   );

   //approve and execute
   push_action(N(alice), N(approve), mvo()
      ("proposer", "alice")
      ("proposal_name", p_name)
      ("level", permission_level{ N(alice), config::active_name })
   );

   transaction_trace_ptr trace;
   control->applied_transaction.connect([&](const transaction_trace_ptr& t) { if (t->scheduled) { trace = t; } });
   push_action(N(alice), N(exec), mvo()
      ("proposer", "alice")
      ("proposal_name", p_name)
      ("executer", "alice")
   );

   BOOST_REQUIRE(bool(trace));
   BOOST_REQUIRE_EQUAL(1, trace->action_traces.size());
   BOOST_REQUIRE_EQUAL(transaction_receipt::executed, trace->receipt->status);
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(propose_delayed, cyber_msig_tester) try {
   uint32_t delay = 30;
   auto trx = reqauth_delayed("alice", {permission_level{N(alice), config::active_name}}, delay);
   const name p_name = N(trx);
   push_action(N(alice), N(propose), mvo()
      ("proposer", "alice")
      ("proposal_name", p_name)
      ("trx", trx)
      ("requested", vector<permission_level>{{ N(alice), config::active_name }})
   );

   //approve and execute
   push_action(N(alice), N(approve), mvo()
      ("proposer", "alice")
      ("proposal_name", p_name)
      ("level", permission_level{ N(alice), config::active_name })
   );

   transaction_trace_ptr trace;
   control->applied_transaction.connect([&](const transaction_trace_ptr& t) { if (t->scheduled) { trace = t; } });
   push_action(N(alice), N(exec), mvo()
      ("proposer", "alice")
      ("proposal_name", p_name)
      ("executer", "alice")
   );

   BOOST_REQUIRE(!trace);
   while (!trace && delay > 0) {
      BOOST_TEST_MESSAGE("wait…" << delay);
      produce_block();
      delay -= 3;
   }

   BOOST_REQUIRE(bool(trace));
   BOOST_REQUIRE_EQUAL(1, trace->action_traces.size());
   BOOST_REQUIRE_EQUAL(transaction_receipt::executed, trace->receipt->status);
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(propose_delayed_exec_cancel, cyber_msig_tester) try {
   uint32_t delay = 30;
   const auto alice = N(alice);
   const auto bob = N(bob);
   const permission_level alice_perm{alice, config::active_name};
   const permission_level bob_perm{bob, config::active_name};
   const vector<permission_level> auths{alice_perm, bob_perm};

   auto trx1 = reqauth_delayed(alice, auths, delay);
   auto trx2 = reqauth_delayed(alice, auths, delay + 20);
   const name name1(N(trx1));
   const name name2(N(trx2));
   auto propose_args = mvo()
      ("proposer", alice)
      ("proposal_name", name1)
      ("trx", trx1)
      ("requested", auths);
   push_action(alice, N(propose), propose_args);
   push_action(alice, N(propose), propose_args("proposal_name", name2)("trx", trx2));

   //approve and execute
   auto approve_args = mvo()
      ("proposer", alice)
      ("proposal_name", name1)
      ("level", alice_perm);
   BOOST_TEST_MESSAGE("approve alice 1");
   push_action(alice, N(approve), approve_args);
   BOOST_TEST_MESSAGE("approve bob 1");
   push_action(bob,   N(approve), approve_args("level", bob_perm));
   BOOST_TEST_MESSAGE("approve bob 2");
   push_action(bob,   N(approve), approve_args("proposal_name", name2));
   BOOST_TEST_MESSAGE("approve alice 2");
   push_action(alice, N(approve), approve_args("level", alice_perm));

   auto exec_args = mvo()
      ("proposer", alice)
      ("proposal_name", name1)
      ("executer", alice);
   transaction_trace_ptr trace;
   control->applied_transaction.connect([&](const transaction_trace_ptr& t) { if (t->scheduled) { trace = t; } });
   push_action(alice, N(exec), exec_args);
   push_action(alice, N(exec), exec_args("proposal_name", name2));

   BOOST_REQUIRE(!trace);
   while (!trace && delay > 15) {
      BOOST_TEST_MESSAGE("wait…" << delay);
      produce_block();
      delay -= 3;
   }
   BOOST_REQUIRE(!trace);

   auto args = mvo()
      ("proposer", alice)
      ("proposal_name", name1)
      ("canceling_auth", alice_perm);
   BOOST_TEST_MESSAGE("-- successful cancel with valid args");
   push_action(alice, N(canceldelayed), args);
   BOOST_TEST_MESSAGE("-- not found if cancel again");
   BOOST_REQUIRE_EXCEPTION(push_action(alice, N(canceldelayed), args),
      eosio_assert_message_exception,
      eosio_assert_message_is("scheduled trx not found")
   );

   BOOST_TEST_MESSAGE("-- fail if not originally authorized");
   args = args
      ("proposal_name", name2)
      ("canceling_auth", permission_level{N(carol), config::active_name});
   BOOST_REQUIRE_EXCEPTION(push_action(N(carol), N(canceldelayed), args),
      eosio_assert_message_exception,
      eosio_assert_message_is("only authorizer can cancel")
   );
   args = args("canceling_auth", bob_perm);
   BOOST_TEST_MESSAGE("-- successful cancel when authorized by other signer");
   push_action(bob, N(canceldelayed), args);
   BOOST_REQUIRE_EXCEPTION(push_action(bob, N(canceldelayed), args),
      eosio_assert_message_exception,
      eosio_assert_message_is("scheduled trx not found")
   );

   // ensure trx don't executed after delay
   delay += 30;
   while (delay > 0) {
      BOOST_TEST_MESSAGE("nop" << delay);
      BOOST_REQUIRE(!trace);
      produce_block();
      delay -= 3;
   }
   BOOST_REQUIRE(!trace);
} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END()
