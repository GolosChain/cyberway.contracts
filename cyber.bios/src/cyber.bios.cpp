#include <cyber.bios/cyber.bios.hpp>
#include <cyber.bios/config.hpp>
#include <cyber.govern/cyber.govern.hpp>
#include <cyber.system/cyber.system.hpp>
#include <cyber.token/cyber.token.hpp>

#include <eosiolib/system.hpp>
#include <eosiolib/transaction.hpp>

namespace cyber {
    
using namespace eosio;
using namespace eosiosystem;
using namespace cyber::config;

void bios::onblock(ignore<block_header> header) {
    require_auth(_self);
    
    eosio::block_timestamp timestamp;
    name producer;
    _ds >> timestamp >> producer;
    INLINE_ACTION_SENDER(govern, onblock)(govern_name, {{govern_name, active_name}}, {producer});
    //TODO: update names
}

void bios::bidname( name bidder, name newname, eosio::asset bid ) {
   require_auth( bidder );
   eosio_assert( newname.suffix() == newname, "you can only bid on top-level suffix" );

   eosio_assert( (bool)newname, "the empty name is not a valid account name to bid on" );
   eosio_assert( (newname.value & 0xFull) == 0, "13 character names are not valid account names to bid on" );
   eosio_assert( (newname.value & 0x1F0ull) == 0, "accounts with 12 character names and no dots can be created without bidding required" );
   eosio_assert( !is_account( newname ), "account already exists" );
   eosio_assert( bid.symbol == system_contract::get_core_symbol(), "asset must be system token" );
   eosio_assert( bid.amount > 0, "insufficient bid" );

   INLINE_ACTION_SENDER(eosio::token, transfer)(
      system_contract::token_account, { {bidder, system_contract::active_permission} },
      { bidder, system_contract::names_account, bid, std::string("bid name ")+ newname.to_string() }
   );

   name_bid_table bids(_self, _self.value);
   print( name{bidder}, " bid ", bid, " on ", name{newname}, "\n" );
   auto current = bids.find( newname.value );
   if( current == bids.end() ) {
      bids.emplace( bidder, [&]( auto& b ) {
         b.newname = newname;
         b.high_bidder = bidder;
         b.high_bid = bid.amount;
         b.last_bid_time = time_point(microseconds(current_time()));
      });
   } else {
      eosio_assert( current->high_bid > 0, "this auction has already closed" );
      eosio_assert( bid.amount - current->high_bid > (current->high_bid / 10), "must increase bid by 10%" );
      eosio_assert( current->high_bidder != bidder, "account is already highest bidder" );

      bid_refund_table refunds_table(_self, newname.value);

      auto it = refunds_table.find( current->high_bidder.value );
      if ( it != refunds_table.end() ) {
         refunds_table.modify( it, same_payer, [&](auto& r) {
               r.amount += asset( current->high_bid, system_contract::get_core_symbol() );
            });
      } else {
         refunds_table.emplace( bidder, [&](auto& r) {
               r.bidder = current->high_bidder;
               r.amount = asset( current->high_bid, system_contract::get_core_symbol() );
            });
      }

      transaction t;
      t.actions.emplace_back( permission_level{_self, system_contract::active_permission},
                              _self, "bidrefund"_n,
                              std::make_tuple( current->high_bidder, newname )
      );
      t.delay_sec = 0;
      uint128_t deferred_id = (uint128_t(newname.value) << 64) | current->high_bidder.value;
//      cancel_deferred( deferred_id );
      t.send( deferred_id, bidder );

      bids.modify( current, bidder, [&]( auto& b ) {
         b.high_bidder = bidder;
         b.high_bid = bid.amount;
         b.last_bid_time = time_point(microseconds(current_time()));
      });
   }
}

void bios::bidrefund( name bidder, name newname ) {
   require_auth( _self );

   bid_refund_table refunds_table(_self, newname.value);
   auto it = refunds_table.find( bidder.value );
   eosio_assert( it != refunds_table.end(), "refund not found" );
   INLINE_ACTION_SENDER(eosio::token, transfer)(
      system_contract::token_account, { {system_contract::names_account, active_name}, {bidder, active_name} },
      { system_contract::names_account, bidder, asset(it->amount), std::string("refund bid on name ")+(name{newname}).to_string() }
   );
   refunds_table.erase( it );
}

void bios::biderase(name creator, name newact, name sender) {
    require_auth( sender );

    name_bid_table bids(_self, _self.value);
    auto current = bids.find( newact.value );
    eosio_assert( current != bids.end(), "no active bid for name" );
    eosio_assert( current->high_bidder == creator, "only highest bidder can claim" );
    eosio_assert( current->high_bid < 0, "auction for name is not closed yet" );
    bids.erase( current );
}
}

EOSIO_DISPATCH( cyber::bios, (setglimits)(setprods)(setparams)(reqauth)(setabi)(setcode)(onblock)(bidname)(bidrefund)(biderase) )
