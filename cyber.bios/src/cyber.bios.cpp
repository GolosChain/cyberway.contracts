#include <cyber.bios/cyber.bios.hpp>
#include <cyber.bios/config.hpp>
#include <cyber.govern/cyber.govern.hpp>
#include <cyber.token/cyber.token.hpp>

#include <eosiolib/system.hpp>
#include <eosiolib/transaction.hpp>

eosio::symbol core_symbol() {
    const static auto sym = cyber::config::system_token;
    return sym;
}

namespace cyber {
    
using namespace eosio;
using namespace eosiosystem;
using namespace cyber::config;

// constants
const uint32_t seconds_per_hour      = 60 * 60;
const uint32_t seconds_per_day       = 24 * 3600;

// config
const uint32_t min_time_from_last_win = seconds_per_day;
const uint32_t min_time_from_last_bid = seconds_per_day;

void bios::onblock(ignore<block_header> header) {
    require_auth(_self);
    
    eosio::block_timestamp timestamp;
    name producer;
    _ds >> timestamp >> producer;
    INLINE_ACTION_SENDER(govern, onblock)(govern_name, {{govern_name, active_name}}, {producer});
    //TODO: update names

    const int64_t now = ::now();
    auto tnow = time_point_sec(now);

    auto state = state_singleton(_self, _self.value);
    bool exists = state.exists();
    auto s = exists ? state.get() : state_info{tnow};
    if (exists) {
        auto diff = now - s.last_close_bid.utc_seconds;
        eosio_assert(diff >= 0, "SYSTEM: last_checkwin is in future");  // must be impossible
        if (diff > min_time_from_last_win) {
            name_bid_table bids(_self, _self.value);
            auto idx = bids.get_index<"highbid"_n>();
            auto highest = idx.lower_bound( std::numeric_limits<uint64_t>::max()/2 );
            if( highest != idx.end() && highest->high_bid > 0 &&
                (microseconds(current_time()) - highest->last_bid_time.time_since_epoch()) > microseconds(min_time_from_last_bid)) {
                s.last_close_bid = tnow;
                idx.modify( highest, same_payer, [&]( auto& b ){
                    b.high_bid = -b.high_bid;
                });
            }
            state.set(s, _self);
        }
    } else {
        state.set(s, _self);
    }
}

void bios::bidname( name bidder, name newname, eosio::asset bid ) {
   require_auth( bidder );
   eosio_assert( newname.suffix() == newname, "you can only bid on top-level suffix" );

   eosio_assert( (bool)newname, "the empty name is not a valid account name to bid on" );
   eosio_assert( (newname.value & 0xFull) == 0, "13 character names are not valid account names to bid on" );
   eosio_assert( (newname.value & 0x1F0ull) == 0, "accounts with 12 character names and no dots can be created without bidding required" );
   eosio_assert( !is_account( newname ), "account already exists" );
   eosio_assert( bid.symbol == core_symbol(), "asset must be system token" );
   eosio_assert( bid.amount > 0, "insufficient bid" );

   INLINE_ACTION_SENDER(eosio::token, transfer)(
      token_name, { {bidder, active_name} },
      { bidder, names_name, bid, std::string("bid name ")+ newname.to_string() }
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
               r.amount += asset( current->high_bid, core_symbol() );
            });
      } else {
         refunds_table.emplace( bidder, [&](auto& r) {
               r.bidder = current->high_bidder;
               r.amount = asset( current->high_bid, system_token );
            });
      }

      transaction t;
      t.actions.emplace_back( permission_level{_self, active_name},
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
        token_name, { {names_name, active_name}, {bidder, active_name} },
        { names_name, bidder, asset(it->amount), std::string("refund bid on name ")+(name{newname}).to_string() }
   );
   refunds_table.erase( it );
}

void bios::newaccount(name creator, name newact, ignore<authority> owner, ignore<authority> active) {
    if( creator != _self ) {
        uint64_t tmp = newact.value >> 4;
        bool has_dot = false;

        for( uint32_t i = 0; i < 12; ++i ) {
            has_dot |= !(tmp & 0x1f);
            tmp >>= 5;
        }
        if( has_dot ) { // or is less than 12 characters
            auto suffix = newact.suffix();
            if( suffix == newact ) {
                name_bid_table bids(_self, _self.value);
                auto current = bids.find( newact.value );
                eosio_assert( current != bids.end(), "no active bid for name" );
                eosio_assert( current->high_bidder == creator, "only highest bidder can claim" );
                eosio_assert( current->high_bid < 0, "auction for name is not closed yet" );
                bids.erase( current );
            } else {
                eosio_assert( creator == suffix, "only suffix may create this account" );
            }
        }
    }
}

}

EOSIO_DISPATCH( cyber::bios, (newaccount)(setglimits)(setprods)(setparams)(reqauth)(setabi)(setcode)(onblock)(bidname)(bidrefund) )
