/**
 *  @file
 *  @copyright defined in eos/LICENSE.txt
 */

#include <cyber.rejector/cyber.rejector.hpp>

namespace eosio {

} /// namespace eosio

extern "C" {
   [[eosio::wasm_entry]]
   void apply( uint64_t receiver, uint64_t code, uint64_t action ) {
      eosio::check(false, "Action disabled");
   }
}
