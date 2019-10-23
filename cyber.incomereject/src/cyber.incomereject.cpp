/**
 *  @file
 *  @copyright defined in eos/LICENSE.txt
 */

#include <cyber.incomereject/cyber.incomereject.hpp>
#include <cyber.token/cyber.token.hpp>
#include <common/dispatchers.hpp>

namespace eosio {

void incomereject::on_transfer(name from, name to, asset quantity, std::string memo) {
    eosio::check(_self != to, "Incoming funds rejected");
}

} /// namespace eosio

extern "C" {
   [[eosio::wasm_entry]]
   void apply( uint64_t receiver, uint64_t code, uint64_t action ) {
      if (code == "cyber.token"_n.value) {
         if (action == "transfer"_n.value) {
            eosio::execute_action(eosio::name(receiver), eosio::name(code), &eosio::incomereject::on_transfer);
         } else if (action == "bulktransfer"_n.value) {
            dispatch_with_transfer_helper(eosio::name(receiver), eosio::name(code), &eosio::incomereject::on_transfer);
         }
      }
   }
}
