/**
 *  @file
 *  @copyright defined in eos/LICENSE.txt
 */
#pragma once

#include <eosio/eosio.hpp>

namespace eosio {

   class [[eosio::contract("cyber.rejector")]] rejector : public contract {
      public:
         using contract::contract;
   };

} /// namespace eosio
