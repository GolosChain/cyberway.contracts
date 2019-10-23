/**
 *  @file
 *  @copyright defined in eos/LICENSE.txt
 */
#pragma once

#include <eosio/eosio.hpp>
#include <eosio/asset.hpp>

namespace eosio {

   class [[eosio::contract("cyber.incomereject")]] incomereject : public contract {
      public:
         using contract::contract;

         void on_transfer(name from, name to, asset quantity, std::string memo);
   };

} /// namespace eosio
