#pragma once
#include <eosio/action.hpp>
#include <eosio/crypto.hpp>
#include <eosio/eosio.hpp>
#include <eosio/asset.hpp>
#include <eosio/privileged.hpp>
#include <eosio/producer_schedule.hpp>
#include <eosio/singleton.hpp>
#include <eosio/time.hpp>
#include <cyber.token/cyber.token.hpp>
#include <common/dispatchers.hpp>

namespace cyber {
   using eosio::permission_level;
   using eosio::public_key;
   using eosio::ignore;
   using eosio::name;
   using eosio::time_point_sec;
   using eosio::contract;
   using eosio::asset;
   using eosio::symbol_code;

   struct permission_level_weight {
      permission_level  permission;
      uint16_t          weight;

      // explicit serialization macro is not necessary, used here only to improve compilation time
      EOSLIB_SERIALIZE( permission_level_weight, (permission)(weight) )
   };

   struct key_weight {
      eosio::public_key  key;
      uint16_t           weight;

      // explicit serialization macro is not necessary, used here only to improve compilation time
      EOSLIB_SERIALIZE( key_weight, (key)(weight) )
   };

   struct wait_weight {
      uint32_t           wait_sec;
      uint16_t           weight;

      // explicit serialization macro is not necessary, used here only to improve compilation time
      EOSLIB_SERIALIZE( wait_weight, (wait_sec)(weight) )
   };

   struct authority {
      uint32_t                              threshold = 0;
      std::vector<key_weight>               keys;
      std::vector<permission_level_weight>  accounts;
      std::vector<wait_weight>              waits;

      // explicit serialization macro is not necessary, used here only to improve compilation time
      EOSLIB_SERIALIZE( authority, (threshold)(keys)(accounts)(waits) )
   };
   
    struct block_header {
        uint32_t                                  timestamp;
        name                                      producer;
        uint16_t                                  confirmed = 0;
        eosio::checksum256                        previous;
        eosio::checksum256                        transaction_mroot;
        eosio::checksum256                        action_mroot;
        uint32_t                                  schedule_version = 0;
        std::optional<eosio::producer_schedule>   new_producers;
   };

   class [[eosio::contract("cyber.bios")]] bios : public contract {
      struct state_info {
          time_point_sec last_close_bid;
      };
      using state_singleton [[eosio::order("id","asc")]] =
        eosio::singleton<"biosstate"_n, state_info>;

      struct bid_refund {
        name         bidder;
        eosio::asset amount;

        uint64_t primary_key()const { return bidder.value; }
      };
      using bid_refund_table [[eosio::order("bidder","asc")]] =
        eosio::multi_index<"bidrefunds"_n, bid_refund>;

      struct name_bid {
        name              newname;
        name              high_bidder;
        int64_t           high_bid = 0; ///< negative high_bid == closed auction waiting to be claimed
        eosio::time_point_sec last_bid_time;

        uint64_t primary_key()const { return newname.value;                    }
        uint64_t by_high_bid()const { return static_cast<uint64_t>(-high_bid); }
      };
      using by_high [[using eosio: order("high_bid","desc"), non_unique]] =
        eosio::indexed_by<"highbid"_n, eosio::const_mem_fun<name_bid, uint64_t, &name_bid::by_high_bid>>;
      using name_bid_table [[eosio::order("newname","asc")]] =
        eosio::multi_index<"namebids"_n, name_bid, by_high>;
        
      struct auto_recall {
        uint64_t id;
        eosio::symbol_code token_code;
        name account;
        bool break_fee_enabled = false;
        bool break_min_stake_enabled = false;
        uint64_t primary_key()const { return id; }
        using key_t = std::tuple<eosio::symbol_code, name>;
        key_t by_key()const { return std::make_tuple(token_code, account); }
      };
      using autorc_key_index [[using eosio: order("token_code"), order("account")]] =
        eosio::indexed_by<"bykey"_n, eosio::const_mem_fun<auto_recall, auto_recall::key_t, &auto_recall::by_key> >;
      using autorcs [[eosio::order("id")]] =
        eosio::multi_index<"stake.autorc"_n, auto_recall, autorc_key_index>;
      void autorcs_dummy() { autorcs autorcs_tabl(_self, _self.value); } // an ugly way to make abi appear
    
      public:
         using contract::contract;
         [[eosio::action]]
         void newaccount( name             creator,
                          name             name,
                          ignore<authority> owner,
                          ignore<authority> active);


         [[eosio::action]]
         void updateauth(  ignore<name>  account,
                           ignore<name>  permission,
                           ignore<name>  parent,
                           ignore<authority> auth ) {}

         [[eosio::action]]
         void deleteauth( ignore<name>  account,
                          ignore<name>  permission ) {}

         [[eosio::action]]
         void linkauth(  ignore<name>    account,
                         ignore<name>    code,
                         ignore<name>    type,
                         ignore<name>    requirement  ) {}

         [[eosio::action]]
         void unlinkauth( ignore<name>  account,
                          ignore<name>  code,
                          ignore<name>  type ) {}

         [[eosio::action]]
         void canceldelay( ignore<permission_level> canceling_auth, ignore<eosio::checksum256> trx_id ) {}

         [[eosio::action]]
         void onerror( ignore<uint128_t> sender_id, ignore<std::vector<char>> sent_trx ) {}

         [[eosio::action]]
         void setcode( name account, uint8_t vmtype, uint8_t vmversion, const std::vector<char>& code ) {}

         [[eosio::action]]
         void setprods( std::vector<eosio::producer_key> schedule ) {
            require_auth( _self );
            eosio::set_proposed_producers( schedule );
         }

         [[eosio::action]]
         void setparams( const eosio::blockchain_parameters& params ) {
            require_auth( _self );
            eosio::set_blockchain_parameters( params );
         }

         [[eosio::action]]
         void reqauth( name from ) {
            require_auth( from );
         }

         [[eosio::action]]
         void setabi( name account, const std::vector<char>& abi ) {}

         [[eosio::action]]
         void checkwin();

         [[eosio::action]]
         void bidname( name bidder, name newname, eosio::asset bid );

         [[eosio::action]]
         void bidrefund( name bidder );

         [[eosio::action]] void onblock(ignore<block_header> header);

         [[eosio::action]]
         void providebw(name provider, name account) {} // defined in cyberway/libraries/chain/cyberway/cyberway_contract.cpp
         
         [[eosio::action]]
         void checkstake(name account, symbol_code token_code);
   };

} /// namespace cyber
