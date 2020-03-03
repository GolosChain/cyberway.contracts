#pragma once
#include <eosio/eosio.hpp>
#include <eosio/ignore.hpp>
#include <eosio/transaction.hpp>
#include <eosio/binary_extension.hpp>

namespace eosio {

   class [[eosio::contract("cyber.msig")]] multisig : public contract {
      public:
         using contract::contract;

         [[eosio::action]]
         void propose(ignore<name> proposer, ignore<name> proposal_name,
               ignore<std::vector<permission_level>> requested, ignore<transaction> trx,
               ignore<const eosio::binary_extension<std::string>> description);
         [[eosio::action]]
         void approve( name proposer, name proposal_name, permission_level level,
                       const eosio::binary_extension<eosio::checksum256>& proposal_hash );
         [[eosio::action]]
         void unapprove( name proposer, name proposal_name, permission_level level );
         [[eosio::action]]
         void cancel( name proposer, name proposal_name, name canceler );
         [[eosio::action]]
         void exec( name proposer, name proposal_name, name executer );
         [[eosio::action]]
         void invalidate( name account );

      private:
         struct proposal {
            name                            proposal_name;
            std::vector<char>               packed_transaction;

            uint64_t primary_key()const { return proposal_name.value; }
         };

         using proposals [[eosio::order("proposal_name")]] =
            eosio::multi_index<"proposal"_n, proposal>;

         struct approval {
            permission_level level;
            time_point       time;
         };

         struct approvals_info {
            uint8_t                 version = 1;
            name                    proposal_name;
            //requested approval doesn't need to cointain time, but we want requested approval
            //to be of exact the same size ad provided approval, in this case approve/unapprove
            //doesn't change serialized data size. So, we use the same type.
            std::vector<approval>   requested_approvals;
            std::vector<approval>   provided_approvals;

            uint64_t primary_key()const { return proposal_name.value; }
         };

         using approvals [[eosio::order("proposal_name")]] =
            eosio::multi_index<"approvals2"_n, approvals_info> ;

         struct invalidation {
            name         account;
            time_point   last_invalidation_time;

            uint64_t primary_key() const { return account.value; }
         };

         using invalidations [[eosio::order("account")]] =
            eosio::multi_index<"invals"_n, invalidation>;
   };

} /// namespace eosio
