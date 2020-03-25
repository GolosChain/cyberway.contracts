/**
 *  @file
 *  @copyright defined in eos/LICENSE.txt
 */
#pragma once

#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>
#include <eosio/singleton.hpp>
#include <eosio/binary_extension.hpp>

#include <string>
#include <vector>

namespace eosiosystem {
   class system_contract;
}

namespace eosio {

   using std::string;
   using std::vector;

   class [[eosio::contract("cyber.token")]] token : public contract {
      public:
         using contract::contract;

         [[eosio::action]]
         void create( name   issuer,
                      asset  maximum_supply);

         [[eosio::action]]
         void issue( name to, asset quantity, string memo );

         [[eosio::action]]
         void retire( asset quantity, string memo );

         [[eosio::action]]
         void transfer( name    from,
                        name    to,
                        asset   quantity,
                        string  memo );

         struct recipient {
             name    to;
             asset   quantity;
             string  memo;
         };

         [[eosio::action]]
         void bulktransfer( name from, vector<recipient> recipients );

         [[eosio::action]]
         void payment( name    from,
                       name    to,
                       asset   quantity,
                       string  memo );

         [[eosio::action]]
         void bulkpayment( name from, vector<recipient> recipients );

         [[eosio::action]]
         void claim(name owner , asset quantity);

         [[eosio::action]]
         void open( name owner, const symbol& symbol, name ram_payer );

         [[eosio::action]]
         void close( name owner, const symbol& symbol );

         /**
            \brief The \ref enablesafe action enables a safe on given balance and sets its initial parameters.

            \param owner account name of safe owner
            \param unlock amount of tokens to initially unlock in the safe. This parameter must be greater than or equal to "0" and have correct token symbol
            \param delay duration of locked period (in seconds). This parameter must be greater than "0"
            \param trusted name of trusted account; empty value means no trusted account set, otherwise account must exist and its name can't be equal to \a owner

            The balance owner calls this action to enable a safe for tokens with symbol provided in asset and set its initial parameters. The safe must not exist when this action is called. The action locks tokens instantly.

            When enabled, the safe locks all tokens except \a unlock amount. Locked tokens can still be used, but they cannot be transferred. When \a owner transfers tokens, the unlocked amount is reduced by a corresponding value. The balance owner can not transfer more tokens than he unlocked. Tokens obtained from incoming transfer/issue are automatically locked.

            \signreq
                  — the \a owner account.
         */
         [[eosio::action]] void enablesafe(name owner, asset unlock, uint32_t delay, name trusted);

         /**
            \brief The \ref disablesafe action disables a safe on given balance and sets its initial parameters.

            \param owner account name of safe owner
            \param sym_code symbol code of the token for which the safe is disabling
            \param mod_id named identifier of the current safe change. It is required to provide the same value to find delayed disable when apply or cancel it. The name must be empty ("") if disable instantly

            The balance owner calls this action to disable his safe for \a sym_code tokens. The safe must be enabled when calling this action. The action disables the safe with a delay set previously. If a trusted account has been set and action contains his authorization, the safe is disabled instantly.

            \signreq
                  — the \a owner account (required)
                  — the trusted account from the currently active safe parameters (optional).
         */
         [[eosio::action]] void disablesafe(name owner, symbol_code sym_code, name mod_id);

         /**
            \brief The \ref unlocksafe action unlocks some funds in a safe.

            \param owner account name of safe owner
            \param unlock amount of tokens to unlock in the safe. This parameter must be greater than "0", it may exceed balance
            \param mod_id identifier of the current change. It is used to find delayed unlock when apply or cancel it. The name must be empty ("") if unlocking instantly

            The balance owner calls this action to increase amount of unlocked tokens in the safe. Tokens are unlocked with a delay set previously. If a trusted account has been set and the action contains his authorization, then the tokens are unlocked instantly, otherwise unlock should be applied after a delay using the \ref applysafemod action.

            \signreq
                  — the \a owner account (required)
                  — the trusted account from the currently active safe parameters (optional).
         */
         [[eosio::action]] void unlocksafe(name owner, asset unlock, name mod_id);

         /**
            \brief The \ref locksafe action locks previously unlocked tokens.

            \param owner account name of safe owner
            \param lock amount of unlocked tokens to lock in the safe. To lock all tokens, it is required to specify "0" (and correct token symbol), otherwise this parameter must be greater than "0" and not greater than amount of currently unlocked tokens

            The balance owner calls this action to lock tokens previously unlocked with \ref enablesafe or \ref unlocksafe (followed by \ref applysafemod). The action instantly reduces amount of unlocked tokens by value provided in \a lock.

            \signreq
                  — the \a owner account.
         */
         [[eosio::action]] void locksafe(name owner, asset lock);

         /**
            \brief The \ref modifysafe action changes delay and/or trusted account of a safe.

            \param owner account name of safe owner
            \param sym_code symbol code of tokens for which safe parameters are to be changed
            \param mod_id identifier of the current change. It is used to find delayed change when apply or cancel it. The name must be empty ("") if changing instantly
            \param delay new duration of locked period (optional, in seconds). This parameter must be greater than "0". It must be specified if no \a trusted account set. The parameter value must be different from the current one if set in instant change
            \param trusted name of a trusted account (optional). To remove trusted account it needs to be an empty name. The name must be specify if no \a delay set. The parameter must differ from the current value if set in instant change

            The balance owner calls this action to change some safe parameters. The safe must be enabled earlier. The change is delayed by the current value of the \a delay parameter. If a trusted account has been set and the action contains his authorization, the new parameters are applied instantly. Otherwise they should be applied after a delay using \ref applysafemod action.

            \signreq
                  — the \a owner account (required)
                  — the trusted account from the currently active parameters (optional).
         */
         [[eosio::action]] void modifysafe(name owner, symbol_code sym_code, name mod_id,
            std::optional<uint32_t> delay, std::optional<name> trusted);

         /**
            \brief The \ref applysafemod action applies delayed change of a safe (tokens unlock or new parameters or disable a safe).

            \param owner account name of safe owner
            \param mod_id identifier of the change to apply

            The balance owner calls this action to apply delayed tokens unlock or change of the safe parameters. If current safe parameters have trusted account and the action contains his authorization, then new parameters are applied instantly. Otherwise they can be applied only after a delay.

            \signreq
                  — the \a owner account (required)
                  — the trusted account from the currently active parameters (optional).
         */
         [[eosio::action]] void applysafemod(name owner, name mod_id);

         /**
            \brief The \ref cancelsafemod action cancels delayed change of a safe (tokens unlock or new parameters, or disable a safe).

            \param owner account name of safe owner
            \param mod_id identifier of the change to cancel

            The balance owner calls this action to instantly cancel delayed tokens unlock or change of the safe parameters.

            \signreq
                  — the \a owner account.
         */
         [[eosio::action]] void cancelsafemod(name owner, name mod_id);

         /**
            \brief The \ref globallock action locks all tokens and delayed mods to given period of time.

            \param owner account name of tokens owner
            \param period lock duration (in seconds). This parameter can not reduce existing global lock duration. Its value must be greater than "0"

            The balance owner (or authorized recovery contract) calls this action to instantly lock all of his tokens and prevent delayed mods execution for a specified period of time. Global lock has higher priority than safe unlocked tokens.

            \signreq
                  — the \a owner account.
         */
         [[eosio::action]] void globallock(name owner, uint32_t period); // TODO: Can also add "deletelock" to free storage

         static asset get_supply( name token_contract_account, symbol_code sym_code )
         {
            stats statstable( token_contract_account, sym_code.raw() );
            const auto& st = statstable.get( sym_code.raw() );
            return st.supply;
         }

         static asset get_max_supply( name token_contract_account, symbol_code sym_code )
         {
            stats statstable( token_contract_account, sym_code.raw() );
            const auto& st = statstable.get( sym_code.raw() );
            return st.max_supply;
         }

         static asset get_balance( name token_contract_account, name owner, symbol_code sym_code )
         {
            accounts accountstable( token_contract_account, owner.value );
            const auto& ac = accountstable.get( sym_code.raw() );
            return ac.balance;
         }

         static name get_issuer( name token_contract_account, symbol_code sym_code )
         {
            stats statstable( token_contract_account, sym_code.raw() );
            const auto& st = statstable.get( sym_code.raw() );
            return st.issuer;
         }

         static bool balance_exist( name token_contract_account, name owner, symbol_code sym_code )
         {
            accounts accountstable( token_contract_account, owner.value );
            return accountstable.find( sym_code.raw() ) != accountstable.end();
         }

         static inline void validate_symbol(name token_contract, const asset a) {
            validate_symbol(token_contract, a.symbol);
         }

         static inline void validate_symbol(name token_contract, const symbol sym) {
            auto supply = get_supply(token_contract, sym.code());
            check(supply.symbol == sym, "symbol precision mismatch");
         }

         static inline time_point_sec get_global_lock_time(name token_contract, name account) {
            lock_singleton lock(token_contract, account.value);
            return lock.get_or_default().unlocks;
         }

         static inline bool get_global_lock_state(name token_contract, name account, uint32_t period=0) {
            auto unlock_time = get_global_lock_time(token_contract, account);
            time_point_sec time{eosio::current_time_point() + eosio::seconds(period)};
            return time <= unlock_time;
         }

      private:
         struct safe_t {
            int64_t  unlocked;   //!< Amount of unlocked tokens in the safe, share_type
            uint32_t delay;      //!< Delay in seconds of unlock/modify period
            name     trusted;    //!< Trusted account, empty name means no trusted account set
         };

         struct account {
            asset    balance;
            asset    payments;

            eosio::binary_extension<safe_t, write_strategy::no_value> safe;

            uint64_t primary_key()const { return balance.symbol.code().raw(); }
         };

         struct [[eosio::event("currency")]] currency_stats {
            asset    supply;
            asset    max_supply;
            name     issuer;

            uint64_t primary_key()const { return supply.symbol.code().raw(); }
         };

         struct [[eosio::event]] balance_event {
            name     account;
            asset    balance;
            asset    payments;
         };

         /**
            \brief DB record containing information about a delayed safe modify
            \ingroup token_tables
         */
         // DOCS_TABLE: safemod
         struct safemod {
            name id;                //!< modification id of the safe
            symbol_code sym_code;   //!< symbol code of the safe (tokens symbol code)
            time_point_sec date;    //!< time when delayed changes become ready to apply
            int64_t unlock;         //!< number of tokens to unlock or 0 (share_type)
            std::optional<uint32_t> delay;  //!< new delay to set
            std::optional<name> trusted;    //!< new trusted account to set

            uint64_t primary_key() const { return id.value; }
            using key_t = std::tuple<symbol_code, name>;
            key_t by_symbol_code() const { return std::make_tuple(sym_code, id); }

#ifndef UNIT_TEST_ENV
            EOSLIB_SERIALIZE(safemod, (id)(sym_code)(date)(unlock)(delay)(trusted))
#endif
         };

         /**
            \brief DB record containing information about a global lock; singleton; scope = safe owner
            \ingroup token_tables
         */
         // DOCS_TABLE: lock
         struct lock {
            time_point_sec unlocks; //!< time when lock becomes ineffective
         };

         using accounts [[eosio::order("balance._sym")]] =
            eosio::multi_index<"accounts"_n, account>;
         using stats [[using eosio: order("supply._sym"), scope_type("symbol_code")]] =
            eosio::multi_index<"stat"_n, currency_stats>;

         using safemod_sym_idx [[using eosio: order("sym_code","asc"), order("id","asc")]] =
            eosio::indexed_by<"bysymbolcode"_n, eosio::const_mem_fun<safemod, safemod::key_t, &safemod::by_symbol_code>>;
         using safemod_tbl [[eosio::order("id","asc")]] =
            eosio::multi_index<"safemod"_n, safemod, safemod_sym_idx>;
         using lock_singleton [[eosio::order("id","asc")]] =
            eosio::singleton<"lock"_n, lock>;

         void sub_balance( name owner, asset value );
         void add_balance( name owner, asset value, name ram_payer );
         void add_payment( name owner, asset value, name ram_payer );

         void send_currency_event(const currency_stats& stat);
         void send_balance_event(name acc, const account& accinfo);

         void do_transfer( name    from,
                           name    to,
                           const asset& quantity,
                           const string& memo,
                           bool payment = false);

         void delay_safe_change(
            name owner, asset unlock, name mod_id, std::optional<uint32_t> delay, std::optional<name> trusted,
            bool check_params = true, bool check_sym = true);
         void delay_safe_change(
            name owner, symbol_code sym_code, name mod_id, std::optional<uint32_t> delay, std::optional<name> trusted,
            bool check_params = true);

         static inline bool is_locked(name token_contract, name owner) {
            lock_singleton lock(token_contract, owner.value);
            return lock.exists() && lock.get().unlocks > eosio::current_time_point();
         }

   };
} /// namespace eosio
