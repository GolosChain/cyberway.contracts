/**
 *  @file
 *  @copyright defined in eos/LICENSE.txt
 */

#include <eosio/event.hpp>
#include <cyber.token/cyber.token.hpp>
#include <set>

namespace eosio {

namespace config {
    static constexpr size_t max_memo_size = 384;
    static constexpr char memo_error[] = "memo has more than 384 bytes";
    const uint32_t seconds_per_day = 24 * 60 * 60; // TODO: move to some global consts
    static constexpr uint32_t safe_max_delay = 30 * seconds_per_day; // max delay and max lock period
}

void token::send_currency_event(const currency_stats& stat) {
    eosio::event(_self, "currency"_n, stat).send();
}

void token::send_balance_event(name acc, const account& accinfo) {
    balance_event data{acc, accinfo.balance, accinfo.payments};
    eosio::event(_self, "balance"_n, data).send();
}

void token::create( name   issuer,
                    asset  maximum_supply )
{
    require_auth( _self );
    eosio::check(is_account(issuer), "issuer account does not exist");

    auto sym = maximum_supply.symbol;
    eosio::check( sym.is_valid(), "invalid symbol name" );
    eosio::check( maximum_supply.is_valid(), "invalid supply");
    eosio::check( maximum_supply.amount > 0, "max-supply must be positive");

    stats statstable( _self, sym.code().raw() );
    auto existing = statstable.find( sym.code().raw() );
    eosio::check( existing == statstable.end(), "token with symbol already exists" );

    statstable.emplace( _self, [&]( auto& s ) {
       s.supply.symbol = maximum_supply.symbol;
       s.max_supply    = maximum_supply;
       s.issuer        = issuer;

       send_currency_event(s);
    });
}


void token::issue( name to, asset quantity, string memo )
{
    auto sym = quantity.symbol;
    eosio::check( sym.is_valid(), "invalid symbol name" );
    eosio::check( memo.size() <= config::max_memo_size, config::memo_error );

    stats statstable( _self, sym.code().raw() );
    auto existing = statstable.find( sym.code().raw() );
    eosio::check( existing != statstable.end(), "token with symbol does not exist, create token before issue" );
    const auto& st = *existing;

    require_auth( st.issuer );
    eosio::check( quantity.is_valid(), "invalid quantity" );
    eosio::check( quantity.amount > 0, "must issue positive quantity" );

    eosio::check( quantity.symbol == st.supply.symbol, "symbol precision mismatch" );
    eosio::check( quantity.amount <= st.max_supply.amount - st.supply.amount, "quantity exceeds available supply");

    statstable.modify( st, same_payer, [&]( auto& s ) {
       s.supply += quantity;
       send_currency_event(s);
    });

    add_balance( st.issuer, quantity, st.issuer );

    if( to != st.issuer ) {
      SEND_INLINE_ACTION( *this, transfer, { {st.issuer, "active"_n} },
                          { st.issuer, to, quantity, memo }
      );
    }
}

void token::retire( asset quantity, string memo )
{
    auto sym = quantity.symbol;
    eosio::check( sym.is_valid(), "invalid symbol name" );
    eosio::check( memo.size() <= config::max_memo_size, config::memo_error );

    stats statstable( _self, sym.code().raw() );
    auto existing = statstable.find( sym.code().raw() );
    eosio::check( existing != statstable.end(), "token with symbol does not exist" );
    const auto& st = *existing;

    require_auth( st.issuer );
    eosio::check( quantity.is_valid(), "invalid quantity" );
    eosio::check( quantity.amount > 0, "must retire positive quantity" );

    eosio::check( quantity.symbol == st.supply.symbol, "symbol precision mismatch" );

    statstable.modify( st, same_payer, [&]( auto& s ) {
       s.supply -= quantity;
       send_currency_event(s);
    });

    sub_balance( st.issuer, quantity );
}

void token::transfer( name    from,
                      name    to,
                      asset   quantity,
                      string  memo )
{
    require_recipient( from );
    require_recipient( to );
    do_transfer(from, to, quantity, memo);
}

void token::payment( name    from,
                     name    to,
                     asset   quantity,
                     string  memo )
{
    do_transfer(from, to, quantity, memo, true);
}

void token::do_transfer( name  from,
                         name  to,
                         const asset& quantity,
                         const string& memo,
                         bool payment )
{
    if (!payment)
        eosio::check( from != to, "cannot transfer to self" );
    require_auth( from );
    eosio::check( is_account( to ), "to account does not exist");
    auto sym = quantity.symbol.code();
    stats statstable( _self, sym.raw() );
    const auto& st = statstable.get( sym.raw() );

    eosio::check( quantity.is_valid(), "invalid quantity" );
    eosio::check( quantity.amount > 0, "must transfer positive quantity" );
    eosio::check( quantity.symbol == st.supply.symbol, "symbol precision mismatch" );
    eosio::check( memo.size() <= config::max_memo_size, config::memo_error );

    auto payer = has_auth( to ) ? to : from;

    sub_balance( from, quantity );
    if (payment)
        add_payment( to, quantity, payer );
    else
        add_balance( to, quantity, payer );
}

void token::sub_balance( name owner, asset value ) {
   accounts from_acnts( _self, owner.value );

   const auto& from = from_acnts.get( value.symbol.code().raw(), "no balance object found" );
   eosio::check( from.balance.amount >= value.amount, "overdrawn balance" );

   from_acnts.modify( from, owner, [&]( auto& a ) {
         a.balance -= value;
         send_balance_event(owner, a);
      });

   check(!is_locked(_self, owner), "balance locked in safe");
   if (from.safe.has_value()) {
      from_acnts.modify(from, owner, [&](auto& a) {
         auto safe = a.safe.value();
         safe.unlocked -= value.amount;
         check(safe.unlocked >= 0, "overdrawn safe unlocked balance");
         a.safe.emplace(safe);
      });
   }
}

void token::add_balance( name owner, asset value, name ram_payer )
{
   accounts to_acnts( _self, owner.value );
   auto to = to_acnts.find( value.symbol.code().raw() );
   if( to == to_acnts.end() ) {
      to_acnts.emplace( ram_payer, [&]( auto& a ){
        a.balance = value;
        a.payments.symbol = value.symbol;
        send_balance_event(owner, a);
      });
   } else {
      to_acnts.modify( to, same_payer, [&]( auto& a ) {
        a.balance += value;
        send_balance_event(owner, a);
      });
   }
}

void token::add_payment( name owner, asset value, name ram_payer )
{
   accounts to_acnts( _self, owner.value );
   auto to = to_acnts.find( value.symbol.code().raw() );
   if( to == to_acnts.end() ) {
      to_acnts.emplace( ram_payer, [&]( auto& a ){
        a.balance.symbol = value.symbol;
        a.payments = value;
        send_balance_event(owner, a);
      });
   } else {
      to_acnts.modify( to, same_payer, [&]( auto& a ) {
        a.payments += value;
        send_balance_event(owner, a);
      });
   }
}

void token::open( name owner, const symbol& symbol, name ram_payer )
{
   require_auth( ram_payer );
   eosio::check( is_account( owner ), "owner account does not exist");

   auto sym_code_raw = symbol.code().raw();

   stats statstable( _self, sym_code_raw );
   const auto& st = statstable.get( sym_code_raw, "symbol does not exist" );
   eosio::check( st.supply.symbol == symbol, "symbol precision mismatch" );

   accounts acnts( _self, owner.value );
   auto it = acnts.find( sym_code_raw );
   if( it == acnts.end() ) {
      acnts.emplace( ram_payer, [&]( auto& a ){
        a.balance = asset{0, symbol};
        a.payments = asset{0, symbol};
      });
   }
}

void token::close( name owner, const symbol& symbol )
{
   require_auth( owner );
   accounts acnts( _self, owner.value );
   auto it = acnts.find( symbol.code().raw() );
   eosio::check( it != acnts.end(), "Balance row already deleted or never existed. Action won't have any effect." );
   eosio::check( it->balance.amount == 0, "Cannot close because the balance is not zero." );
   eosio::check( it->payments.amount == 0, "Cannot close because account has payments." );
   eosio::check( !it->safe.has_value(), "Cannot close because safe enabled." );
   acnts.erase( it );
}

void token::claim( name owner, asset quantity )
{
   require_auth( owner );

   eosio::check( quantity.is_valid(), "invalid quantity" );
   eosio::check( quantity.amount > 0, "must transfer positive quantity" );

   accounts owner_acnts( _self, owner.value );
   auto account = owner_acnts.find( quantity.symbol.code().raw() );
   eosio::check( account != owner_acnts.end(), "not found object account" );
   eosio::check( quantity.symbol == account->payments.symbol, "symbol precision mismatch" );
   eosio::check( account->payments >= quantity, "insufficient funds" );
   owner_acnts.modify( account, owner, [&]( auto& a ) {
       a.balance += quantity;
       a.payments -= quantity;

       send_balance_event(owner, a);
   });
}

void token::bulktransfer(name from, vector<recipient> recipients)
{
    require_recipient(from);
    eosio::check(recipients.size(), "recipients must not be empty");

    symbol temp_symbol = recipients.at(0).quantity.symbol;
    std::set<name> require_recipients;
    for (auto recipient_obj : recipients) {
        eosio::check(temp_symbol == recipient_obj.quantity.symbol, "transfer of different tokens is prohibited");
        do_transfer(from, recipient_obj.to, recipient_obj.quantity, recipient_obj.memo);

        auto result = require_recipients.insert(recipient_obj.to);
        if (result.second)
            require_recipient(recipient_obj.to);
    }
}

void token::bulkpayment(name from, vector<recipient> recipients)
{
    require_recipient(from);
    eosio::check(recipients.size(), "recipients must not be empty");

    symbol temp_symbol = recipients.at(0).quantity.symbol;
    for (auto recipient_obj : recipients) {
        eosio::check(temp_symbol == recipient_obj.quantity.symbol, "payment of different tokens is prohibited");
        do_transfer(from, recipient_obj.to, recipient_obj.quantity, recipient_obj.memo, true);
    }
}

////////////////////////////////////////////////////////////////
// safe related actions
using std::optional;

void check_safe_params(name owner, optional<uint32_t> delay, optional<name> trusted) {
   if (delay) {
      check(*delay > 0, "delay must be > 0");
      check(*delay <= config::safe_max_delay, "delay must be <= " + std::to_string(config::safe_max_delay));
   }
   if (trusted && *trusted != name()) {
      check(owner != *trusted, "trusted and owner must be different accounts");
      check(is_account(*trusted), "trusted account does not exist");
   }
}

void token::enablesafe(name owner, asset unlock, uint32_t delay, name trusted) {
   require_auth(owner);

   check(unlock.amount >= 0, "unlock amount must be >= 0");
   check_safe_params(owner, delay, trusted);
   if (unlock.symbol != symbol{}) {
      validate_symbol(_self, unlock);
   }

   accounts tbl(_self, owner.value);
   const auto scode = unlock.symbol.code();
   const auto& acc = tbl.get(scode.raw(), "no token account object found");
   check(!acc.safe.has_value(), "safe already enabled");

   // Do not allow to have delayed changes when enable the safe, they came from the previously enabled safe
   // and should be cancelled to make clean safe setup.
   safemod_tbl mods(_self, owner.value);
   auto idx = mods.get_index<"bysymbolcode"_n>();
   auto itr = idx.lower_bound(scode);
   check(itr == idx.end() || itr->sym_code != scode, "can't enable safe with existing delayed mods");

   tbl.modify(acc, owner, [&](auto& a) {
      a.safe.emplace(safe_t{unlock.amount, delay, trusted});
   });
}

template<typename Tbl, typename S>
void instant_safe_change(Tbl& tbl, S& acc,
   name owner, int64_t unlock, optional<uint32_t> delay, optional<name> trusted, bool ensure_change
) {
   if (delay && *delay == 0) {
      check(!unlock && !trusted, "SYS: incorrect disabling safe mod");
      tbl.modify(acc, owner, [](auto& a){
         a.safe.reset();
      });
   } else {
      bool changed = !ensure_change;
      auto safe = acc.safe.value();
      if (unlock) {
            safe.unlocked += unlock;
            check(safe.unlocked >= 0 && safe.unlocked <= asset::max_amount, "unlocked overflow");
            changed = true;
      }
      if (delay && *delay != safe.delay) {
            safe.delay = *delay;
            changed = true;
      }
      if (trusted && *trusted != safe.trusted) {
            safe.trusted = *trusted;
            changed = true;
      }
      check(changed, "change has no effect and can be cancelled");
      tbl.modify(acc, owner, [&](auto& a) {
         a.safe.emplace(safe);
      });
   }
}

// helper for actions which do not change `unlocked` and have incomplete asset symbol
void token::delay_safe_change(
   name owner, symbol_code scode, name mod_id, optional<uint32_t> delay, optional<name> trusted,
   bool check_params/*=true*/
) {
   const asset fake_asset{0, symbol{scode, 0}};
   delay_safe_change(owner, fake_asset, mod_id, delay, trusted, check_params, false);
}

void token::delay_safe_change(
   name owner, asset unlock, name mod_id, optional<uint32_t> delay, optional<name> trusted,
   bool check_params/*=true*/, bool check_sym/*=true*/
) {
   if (check_params) {
      check_safe_params(owner, delay, trusted);
   }
   if (check_sym) {
      validate_symbol(_self, unlock);
   }

   const auto scode = unlock.symbol.code();
   accounts tbl(_self, owner.value);
   const auto& acc = tbl.get(scode.raw(), "no token account object found");
   check(acc.safe.has_value(), "safe disabled");
   auto safe = acc.safe.value();

   const bool have_id = mod_id != name();
   const auto trusted_acc = safe.trusted;
   if (trusted_acc != name() && has_auth(trusted_acc)) {
      check(!have_id, "mod_id must be empty for trusted action");
      check(!delay || *delay != safe.delay, "can't set same delay");
      check(!trusted || *trusted != trusted_acc, "can't set same trusted");
      instant_safe_change(tbl, acc, owner, unlock.amount, delay, trusted, false);
   } else {
      check(have_id, "mod_id must not be empty");
      safemod_tbl mods(_self, owner.value);
      check(mods.find(mod_id.value) == mods.end(), "safe mod with the same id is already exists");
      mods.emplace(owner, [&](auto& d) {
         d.id = mod_id;
         d.sym_code = scode;
         d.date = eosio::current_time_point() + eosio::seconds(safe.delay);
         d.unlock = unlock.amount;
         d.delay = delay;
         d.trusted = trusted;
      });
   }
}

void token::disablesafe(name owner, symbol_code sym_code, name mod_id) {
   require_auth(owner);
   delay_safe_change(owner, sym_code, mod_id, 0, {}, false);
}

void token::unlocksafe(name owner, asset unlock, name mod_id) {
   require_auth(owner);
   check(unlock.amount > 0, "unlock amount must be > 0");
   delay_safe_change(owner, unlock, mod_id, {}, {});
}

void token::locksafe(name owner, asset lock) {
   require_auth(owner);
   check(lock.amount >= 0, "lock amount must be >= 0");
   validate_symbol(_self, lock); // checked within "<= unlocked", but have confusing message, so check here

   const auto scode = lock.symbol.code();
   accounts tbl(_self, owner.value);
   const auto& acc = tbl.get(scode.raw(), "no token account object found");
   check(acc.safe.has_value(), "safe disabled");
   auto safe = acc.safe.value();
   check(safe.unlocked > 0, "nothing to lock");
   check(safe.unlocked >= lock.amount, "lock must be <= unlocked");

   bool lock_all = lock.amount == 0;
   tbl.modify(acc, owner, [&](auto& a) {
      auto safe = a.safe.value();
      safe.unlocked -= lock_all ? safe.unlocked : lock.amount;
      a.safe.emplace(safe);
   });
}

void token::modifysafe(
   name owner, symbol_code sym_code, name mod_id, optional<uint32_t> delay, optional<name> trusted
) {
   require_auth(owner);
   check(delay || trusted, "delay and/or trusted must be set");
   delay_safe_change(owner, sym_code, mod_id, delay, trusted);
}

void token::applysafemod(name owner, name mod_id) {
   require_auth(owner);
   safemod_tbl mods(_self, owner.value);
   const auto& mod = mods.get(mod_id.value, "safe mod not found");

   accounts tbl(_self, owner.value);
   const auto& acc = tbl.get(mod.sym_code.raw(), "no token account object found");
   check(acc.safe.has_value(), "safe disabled");
   const auto& safe = acc.safe.value();

   bool trusted_apply = safe.trusted != name() && has_auth(safe.trusted);
   if (!trusted_apply) {
      check(mod.date <= eosio::current_time_point(), "safe change is time locked");
      check(!is_locked(_self, owner), "safe locked globally");
   }
   instant_safe_change(tbl, acc, owner, mod.unlock, mod.delay, mod.trusted, true);
   mods.erase(mod);
}

void token::cancelsafemod(name owner, name mod_id) {
   require_auth(owner);
   safemod_tbl mods(_self, owner.value);
   const auto& mod = mods.get(mod_id.value, "safe mod not found");
   mods.erase(mod);
}

void token::globallock(name owner, uint32_t period) {
   require_auth(owner);
   check(period > 0, "period must be > 0");
   check(period <= config::safe_max_delay, "period must be <= " + std::to_string(config::safe_max_delay));

   time_point_sec unlocks{eosio::current_time_point() + eosio::seconds(period)};
   lock_singleton lock(_self, owner.value);
   check(unlocks > lock.get_or_default().unlocks, "new unlock time must be greater than current");

   lock.set({unlocks}, owner);
}

} /// namespace eosio
