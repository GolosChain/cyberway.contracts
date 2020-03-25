#pragma once
#include "test_api_helper.hpp"


namespace eosio { namespace testing {

struct recipient {
    name    to;
    asset   quantity;
    string  memo;
};

struct cyber_token_api: base_contract_api {
    cyber_token_api(golos_tester* tester, name code, symbol sym)
    :   base_contract_api(tester, code)
    ,   _symbol(sym)
    ,   _symbol_code(sym.to_symbol_code()) {}

    symbol _symbol;
    symbol_code _symbol_code;

    //// token actions
    action_result create(account_name issuer, asset maximum_supply) {
        return push(N(create), _code, args()
            ("issuer", issuer)
            ("maximum_supply", maximum_supply)
        );
    }

    action_result issue(account_name issuer, account_name to, double quantity, string memo = "") {
        return issue(issuer, to, make_asset(quantity), memo);
    }
    action_result issue(account_name issuer, account_name to, asset quantity, string memo = "") {
        return push(N(issue), issuer, args()
            ("to", to)
            ("quantity", quantity)
            ("memo", memo)
        );
    }

    action_result open(account_name owner, account_name payer = {}) {
        if (payer.empty()) payer = owner;
        return open(owner, _symbol, payer);
    }
    action_result open(account_name owner, symbol symbol, account_name payer) {
        return push(N(open), owner, args()
            ("owner", owner)
            ("symbol", symbol)
            ("ram_payer", payer)
        );
    }

    action_result close(account_name owner) {
        return close(owner, _symbol);
    }
    action_result close(account_name owner, symbol symbol) {
        return push(N(close), owner, args()
            ("owner", owner)
            ("symbol", symbol)
        );
    }

    action_result transfer(account_name from, account_name to, double quantity, string memo = "") {
        return transfer(from, to, make_asset(quantity), memo);
    }
    action_result transfer(account_name from, account_name to, asset quantity, string memo = "") {
        return push(N(transfer), from, args()
            ("from", from)
            ("to", to)
            ("quantity", quantity)
            ("memo", memo)
        );
    }

    action_result bulk_transfer( account_name from, std::vector<recipient> recipients ) {
        return push( N(bulktransfer), from, args()
            ( "from", from)
            ( "recipients", recipients)
        );
    }

    action_result retire(name signer, double quantity, string memo = "") {
        return retire(signer, make_asset(quantity), memo);
    }
    action_result retire(name signer, asset quantity, string memo = "") {
        return push(N(retire), signer, args()
            ("quantity", quantity)
            ("memo", memo)
        );
    }

    // safe
    action_result enable_safe(name owner, asset unlock, uint32_t delay, name trusted = {}) {
        return push(N(enablesafe), owner, args()
            ("owner", owner)
            ("unlock", unlock)
            ("delay", delay)
            ("trusted", trusted)
        );
    }

    action_result _disable_safe(name owner, name mod_id, signers_t signers) {
        return push_msig(N(disablesafe), signers, args()
            ("owner", owner)
            ("sym_code", _symbol_code)
            ("mod_id", mod_id)
        );
    }

    action_result _unlock_safe(name owner, asset unlock, name mod_id, signers_t signers) {
        return push_msig(N(unlocksafe), signers, args()
            ("owner", owner)
            ("unlock", unlock)
            ("mod_id", mod_id)
        );
    }

    action_result lock_safe(name owner, asset lock) {
        return push(N(locksafe), owner, args()
            ("owner", owner)
            ("lock", lock)
        );
    }

    action_result _modify_safe(
        name owner, optional<uint32_t> delay, optional<name> trusted, name mod_id, signers_t signers
    ) {
        return push_msig(N(modifysafe), signers, args()
            ("owner", owner)
            ("sym_code", _symbol_code)
            ("mod_id", mod_id)
            ("delay", delay)
            ("trusted", trusted)
        );
    }

    action_result _apply_safe_mod(name owner, name mod_id, signers_t signers) {
        return push_msig(N(applysafemod), signers, args()
            ("owner", owner)
            ("mod_id", mod_id)
        );
    }

    action_result cancel_safe_mod(name owner, name mod_id) {
        return push(N(cancelsafemod), owner, args()
            ("owner", owner)
            ("mod_id", mod_id)
        );
    }

    action_result global_lock(name owner, uint32_t period) {
        return push(N(globallock), owner, args()
            ("owner", owner)
            ("period", period)
        );
    }

    // safe shortcuts
    action_result enable_safe(name owner, double unlock, uint32_t delay, name trusted = {}) {
        return enable_safe(owner, make_asset(unlock), delay, trusted);
    }
    action_result disable_safe(name owner, name mod_id) {
        return _disable_safe(owner, mod_id, {owner});
    }
    action_result disable_safe2(name owner, name signer, name force_mod_id = {}) {
        return _disable_safe(owner, force_mod_id, {owner, signer});
    }
    action_result unlock_safe(name owner, name mod_id, double unlock) {
        return unlock_safe(owner, mod_id, make_asset(unlock));
    }
    action_result unlock_safe(name owner, name mod_id, asset unlock) {
        return _unlock_safe(owner, unlock, mod_id, {owner});
    }
    action_result unlock_safe2(name owner, double unlock, name signer, name force_mod_id = {}) {
        return unlock_safe2(owner, make_asset(unlock), signer, force_mod_id);
    }
    action_result unlock_safe2(name owner, asset unlock, name signer, name force_mod_id = {}) {
        return _unlock_safe(owner, unlock, force_mod_id, {owner, signer});
    }
    action_result lock_safe(name owner, double lock = 0) {
        return lock_safe(owner, make_asset(lock));
    }
    action_result modify_safe(name owner, name mod_id, optional<uint32_t> delay = {}, optional<name> trusted = {}) {
        return _modify_safe(owner, delay, trusted, mod_id, {owner});
    }
    action_result modify_safe2(
        name owner, optional<uint32_t> delay, optional<name> trusted, name signer, name force_mod_id = {}
    ) {
        return _modify_safe(owner, delay, trusted, force_mod_id, {owner, signer});
    }
    action_result apply_safe_mod(name owner, name mod_id) {
        return _apply_safe_mod(owner, mod_id, {owner});
    }
    action_result apply_safe_mod2(name owner, name mod_id, name signer) {
        return _apply_safe_mod(owner, mod_id, {owner, signer});
    }


    //// token tables
    variant get_stats() {
        auto sname = _symbol.to_symbol_code().value;
        auto v = get_struct(sname, N(stat), sname, "currency_stats");
        if (v.is_object()) {
            auto o = mvo(v);
            o["supply"] = o["supply"].as<asset>().to_string();
            o["max_supply"] = o["max_supply"].as<asset>().to_string();
            v = o;
        }
        return v;
    }

    variant get_account(account_name acc) {
        auto v = get_struct(acc, N(accounts), _symbol.to_symbol_code().value, "account");
        if (v.is_object()) {
            auto o = mvo(v);
            o["balance"] = o["balance"].as<asset>().to_string();
            o["payments"] = o["payments"].as<asset>().to_string();
            v = o;
        }
        return v;
    }

    std::vector<variant> get_accounts(account_name user) {
        return _tester->get_all_chaindb_rows(_code, user, N(accounts), false);
    }

    variant get_safe(name acc) {
        auto v = get_struct(acc, N(accounts), _symbol_code.value, "");
        return v.is_object() && v.get_object().contains("safe") ? v["safe"] : variant{};
    }

    variant get_safe_mod(name acc, name mod_id) {
        return get_struct(acc, N(safemod), mod_id.value, "");
    }

    variant get_global_lock(name acc) {
        return get_singleton(acc, N(lock), "");
    }

    // generated objects
    variant make_safe(double unlocked, uint32_t delay, name trusted = {}) {
        return mvo()("unlocked", make_asset(unlocked).get_amount())("delay", delay)("trusted", trusted);
    }
    variant make_safe_mod(name id, double unlock, optional<uint32_t> delay = {}, optional<name> trusted = {}) {
        auto mod = mvo()("id", id)("sym_code", _symbol_code)("unlock", to_shares(unlock));
        if (delay) mod = mod("delay", *delay);
        if (trusted) mod = mod("trusted", *trusted);
        // date
        return mod;
    }

    //// helpers
    string name() const {
        return _symbol.name();
    }
    double satoshi() const {
        return 1. / _symbol.precision();
    }
    asset satoshi_asset() {
        return make_asset(satoshi());
    }
    int64_t to_shares(double x) const {
        return x * _symbol.precision() + .5 * (x < 0 ? 0 : 1);
    }
    asset make_asset(double x = 0) const {
        return asset(to_shares(x), _symbol);
    }
    asset from_amount(int64_t x) const {
        return asset(x, _symbol);
    }
    string asset_str(double x = 0) {
        return make_asset(x).to_string();
    }
    symbol bad_sym(int diff = 1) const {
        return symbol{static_cast<uint8_t>(_symbol.decimals() + diff), name().c_str()};
    }

};


}} // eosio::testing
FC_REFLECT(eosio::testing::recipient, (to)(quantity)(memo))
