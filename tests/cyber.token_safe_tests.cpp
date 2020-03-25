#include "golos_tester.hpp"
#include "cyber.token_test_api.hpp"
#include "common/config.hpp"
#include "contracts.hpp"


using namespace cyber;
using namespace eosio::testing;
using namespace eosio::chain;
using namespace fc;
static const auto _token = symbol(3, "GLS");
static const auto _token2 = symbol(3, "TEST");

namespace cfg {
    const account_name token_name = N(cyber.token);
    constexpr uint32_t safe_max_delay = 30*24*60*60;
}


class cyber_token_safe_tester : public golos_tester {
protected:
    cyber_token_api token;
    cyber_token_api token2;

public:
    cyber_token_safe_tester()
        : golos_tester(cfg::token_name)
        , token({this, _code, _token})
        , token2({this, _code, _token2}) {
        create_accounts({_issuer, _alice, _bob, _carol, cfg::token_name});
        produce_block();
        install_contract(_code, contracts::token_wasm(), contracts::token_abi());
    }

protected:
    const uint32_t _delay = 60;
    const double _total = 400;

public:
    void init_without_open() {
        init(name{}, false);
    }
    void init(name issuer = {}, bool open = true) {
        if (!issuer) issuer = _issuer;
        const auto init_tokens = [&](cyber_token_api& token) {
            BOOST_CHECK_EQUAL(success(), token.create(issuer, token.make_asset(_total * 5)));
            BOOST_CHECK_EQUAL(success(), token.issue(issuer, issuer, token.make_asset(_total)));
        };
        init_tokens(token);
        init_tokens(token2);
        if (open) {
            BOOST_CHECK_EQUAL(success(), token.open(_alice));
            BOOST_CHECK_EQUAL(success(), token.open(_bob));
            BOOST_CHECK_EQUAL(success(), token2.open(_alice));
            BOOST_CHECK_EQUAL(success(), token2.open(_bob));
        }
    }

    const account_name _issuer = N(issuer);
    const account_name _alice = N(alice);
    const account_name _bob = N(bob);
    const account_name _carol = N(carol);
    const account_name _nobody = N(nobody); // not existing account

    struct errors: contract_error_messages {
        const string no_token_account = amsg("no token account object found");
        const string symbol_precision = amsg("symbol precision mismatch");
        const string unlock_lt0 = amsg("unlock amount must be >= 0");
        const string unlock_lte0 = amsg("unlock amount must be > 0");
        const string lock_lt0 = amsg("lock amount must be >= 0");
        const string unlocked_eq0 = amsg("nothing to lock");
        const string delay_lte0 = amsg("delay must be > 0");
        const string delay_gt_max = amsg("delay must be <= " + std::to_string(cfg::safe_max_delay));
        const string trusted_eq_owner = amsg("trusted and owner must be different accounts");
        const string trusted_not_exists = amsg("trusted account does not exist");
        const string already_enabled = amsg("safe already enabled");
        const string have_mods = amsg("can't enable safe with existing delayed mods");
        const string disabled = amsg("safe disabled");
        const string same_delay = amsg("can't set same delay");
        const string same_trusted = amsg("can't set same trusted");
        const string empty_mod_id = amsg("mod_id must not be empty");
        const string have_mod_id = amsg("mod_id must be empty for trusted action");
        const string same_mod_id = amsg("safe mod with the same id is already exists");
        const string lock_gt_unlocked = amsg("lock must be <= unlocked");
        const string nothing_set = amsg("delay and/or trusted must be set");
        const string mod_not_exists = amsg("safe mod not found");
        const string still_locked = amsg("safe change is time locked");
        const string nothing_to_apply = amsg("change has no effect and can be cancelled");
        const string global_lock = amsg("balance locked in safe");
        const string mod_global_lock = amsg("safe locked globally");
        const string balance_lock = amsg("overdrawn safe unlocked balance");
        const string balance_over = amsg("overdrawn balance");
        const string unlocked_over = amsg("unlocked overflow");
        const string period_le0 = amsg("period must be > 0");
        const string period_gt_max = amsg("period must be <= " + std::to_string(cfg::safe_max_delay));
        const string period_le_cur = amsg("new unlock time must be greater than current");
        const string close_with_safe = amsg("Cannot close because safe enabled.");
    } err;
};

BOOST_AUTO_TEST_SUITE(cyber_token_safe)

BOOST_FIXTURE_TEST_CASE(no_balance, cyber_token_safe_tester) try {
    BOOST_TEST_MESSAGE("Works only with opened balance");
    init_without_open();
    BOOST_CHECK(token.get_safe(_bob).is_null());

    BOOST_TEST_MESSAGE("--- fail if account object doesn't exist");
    const name mod_id = N(mod);
    BOOST_CHECK_EQUAL(err.no_token_account, token.enable_safe(_bob, 0, _delay));
    BOOST_CHECK_EQUAL(err.no_token_account, token.disable_safe(_bob, mod_id));
    BOOST_CHECK_EQUAL(err.no_token_account, token.unlock_safe(_bob, mod_id, 1));
    BOOST_CHECK_EQUAL(err.no_token_account, token.lock_safe(_bob, 1));
    BOOST_CHECK_EQUAL(err.no_token_account, token.modify_safe(_bob, mod_id, cfg::safe_max_delay/2));
    // Can't test apply_safe_mod with unexistig balance
    BOOST_TEST_MESSAGE("--- success after open balance");
    BOOST_CHECK_EQUAL(success(), token.open(_bob));
    BOOST_CHECK_EQUAL(success(), token.enable_safe(_bob, 0, _delay, _alice));

    BOOST_TEST_MESSAGE("--- fail to close balance with enabled safe");
    BOOST_CHECK_EQUAL(err.close_with_safe, token.close(_bob));
    BOOST_TEST_MESSAGE("--- success after disable safe");
    BOOST_CHECK_EQUAL(success(), token.disable_safe2(_bob, _alice));
    BOOST_CHECK_EQUAL(success(), token.close(_bob));

} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(enable, cyber_token_safe_tester) try {
    BOOST_TEST_MESSAGE("Enable the safe");
    init();
    BOOST_CHECK(token.get_safe(_bob).is_null());
    BOOST_TEST_MESSAGE("--- fail on bad params");
    BOOST_CHECK_EQUAL(err.unlock_lt0, token.enable_safe(_bob, -1, 0));
    BOOST_CHECK_EQUAL(err.unlock_lt0, token.enable_safe(_bob, -token.satoshi(), 0));
    BOOST_CHECK_EQUAL(err.delay_lte0, token.enable_safe(_bob, 0, 0));
    BOOST_CHECK_EQUAL(err.delay_gt_max, token.enable_safe(_bob, 0, cfg::safe_max_delay + 1));
    BOOST_CHECK_EQUAL(err.trusted_eq_owner, token.enable_safe(_bob, 0, _delay, _bob));
    BOOST_CHECK_EQUAL(err.trusted_not_exists, token.enable_safe(_bob, 0, _delay, _nobody));
    const asset bad_asset{0, token.bad_sym()};
    BOOST_CHECK_EQUAL(err.symbol_precision, token.enable_safe(_bob, bad_asset, _delay));

    BOOST_TEST_MESSAGE("--- success on valid params");
    BOOST_CHECK_EQUAL(success(), token.enable_safe(_bob, 0, _delay));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(0, _delay));
    produce_block();

    BOOST_TEST_MESSAGE("--- fail if already created");
    BOOST_CHECK_EQUAL(err.already_enabled, token.enable_safe(_bob, 0, _delay));
    BOOST_CHECK_EQUAL(err.already_enabled, token.enable_safe(_bob, 100500, cfg::safe_max_delay));

    BOOST_TEST_MESSAGE("--- success when create for different tokens with over-limit and max delay");
    BOOST_CHECK_EQUAL(success(), token2.enable_safe(_bob, 100500, cfg::safe_max_delay));
    CHECK_MATCHING_OBJECT(token2.get_safe(_bob), token2.make_safe(100500, cfg::safe_max_delay));

    // enable_safe with existing delayed mods checked in "disable safe test"
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(disable, cyber_token_safe_tester) try {
    BOOST_TEST_MESSAGE("Disable the safe");
    const auto mod_id = N(mod);
    init();

    BOOST_TEST_MESSAGE("--- fail if not enabled");
    BOOST_CHECK_EQUAL(err.disabled, token.disable_safe(_bob, {}));
    BOOST_CHECK_EQUAL(err.disabled, token.disable_safe(_bob, mod_id));

    BOOST_TEST_MESSAGE("--- enable for " << token.name());
    BOOST_CHECK_EQUAL(success(), token.enable_safe(_bob, 0, _delay));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(0, _delay));
    produce_block();

    BOOST_TEST_MESSAGE("--- still fail for " << token2.name());
    BOOST_CHECK_EQUAL(err.disabled, token2.disable_safe(_bob, {}));
    BOOST_CHECK_EQUAL(err.disabled, token2.disable_safe(_bob, mod_id));

    BOOST_TEST_MESSAGE("--- fail on bad params");
    BOOST_CHECK_EQUAL(err.empty_mod_id, token.disable_safe(_bob, {}));

    BOOST_TEST_MESSAGE("--- success on valid params");
    BOOST_CHECK_EQUAL(success(), token.disable_safe(_bob, mod_id));
    CHECK_MATCHING_OBJECT(token.get_safe_mod(_bob, mod_id), token.make_safe_mod(mod_id, 0, 0));
    BOOST_CHECK_EQUAL(err.still_locked, token.apply_safe_mod(_bob, mod_id));
    produce_block();

    BOOST_TEST_MESSAGE("--- fail if same mod_id and success if other");
    const auto mod2_id = N(mod2);
    BOOST_CHECK_EQUAL(success(), token.disable_safe(_bob, mod2_id));
    produce_block();
    BOOST_CHECK_EQUAL(err.same_mod_id, token.disable_safe(_bob, mod_id));
    BOOST_CHECK_EQUAL(err.same_mod_id, token.disable_safe(_bob, mod2_id));

    BOOST_TEST_MESSAGE("--- wait and disable");
    const auto blocks = seconds_to_blocks(_delay);
    produce_blocks(blocks - 1 - 2); // 2 for two produce_block() calls
    BOOST_CHECK_EQUAL(err.still_locked, token.apply_safe_mod(_bob, mod_id));
    produce_block();
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod(_bob, mod_id));
    BOOST_CHECK_EQUAL(err.disabled, token.disable_safe(_bob, mod_id));
    BOOST_CHECK(token.get_safe(_bob).is_null());
    BOOST_CHECK(token.get_safe_mod(_bob, mod_id).is_null());

    BOOST_TEST_MESSAGE("--- fail on re-enabling with existing mod");
    BOOST_CHECK_EQUAL(err.have_mods, token.enable_safe(_bob, 0, _delay));

    BOOST_TEST_MESSAGE("--- success when existing mod is for other symbol");
    BOOST_CHECK_EQUAL(success(), token2.enable_safe(_bob, 0, _delay));

    BOOST_TEST_MESSAGE("--- success when no more mods");
    BOOST_CHECK_EQUAL(success(), token.cancel_safe_mod(_bob, mod2_id));
    BOOST_CHECK_EQUAL(success(), token.enable_safe(_bob, 0, _delay));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(0, _delay));
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(lock_unlock, cyber_token_safe_tester) try {
    BOOST_TEST_MESSAGE("Unlock and lock the safe");
    init();

    BOOST_TEST_MESSAGE("--- fail if not enabled");
    const double one = 1;
    const auto mod_id = N(mod);
    BOOST_CHECK_EQUAL(err.disabled, token.unlock_safe(_bob, {}, one));
    BOOST_CHECK_EQUAL(err.disabled, token.unlock_safe(_bob, mod_id, one));
    BOOST_CHECK_EQUAL(err.disabled, token.lock_safe(_bob, one));

    BOOST_TEST_MESSAGE("--- fail if negative amount");
    BOOST_CHECK_EQUAL(err.unlock_lte0, token.unlock_safe(_bob, {}, -1));
    BOOST_CHECK_EQUAL(err.unlock_lte0, token.unlock_safe(_bob, mod_id, -1));
    BOOST_CHECK_EQUAL(err.lock_lt0, token.lock_safe(_bob, -1));
    BOOST_TEST_MESSAGE("--- fail if unlock with wrong precision");
    const asset bad{1, token.bad_sym()};
    BOOST_CHECK_EQUAL(err.symbol_precision, token.unlock_safe(_bob, {}, bad));
    BOOST_CHECK_EQUAL(err.symbol_precision, token.unlock_safe(_bob, mod_id, bad));
    BOOST_CHECK_EQUAL(err.symbol_precision, token.lock_safe(_bob, bad));
    BOOST_CHECK_EQUAL(err.symbol_precision, token.lock_safe(_bob, asset{1, token.bad_sym(-1)}));

    BOOST_TEST_MESSAGE("--- enable 1 token unlocked for " << token.name());
    BOOST_CHECK_EQUAL(success(), token.enable_safe(_bob, one, _delay));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(one, _delay));
    BOOST_TEST_MESSAGE("--- enable full locked for " << token2.name());
    BOOST_CHECK_EQUAL(success(), token2.enable_safe(_bob, 0, _delay));
    produce_block();

    BOOST_TEST_MESSAGE("--- fail if unlock with empty id");
    BOOST_CHECK_EQUAL(err.empty_mod_id, token.unlock_safe(_bob, {}, one));
    BOOST_TEST_MESSAGE("--- fail if lock too much");
    const auto satoshi = token.satoshi();
    BOOST_CHECK_EQUAL(err.lock_gt_unlocked, token.lock_safe(_bob, one + satoshi));
    BOOST_CHECK_EQUAL(err.unlocked_eq0, token2.lock_safe(_bob, token2.satoshi()));

    BOOST_TEST_MESSAGE("--- success if lock satoshi");
    BOOST_CHECK_EQUAL(success(), token.lock_safe(_bob, satoshi));
    BOOST_TEST_MESSAGE("--- success if lock half");
    const auto half = one / 2;
    BOOST_CHECK_EQUAL(success(), token.lock_safe(_bob, half));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(one - half - satoshi, _delay));
    produce_block();
    BOOST_CHECK_EQUAL(err.lock_gt_unlocked, token.lock_safe(_bob, half));
    BOOST_TEST_MESSAGE("--- success if lock remainig");
    BOOST_CHECK_EQUAL(success(), token.lock_safe(_bob, half - satoshi));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(0, _delay));
    BOOST_TEST_MESSAGE("--- fail if lock one more satoshi");
    BOOST_CHECK_EQUAL(err.unlocked_eq0, token.lock_safe(_bob));
    BOOST_CHECK_EQUAL(err.unlocked_eq0, token.lock_safe(_bob, satoshi));
    BOOST_CHECK_EQUAL(err.unlocked_eq0, token2.lock_safe(_bob));

    BOOST_TEST_MESSAGE("--- success if schedule valid unlock");
    const auto mod2_id = N(mod2);
    BOOST_CHECK(token.get_safe_mod(_bob, mod_id).is_null());
    BOOST_CHECK(token.get_safe_mod(_bob, mod2_id).is_null());
    BOOST_CHECK_EQUAL(success(), token.unlock_safe(_bob, mod_id, one));
    BOOST_CHECK_EQUAL(success(), token.unlock_safe(_bob, mod2_id, one));
    CHECK_MATCHING_OBJECT(token.get_safe_mod(_bob, mod_id), token.make_safe_mod(mod_id, one));
    CHECK_MATCHING_OBJECT(token.get_safe_mod(_bob, mod2_id), token.make_safe_mod(mod2_id, one));
    BOOST_CHECK_EQUAL(err.same_mod_id, token.unlock_safe(_bob, mod_id, half));

    BOOST_TEST_MESSAGE("--- fail to apply");
    BOOST_CHECK_EQUAL(err.still_locked, token.apply_safe_mod(_bob, mod_id));
    BOOST_TEST_MESSAGE("--- wait half time and add one more unlock");
    const auto blocks = seconds_to_blocks(_delay);
    const auto half_blocks = blocks/2;
    produce_blocks(half_blocks);
    BOOST_CHECK_EQUAL(err.still_locked, token.apply_safe_mod(_bob, mod_id));
    const auto fat_id = N(fatmod);
    BOOST_CHECK_EQUAL(success(), token.unlock_safe(_bob, fat_id, 100500));

    BOOST_TEST_MESSAGE("--- wait to 1 block before 1st unlocks end ensure it's locked");
    const auto remaining_blocks = blocks - half_blocks;
    produce_blocks(remaining_blocks - 1);
    BOOST_CHECK_EQUAL(err.still_locked, token.apply_safe_mod(_bob, mod_id));
    BOOST_TEST_MESSAGE("--- wait 1 more block and unlock");
    produce_block();
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod(_bob, mod_id));
    BOOST_CHECK_EQUAL(err.still_locked, token.apply_safe_mod(_bob, fat_id));
    BOOST_CHECK(token.get_safe_mod(_bob, mod_id).is_null());
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(one, _delay));

    BOOST_TEST_MESSAGE("--- wait fat unlock time and check both fat and mod2 applied");
    produce_blocks(blocks - remaining_blocks - 1);
    BOOST_CHECK_EQUAL(err.still_locked, token.apply_safe_mod(_bob, fat_id));
    produce_block();
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod(_bob, fat_id));
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod(_bob, mod2_id));
    BOOST_CHECK(token.get_safe_mod(_bob, fat_id).is_null());
    BOOST_CHECK(token.get_safe_mod(_bob, mod2_id).is_null());
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(one+one+100500, _delay));

    BOOST_TEST_MESSAGE("--- lock all");
    BOOST_CHECK_EQUAL(success(), token.lock_safe(_bob));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(0, _delay));
    produce_block();
    BOOST_CHECK_EQUAL(err.unlocked_eq0, token.lock_safe(_bob));
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(modify, cyber_token_safe_tester) try {
    BOOST_TEST_MESSAGE("Modify the safe");
    init();
    const auto mod_id = N(mod);
    const auto delay1 = _delay / 2;
    const auto delay2 = _delay * 2;

    BOOST_TEST_MESSAGE("--- fail on bad params");
    BOOST_CHECK_EQUAL(err.nothing_set, token.modify_safe(_bob, mod_id));
    BOOST_CHECK_EQUAL(err.delay_lte0, token.modify_safe(_bob, mod_id, 0));
    BOOST_CHECK_EQUAL(err.delay_gt_max, token.modify_safe(_bob, mod_id, cfg::safe_max_delay + 1));
    BOOST_CHECK_EQUAL(err.trusted_eq_owner, token.modify_safe(_bob, mod_id, {}, _bob));
    BOOST_CHECK_EQUAL(err.trusted_not_exists, token.modify_safe(_bob, mod_id, {}, _nobody));

    BOOST_TEST_MESSAGE("--- fail if not enabled");
    BOOST_CHECK_EQUAL(err.disabled, token.modify_safe(_bob, mod_id, delay1));
    BOOST_CHECK_EQUAL(err.disabled, token.modify_safe(_bob, mod_id, delay1, _alice));
    BOOST_CHECK_EQUAL(err.disabled, token.modify_safe(_bob, mod_id, {}, _alice));

    BOOST_TEST_MESSAGE("--- enable full locked for " << token.name());
    BOOST_CHECK_EQUAL(success(), token.enable_safe(_bob, 0, _delay, _alice));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(0, _delay, _alice));
    produce_block();

    BOOST_TEST_MESSAGE("--- success with enabled and correct params");
    BOOST_CHECK_EQUAL(success(), token.modify_safe(_bob, mod_id, _delay, _alice));
    CHECK_MATCHING_OBJECT(token.get_safe_mod(_bob, mod_id), token.make_safe_mod(mod_id, 0, _delay, _alice));

    BOOST_TEST_MESSAGE("--- prepare mods to check all change cases");
    BOOST_TEST_MESSAGE("------ 1 param: same delay, same trusted, other delay, other trusted");
    const auto mod_delay0 = N(mod.delay);
    const auto mod_delay1 = N(mod.delay1);
    const auto mod_delay2 = N(mod.delay2);
    const auto mod_trust1 = N(mod.trust1);
    const auto mod_trust2 = N(mod.trust2);
    BOOST_CHECK_EQUAL(success(), token.modify_safe(_bob, mod_delay0, _delay));
    BOOST_CHECK_EQUAL(success(), token.modify_safe(_bob, mod_delay1, delay1));
    BOOST_CHECK_EQUAL(success(), token.modify_safe(_bob, mod_delay2, delay2));
    BOOST_CHECK_EQUAL(success(), token.modify_safe(_bob, mod_trust1, {}, _alice));
    BOOST_CHECK_EQUAL(success(), token.modify_safe(_bob, mod_trust2, {}, _carol));
    CHECK_MATCHING_OBJECT(token.get_safe_mod(_bob, mod_delay0), token.make_safe_mod(mod_delay0, 0, _delay));
    CHECK_MATCHING_OBJECT(token.get_safe_mod(_bob, mod_delay1), token.make_safe_mod(mod_delay1, 0, delay1));
    CHECK_MATCHING_OBJECT(token.get_safe_mod(_bob, mod_delay2), token.make_safe_mod(mod_delay2, 0, delay2));
    CHECK_MATCHING_OBJECT(token.get_safe_mod(_bob, mod_trust1), token.make_safe_mod(mod_trust1, 0, {}, _alice));
    CHECK_MATCHING_OBJECT(token.get_safe_mod(_bob, mod_trust2), token.make_safe_mod(mod_trust2, 0, {}, _carol));
    BOOST_TEST_MESSAGE("------ 2 params: same both, same delay, same trusted, other both");
    const auto mod_d2t2 = N(mod.d2t2);
    const auto mod_d1t2 = N(mod.d1t2);
    const auto mod_d1t1 = N(mod.d1t1);
    const auto mod_dmt2 = N(mod.dmt2);
    BOOST_CHECK_EQUAL(success(), token.modify_safe(_bob, mod_d2t2, delay2, _carol));
    BOOST_CHECK_EQUAL(success(), token.modify_safe(_bob, mod_d1t2, _delay, _carol));
    BOOST_CHECK_EQUAL(success(), token.modify_safe(_bob, mod_d1t1, _delay, _alice));
    BOOST_CHECK_EQUAL(success(), token.modify_safe(_bob, mod_dmt2, cfg::safe_max_delay, _carol));
    CHECK_MATCHING_OBJECT(token.get_safe_mod(_bob, mod_d2t2), token.make_safe_mod(mod_d2t2, 0, delay2, _carol));
    CHECK_MATCHING_OBJECT(token.get_safe_mod(_bob, mod_dmt2), token.make_safe_mod(mod_dmt2, 0, cfg::safe_max_delay, _carol));

    BOOST_TEST_MESSAGE("--- Wait 1 block before unlock time");
    auto blocks = seconds_to_blocks(_delay);
    produce_blocks(blocks - 1);
    BOOST_CHECK_EQUAL(err.still_locked, token.apply_safe_mod(_bob, mod_id));
    BOOST_CHECK_EQUAL(err.same_mod_id, token.modify_safe(_bob, mod_id, _delay));

    BOOST_TEST_MESSAGE("--- Wait 1 more block and check changes");
    produce_block();
    BOOST_TEST_MESSAGE("------ fail if 2 params are the same as in current safe");
    BOOST_CHECK_EQUAL(err.nothing_to_apply, token.apply_safe_mod(_bob, mod_id));
    BOOST_TEST_MESSAGE("------ fail if 1 param and same delay");
    BOOST_CHECK_EQUAL(err.nothing_to_apply, token.apply_safe_mod(_bob, mod_delay0));
    BOOST_TEST_MESSAGE("------ fail if 1 param asd same trusted");
    BOOST_CHECK_EQUAL(err.nothing_to_apply, token.apply_safe_mod(_bob, mod_trust1));
    BOOST_TEST_MESSAGE("------ success if 1 param differs from value in current safe");
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod(_bob, mod_delay2));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(0, delay2, _alice));
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod(_bob, mod_trust2));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(0, delay2, _carol));
    BOOST_CHECK(token.get_safe_mod(_bob, mod_delay2).is_null());
    BOOST_CHECK(token.get_safe_mod(_bob, mod_trust2).is_null());
    BOOST_TEST_MESSAGE("------ fail if 2 params are the same as in current safe");
    BOOST_CHECK_EQUAL(err.nothing_to_apply, token.apply_safe_mod(_bob, mod_d2t2));
    BOOST_TEST_MESSAGE("------ success if 1 of 2 params differs from value in current safe");
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod(_bob, mod_d1t2));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(0, _delay, _carol));
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod(_bob, mod_d1t1));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(0, _delay, _alice));
    BOOST_TEST_MESSAGE("------ success if both params differ");
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod(_bob, mod_dmt2));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(0, cfg::safe_max_delay, _carol));
    BOOST_CHECK(token.get_safe_mod(_bob, mod_dmt2).is_null());

    BOOST_TEST_MESSAGE("--- reduce delay");
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod(_bob, mod_delay1));
    BOOST_TEST_MESSAGE("--- reuse old mod id to create new mod and ensure it's applied at time");
    BOOST_CHECK_EQUAL(success(), token.modify_safe(_bob, mod_delay1, delay2));
    const auto blocks2 = seconds_to_blocks(delay1);
    produce_blocks(blocks2 - 1);
    BOOST_CHECK_EQUAL(err.still_locked, token.apply_safe_mod(_bob, mod_delay1));
    produce_block();
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod(_bob, mod_delay1));

    BOOST_TEST_MESSAGE("--- apply mod with increased delay and check it's applied at time");
    BOOST_CHECK_EQUAL(success(), token.modify_safe(_bob, mod_delay1, _delay, name{}));
    const auto blocks3 = seconds_to_blocks(delay2);
    produce_blocks(blocks3 - 1);
    BOOST_CHECK_EQUAL(err.still_locked, token.apply_safe_mod(_bob, mod_delay1));
    produce_block();
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod(_bob, mod_delay1));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(0, _delay));
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(apply_cancel, cyber_token_safe_tester) try {
    BOOST_TEST_MESSAGE("Apply/cancel safe mod");
    init();
    const auto modify_mod = N(mod);
    const auto unlock_mod = N(unlock);
    const auto killit_mod = N(.k..i...ll); // test exotic name

    const auto create_mods = [&]() {
        // create all mod types
        BOOST_CHECK_EQUAL(success(), token.unlock_safe(_bob, unlock_mod, 1));
        BOOST_CHECK_EQUAL(success(), token.modify_safe(_bob, modify_mod, _delay, _carol));
        BOOST_CHECK_EQUAL(success(), token.disable_safe(_bob, killit_mod));
        CHECK_MATCHING_OBJECT(token.get_safe_mod(_bob, unlock_mod), token.make_safe_mod(unlock_mod, 1));
        CHECK_MATCHING_OBJECT(token.get_safe_mod(_bob, modify_mod), token.make_safe_mod(modify_mod, 0, _delay, _carol));
        CHECK_MATCHING_OBJECT(token.get_safe_mod(_bob, killit_mod), token.make_safe_mod(killit_mod, 0, 0));
    };

    BOOST_TEST_MESSAGE("--- fail on non-existing mods");
    BOOST_CHECK_EQUAL(err.mod_not_exists, token.apply_safe_mod(_bob, _bob));
    BOOST_CHECK_EQUAL(err.mod_not_exists, token.cancel_safe_mod(_bob, _bob));

    BOOST_CHECK_EQUAL(success(), token.enable_safe(_bob, 0, _delay, _alice));
    create_mods();
    BOOST_CHECK_EQUAL(err.mod_not_exists, token.apply_safe_mod(_bob, _bob));
    BOOST_CHECK_EQUAL(err.mod_not_exists, token.cancel_safe_mod(_bob, _bob));

    BOOST_TEST_MESSAGE("--- success on cancel existing");
    BOOST_CHECK_EQUAL(success(), token.cancel_safe_mod(_bob, unlock_mod));
    BOOST_CHECK_EQUAL(success(), token.cancel_safe_mod(_bob, modify_mod));
    BOOST_CHECK_EQUAL(success(), token.cancel_safe_mod(_bob, killit_mod));
    BOOST_CHECK(token.get_safe_mod(_bob, unlock_mod).is_null());
    BOOST_CHECK(token.get_safe_mod(_bob, modify_mod).is_null());
    BOOST_CHECK(token.get_safe_mod(_bob, killit_mod).is_null());
    produce_block();

    BOOST_TEST_MESSAGE("--- success on trusted apply");
    create_mods();
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod2(_bob, unlock_mod, _alice));
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod2(_bob, modify_mod, _alice));
    BOOST_CHECK_EQUAL(err.still_locked, token.apply_safe_mod2(_bob, killit_mod, _alice));
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod2(_bob, killit_mod, _carol));
    BOOST_CHECK(token.get_safe_mod(_bob, unlock_mod).is_null());
    BOOST_CHECK(token.get_safe_mod(_bob, modify_mod).is_null());
    BOOST_CHECK(token.get_safe_mod(_bob, killit_mod).is_null());
    produce_block();
    BOOST_CHECK_EQUAL(success(), token.enable_safe(_bob, 0, _delay));

    BOOST_TEST_MESSAGE("--- success on delayed apply");
    create_mods();
    const auto blocks = seconds_to_blocks(_delay);
    produce_blocks(blocks - 1);
    BOOST_CHECK_EQUAL(err.still_locked, token.apply_safe_mod(_bob, unlock_mod));
    BOOST_CHECK_EQUAL(err.still_locked, token.apply_safe_mod(_bob, modify_mod));
    BOOST_CHECK_EQUAL(err.still_locked, token.apply_safe_mod(_bob, killit_mod));
    produce_block();
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod(_bob, unlock_mod));
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod(_bob, modify_mod));
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod(_bob, killit_mod));
    BOOST_CHECK(token.get_safe_mod(_bob, unlock_mod).is_null());
    BOOST_CHECK(token.get_safe_mod(_bob, modify_mod).is_null());
    BOOST_CHECK(token.get_safe_mod(_bob, killit_mod).is_null());
    produce_block();

    BOOST_TEST_MESSAGE("--- fail apply on disabled safe");
    BOOST_CHECK_EQUAL(success(), token.enable_safe(_bob, 0, _delay, _alice));
    produce_block();
    create_mods();
    BOOST_CHECK_EQUAL(success(), token.disable_safe2(_bob, _alice));
    const auto try_apply_all = [&]() {
        BOOST_CHECK_EQUAL(err.disabled, token.apply_safe_mod(_bob, unlock_mod));
        BOOST_CHECK_EQUAL(err.disabled, token.apply_safe_mod(_bob, modify_mod));
        BOOST_CHECK_EQUAL(err.disabled, token.apply_safe_mod(_bob, killit_mod));
        BOOST_CHECK_EQUAL(err.disabled, token.apply_safe_mod2(_bob, unlock_mod, _alice));
        BOOST_CHECK_EQUAL(err.disabled, token.apply_safe_mod2(_bob, modify_mod, _alice));
        BOOST_CHECK_EQUAL(err.disabled, token.apply_safe_mod2(_bob, killit_mod, _alice));
    };
    try_apply_all();
    BOOST_TEST_MESSAGE("--- fail apply on disabled safe after delay");
    produce_blocks(blocks);
    try_apply_all();
    BOOST_TEST_MESSAGE("--- success cancel on disabled safe");
    BOOST_CHECK_EQUAL(success(), token.cancel_safe_mod(_bob, unlock_mod));
    BOOST_CHECK_EQUAL(success(), token.cancel_safe_mod(_bob, modify_mod));
    BOOST_CHECK_EQUAL(success(), token.cancel_safe_mod(_bob, killit_mod));
    BOOST_CHECK(token.get_safe_mod(_bob, unlock_mod).is_null());
    BOOST_CHECK(token.get_safe_mod(_bob, modify_mod).is_null());
    BOOST_CHECK(token.get_safe_mod(_bob, killit_mod).is_null());

    // change params requirements on apply already tested in "modify"
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(trusted, cyber_token_safe_tester) try {
    BOOST_TEST_MESSAGE("Instant actions with trusted account");
    init();
    const auto mod_id = N(mod);

    BOOST_CHECK_EQUAL(success(), token.enable_safe(_bob, 0, _delay, _alice));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(0, _delay, _alice));
    BOOST_TEST_MESSAGE("--- fail if have mod_id");
    BOOST_CHECK_EQUAL(err.have_mod_id, token.unlock_safe2(_bob, 1, _alice, mod_id));
    BOOST_CHECK_EQUAL(err.have_mod_id, token.modify_safe2(_bob, _delay + 1, {}, _alice, mod_id));
    BOOST_CHECK_EQUAL(err.have_mod_id, token.disable_safe2(_bob, _alice, mod_id));
    BOOST_TEST_MESSAGE("--- fail if bad unlock");
    BOOST_CHECK_EQUAL(err.symbol_precision, token.unlock_safe2(_bob, asset(1, token.bad_sym()), _alice));
    BOOST_CHECK_EQUAL(err.unlock_lte0, token.unlock_safe2(_bob, 0, _alice));
    BOOST_CHECK_EQUAL(err.unlock_lte0, token.unlock_safe2(_bob, -1, _alice));
    BOOST_TEST_MESSAGE("--- fail if not changed modify");
    BOOST_CHECK_EQUAL(err.nothing_set, token.modify_safe2(_bob, {}, {}, _alice));
    BOOST_CHECK_EQUAL(err.same_trusted, token.modify_safe2(_bob, {}, _alice, _alice));
    BOOST_CHECK_EQUAL(err.same_delay, token.modify_safe2(_bob, _delay, {}, _alice));
    BOOST_CHECK_EQUAL(err.same_delay, token.modify_safe2(_bob, _delay, _alice, _alice));
    BOOST_TEST_MESSAGE("--- fail if bad delay");
    BOOST_CHECK_EQUAL(err.delay_lte0, token.modify_safe2(_bob, 0, {}, _alice));
    BOOST_CHECK_EQUAL(err.delay_lte0, token.modify_safe2(_bob, 0, _carol, _alice));
    BOOST_CHECK_EQUAL(err.delay_gt_max, token.modify_safe2(_bob, cfg::safe_max_delay+1, {}, _alice));
    BOOST_CHECK_EQUAL(err.delay_gt_max, token.modify_safe2(_bob, cfg::safe_max_delay+1, _carol, _alice));
    BOOST_TEST_MESSAGE("--- fail if bad trusted");
    BOOST_CHECK_EQUAL(err.trusted_eq_owner, token.modify_safe2(_bob, {}, _bob, _alice));
    BOOST_CHECK_EQUAL(err.trusted_eq_owner, token.modify_safe2(_bob, 60, _bob, _alice));
    BOOST_CHECK_EQUAL(err.trusted_not_exists, token.modify_safe2(_bob, {}, _nobody, _alice));
    BOOST_CHECK_EQUAL(err.trusted_not_exists, token.modify_safe2(_bob, 60, _nobody, _alice));
    BOOST_TEST_MESSAGE("--- fail if bad delay and trusted");
    BOOST_CHECK_EQUAL(err.delay_lte0, token.modify_safe2(_bob, 0, _bob, _alice));
    BOOST_CHECK_EQUAL(err.delay_lte0, token.modify_safe2(_bob, 0, _nobody, _alice));
    BOOST_CHECK_EQUAL(err.delay_gt_max, token.modify_safe2(_bob, cfg::safe_max_delay+1, _bob, _alice));
    BOOST_CHECK_EQUAL(err.delay_gt_max, token.modify_safe2(_bob, cfg::safe_max_delay+1, _nobody, _alice));

    BOOST_TEST_MESSAGE("--- success on unlock");
    BOOST_CHECK_EQUAL(success(), token.unlock_safe2(_bob, 1, _alice));
    double unlocked = 1;
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(unlocked, _delay, _alice));
    BOOST_CHECK_EQUAL(success(), token.unlock_safe2(_bob, 100500, _alice));
    unlocked += 100500;
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(unlocked, _delay, _alice));
    BOOST_TEST_MESSAGE("--- success on modify");
    BOOST_CHECK_EQUAL(success(), token.modify_safe2(_bob, _delay*2, {}, _alice));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(unlocked, _delay*2, _alice));
    BOOST_CHECK_EQUAL(success(), token.modify_safe2(_bob, cfg::safe_max_delay, {}, _alice));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(unlocked, cfg::safe_max_delay, _alice));
    BOOST_CHECK_EQUAL(success(), token.modify_safe2(_bob, {}, _carol, _alice));
    BOOST_CHECK_EQUAL(err.empty_mod_id, token.modify_safe2(_bob, _delay, _alice, _alice));
    BOOST_CHECK_EQUAL(success(), token.modify_safe2(_bob, _delay, _alice, _carol));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(unlocked, _delay, _alice));
    BOOST_TEST_MESSAGE("--- success on disable");
    BOOST_CHECK_EQUAL(success(), token.disable_safe2(_bob, _alice));
    BOOST_CHECK(token.get_safe(_bob).is_null());

    BOOST_TEST_MESSAGE("--- remove trusted");
    produce_block();
    BOOST_CHECK_EQUAL(success(), token.enable_safe(_bob, 0, _delay, _alice));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(0, _delay, _alice));
    BOOST_CHECK_EQUAL(success(), token.modify_safe2(_bob, {}, name{}, _alice));
    CHECK_MATCHING_OBJECT(token.get_safe(_bob), token.make_safe(0, _delay));
    BOOST_CHECK_EQUAL(err.empty_mod_id, token.modify_safe2(_bob, {}, _alice, _alice));
    BOOST_CHECK_EQUAL(err.empty_mod_id, token.unlock_safe2(_bob, 1, _alice));
    BOOST_CHECK_EQUAL(err.empty_mod_id, token.disable_safe2(_bob, _alice));
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(safe, cyber_token_safe_tester) try {
    BOOST_TEST_MESSAGE("Limit transfers with enabled safe");
    init(_alice); // only issuer can retire so issue by alice
    const auto mod_id = N(mod);
    const double money = 100;
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _bob, money));
    BOOST_CHECK_EQUAL(success(), token2.transfer(_alice, _bob, money));
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _carol, _total - 2*money));
    BOOST_CHECK_EQUAL(success(), token2.transfer(_alice, _carol, _total - 2*money));
    auto alices = money;

    const auto showBalances = [&]() {
        BOOST_TEST_MESSAGE("------ alices safe: " <<
            fc::json::to_string(token.get_safe(_alice)) << " / " << fc::json::to_string(token2.get_safe(_alice)));
        BOOST_TEST_MESSAGE("------ alices balance: " <<
            fc::json::to_string(token.get_account(_alice)) << " / " << fc::json::to_string(token2.get_account(_alice)));
        BOOST_TEST_MESSAGE("------ bobs balance: " <<
            fc::json::to_string(token.get_account(_bob)) << " / " << fc::json::to_string(token2.get_account(_bob)));
    };
    showBalances();

    BOOST_TEST_MESSAGE("--- transfer without safe");
    const double half = money / 2;
    alices -= half;
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _bob, half));
    BOOST_CHECK_EQUAL(success(), token2.transfer(_alice, _bob, half));
    showBalances();

    BOOST_TEST_MESSAGE("--- issuer enables safe for " << token.name());
    BOOST_CHECK_EQUAL(success(), token.enable_safe(_alice, 0, _delay, _bob));

    BOOST_TEST_MESSAGE("--- transfer out blocked by the safe");
    const double tenth = money / 10;
    const auto satoshi = token.satoshi();
    BOOST_CHECK_EQUAL(err.balance_lock, token.transfer(_alice, _bob, tenth));
    BOOST_CHECK_EQUAL(err.balance_lock, token.transfer(_alice, _bob, satoshi));
    BOOST_CHECK_EQUAL(err.balance_lock, token.retire(_alice, tenth));
    BOOST_CHECK_EQUAL(err.balance_lock, token.retire(_alice, satoshi));
    BOOST_CHECK_EQUAL(success(), token2.transfer(_alice, _bob, tenth));
    showBalances();

    BOOST_TEST_MESSAGE("--- transfer in succeed");
    alices += tenth;
    BOOST_CHECK_EQUAL(success(), token.transfer(_bob, _alice, tenth));
    BOOST_CHECK_EQUAL(success(), token2.transfer(_bob, _alice, tenth));
    showBalances();

    BOOST_TEST_MESSAGE("--- prepare unlocked tokens");
    BOOST_CHECK_EQUAL(success(), token.unlock_safe2(_alice, tenth, _bob));
    BOOST_CHECK_EQUAL(success(), token2.enable_safe(_alice, tenth, _delay, _bob));
    produce_block();

    showBalances();
    BOOST_TEST_MESSAGE("--- success when transfer unlocked");
    alices -= tenth;
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _bob, tenth));
    const auto one = tenth/10;
    BOOST_CHECK_EQUAL(success(), token2.transfer(_alice, _bob, one));
    BOOST_CHECK_EQUAL(success(), token2.transfer(_alice, _bob, tenth - one));
    showBalances();
    BOOST_TEST_MESSAGE("--- fail when out of unlocked");
    BOOST_CHECK_EQUAL(err.balance_lock, token.transfer(_alice, _bob, satoshi));
    BOOST_CHECK_EQUAL(err.balance_lock, token2.transfer(_alice, _bob, satoshi));
    BOOST_CHECK_EQUAL(err.balance_lock, token.retire(_alice, satoshi));
    BOOST_CHECK_EQUAL(err.balance_lock, token2.retire(_alice, satoshi));

    BOOST_TEST_MESSAGE("--- fail when out of balance with enough unlocked");
    BOOST_CHECK_EQUAL(success(), token.unlock_safe2(_alice, money*100, _bob));
    BOOST_CHECK_EQUAL(err.balance_over, token.transfer(_alice, _bob, money));
    BOOST_CHECK_EQUAL(err.balance_over, token.transfer(_alice, _bob, alices + satoshi));
    BOOST_CHECK_EQUAL(err.balance_over, token.retire(_alice, alices + satoshi));
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _bob, alices));
    showBalances();
    produce_block();

    BOOST_TEST_MESSAGE("--- unlock and then lock");
    BOOST_CHECK_EQUAL(success(), token.transfer(_bob, _alice, half));
    BOOST_CHECK_EQUAL(success(), token.lock_safe(_alice));
    BOOST_CHECK_EQUAL(success(), token.unlock_safe2(_alice, half, _bob));
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _bob, tenth));
    BOOST_CHECK_EQUAL(success(), token.lock_safe(_alice, tenth));
    BOOST_CHECK_EQUAL(err.balance_lock, token.transfer(_alice, _bob, half - tenth));
    const auto max = half - 2 * tenth;
    BOOST_CHECK_EQUAL(err.balance_lock, token.transfer(_alice, _bob, max + satoshi));
    BOOST_CHECK_EQUAL(err.balance_lock, token.retire(_alice, max + satoshi));
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _bob, max));
    showBalances();
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(global_lock, cyber_token_safe_tester) try {
    BOOST_TEST_MESSAGE("Globally locked balance");
    init(_alice); // only issuer can retire so issue by alice
    BOOST_TEST_MESSAGE("--- issue tokens");
    const double money = 100;
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _bob, money));
    BOOST_CHECK_EQUAL(success(), token2.transfer(_alice, _bob, money));
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _carol, _total - 2*money));
    BOOST_CHECK_EQUAL(success(), token2.transfer(_alice, _carol, _total - 2*money));
    BOOST_TEST_MESSAGE("--- enable safe for " << token.name() << "; no safe for " << token2.name());
    BOOST_CHECK_EQUAL(success(), token.enable_safe(_alice, money / 2, _delay, _bob));
    BOOST_TEST_MESSAGE("--- transfer/retire allowed");
    const double tenth = money / 10;
    const auto satoshi = token.satoshi();
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _bob, tenth));
    BOOST_CHECK_EQUAL(success(), token2.transfer(_alice, _bob, tenth));
    BOOST_CHECK_EQUAL(success(), token.retire(_alice, tenth));
    BOOST_CHECK_EQUAL(success(), token2.retire(_alice, tenth));

    BOOST_TEST_MESSAGE("--- global lock fails if bad period");
    BOOST_CHECK_EQUAL(err.period_le0, token.global_lock(_alice, 0));
    BOOST_CHECK_EQUAL(err.period_gt_max, token.global_lock(_alice, cfg::safe_max_delay + 1));
    BOOST_TEST_MESSAGE("--- succeeds if increase lock period");
    auto locked = 30;
    BOOST_CHECK_EQUAL(success(), token.global_lock(_alice, 1));
    BOOST_CHECK_EQUAL(success(), token.global_lock(_alice, 3));
    BOOST_CHECK_EQUAL(success(), token.global_lock(_alice, locked));
    produce_block(); locked -= 3;
    BOOST_TEST_MESSAGE("--- fails if decrease lock period");
    BOOST_CHECK_EQUAL(err.period_le_cur, token.global_lock(_alice, 1));
    BOOST_CHECK_EQUAL(err.period_le_cur, token.global_lock(_alice, locked));
    locked++;
    BOOST_CHECK_EQUAL(success(), token.global_lock(_alice, locked));
    locked = _delay*2;
    BOOST_CHECK_EQUAL(success(), token.global_lock(_alice, locked));
    BOOST_TEST_MESSAGE("--- transfers disallowed on both " << token.name() << " & " << token2.name());
    BOOST_CHECK_EQUAL(err.global_lock, token.transfer(_alice, _bob, tenth));
    BOOST_CHECK_EQUAL(err.global_lock, token2.transfer(_alice, _bob, tenth));
    BOOST_CHECK_EQUAL(err.global_lock, token.retire(_alice, tenth));
    BOOST_CHECK_EQUAL(err.global_lock, token2.retire(_alice, tenth));
    BOOST_TEST_MESSAGE("--- delayed mods disallowed when locked globally");
    BOOST_CHECK_EQUAL(success(), token.unlock_safe(_alice, N(unlock), tenth));
    BOOST_CHECK_EQUAL(success(), token.modify_safe(_alice, N(mod), _delay/2));
    BOOST_CHECK_EQUAL(success(), token.disable_safe(_alice, N(off)));
    BOOST_CHECK_EQUAL(success(), token.unlock_safe(_alice, N(u2), 1));
    BOOST_CHECK_EQUAL(success(), token.modify_safe(_alice, N(m2), _delay*2));
    auto blocks = seconds_to_blocks(_delay);
    produce_blocks(blocks);
    locked -= blocks*3;
    BOOST_CHECK_EQUAL(err.global_lock, token.transfer(_alice, _bob, tenth));
    BOOST_CHECK_EQUAL(err.global_lock, token2.transfer(_alice, _bob, tenth));
    BOOST_CHECK_EQUAL(err.global_lock, token.retire(_alice, tenth));
    BOOST_CHECK_EQUAL(err.global_lock, token2.retire(_alice, tenth));
    BOOST_CHECK_EQUAL(err.mod_global_lock, token.apply_safe_mod(_alice, N(unlock)));
    BOOST_CHECK_EQUAL(err.mod_global_lock, token.apply_safe_mod(_alice, N(mod)));
    BOOST_CHECK_EQUAL(err.mod_global_lock, token.apply_safe_mod(_alice, N(off)));
    BOOST_TEST_MESSAGE("--- but still allowed with trusted");
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod2(_alice, N(unlock), _bob));
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod2(_alice, N(mod), _bob));
    BOOST_CHECK_EQUAL(success(), token.unlock_safe2(_alice, tenth, _bob));
    BOOST_CHECK_EQUAL(success(), token.modify_safe2(_alice, _delay, {}, _bob));
    BOOST_TEST_MESSAGE("--- wait 1 block before global unlock and ensure it's still locked");
    blocks = seconds_to_blocks(locked);
    produce_blocks(blocks - 1);
    BOOST_CHECK_EQUAL(err.global_lock, token.transfer(_alice, _bob, tenth));
    BOOST_CHECK_EQUAL(err.global_lock, token2.transfer(_alice, _bob, tenth));
    BOOST_CHECK_EQUAL(err.global_lock, token.retire(_alice, tenth));
    BOOST_CHECK_EQUAL(err.global_lock, token2.retire(_alice, tenth));
    BOOST_CHECK_EQUAL(err.mod_global_lock, token.apply_safe_mod(_alice, N(u2)));
    BOOST_CHECK_EQUAL(err.mod_global_lock, token.apply_safe_mod(_alice, N(m2)));
    BOOST_CHECK_EQUAL(err.mod_global_lock, token.apply_safe_mod(_alice, N(off)));
    BOOST_TEST_MESSAGE("--- delayed mods and transfers allowed after global unlock");
    produce_block();
    BOOST_CHECK_EQUAL(success(), token.transfer(_alice, _bob, tenth));
    BOOST_CHECK_EQUAL(success(), token2.transfer(_alice, _bob, tenth));
    BOOST_CHECK_EQUAL(success(), token.retire(_alice, tenth));
    BOOST_CHECK_EQUAL(success(), token2.retire(_alice, tenth));
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod(_alice, N(u2)));
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod(_alice, N(m2)));
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod(_alice, N(off)));
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(unlock_overflow, cyber_token_safe_tester) try {
    BOOST_TEST_MESSAGE("Unlocked overflow");
    init();
    BOOST_TEST_MESSAGE("--- enable safes");
    const asset max{asset::max_amount, token._symbol};
    BOOST_CHECK_EQUAL(success(), token.enable_safe(_bob, 0, _delay, _alice));
    BOOST_CHECK_EQUAL(success(), token.enable_safe(_alice, max, _delay, _bob));
    BOOST_TEST_MESSAGE("--- bob unlocks until limit");
    const asset qtr{(asset::max_amount + 1) / 4, token._symbol};
    BOOST_CHECK_EQUAL(success(), token.unlock_safe2(_bob, qtr, _alice));
    produce_block();
    BOOST_CHECK_EQUAL(success(), token.unlock_safe2(_bob, qtr, _alice));
    produce_block();
    BOOST_CHECK_EQUAL(success(), token.unlock_safe2(_bob, qtr, _alice));
    produce_block();
    BOOST_CHECK_EQUAL(err.unlocked_over, token.unlock_safe2(_bob, qtr, _alice));
    const auto satoshi = token.satoshi_asset();
    BOOST_CHECK_EQUAL(success(), token.unlock_safe2(_bob, qtr - satoshi, _alice));

    BOOST_TEST_MESSAGE("--- alice fails to unlock because already unlocked max");
    BOOST_CHECK_EQUAL(err.unlocked_over, token.unlock_safe2(_alice, max, _bob));
    BOOST_CHECK_EQUAL(err.unlocked_over, token.unlock_safe2(_alice, qtr, _bob));
    BOOST_CHECK_EQUAL(err.unlocked_over, token.unlock_safe2(_alice, 1, _bob));
    BOOST_CHECK_EQUAL(err.unlocked_over, token.unlock_safe2(_alice, satoshi, _bob));
    BOOST_TEST_MESSAGE("------ delayed fails too");
    BOOST_CHECK_EQUAL(success(), token.unlock_safe(_alice, N(max), max));
    BOOST_CHECK_EQUAL(success(), token.unlock_safe(_alice, N(one), 1));
    BOOST_CHECK_EQUAL(success(), token.unlock_safe(_alice, N(sat), satoshi));
    const auto blocks = seconds_to_blocks(_delay);
    produce_blocks(blocks);
    BOOST_CHECK_EQUAL(err.unlocked_over, token.apply_safe_mod(_alice, N(max)));
    BOOST_CHECK_EQUAL(err.unlocked_over, token.apply_safe_mod(_alice, N(one)));
    BOOST_CHECK_EQUAL(err.unlocked_over, token.apply_safe_mod(_alice, N(sat)));
    BOOST_TEST_MESSAGE("--- success if lock some amount");
    BOOST_CHECK_EQUAL(success(), token.lock_safe(_alice, 1));
    BOOST_CHECK_EQUAL(success(), token.apply_safe_mod(_alice, N(one)));
    BOOST_CHECK_EQUAL(err.unlocked_over, token.apply_safe_mod(_alice, N(sat)));
} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END()
