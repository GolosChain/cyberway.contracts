#pragma once
#include "golos_tester.hpp"
#include <boost/algorithm/string/replace.hpp>

namespace eosio { namespace testing {

using mvo = fc::mutable_variant_object;
using action_result = base_tester::action_result;

// allows to use ' quotes instead of ", but will break if ' used not as quote
inline fc::variant json_str_to_obj(std::string s) {
    return fc::json::from_string(boost::replace_all_copy(s, "'", "\""));
}

inline account_name user_name(size_t n) {
    string ret_str("user");
    while (n) {
        constexpr auto q = 'z' - 'a' + 1;
        ret_str += std::string(1, 'a' + n % q);
        n /= q;
    }
    return string_to_name(ret_str.c_str());
};

struct base_contract_api {
    using signers_t = std::vector<account_name>;
protected:
    uint32_t billed_cpu_time_us = base_tester::DEFAULT_BILLED_CPU_TIME_US;
    uint64_t billed_ram_bytes = base_tester::DEFAULT_BILLED_RAM_BYTES;
public:
    golos_tester* _tester;
    name _code;

    base_contract_api(golos_tester* tester, name code): _tester(tester), _code(code) {}

    base_tester::action_result push_msig(action_name name, signers_t signers, const variant_object& data) {
        std::vector<permission_level> perms{signers.size()};
        std::transform(signers.begin(), signers.end(), perms.begin(), [](const auto& s){
            return permission_level{s, config::active_name};
        });
        return _tester->push_action_msig_tx(_code, name, perms, signers, data, false); // NOTE: doesn't produce block
    }

    base_tester::action_result push_msig(action_name name, std::vector<permission_level> perms, signers_t signers,
        const variant_object& data
    ) {
        return _tester->push_action_msig_tx(_code, name, perms, signers, data);
    }

    variant get_struct(uint64_t scope, name tbl, uint64_t id, const string& name) const {
        return _tester->get_chaindb_struct(_code, scope, tbl, id, name);
    }

    variant get_singleton(uint64_t scope, name tbl, const string& name) const {
        return _tester->get_chaindb_singleton(_code, scope, tbl, name);
    }

    virtual mvo args() {
        return mvo();
    }

    void set_billed(uint32_t cpu_time_us, uint64_t ram_bytes) {
        billed_cpu_time_us = cpu_time_us;
        billed_ram_bytes   = ram_bytes;
    }

    action_result push(action_name name, account_name signer, const variant_object& data) {
        try {
            signed_transaction trx;
            vector<permission_level> auths;

            auths.push_back( permission_level{signer, config::active_name} );

            trx.actions.emplace_back( _tester->get_action( _code, name, auths, data ) );
            _tester->set_transaction_headers( trx, _tester->DEFAULT_EXPIRATION_DELTA, 0 );
            for (const auto& auth : auths) {
                trx.sign( _tester->get_private_key( auth.actor, auth.permission.to_string() ), _tester->control->get_chain_id() );
            }

            _tester->push_transaction(trx, fc::time_point::maximum(), billed_cpu_time_us, billed_ram_bytes);

        } catch (const fc::exception& ex) {
            edump((ex.to_detail_string()));
            return _tester->error(ex.top_message());
        }
        return _tester->success();
    }

};


} }
