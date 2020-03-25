#pragma once
#include <eosio/eosio.hpp>
#include <eosio/singleton.hpp>
#include <eosio/time.hpp>
#include <eosio/crypto.hpp>
#include <cyber.govern/config.hpp>
#include <eosio/binary_extension.hpp>

namespace cyber {
using eosio::name;
using eosio::contract;
using eosio::public_key;
using eosio::time_point_sec;

class [[eosio::contract("cyber.govern")]] govern : public contract {

struct structures {
    struct state_info {
        time_point_sec last_schedule_increase;
        uint32_t block_num = 0;
        int64_t target_emission_per_block = 0;
        int64_t funds = 0;
        uint32_t last_propose_block_num = 0;
        uint16_t required_producers_num = config::min_producers_num;
        uint16_t last_producers_num = 1;

        // using of binary_extension is a temporary decision only for upgrade phase
        eosio::binary_extension<uint32_t, eosio::write_strategy::no_value> schedule_version;
        eosio::binary_extension<int8_t, eosio::write_strategy::no_value> resize_shift;
        eosio::binary_extension<time_point_sec, eosio::write_strategy::no_value> last_resize_step;
    };

    struct [[using eosio: event("burnreward"), contract("cyber.govern")]] balance_struct {
        name account;
        int64_t amount;
        uint64_t primary_key()const { return account.value; }
    };
    
    struct producer_struct {
        name account;
        bool is_oblidged = false;
        int64_t amount = 0;
        int64_t unconfirmed_amount = 0;
        uint16_t omission_count = 0;
        uint16_t omission_resets = 0;
        eosio::time_point_sec last_time;

        uint64_t primary_key()const { return account.value; }
        bool by_oblidged()const { return is_oblidged; }
        int64_t by_amount()const { return amount; }
        eosio::time_point_sec by_last_time()const { return last_time; }
    };
};

    using state_singleton [[eosio::order("id","asc")]] = eosio::singleton<"governstate"_n, structures::state_info>;
    using balances [[eosio::order("account","asc")]] = eosio::multi_index<"balance"_n, structures::balance_struct>;

    using oblidged_index [[using eosio: order("is_oblidged","desc"), non_unique]] = eosio::indexed_by<"byoblidged"_n, eosio::const_mem_fun<structures::producer_struct, bool, &structures::producer_struct::by_oblidged> >;
    using balance_index [[using eosio: order("amount","desc"), non_unique]] = eosio::indexed_by<"bybalance"_n, eosio::const_mem_fun<structures::producer_struct, int64_t, &structures::producer_struct::by_amount> >;
    using last_time_index [[using eosio: order("last_time","asc"), non_unique]] = eosio::indexed_by<"bytime"_n, eosio::const_mem_fun<structures::producer_struct, eosio::time_point_sec, &structures::producer_struct::by_last_time> >;
    using producers [[eosio::order("account","asc")]] = eosio::multi_index<"producer"_n, structures::producer_struct, oblidged_index, balance_index, last_time_index>;
    
    void promote_producers(producers& producers_table);
    void propose_producers(structures::state_info& s);
    void reward_producers(producers& producers_table, structures::state_info& s);
    void reward_workers(structures::state_info& s);
    void burn_reward(const eosio::name& account, const int64_t& amount) const;
    void remove_old_producers(producers& producers_table);
    int64_t get_target_emission_per_block(int64_t supply) const;
    
public:
    using contract::contract;
    [[eosio::action]] void onblock(name producer, eosio::binary_extension<uint32_t> schedule_version);
    [[eosio::action]] void setshift(int8_t shift);
};

} /// cyber
