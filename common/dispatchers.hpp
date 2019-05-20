#pragma once

#include "config.hpp"
#include <eosiolib/dispatcher.hpp>

template<typename T, typename... Args>
bool bulk_execute_action( eosio::name self, eosio::name code, void (T::*func)(Args...) ) {
    struct transfer_st {
        eosio::name from;
        std::vector<eosio::token::recipient> recipients;
    };
    auto data = eosio::unpack_action_data<transfer_st>();

    for (auto recipient : data.recipients) {
        std::tuple<std::decay_t<Args>...> args{data.from, recipient.to, recipient.quantity, recipient.memo};
        eosio::datastream<const char*> ds = eosio::datastream<const char*>(nullptr, 0);

        T inst(self, code, ds);
        auto f2 = [&]( auto... a ){
            ((&inst)->*func)( a... );
        };

        boost::mp11::tuple_apply( f2, args );
    }
    return true;
}


#define DISPATCH_WITH_TRANSFER(TYPE, TOKEN, TRANSFER, MEMBERS) \
extern "C" { \
   void apply(uint64_t receiver, uint64_t code, uint64_t action) { \
        if (code == receiver) { \
            switch (action) { \
                EOSIO_DISPATCH_HELPER(TYPE, MEMBERS) \
            } \
        } else if (code == TOKEN.value && action == "transfer"_n.value) { \
            eosio::execute_action(eosio::name(receiver), eosio::name(code), &TYPE::TRANSFER); \
        } else if (code == TOKEN.value && action == "bulktransfer"_n.value) { \
            bulk_execute_action(eosio::name(receiver), eosio::name(code), &TYPE::TRANSFER); \
        } \
   } \
} \

#define DISPATCH_WITH_BULK_TRANSFER(TYPE, TOKEN, TRANSFER, BULKTRANSFER, MEMBERS) \
extern "C" { \
   void apply(uint64_t receiver, uint64_t code, uint64_t action) { \
        if (code == receiver) { \
            switch (action) { \
                EOSIO_DISPATCH_HELPER(TYPE, MEMBERS) \
            } \
        } else if (code == TOKEN.value && action == "transfer"_n.value) { \
            eosio::execute_action(eosio::name(receiver), eosio::name(code), &TYPE::TRANSFER); \
        } \
        else if (code == TOKEN.value && action == "bulktransfer"_n.value) { \
            eosio::execute_action(eosio::name(receiver), eosio::name(code), &TYPE::BULKTRANSFER); \
        } \
   } \
} \
