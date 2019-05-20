#pragma once

#include "config.hpp"
#include <eosiolib/dispatcher.hpp>

template<typename T, typename... Args>
bool dispatch_with_transfer_helper( eosio::name self, eosio::name code, void (T::*func)(Args...) ) {
    struct transfer_st {
        eosio::name from;
        std::vector<eosio::token::recipient> recipients;
    };
    auto data = eosio::unpack_action_data<transfer_st>();

    for (auto recipient : data.recipients) {
        T inst(self, code, eosio::datastream<const char*>(nullptr, 0));
        ((&inst)->*func)(data.from, recipient.to, recipient.quantity, recipient.memo);
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
            dispatch_with_transfer_helper(eosio::name(receiver), eosio::name(code), &TYPE::TRANSFER); \
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
