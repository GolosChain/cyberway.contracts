#include <cyber.box/cyber.box.hpp>
namespace cyber {

void box::create(name contract, name treasurer, name title) {
    eosio::check(is_account(contract), "contract account does not exist");
    require_auth(treasurer);
    boxes boxes_table(_self, treasurer.value);
    auto boxes_idx = boxes_table.get_index<"bykey"_n>();
    eosio::check(boxes_idx.find({contract, title}) == boxes_idx.end(), "such a box already exists");
    boxes_table.emplace(treasurer, [&](auto& b) { b = {
        .id = boxes_table.available_primary_key(),
        .contract = contract,
        .title = title,
        .owner = treasurer,
        .empty = true
    };});
}

void box::packup(name contract, name treasurer, name title) {
    require_auth(contract);
    boxes boxes_table(_self, treasurer.value);
    auto boxes_idx = boxes_table.get_index<"bykey"_n>();
    auto box_itr = boxes_idx.find({contract, title});
    eosio::check(box_itr != boxes_idx.end(), "box does not exist");
    eosio::check(box_itr->empty, "the box is not empty");
    eosio::check(treasurer == box_itr->owner, "SYSTEM: invalid box owner");
    boxes_idx.modify(box_itr, name(), [&](auto& b) { b.empty = false; });
}

void box::erase_box(name contract, name treasurer, name title, name owner) {
    boxes boxes_table(_self, treasurer.value);
    auto boxes_idx = boxes_table.get_index<"bykey"_n>();
    auto box_itr = boxes_idx.find({contract, title});
    eosio::check(box_itr != boxes_idx.end(), "box does not exist");
    eosio::check(!owner || owner == box_itr->owner, "incorrect owner");
    eosio::check(!owner || !box_itr->empty, "cannot unpack an empty box");
    if (!box_itr->empty) {
        require_recipient(contract);
    }
    require_auth(box_itr->owner);
    boxes_idx.erase(box_itr);
}

void box::unpack(name contract, name treasurer, name title, name owner) {
    eosio::check(static_cast<bool>(owner), "owner not specified");
    erase_box(contract, treasurer, title, owner);
}

void box::burn(name contract, name treasurer, name title) {
    erase_box(contract, treasurer, title);
}

void box::transfer(name contract, name treasurer, name title, name from, name to, std::string memo) {
    eosio::check(is_account(to), "to account does not exist");
    eosio::check(memo.size() <= config::max_memo_size, config::memo_error);
    boxes boxes_table(_self, treasurer.value);
    auto boxes_idx = boxes_table.get_index<"bykey"_n>();
    auto box_itr = boxes_idx.find({contract, title});
    eosio::check(box_itr != boxes_idx.end(), "box does not exist");
    require_auth(from);
    eosio::check(box_itr->owner == from, "only the owner can do it");
    eosio::check(from != to, "cannot transfer to self");
    eosio::check(!box_itr->empty, "cannot transfer an empty box");
    require_recipient(from);
    require_recipient(to);
    boxes_idx.modify(box_itr, name(), [&](auto& b) { b.owner = to; });
}

} /// namespace cyber
