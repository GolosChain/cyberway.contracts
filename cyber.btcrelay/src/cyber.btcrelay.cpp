#include <cyber.btcrelay/cyber.btcrelay.hpp>
#include <eosio/crypto.hpp>

namespace cyber {
void btcrelay::init(block_header_arg h, uint64_t height) {
    
    require_auth(_self);
    auto header = get_header(h);
    
    eosio::check(height % config::difficulty_adjustment_interval == 0, "initial block should be the first in the difficulty adjustment interval");
    const auto block_hash = get_hash(header.serialize());
    const auto target = header.target();
    eosio::print("initial block hash = \n", block_hash, "\ntarget = \n", target, "\n");

    const auto block_hash_arith = to_arith256(block_hash);
    eosio::check(block_hash_arith > 0 && block_hash_arith < target, "PoW error");

    blocks blocks_table(_self, _self.value);
    eosio::check(blocks_table.find(0) == blocks_table.end(), "already initialized");
    auto id = blocks_table.available_primary_key();
    eosio::check(!id, "SYSTEM: invalid internal block id");
    
    blocks_table.emplace(_self, [&](auto& b) { b = structures::block {
        .id = id,
        .key = block_hash,
        .header = header,
        .height = height
    };});
    
    auto mainchain = mainchain_singleton(_self, _self.value);
    mainchain.set(structures::mainchain_info { .heaviest_block = 0 }, _self);
}

void btcrelay::addheaderhex(std::string header_hex, name payer) {
    eosio::check(header_hex.size() == block_header::raw_size * 2, "incorrect header hex string size");
    auto bytes = bytes_from_hex(header_hex);
    add_header(get_header(bytes), payer);
}

void btcrelay::addheader(block_header_arg h, name payer) {
    add_header(get_header(h), payer);
}

void btcrelay::verifytx(std::string tx_hex, uint32_t tx_index, std::vector<std::string> siblings_hex, std::string header_hash_hex, uint64_t min_confirmations_num) {
    //require_auth(anyone);
    eosio::check(get_confirmations_num(_self, tx_hex, tx_index, siblings_hex, header_hash_hex) >= min_confirmations_num, "insufficient transaction confirmations");
}

void btcrelay::checkpayment(std::string tx_hex, std::string address_hex, asset min_quantity) {
    //require_auth(anyone);
    eosio::check(min_quantity.symbol == config::btc_symbol, "invalid symbol name or precision");
    eosio::check(min_quantity.is_valid(), "invalid quantity");
    eosio::check(min_quantity.amount > 0, "must require positive quantity");
    eosio::check(get_payment_quantity(tx_hex, address_hex) >= min_quantity, "insufficient payment");
}

void btcrelay::checkaddress(std::string address_hex) {
    //require_auth(anyone);
    eosio::check(supported_address(address_hex), "unsupported address");
}

void btcrelay::add_header(block_header header, name payer) {
    require_auth(payer);
    auto mainchain = mainchain_singleton(_self, _self.value);
    eosio::check(mainchain.exists(), "relay not initialized");
    
    blocks blocks_table(_self, _self.value);
    auto blocks_idx = blocks_table.get_index<"bykey"_n>();
    auto prev_block = blocks_idx.find(header.prev_hash);
    eosio::check(prev_block != blocks_idx.end(), "no previous block");
    
    const auto block_hash = get_hash(header.serialize());
    eosio::check(blocks_idx.find(block_hash) == blocks_idx.end(), "already added");
    
    auto target = header.target();
    const auto& block_hash_arith = to_arith256(block_hash);
    
    eosio::check(block_hash_arith > 0 && block_hash_arith < target, "PoW error");
    
    auto height = prev_block->height + 1;
    auto prev_bits = prev_block->header.bits;
    
    if (height % config::difficulty_adjustment_interval) {
        eosio::check(header.bits == prev_bits, "mismatching difficulty bits");
    }
    else {
        eosio::check(height >= config::difficulty_adjustment_interval, "SYSTEM: height < difficulty_adjustment_interval");
        auto start_time = get_block_itr(blocks_table, height - config::difficulty_adjustment_interval, mainchain.get().heaviest_block)->header.time;
        auto prev_time = prev_block->header.time;
        auto new_bits = get_new_bits(prev_bits, start_time, prev_time);
        eosio::check(header.bits == new_bits, "invalid difficulty bits");
    }
    
    auto id = blocks_table.available_primary_key();
    
    auto block_proof = (~target / (target + 1)) + 1; //see bitcoin/src/chain.cpp: GetBlockProof
    auto chain_work = to_arith256(prev_block->chain_work_data) + block_proof;
    auto chain_work_data = to_hash256(chain_work);
    structures::block new_block {
        .id = id,
        .key = block_hash,
        .header = header,
        .height = height,
        .chain_work_data = chain_work_data
    };
    new_block.ancestors.reserve(config::ancestors_num);
    new_block.ancestors.push_back(prev_block->id);
    eosio::check(!prev_block->id || prev_block->ancestors.size() == config::ancestors_num, "SYSTEM: incorrect number of ancestors");
    for (size_t anc = 1; anc < config::ancestors_num; anc++) {
        new_block.ancestors.push_back(!prev_block->id || (height % ancestor_depth(anc) == 1) ? prev_block->id : prev_block->ancestors[anc]);
    }
    
    blocks_table.emplace(payer, [&new_block](auto& b) { b = new_block; });
    if (chain_work >= to_arith256(mainchain.get().chain_work_data)) {
        mainchain.set(structures::mainchain_info { .heaviest_block = id, .chain_work_data = chain_work_data }, payer);
    }
}

uint32_t btcrelay::get_new_bits(uint32_t prev_bits, uint32_t start_time, uint32_t prev_time) {
    auto timespan = static_cast<int64_t>(prev_time) - static_cast<int64_t>(start_time);
    timespan = std::min(std::max(timespan, config::target_timespan / 4), config::target_timespan * 4);
    arith_uint256 ret_target;
    ret_target.SetCompact(prev_bits);
    ret_target *= timespan;
    ret_target /= config::target_timespan;
    ret_target = std::min(ret_target, config::pow_limit);
    return ret_target.GetCompact();
}

}

EOSIO_DISPATCH(cyber::btcrelay, (init)(addheader)(addheaderhex)(verifytx)(checkpayment)(checkaddress))
