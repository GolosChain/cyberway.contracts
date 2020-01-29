#pragma once
namespace cyber {
namespace config {
constexpr uint64_t difficulty_adjustment_interval = 2016;
constexpr int64_t target_timespan = 14 * 24 * 60 * 60;
constexpr size_t ancestors_num = 8;
constexpr uint64_t ancestor_depth_base = 5;

static const std::array<uint32_t, 8> __pow_limit_data{{0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0}};
static const arith_uint256 pow_limit = reinterpret_cast<const arith_uint256&>(__pow_limit_data);

constexpr uint8_t base58_PKH_prefix = 0;
constexpr uint8_t base58_SH_prefix  = 5;
static const std::string bech32_hrp = "bc";

constexpr auto btc_symbol = eosio::symbol("BTC", 8);
}
}
