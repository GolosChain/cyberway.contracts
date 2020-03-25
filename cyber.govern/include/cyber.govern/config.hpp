#pragma once
#include <common/config.hpp>

namespace cyber { namespace config {
    
static const auto issuer_name = internal_name;
    
static const auto reward_interval = 3499;
static const auto schedule_period_factor = 4;
static const auto update_emission_per_block_interval = 997;

static const auto rewarded_for_votes_limit_displ = 50;

static const auto schedule_increase_blocking_votes_pct = 90 * _1percent;

static constexpr uint16_t min_producers_num = 21;
static constexpr uint16_t max_producers_num = 101;

static const auto schedule_resize_min_delay = 60 * 60 * 24 * 14;
static constexpr  int8_t schedule_size_shift_min = -1;
static constexpr  int8_t schedule_size_shift_max = 1;

static constexpr uint16_t active_reserve_producers_num = 1;

static constexpr auto emission_addition = 953 * _1percent / 100; // 10% annual
static constexpr auto emission_factor   = 870 * _1percent / 100; //+10% annual

static constexpr auto emission_min_arg = 25 * _1percent;
static constexpr auto emission_max_arg = 75 * _1percent;
//annual emission is equal to 10% if share of tokens voted <= emission_min_arg
//annual emission is equal to 20% if share of tokens voted >= emission_max_arg
//linear interpolation between these two points (actually, due to the compound pct, this function is slightly convex)

static constexpr auto block_reward_pct     = 10 * _1percent;
static constexpr auto workers_reward_pct   = 2222 * _1percent / 100; // not including block reward

static constexpr uint16_t omission_limit = 100;
static constexpr uint16_t resets_limit = 4;
}

} // cyber::config
