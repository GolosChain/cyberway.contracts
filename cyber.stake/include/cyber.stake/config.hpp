#pragma once
#include <common/config.hpp>

namespace cyber { namespace config {
static const int32_t priority_precision = 1000000;
static const auto key_recovery_delay = 60 * 60 * 24;
static const auto proxylvl_recovery_delay = 60 * 60 * 24 * 7;
static const auto max_no_pick_period = 60 * 60 * 24 * 30;
static const auto reward_memo = "$reward";

constexpr size_t max_validator_meta_size = 2048;

}

} // cyber::config
