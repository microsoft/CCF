// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// Binds the commands of the consensus scenarios to the Lean model of the
// protocol. tests/cft_scenarios/CftDriver.lean declares each command as a C
// function cft_*, which borrows its arguments. ModelDriver.lean implements it
// as model_cft_*, and a function which Lean exports owns its arguments, so
// each object is given a reference before it is passed on.

#include <lean/lean.h>
#include <stdint.h>

// A command which takes no argument
#define COMMAND(name) \
  lean_obj_res model_##name(void); \
  lean_obj_res name(void) \
  { \
    return model_##name(); \
  }

// A command which takes a number
#define COMMAND_N(name) \
  lean_obj_res model_##name(uint64_t); \
  lean_obj_res name(uint64_t n) \
  { \
    return model_##name(n); \
  }

// A command which takes an object
#define COMMAND_1(name) \
  lean_obj_res model_##name(lean_obj_arg); \
  lean_obj_res name(b_lean_obj_arg a) \
  { \
    lean_inc(a); \
    return model_##name(a); \
  }

// A command which takes an object and a number
#define COMMAND_1_N(name) \
  lean_obj_res model_##name(lean_obj_arg, uint64_t); \
  lean_obj_res name(b_lean_obj_arg a, uint64_t n) \
  { \
    lean_inc(a); \
    return model_##name(a, n); \
  }

// A command which takes two objects
#define COMMAND_2(name) \
  lean_obj_res model_##name(lean_obj_arg, lean_obj_arg); \
  lean_obj_res name(b_lean_obj_arg a, b_lean_obj_arg b) \
  { \
    lean_inc(a); \
    lean_inc(b); \
    return model_##name(a, b); \
  }

// A command which takes an object, a number and an object
#define COMMAND_1_N_1(name) \
  lean_obj_res model_##name(lean_obj_arg, uint64_t, lean_obj_arg); \
  lean_obj_res name(b_lean_obj_arg a, uint64_t n, b_lean_obj_arg b) \
  { \
    lean_inc(a); \
    lean_inc(b); \
    return model_##name(a, n, b); \
  }

// A command which takes three objects
#define COMMAND_3(name) \
  lean_obj_res model_##name(lean_obj_arg, lean_obj_arg, lean_obj_arg); \
  lean_obj_res name(b_lean_obj_arg a, b_lean_obj_arg b, b_lean_obj_arg c) \
  { \
    lean_inc(a); \
    lean_inc(b); \
    lean_inc(c); \
    return model_##name(a, b, c); \
  }

// In the order of CftDriver.lean
COMMAND_1(cft_start_node)
COMMAND_2(cft_trust_node)
COMMAND_2(cft_trust_nodes)
COMMAND_3(cft_swap_node)
COMMAND_3(cft_swap_nodes)
COMMAND_2(cft_cleanup_nodes)
COMMAND_1(cft_nominate_successor)
COMMAND_1(cft_nodes)
COMMAND_1(cft_create_new_node)
COMMAND_2(cft_replicate_new_configuration)
COMMAND_2(cft_replicate)
COMMAND_1_N(cft_periodic_one)
COMMAND_N(cft_periodic_all)
COMMAND_2(cft_connect)
COMMAND_2(cft_disconnect)
COMMAND_1(cft_disconnect_node)
COMMAND_2(cft_reconnect)
COMMAND_1(cft_reconnect_node)
COMMAND_1(cft_dispatch_one)
COMMAND_2(cft_dispatch_single)
COMMAND(cft_dispatch_all_once)
COMMAND(cft_dispatch_all)
COMMAND_1(cft_drop_pending)
COMMAND_2(cft_drop_pending_to)
COMMAND_1(cft_shuffle_one)
COMMAND(cft_shuffle_all)
COMMAND_1(cft_state_one)
COMMAND(cft_state_all)
COMMAND_1(cft_summarise_log)
COMMAND(cft_summarise_logs_all)
COMMAND_2(cft_summarise_messages)
COMMAND(cft_assert_state_sync)
COMMAND_1(cft_assert_commit_safety)
COMMAND_1_N(cft_assert_commit_idx)
COMMAND_3(cft_assert_detail)
COMMAND_3(cft_assert_not_detail)
COMMAND_1_N_1(cft_assert_config)
COMMAND_1_N(cft_assert_absent_config)
COMMAND_2(cft_assert_last_txid)
COMMAND(cft_loop_until_sync)
COMMAND_1(cft_start)
COMMAND(cft_finish)
