// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "consensus/aft/raft_trace_msgpack.h"

#include <doctest/doctest.h>

namespace
{
  template <typename T>
  void check_encoding(const T& value)
  {
    std::vector<uint8_t> bytes;
    aft::trace::write_msgpack(bytes, value);
    CHECK(nlohmann::json::from_msgpack(bytes) == nlohmann::json(value));
  }
}

TEST_CASE("Raft trace State matches JSON, including absent optional fields")
{
  aft::State state(ccf::NodeId("node"));
  for (unsigned mask = 0; mask < 16; ++mask)
  {
    state.retirement_phase = mask & 1 ?
      std::make_optional(ccf::kv::RetirementPhase::Ordered) :
      std::nullopt;
    state.retirement_idx =
      mask & 2 ? std::make_optional<uint64_t>(7) : std::nullopt;
    state.retirement_committable_idx =
      mask & 4 ? std::make_optional<uint64_t>(8) : std::nullopt;
    state.retired_committed_idx =
      mask & 8 ? std::make_optional<uint64_t>(9) : std::nullopt;
    for (size_t n = 0; n < 4; ++n)
    {
      state.committable_indices.clear();
      for (size_t i = 0; i < n; ++i)
      {
        state.committable_indices.push_back(i + 1);
      }
      auto expected = nlohmann::json(state);
      std::vector<uint8_t> bytes;
      aft::trace::write_msgpack<false>(bytes, state);
      CHECK(nlohmann::json::from_msgpack(bytes) == expected);
      expected["committable_indices"] = nlohmann::json::array();
      if (n != 0)
      {
        expected["committable_indices"].push_back(1);
        if (n > 1)
        {
          expected["committable_indices"].push_back(n);
        }
      }
      bytes.clear();
      aft::trace::write_msgpack(bytes, state);
      CHECK(nlohmann::json::from_msgpack(bytes) == expected);
    }
  }
  for (auto phase :
       {ccf::kv::RetirementPhase::Ordered,
        ccf::kv::RetirementPhase::Signed,
        ccf::kv::RetirementPhase::Completed,
        ccf::kv::RetirementPhase::RetiredCommitted})
  {
    check_encoding(phase);
  }
}

TEST_CASE("Raft packet and configuration encodings match JSON")
{
  aft::AppendEntries append{};
  append.idx = std::numeric_limits<uint64_t>::max();
  append.contains_new_view = true;
  check_encoding(append);
  for (auto response :
       {aft::AppendEntriesResponseType::OK,
        aft::AppendEntriesResponseType::FAIL})
  {
    check_encoding(aft::AppendEntriesResponse{
      .term = 2, .last_log_idx = 3, .success = response});
  }
  check_encoding(aft::RequestVote{
    .term = 4, .last_committable_idx = 7, .term_of_last_committable_idx = 3});
  check_encoding(aft::RequestPreVote{
    .term = 5, .last_committable_idx = 8, .term_of_last_committable_idx = 4});
  check_encoding(aft::RequestVoteResponse{.term = 5, .vote_granted = false});
  check_encoding(aft::RequestPreVoteResponse{.term = 6, .vote_granted = true});
  check_encoding(aft::ProposeRequestVote{.term = 7});
  check_encoding(ccf::kv::Configuration{
    1,
    {{ccf::NodeId("v4"), {"127.0.0.1", "123"}},
     {ccf::NodeId("v6"), {"::1", "456"}}},
    2});
  check_encoding(ccf::kv::Configuration{});
}
