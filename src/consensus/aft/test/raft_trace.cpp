// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "consensus/aft/raft_trace_msgpack.h"

#include <doctest/doctest.h>

namespace
{
  template <typename T>
  void check_encoding(
    const T& value, std::initializer_list<const char*> wire_fields = {})
  {
    std::vector<uint8_t> bytes;
    using ccf::msgpack::write_msgpack;
    write_msgpack(bytes, value);
    CHECK(nlohmann::json::from_msgpack(bytes) == nlohmann::json(value));
    if (wire_fields.size() != 0)
    {
      const nlohmann::json json = value;
      auto ordered = nlohmann::ordered_json::object();
      for (const auto* field : wire_fields)
      {
        ordered[field] = json.at(field);
      }
      CHECK(bytes == nlohmann::ordered_json::to_msgpack(ordered));
    }
  }

  template <typename T>
  void check_record(const T& record, const nlohmann::ordered_json& expected)
  {
    record();
    const auto frame =
      nlohmann::ordered_json::from_msgpack(ccf::tracing::event_buffer());
    CHECK(
      nlohmann::ordered_json::to_msgpack(frame[2]["msg"]) ==
      nlohmann::ordered_json::to_msgpack(expected));
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
      aft::trace::write_msgpack(
        bytes, aft::trace::StateWithoutIndicesView{state});
      CHECK(nlohmann::json::from_msgpack(bytes) == expected);
      auto without_indices = nlohmann::ordered_json::object();
      for (const auto* key :
           {"node_id",
            "current_view",
            "last_idx",
            "commit_idx",
            "leadership_state",
            "membership_state",
            "pre_vote_enabled",
            "retirement_phase",
            "retirement_idx",
            "retirement_committable_idx",
            "retired_committed_idx"})
      {
        if (expected.contains(key))
          without_indices[key] = expected.at(key);
      }
      CHECK(bytes == nlohmann::ordered_json::to_msgpack(without_indices));
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
      aft::write_msgpack(bytes, state);
      CHECK(nlohmann::json::from_msgpack(bytes) == expected);
      auto ordered = nlohmann::ordered_json::object();
      for (const auto* key :
           {"node_id",
            "current_view",
            "last_idx",
            "commit_idx",
            "leadership_state",
            "membership_state",
            "pre_vote_enabled",
            "retirement_phase",
            "retirement_idx",
            "retirement_committable_idx",
            "retired_committed_idx",
            "committable_indices"})
      {
        if (expected.contains(key))
          ordered[key] = expected.at(key);
      }
      CHECK(bytes == nlohmann::ordered_json::to_msgpack(ordered));
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

TEST_CASE(
  "Raft events preserve field order and flatten configuration arguments")
{
  using nlohmann::ordered_json;
  aft::State state(ccf::NodeId("node"));
  std::vector<uint8_t> state_bytes;
  aft::write_msgpack(state_bytes, state);
  const auto state_json = ordered_json::from_msgpack(state_bytes);
  std::vector<uint8_t> bytes;
  ccf::tracing::FluentdSink::configure(
    ccf::tracing::FluentdSink::Endpoint{"127.0.0.1", "1"});
  ccf::tracing::FluentdSink::bind_producer(0);
  check_record(
    [&] { aft::trace::replicate(state, 4, 7, true); },
    ordered_json{
      {"function", "replicate"},
      {"state", state_json},
      {"view", 4},
      {"seqno", 7},
      {"globally_committable", true}});
  const ccf::kv::Configuration::Nodes nodes = {
    {ccf::NodeId("node"), {"::1", "456"}}};

  const std::list<ccf::kv::Configuration> configurations = {{7, nodes, 7}};
  const ordered_json configuration_json = {
    {"idx", 7}, {"nodes", {{"node", {{"address", "[::1]:456"}}}}}, {"rid", 7}};
  const auto configurations_json = ordered_json::array({configuration_json});
  check_record(
    [&] { aft::trace::become_leader(state, configurations); },
    {{"function", "become_leader"},
     {"state", state_json},
     {"configurations", configurations_json}});
  check_record(
    [&] { aft::trace::add_configuration(state, configurations, 7, nodes, 7); },
    {{"function", "add_configuration"},
     {"state", state_json},
     {"configurations", configurations_json},
     {"idx", 7},
     {"nodes", configuration_json["nodes"]},
     {"rid", 7}});
  check_record(
    [&] { aft::trace::commit(state, 7, configurations); },
    {{"function", "commit"},
     {"state", state_json},
     {"idx", 7},
     {"configurations", configurations_json}});
  check_record(
    [&] { aft::trace::execute_append_entries_sync(state, "peer"); },
    {{"function", "execute_append_entries_sync"},
     {"state", state_json},
     {"from_node_id", "peer"}});

  const aft::RequestVoteResponse vote{.term = 4, .vote_granted = false};
  const ordered_json vote_json = {
    {"msg", "raft_request_vote_response"},
    {"term", 4},
    {"vote_granted", false}};
  check_record(
    [&] { aft::trace::send_request_vote_response(state, vote, "peer"); },
    {{"function", "send_request_vote_response"},
     {"state", state_json},
     {"packet", vote_json},
     {"to_node_id", "peer"}});
  check_record(
    [&] { aft::trace::recv_request_vote_response(state, vote, "peer"); },
    {{"function", "recv_request_vote_response"},
     {"state", state_json},
     {"packet", vote_json},
     {"from_node_id", "peer"}});
  auto dropped_state = state_json;
  dropped_state.erase("committable_indices");
  check_record(
    [&] {
      aft::trace::drop_pending_to(
        aft::trace::StateWithoutIndicesView{state}, "node", "peer", vote);
    },
    {{"function", "drop_pending_to"},
     {"state", dropped_state},
     {"from_node_id", "node"},
     {"to_node_id", "peer"},
     {"packet", vote_json}});

  const aft::AppendEntries append{};
  bytes.clear();
  aft::write_msgpack(bytes, append);
  check_record(
    [&] { aft::trace::send_append_entries(state, append, "peer", 3, 5); },
    {{"function", "send_append_entries"},
     {"state", state_json},
     {"packet", ordered_json::from_msgpack(bytes)},
     {"to_node_id", "peer"},
     {"match_idx", 3},
     {"sent_idx", 5}});
  const aft::AppendEntriesResponse response{};
  bytes.clear();
  aft::write_msgpack(bytes, response);
  check_record(
    [&] {
      aft::trace::recv_append_entries_response(state, response, "peer", 3, 5);
    },
    {{"function", "recv_append_entries_response"},
     {"state", state_json},
     {"packet", ordered_json::from_msgpack(bytes)},
     {"from_node_id", "peer"},
     {"match_idx", 3},
     {"sent_idx", 5}});
  ccf::tracing::FluentdSink::shutdown();
}
TEST_CASE("Raft packet and configuration encodings match JSON")
{
  aft::AppendEntries append{};
  append.idx = std::numeric_limits<uint64_t>::max();
  append.contains_new_view = true;
  check_encoding(
    append,
    {"msg",
     "idx",
     "prev_idx",
     "term",
     "prev_term",
     "leader_commit_idx",
     "term_of_idx",
     "contains_new_view"});
  for (auto response :
       {aft::AppendEntriesResponseType::OK,
        aft::AppendEntriesResponseType::FAIL})
  {
    check_encoding(
      aft::AppendEntriesResponse{
        .term = 2, .last_log_idx = 3, .success = response},
      {"msg", "term", "last_log_idx", "success"});
  }
  check_encoding(
    aft::RequestVote{
      .term = 4, .last_committable_idx = 7, .term_of_last_committable_idx = 3},
    {"msg", "term", "last_committable_idx", "term_of_last_committable_idx"});
  check_encoding(
    aft::RequestPreVote{
      .term = 5, .last_committable_idx = 8, .term_of_last_committable_idx = 4},
    {"msg", "term", "last_committable_idx", "term_of_last_committable_idx"});
  check_encoding(
    aft::RequestVoteResponse{.term = 5, .vote_granted = false},
    {"msg", "term", "vote_granted"});
  check_encoding(
    aft::RequestPreVoteResponse{.term = 6, .vote_granted = true},
    {"msg", "term", "vote_granted"});
  check_encoding(aft::ProposeRequestVote{.term = 7}, {"msg", "term"});
  const ccf::kv::Configuration configuration{
    1,
    {{ccf::NodeId("v4"), {"127.0.0.1", "123"}},
     {ccf::NodeId("v6"), {"::1", "456"}}},
    2};
  for (const auto& config : {configuration, ccf::kv::Configuration{}})
  {
    std::vector<uint8_t> bytes;
    ccf::kv::write_msgpack(bytes, config);
    CHECK(nlohmann::json::from_msgpack(bytes) == nlohmann::json(config));
  }
}
