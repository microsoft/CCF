// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
#include "consensus/aft/impl/state.h"
#include "consensus/aft/raft_types.h"
#include "msgpack/serialization.h"
#include "tracing/trace.h"

#include <algorithm>
#include <list>

namespace aft
{
  DECLARE_MSGPACK_TYPE(AppendEntries);
  DECLARE_MSGPACK_FIELDS(
    AppendEntries,
    msg,
    idx,
    prev_idx,
    term,
    prev_term,
    leader_commit_idx,
    term_of_idx,
    contains_new_view);

  DECLARE_MSGPACK_TYPE(AppendEntriesResponse);
  DECLARE_MSGPACK_FIELDS(
    AppendEntriesResponse, msg, term, last_log_idx, success);

  DECLARE_MSGPACK_TYPE(RequestVote);
  DECLARE_MSGPACK_FIELDS(
    RequestVote, msg, term, last_committable_idx, term_of_last_committable_idx);

  DECLARE_MSGPACK_TYPE(RequestPreVote);
  DECLARE_MSGPACK_FIELDS(
    RequestPreVote,
    msg,
    term,
    last_committable_idx,
    term_of_last_committable_idx);

  DECLARE_MSGPACK_TYPE(RequestVoteResponse);
  DECLARE_MSGPACK_FIELDS(RequestVoteResponse, msg, term, vote_granted);

  DECLARE_MSGPACK_TYPE(RequestPreVoteResponse);
  DECLARE_MSGPACK_FIELDS(RequestPreVoteResponse, msg, term, vote_granted);

  DECLARE_MSGPACK_TYPE(ProposeRequestVote);
  DECLARE_MSGPACK_FIELDS(ProposeRequestVote, msg, term);

  inline void write_trace_state(
    std::vector<uint8_t>& out, const State& state, bool include_indices)
  {
    using namespace ccf::msgpack;
    using ccf::msgpack::write_msgpack;
    write_map_header(
      out,
      7 + static_cast<uint32_t>(state.retirement_phase.has_value()) +
        static_cast<uint32_t>(state.retirement_idx.has_value()) +
        static_cast<uint32_t>(state.retirement_committable_idx.has_value()) +
        static_cast<uint32_t>(state.retired_committed_idx.has_value()) +
        static_cast<uint32_t>(include_indices));
    write_pair(out, "node_id", state.node_id.value());
    write_pair(out, "current_view", state.current_view);
    write_pair(out, "last_idx", state.last_idx);
    write_pair(out, "commit_idx", state.commit_idx);
    write_pair(out, "leadership_state", state.leadership_state.load());
    write_pair(out, "membership_state", state.membership_state);
    write_pair(out, "pre_vote_enabled", state.pre_vote_enabled);
    write_optional(out, "retirement_phase", state.retirement_phase);
    write_optional(out, "retirement_idx", state.retirement_idx);
    write_optional(
      out, "retirement_committable_idx", state.retirement_committable_idx);
    write_optional(out, "retired_committed_idx", state.retired_committed_idx);
    if (include_indices)
    {
      write_key(out, "committable_indices");
      const auto count = static_cast<uint32_t>(
        std::min<size_t>(state.committable_indices.size(), 2));
      write_array_header(out, count);
      if (count > 0)
      {
        write_msgpack(out, state.committable_indices.front());
      }
      if (count > 1)
      {
        write_msgpack(out, state.committable_indices.back());
      }
    }
  }

  inline void write_msgpack(std::vector<uint8_t>& out, const State& state)
  {
    write_trace_state(out, state, true);
  }
}

namespace ccf::kv
{
  inline void write_msgpack(
    std::vector<uint8_t>& out, const Configuration::Nodes& nodes)
  {
    msgpack::write_map_header(out, msgpack::container_size(nodes.size()));
    for (const auto& [node_id, node_info] : nodes)
    {
      msgpack::write_key(out, node_id.value());
      msgpack::write_map(
        out,
        "address",
        ccf::make_net_address(node_info.hostname, node_info.port));
    }
  }

  DECLARE_MSGPACK_TYPE(Configuration);
  DECLARE_MSGPACK_FIELDS(Configuration, idx, nodes, rid);

  inline void write_msgpack(
    std::vector<uint8_t>& out, const std::list<Configuration>& configurations)
  {
    msgpack::write_array_header(
      out, msgpack::container_size(configurations.size()));
    for (const auto& configuration : configurations)
    {
      write_msgpack(out, configuration);
    }
  }
}

namespace aft::trace
{
  constexpr std::string_view raft_trace_tag = "ccf.raft_trace";

  // Dropped packets use the legacy state shape without committable indices.
  struct StateWithoutIndicesView
  {
    const State& state;
  };

  inline void write_msgpack(
    std::vector<uint8_t>& out, const StateWithoutIndicesView& value)
  {
    write_trace_state(out, value.state, false);
  }

  DECLARE_TRACE_EVENT(
    send_append_entries,
    raft_trace_tag,
    state,
    packet,
    to_node_id,
    match_idx,
    sent_idx);
  DECLARE_TRACE_EVENT(
    recv_append_entries_response,
    raft_trace_tag,
    state,
    packet,
    from_node_id,
    match_idx,
    sent_idx);
  DECLARE_TRACE_EVENT(
    recv_append_entries, raft_trace_tag, state, packet, from_node_id);
  DECLARE_TRACE_EVENT(
    execute_append_entries_sync, raft_trace_tag, state, from_node_id);
  DECLARE_TRACE_EVENT(
    send_append_entries_response, raft_trace_tag, state, packet, to_node_id);
  DECLARE_TRACE_EVENT(
    send_request_vote, raft_trace_tag, state, packet, to_node_id);
  DECLARE_TRACE_EVENT(
    send_request_vote_response, raft_trace_tag, state, packet, to_node_id);
  DECLARE_TRACE_EVENT(
    recv_request_vote, raft_trace_tag, state, packet, from_node_id);
  DECLARE_TRACE_EVENT(
    recv_request_vote_response, raft_trace_tag, state, packet, from_node_id);
  DECLARE_TRACE_EVENT(
    recv_propose_request_vote, raft_trace_tag, state, packet, from_node_id);
  DECLARE_TRACE_EVENT(
    become_pre_vote_candidate, raft_trace_tag, state, configurations);
  DECLARE_TRACE_EVENT(become_candidate, raft_trace_tag, state, configurations);
  DECLARE_TRACE_EVENT(become_leader, raft_trace_tag, state, configurations);
  DECLARE_TRACE_EVENT(become_follower, raft_trace_tag, state, configurations);
  DECLARE_TRACE_EVENT(
    step_down_and_nominate_successor, raft_trace_tag, state, configurations);
  DECLARE_TRACE_EVENT(
    replicate, raft_trace_tag, state, view, seqno, globally_committable);
  // This event preserves the nested args.configuration wire shape without
  // constructing/copying a Configuration.
  inline void emit_add_configuration(
    const State& state,
    const std::list<ccf::kv::Configuration>& configurations,
    Index idx,
    const ccf::kv::Configuration::Nodes& nodes)
  {
    ccf::tracing::emit(
      raft_trace_tag,
      "function",
      "add_configuration",
      "state",
      state,
      "configurations",
      configurations,
      "args",
      ccf::msgpack::map(
        "configuration",
        ccf::msgpack::map("idx", idx, "nodes", nodes, "rid", idx)));
  }

  DECLARE_TRACE_EVENT(commit, raft_trace_tag, state, args, configurations);
  DECLARE_TRACE_EVENT(
    drop_pending_to, raft_trace_tag, state, from_node_id, to_node_id, packet);
}
