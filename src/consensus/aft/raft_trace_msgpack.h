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

  inline void write_msgpack(std::vector<uint8_t>& out, const State& state)
  {
    using namespace ccf::msgpack;
    using ccf::msgpack::write_msgpack;
    write_map_header(
      out,
      8 + static_cast<uint32_t>(state.retirement_phase.has_value()) +
        static_cast<uint32_t>(state.retirement_idx.has_value()) +
        static_cast<uint32_t>(state.retirement_committable_idx.has_value()) +
        static_cast<uint32_t>(state.retired_committed_idx.has_value()));
    write_str(out, "node_id");
    write_msgpack(out, state.node_id.value());
    write_str(out, "current_view");
    write_msgpack(out, state.current_view);
    write_str(out, "last_idx");
    write_msgpack(out, state.last_idx);
    write_str(out, "commit_idx");
    write_msgpack(out, state.commit_idx);
    write_str(out, "leadership_state");
    write_msgpack(out, state.leadership_state.load());
    write_str(out, "membership_state");
    write_msgpack(out, state.membership_state);
    write_str(out, "pre_vote_enabled");
    write_msgpack(out, state.pre_vote_enabled);
    if (state.retirement_phase.has_value())
    {
      write_str(out, "retirement_phase");
      write_msgpack(out, *state.retirement_phase);
    }
    if (state.retirement_idx.has_value())
    {
      write_str(out, "retirement_idx");
      write_msgpack(out, *state.retirement_idx);
    }
    if (state.retirement_committable_idx.has_value())
    {
      write_str(out, "retirement_committable_idx");
      write_msgpack(out, *state.retirement_committable_idx);
    }
    if (state.retired_committed_idx.has_value())
    {
      write_str(out, "retired_committed_idx");
      write_msgpack(out, *state.retired_committed_idx);
    }
    write_str(out, "committable_indices");
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

namespace ccf::kv
{
  inline void write_msgpack(
    std::vector<uint8_t>& out, const Configuration::Nodes& nodes)
  {
    msgpack::write_map_header(out, msgpack::container_size(nodes.size()));
    for (const auto& [node_id, node_info] : nodes)
    {
      msgpack::write_str(out, node_id.value());
      msgpack::write_map_header(out, 1);
      msgpack::write_str(out, "address");
      msgpack::write_str(
        out, ccf::make_net_address(node_info.hostname, node_info.port));
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
  DECLARE_TRACE_EVENT(
    add_configuration, raft_trace_tag, state, configurations, idx, nodes, rid);
  DECLARE_TRACE_EVENT(commit, raft_trace_tag, state, idx, configurations);
  DECLARE_TRACE_EVENT(
    drop_pending_to, raft_trace_tag, state, from_node_id, to_node_id, packet);
}
