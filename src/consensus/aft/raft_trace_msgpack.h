// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
#include "consensus/aft/impl/state.h"
#include "consensus/aft/raft_types.h"
#include "msgpack/fields.h"
#include "tracing/trace.h"

#include <algorithm>
#include <string_view>
#include <vector>

namespace aft::trace
{
  constexpr std::string_view raft_trace_tag = "ccf.raft_trace";

  using ccf::msgpack::container_size;
  using ccf::msgpack::Field;
  using ccf::msgpack::write_fields;
  using ccf::msgpack::write_key;
  using ccf::msgpack::write_msgpack;
  using ccf::msgpack::write_optional;

  inline void write_msgpack(std::vector<uint8_t>& out, const ccf::NodeId& id)
  {
    ccf::msgpack::write_str(out, id.value());
  }

  template <bool IncludeCommittableIndices = true>
  inline void write_msgpack(std::vector<uint8_t>& out, const State& state)
  {
    const auto optional_field_count =
      static_cast<uint32_t>(state.retirement_phase.has_value()) +
      static_cast<uint32_t>(state.retirement_idx.has_value()) +
      static_cast<uint32_t>(state.retirement_committable_idx.has_value()) +
      static_cast<uint32_t>(state.retired_committed_idx.has_value());
    ccf::msgpack::write_map_header(
      out, 7 + IncludeCommittableIndices + optional_field_count);

    write_key(out, "node_id");
    write_msgpack(out, state.node_id);
    write_key(out, "current_view");
    ccf::msgpack::write_uint(out, state.current_view);
    write_key(out, "last_idx");
    ccf::msgpack::write_uint(out, state.last_idx);
    write_key(out, "commit_idx");
    ccf::msgpack::write_uint(out, state.commit_idx);
    write_key(out, "leadership_state");
    write_msgpack(out, state.leadership_state.load());
    write_key(out, "membership_state");
    write_msgpack(out, state.membership_state);
    write_key(out, "pre_vote_enabled");
    ccf::msgpack::write_bool(out, state.pre_vote_enabled);

    write_optional(
      out,
      "retirement_phase",
      state.retirement_phase,
      [](auto& buffer, auto value) { write_msgpack(buffer, value); });
    write_optional(
      out,
      "retirement_idx",
      state.retirement_idx,
      [](auto& buffer, auto value) {
        ccf::msgpack::write_uint(buffer, value);
      });
    write_optional(
      out,
      "retirement_committable_idx",
      state.retirement_committable_idx,
      [](auto& buffer, auto value) {
        ccf::msgpack::write_uint(buffer, value);
      });
    write_optional(
      out,
      "retired_committed_idx",
      state.retired_committed_idx,
      [](auto& buffer, auto value) {
        ccf::msgpack::write_uint(buffer, value);
      });

    if constexpr (IncludeCommittableIndices)
    {
      write_key(out, "committable_indices");
      const auto& indices = state.committable_indices;
      const auto count =
        static_cast<uint32_t>(std::min<size_t>(indices.size(), 2));
      ccf::msgpack::write_array_header(out, count);
      if (count > 0)
      {
        ccf::msgpack::write_uint(out, indices.front());
      }
      if (count > 1)
      {
        ccf::msgpack::write_uint(out, indices.back());
      }
    }
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, const ccf::kv::Configuration::NodeInfo& node)
  {
    const auto address = ccf::make_net_address(node.hostname, node.port);
    write_fields(out, Field{"address", std::string_view(address)});
  }

  inline void write_configuration(
    std::vector<uint8_t>& out,
    Index idx,
    const ccf::kv::Configuration::Nodes& nodes,
    ccf::kv::ReconfigurationId rid)
  {
    const auto write_nodes = [&](auto& buffer) {
      ccf::msgpack::write_map_header(buffer, container_size(nodes.size()));
      for (const auto& [node_id, node_info] : nodes)
      {
        write_msgpack(buffer, node_id);
        write_msgpack(buffer, node_info);
      }
    };
    write_fields(
      out, Field{"idx", idx}, Field{"nodes", write_nodes}, Field{"rid", rid});
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, const ccf::kv::Configuration& configuration)
  {
    write_configuration(
      out, configuration.idx, configuration.nodes, configuration.rid);
  }

  template <typename Configurations>
  inline void write_configurations(
    std::vector<uint8_t>& out, const Configurations& configurations)
  {
    ccf::msgpack::write_array_header(
      out, container_size(configurations.size()));
    for (const auto& configuration : configurations)
    {
      write_msgpack(out, configuration);
    }
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, const AppendEntries& packet)
  {
    write_fields(
      out,
      Field{"msg", packet.msg},
      Field{"idx", packet.idx},
      Field{"prev_idx", packet.prev_idx},
      Field{"term", packet.term},
      Field{"prev_term", packet.prev_term},
      Field{"leader_commit_idx", packet.leader_commit_idx},
      Field{"term_of_idx", packet.term_of_idx},
      Field{"contains_new_view", packet.contains_new_view});
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, const AppendEntriesResponse& packet)
  {
    write_fields(
      out,
      Field{"msg", packet.msg},
      Field{"term", packet.term},
      Field{"last_log_idx", packet.last_log_idx},
      Field{"success", packet.success});
  }

  template <typename VoteRequest>
  inline void write_vote_request(
    std::vector<uint8_t>& out, const VoteRequest& packet)
  {
    write_fields(
      out,
      Field{"msg", packet.msg},
      Field{"term", packet.term},
      Field{"last_committable_idx", packet.last_committable_idx},
      Field{
        "term_of_last_committable_idx", packet.term_of_last_committable_idx});
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, const RequestVote& packet)
  {
    write_vote_request(out, packet);
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, const RequestPreVote& packet)
  {
    write_vote_request(out, packet);
  }

  template <typename VoteResponse>
  inline void write_vote_response(
    std::vector<uint8_t>& out, const VoteResponse& packet)
  {
    write_fields(
      out,
      Field{"msg", packet.msg},
      Field{"term", packet.term},
      Field{"vote_granted", packet.vote_granted});
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, const RequestVoteResponse& packet)
  {
    write_vote_response(out, packet);
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, const RequestPreVoteResponse& packet)
  {
    write_vote_response(out, packet);
  }

  inline void write_msgpack(
    std::vector<uint8_t>& out, const ProposeRequestVote& packet)
  {
    write_fields(out, Field{"msg", packet.msg}, Field{"term", packet.term});
  }

  template <typename... Fields>
  inline void emit_fields(const Fields&... fields)
  {
    ccf::tracing::emit(raft_trace_tag, sizeof...(Fields), [&](auto& out) {
      ((write_key(out, fields.name), write_msgpack(out, fields.value)), ...);
    });
  }

  inline void emit_state_node(
    std::string_view function,
    const State& state,
    std::string_view node_key,
    const ccf::NodeId& node_id)
  {
    emit_fields(
      Field{"function", function},
      Field{"state", state},
      Field{node_key, node_id});
  }

  template <typename Configurations>
  inline void emit_state_configurations(
    std::string_view function,
    const State& state,
    const Configurations& configurations)
  {
    const auto write = [&](auto& out) {
      write_configurations(out, configurations);
    };
    emit_fields(
      Field{"function", function},
      Field{"state", state},
      Field{"configurations", write});
  }

  template <typename Packet>
  inline void emit_state_packet_node(
    std::string_view function,
    const State& state,
    const Packet& packet,
    std::string_view node_key,
    const ccf::NodeId& node_id)
  {
    emit_fields(
      Field{"function", function},
      Field{"state", state},
      Field{"packet", packet},
      Field{node_key, node_id});
  }

  template <typename Packet>
  inline void emit_state_packet_node_indices(
    std::string_view function,
    const State& state,
    const Packet& packet,
    std::string_view node_key,
    const ccf::NodeId& node_id,
    Index match_idx,
    Index sent_idx)
  {
    emit_fields(
      Field{"function", function},
      Field{"state", state},
      Field{"packet", packet},
      Field{node_key, node_id},
      Field{"match_idx", match_idx},
      Field{"sent_idx", sent_idx});
  }

  template <typename Configurations>
  inline void emit_add_configuration(
    const State& state,
    const Configurations& configurations,
    Index idx,
    const ccf::kv::Configuration::Nodes& nodes)
  {
    const auto write_configs = [&](auto& out) {
      write_configurations(out, configurations);
    };
    const auto write_args = [&](auto& out) {
      const auto write_config = [&](auto& buffer) {
        write_configuration(buffer, idx, nodes, idx);
      };
      write_fields(out, Field{"configuration", write_config});
    };
    emit_fields(
      Field{"function", std::string_view("add_configuration")},
      Field{"state", state},
      Field{"configurations", write_configs},
      Field{"args", write_args});
  }

  inline void emit_replicate(
    const State& state, Term view, Index seqno, bool globally_committable)
  {
    emit_fields(
      Field{"function", std::string_view("replicate")},
      Field{"state", state},
      Field{"view", view},
      Field{"seqno", seqno},
      Field{"globally_committable", globally_committable});
  }

  template <typename Configurations>
  inline void emit_commit(
    const State& state, const Configurations& configurations, Index idx)
  {
    const auto write_args = [&](auto& out) {
      write_fields(out, Field{"idx", idx});
    };
    const auto write_configs = [&](auto& out) {
      write_configurations(out, configurations);
    };
    emit_fields(
      Field{"function", std::string_view("commit")},
      Field{"state", state},
      Field{"args", write_args},
      Field{"configurations", write_configs});
  }

  template <typename Packet>
  inline void emit_drop_pending_to(
    const State& state,
    const Packet& packet,
    const ccf::NodeId& from,
    const ccf::NodeId& to)
  {
    const auto write_state = [&](auto& out) {
      write_msgpack<false>(out, state);
    };
    emit_fields(
      Field{"function", std::string_view("drop_pending_to")},
      Field{"state", write_state},
      Field{"from_node_id", from},
      Field{"to_node_id", to},
      Field{"packet", packet});
  }
} // namespace aft::trace
