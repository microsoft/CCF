// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/consensus_channels.h"
#include "consensus/aft/raft_types.h"
#include "ds/internal_logger.h"
#include "ds/serialized.h"
#include "node/rpc/rpc_handler.h"
#include "node_types.h"

#include <algorithm>
#include <exception>
#include <span>
#include <utility>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ccf
{
  class NodeToNode : public aft::ConsensusChannels
  {
  public:
    ~NodeToNode() override = default;

    class DroppedMessageException : public std::exception
    {
    public:
      NodeId from;

      DroppedMessageException(NodeId from_) : from(std::move(from_)) {}
    };

    virtual void close_channel(const NodeId& peer_id) = 0;

    virtual bool have_channel(const NodeId& nid) = 0;

    template <class T>
    bool send_authenticated(const NodeId& to, NodeMsgType type, const T& data)
    {
      return send_authenticated(
        to, type, reinterpret_cast<const uint8_t*>(&data), sizeof(T));
    }

    template <>
    bool send_authenticated(
      const NodeId& to, NodeMsgType type, const std::vector<uint8_t>& data)
    {
      return send_authenticated(to, type, data.data(), data.size());
    }

    virtual bool send_authenticated(
      const NodeId& to, NodeMsgType type, const uint8_t* data, size_t size) = 0;

    using aft::ConsensusChannels::send_consensus_message;

    bool send_consensus_message(
      const NodeId& to, const uint8_t* data, size_t size) final
    {
      return send_authenticated(to, NodeMsgType::consensus_msg, data, size);
    }

    virtual bool recv_authenticated(
      const NodeId& from,
      std::span<const uint8_t> header,
      const uint8_t*& data,
      size_t& size) = 0;

    // Returns borrowed message and payload views after verifying the legacy
    // header and replay counter. The caller must keep the buffer alive and
    // unchanged until synchronous consensus processing has finished.
    std::pair<std::span<const uint8_t>, std::span<const uint8_t>>
    recv_consensus_message(
      const NodeId& from, const uint8_t* buffer, size_t size)
    {
      const uint8_t* data = buffer;
      size_t header_size = 0;
      switch (serialized::peek<aft::RaftMsgType>(data, size))
      {
        case aft::raft_append_entries:
        {
          header_size = sizeof(aft::AppendEntries);
          break;
        }
        case aft::raft_append_entries_response:
        {
          header_size = sizeof(aft::AppendEntriesResponse);
          break;
        }
        case aft::raft_request_vote:
        {
          header_size = sizeof(aft::RequestVote);
          break;
        }
        case aft::raft_request_vote_response:
        {
          header_size = sizeof(aft::RequestVoteResponse);
          break;
        }
        case aft::raft_request_pre_vote:
        {
          header_size = sizeof(aft::RequestPreVote);
          break;
        }
        case aft::raft_request_pre_vote_response:
        {
          header_size = sizeof(aft::RequestPreVoteResponse);
          break;
        }
        case aft::raft_propose_request_vote:
        {
          header_size = sizeof(aft::ProposeRequestVote);
          break;
        }
        case aft::raft_append_entries_signed_response:
        default:
        {
          throw std::runtime_error("Unsupported legacy consensus message");
        }
      }

      serialized::skip(data, size, header_size);
      if (!recv_authenticated(from, {buffer, header_size}, data, size))
      {
        throw DroppedMessageException(from);
      }

      // The payload has independent ledger protection, not channel
      // authentication.
      return {{buffer, header_size}, {data, size}};
    }

    template <class T>
    const T& recv_authenticated_with_load(
      const NodeId& from, const uint8_t*& data, size_t& size)
    {
      const auto* data_ = data;
      auto size_ = size;

      const auto& t = serialized::overlay<T>(data_, size_);

      if (!recv_authenticated_with_load(from, data, size))
      {
        throw DroppedMessageException(from);
      }
      serialized::skip(data, size, sizeof(T));

      return t;
    }

    virtual bool recv_authenticated_with_load(
      const NodeId& from, const uint8_t*& data, size_t& size) = 0;

    virtual bool recv_channel_message(
      const NodeId& from, const uint8_t* data, size_t size) = 0;

    virtual void initialize(
      const NodeId& self_id,
      const ccf::crypto::Pem& service_cert,
      ccf::crypto::ECKeyPairPtr node_kp,
      const std::optional<ccf::crypto::Pem>& node_cert = std::nullopt) = 0;

    virtual void set_endorsed_node_cert(
      const ccf::crypto::Pem& endorsed_node_cert) = 0;

    virtual bool send_encrypted(
      const NodeId& to,
      NodeMsgType type,
      std::span<const uint8_t> header,
      const std::vector<uint8_t>& data) = 0;

    template <class T>
    bool send_encrypted(
      const NodeId& to,
      NodeMsgType type,
      const std::vector<uint8_t>& data,
      const T& msg_hdr)
    {
      std::span<const uint8_t> hdr_s{
        reinterpret_cast<const uint8_t*>(&msg_hdr), sizeof(T)};
      return send_encrypted(to, type, hdr_s, data);
    }

    template <class T>
    std::pair<T, std::vector<uint8_t>> recv_encrypted(
      const NodeId& from, const uint8_t*& data, size_t& size)
    {
      std::span<const uint8_t> ts(data, sizeof(T));
      auto t = serialized::read<T>(data, size);

      std::vector<uint8_t> plain = recv_encrypted(from, ts, data, size);
      return std::make_pair(t, plain);
    }

    virtual std::vector<uint8_t> recv_encrypted(
      const NodeId& from,
      std::span<const uint8_t> header,
      const uint8_t* data,
      size_t size) = 0;

    virtual void set_message_limit(size_t message_limit) = 0;
    virtual void set_idle_timeout(std::chrono::milliseconds idle_timeout) = 0;

    virtual void tick(std::chrono::milliseconds elapsed) = 0;
  };
}
