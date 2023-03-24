// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ds/serialized.h"
#include "enclave/rpc_handler.h"
#include "node_types.h"

#include <algorithm>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ccf
{
  class NodeToNode
  {
  public:
    virtual ~NodeToNode() = default;

    class DroppedMessageException : public std::exception
    {
    public:
      NodeId from;
      DroppedMessageException(const NodeId& from) : from(from) {}
    };

    virtual void associate_node_address(
      const NodeId& peer_id,
      const std::string& peer_hostname,
      const std::string& peer_service) = 0;

    virtual void close_channel(const NodeId& peer_id) = 0;

    virtual bool have_channel(const NodeId& nid) const = 0;

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

    template <class T>
    const T& recv_authenticated(
      const NodeId& from, const uint8_t*& data, size_t& size)
    {
      std::span<const uint8_t> ts(data, sizeof(T));
      auto& t = serialized::overlay<T>(data, size);

      if (!recv_authenticated(from, ts, data, size))
      {
        throw DroppedMessageException(from);
      }

      return t;
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

    virtual bool recv_authenticated(
      const NodeId& from,
      std::span<const uint8_t> header,
      const uint8_t*& data,
      size_t& size) = 0;

    virtual bool recv_channel_message(
      const NodeId& from, const uint8_t* data, size_t size) = 0;

    virtual void initialize(
      const NodeId& self_id,
      const crypto::Pem& service_cert,
      crypto::KeyPairPtr node_kp,
      const std::optional<crypto::Pem>& node_cert = std::nullopt) = 0;

    virtual void set_endorsed_node_cert(
      const crypto::Pem& endorsed_node_cert) = 0;

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
  };
}
