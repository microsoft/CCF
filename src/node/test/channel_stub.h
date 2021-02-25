// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/entities.h"
#include "node/node_types.h"

#include <vector>

namespace ccf
{
  class ChannelStubProxy
  {
  public:
    std::vector<std::vector<uint8_t>> sent_encrypted_messages;

    ChannelStubProxy() {}

    template <class T>
    bool send_encrypted(
      NodeId to,
      const NodeMsgType& msg_type,
      const std::vector<uint8_t>& data,
      const T& msg)
    {
      sent_encrypted_messages.push_back(data);
      return true;
    }

    template <class T>
    bool send_authenticated(
      NodeId to, const ccf::NodeMsgType& msg_type, const T& data)
    {
      return true;
    }

    void send_request_hash_to_nodes(
      std::shared_ptr<enclave::RpcContext> rpc_ctx, std::set<ccf::NodeId> nodes)
    {}

    template <class T>
    std::pair<T, std::vector<uint8_t>> recv_encrypted(
      NodeId from, const uint8_t* data, size_t size)
    {
      T msg;
      return std::make_pair(msg, std::vector<uint8_t>(data, data + size));
    }

    std::vector<uint8_t> get_pop_back()
    {
      auto back = sent_encrypted_messages.back();
      sent_encrypted_messages.pop_back();
      return back;
    }

    void clear()
    {
      sent_encrypted_messages.clear();
    }

    size_t size() const
    {
      return sent_encrypted_messages.size();
    }

    bool is_empty() const
    {
      return sent_encrypted_messages.empty();
    }
  };
}