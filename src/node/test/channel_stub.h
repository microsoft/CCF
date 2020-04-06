// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/entities.h"
#include "node/nodetypes.h"

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
      const NodeMsgType& msg_type,
      NodeId to,
      const std::vector<uint8_t>& data,
      const T& msg)
    {
      sent_encrypted_messages.push_back(data);
      return true;
    }

    template <class T>
    std::pair<T, std::vector<uint8_t>> recv_encrypted(
      const uint8_t* data, size_t size)
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