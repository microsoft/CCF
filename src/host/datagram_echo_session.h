// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/session.h"
#include "enclave/session_writer.h"

#include <span>
#include <vector>

namespace ccf
{
  class DatagramEchoSession : public Session
  {
  private:
    ::tcp::ConnID session_id;
    ccf::SessionWriter& writer;

  public:
    DatagramEchoSession(
      ::tcp::ConnID session_id_, ccf::SessionWriter& writer_) :
      session_id(session_id_),
      writer(writer_)
    {}

    void handle_incoming_data(
      std::span<const uint8_t> data, sockaddr addr = {}) override
    {
      writer.write_outbound(session_id, data, addr);
    }

    void send_data(std::vector<uint8_t>&& data) override
    {
      writer.write_outbound(session_id, {data.data(), data.size()});
    }

    void close_session() override
    {
      writer.close_socket(session_id);
    }
  };
}