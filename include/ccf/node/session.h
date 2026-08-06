// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <span>
#include <sys/socket.h>

namespace ccf
{
  // A peer address for connectionless (datagram) transports.
  //
  // sockaddr_storage rather than sockaddr, because sockaddr is too small to
  // hold an IPv6 address, and the length is carried with it because only the
  // first `len` bytes are meaningful - and sendto() requires it.
  struct SessionEndpoint
  {
    sockaddr_storage addr{};
    socklen_t len = 0;
  };

  class Session
  {
  public:
    virtual ~Session() = default;

    // Inbound bytes for this session. `peer` is the source address of the
    // datagram for connectionless (UDP) transports, and is unused (default)
    // for stream (TCP) transports.
    virtual void handle_incoming_data(
      std::span<const uint8_t> data, const SessionEndpoint& peer = {}) = 0;
    virtual void send_data(std::vector<uint8_t>&& data) = 0;
    virtual void close_session() = 0;
  };
}