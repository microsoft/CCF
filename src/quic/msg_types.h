// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ring_buffer_types.h"

#include <sys/socket.h>

namespace udp
{
  using ConnID = int64_t;

  enum : ringbuffer::Message
  {
    DEFINE_RINGBUFFER_MSG_TYPE(start),
    DEFINE_RINGBUFFER_MSG_TYPE(inbound),
    DEFINE_RINGBUFFER_MSG_TYPE(outbound),
  };

  static std::tuple<short, std::vector<uint8_t>> sockaddr_encode(sockaddr& addr)
  {
    short family = addr.sa_family;
    std::vector<uint8_t> data(14, '\0');
    memcpy(&data[0], &addr.sa_data, 14);
    return std::make_pair(family, data);
  }

  static sockaddr sockaddr_decode(
    short family, const std::vector<uint8_t>& data)
  {
    sockaddr addr;
    addr.sa_family = family;
    memcpy(&addr.sa_data, &data[0], 14);
    return addr;
  }
}

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(udp::start, udp::ConnID, std::string);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  udp::inbound, int64_t, short, std::vector<uint8_t>, serializer::ByteRange);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  udp::outbound, int64_t, short, std::vector<uint8_t>, serializer::ByteRange);

namespace quic
{
  using ConnID = udp::ConnID;

  /// QUIC-related ringbuffer messages, UDP doesn't have sessions
  /// The body of each message will begin with a connection ID
  enum : ringbuffer::Message
  {
    /// Does nothing but registers the interface name to listen. Host -> Enclave
    quic_start = udp::start,

    /// Data read from socket, to be read inside enclave. Host -> Enclave
    quic_inbound = udp::inbound,

    /// Data sent from the enclave, to be written to socket. Enclave -> Host
    quic_outbound = udp::outbound
  };
}
