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
    DEFINE_RINGBUFFER_MSG_TYPE(udp_start),
    DEFINE_RINGBUFFER_MSG_TYPE(udp_inbound),
    DEFINE_RINGBUFFER_MSG_TYPE(udp_outbound),
  };

  static std::tuple<short, std::vector<uint8_t>> sockaddr_encode(sockaddr& addr)
  {
    short family = addr.sa_family;
    std::vector<uint8_t> data(14, '\0');
    memcpy(data.data(), &addr.sa_data, 14);
    return std::make_pair(family, data);
  }

  static sockaddr sockaddr_decode(
    short family, const std::vector<uint8_t>& data)
  {
    sockaddr addr{};
    addr.sa_family = family;
    memcpy(&addr.sa_data, data.data(), 14);
    return addr;
  }
}

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(udp::udp_start, udp::ConnID, std::string);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  udp::udp_inbound,
  int64_t,
  short,
  std::vector<uint8_t>,
  serializer::ByteRange);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  udp::udp_outbound,
  int64_t,
  short,
  std::vector<uint8_t>,
  serializer::ByteRange);
