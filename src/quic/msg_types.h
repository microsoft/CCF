// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ring_buffer_types.h"

namespace quic
{
  using ConnID = int64_t;

  /// QUIC-related ringbuffer messages, UDP doesn't have sessions
  /// The body of each message will begin with a connection ID
  enum : ringbuffer::Message
  {
    /// Does nothing but registers the interface name to listen. Host -> Enclave
    DEFINE_RINGBUFFER_MSG_TYPE(quic_start),

    /// Data read from socket, to be read inside enclave. Host -> Enclave
    DEFINE_RINGBUFFER_MSG_TYPE(quic_inbound),

    /// Data sent from the enclave, to be written to socket. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(quic_outbound),
  };

  struct sockaddr_encoding
  {
    uint64_t lhs;
    uint64_t rhs;
  };
}

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(quic::quic_start, quic::ConnID, std::string);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  quic::quic_inbound, quic::ConnID, uint64_t, uint64_t, serializer::ByteRange);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  quic::quic_outbound, quic::ConnID, uint64_t, uint64_t, serializer::ByteRange);
