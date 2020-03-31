// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../ds/ring_buffer_types.h"

namespace tls
{
  using ConnID = size_t;

  /// TLS-related ringbuffer messages
  /// The body of each message will begin with a connection ID
  enum : ringbuffer::Message
  {
    /// New connection has been opened. This will always be the first message
    /// sent regarding a connection. Host -> Enclave
    DEFINE_RINGBUFFER_MSG_TYPE(tls_start),

    /// Request for a new connection to a remote peer. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(tls_connect),

    /// Data read from socket, to be read inside enclave. Host -> Enclave
    DEFINE_RINGBUFFER_MSG_TYPE(tls_inbound),

    /// Data sent from the enclave, to be written to socket. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(tls_outbound),

    /// While processing data, the enclave decided this connection is stopped.
    /// Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(tls_stop),

    /// Connection has been invalidated. No more messages will be sent regarding
    /// this connection. Host -> Enclave
    DEFINE_RINGBUFFER_MSG_TYPE(tls_close),

    /// Enclave session has been deleted. Host can now safely remove the
    /// corresponding connection. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(tls_closed),
  };
}

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(tls::tls_start, tls::ConnID);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  tls::tls_connect, tls::ConnID, std::string, std::string);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  tls::tls_inbound, tls::ConnID, serializer::ByteRange);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  tls::tls_outbound, tls::ConnID, serializer::ByteRange);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(tls::tls_stop, tls::ConnID, std::string);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(tls::tls_close, tls::ConnID);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(tls::tls_closed, tls::ConnID);