// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "grpc_message.h"
#include "http/http2_session.h"

#include <memory>

namespace ccf::grpc
{
  template <typename T>
  class Stream
  {
  private:
    std::shared_ptr<http::HTTPResponder> http_responder;

  public:
    Stream() =
      default; // TODO: Remove once streaming endpoints can return nothing

    Stream(const std::shared_ptr<http::HTTPResponder>& http_responder_) :
      http_responder(http_responder_)
    {}

    void stream_msg(const T& data, bool close_stream = false)
    {
      http_responder->stream_data(make_grpc_message(data), close_stream);
    }
  };

  template <typename T>
  struct is_grpc_stream : std::false_type
  {};

  template <typename T>
  struct is_grpc_stream<Stream<T>> : public std::true_type
  {};

  template <typename T>
  using StreamPtr = std::shared_ptr<Stream<T>>;

  template <typename T>
  static StreamPtr<T> make_stream(
    const std::shared_ptr<ccf::RpcContext>& rpc_ctx,
    const std::shared_ptr<http::AbstractResponderLookup>& responder_lookup)
  {
    auto http2_session_context =
      std::dynamic_pointer_cast<http::HTTP2SessionContext>(
        rpc_ctx->get_session_context());
    if (http2_session_context == nullptr)
    {
      throw std::logic_error("Unexpected session context type");
    }

    const auto session_id = http2_session_context->client_session_id;
    const auto stream_id = http2_session_context->stream_id;

    auto http_responder =
      responder_lookup->lookup_responder(session_id, stream_id);
    if (http_responder == nullptr)
    {
      throw std::logic_error(fmt::format(
        "Found no responder for session {}, stream {}", session_id, stream_id));
    }

    return std::make_shared<Stream<T>>(http_responder);
  }
}