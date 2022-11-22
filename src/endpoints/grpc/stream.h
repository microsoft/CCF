// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "http/http2_session.h"
#include "message.h"

#include <memory>

namespace ccf::grpc
{
  template <typename T>
  class BaseStream
  {
  private:
    std::shared_ptr<http::HTTPResponder> http_responder;

  public:
    BaseStream() = default;

    BaseStream(const std::shared_ptr<http::HTTPResponder>& http_responder_) :
      http_responder(http_responder_)
    {}

    void stream_msg(const T& data, bool close_stream)
    {
      http_responder->stream_data(make_grpc_message(data), close_stream);
    }
  };

  template <typename T>
  class DetachedStream : public BaseStream<T>
  {
  private:
    BaseStream<T> stream;
    // TODO: Add close callback?

  public:
    DetachedStream() =
      default; // TODO: Remove once streaming endpoints can return nothing

    DetachedStream(const BaseStream<T>& s) : stream(s) {}

    void stream_msg(const T& data, bool close_stream = false)
    {
      stream.stream_msg(data, close_stream);
    }
  };

  template <typename T>
  class Stream : public BaseStream<T>
  {
  private:
    BaseStream<T> stream;

  public:
    Stream() =
      default; // TODO: Remove once streaming endpoints can return nothing

    // TODO : Uncomment once streaming endpoints can return nothing
    // Stream(const Stream&) = delete;
    // Stream(Stream&&) = delete;

    Stream(const BaseStream<T>& s) : stream(s) {}

    void stream_msg(const T& data)
    {
      stream.stream_msg(data, false);
    }

    std::shared_ptr<DetachedStream<T>> detach()
    {
      return std::make_shared<DetachedStream<T>>(stream);
    }
  };

  template <typename T>
  struct is_grpc_stream : std::false_type
  {};

  template <typename T>
  struct is_grpc_stream<Stream<T>> : public std::true_type
  {};

  template <typename T>
  struct is_grpc_stream<DetachedStream<T>> : public std::true_type
  {};

  template <typename T>
  using StreamPtr = std::shared_ptr<Stream<T>>;

  template <typename T>
  using DetachedStreamPtr = std::shared_ptr<DetachedStream<T>>;

  static std::shared_ptr<http::HTTPResponder> get_http_responder(
    const std::shared_ptr<ccf::RpcContext>& rpc_ctx)
  {
    auto http_responder = rpc_ctx->get_responder();
    if (http_responder == nullptr)
    {
      throw std::logic_error("Found no responder for current session/stream");
    }
    return http_responder;
  }

  template <typename T>
  static StreamPtr<T> make_stream(
    const std::shared_ptr<ccf::RpcContext>& rpc_ctx)
  {
    return std::make_shared<Stream<T>>(get_http_responder(rpc_ctx));
  }

  template <typename T>
  static DetachedStreamPtr<T> make_detached_stream(
    const std::shared_ptr<ccf::RpcContext>& rpc_ctx)
  {
    return std::make_shared<DetachedStream<T>>(get_http_responder(rpc_ctx));
  }
}