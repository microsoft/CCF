// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "message.h"

#include <memory>

namespace ccf::grpc
{
  template <typename T>
  class Stream;

  template <typename T>
  using StreamPtr = std::shared_ptr<Stream<T>>;

  template <typename T>
  class Stream
  {
  private:
    std::shared_ptr<http::HTTPResponder> http_responder;

  protected:
    void stream_data(std::vector<uint8_t>&& data, bool close_stream)
    {
      http_responder->stream_data(std::move(data), close_stream);
    }

  public:
    Stream() = default;

    Stream(const Stream&) = delete;
    Stream(Stream&&) = delete;

    Stream(const std::shared_ptr<http::HTTPResponder>& http_responder_) :
      http_responder(http_responder_)
    {}

    Stream(StreamPtr<T>&& stream) :
      http_responder(std::move(stream->http_responder))
    {}

    void stream_msg(const T& msg)
    {
      stream_data(make_grpc_message(msg), false);
    }
  };

  template <typename T>
  class DetachedStream : public Stream<T>
  {
  public:
    DetachedStream() =
      default; // TODO: Remove once streaming endpoints can return nothing

    DetachedStream(StreamPtr<T>&& s) : Stream<T>(std::move(s)) {}

    void stream_msg(const T& msg, bool close_stream = false)
    {
      this->stream_data(make_grpc_message(msg), close_stream);
    }
  };

  template <typename T>
  using DetachedStreamPtr = std::shared_ptr<DetachedStream<T>>;

  template <typename T>
  static DetachedStreamPtr<T> detach_stream(StreamPtr<T>&& stream)
  {
    return std::make_shared<DetachedStream<T>>(std::move(stream));
  }

  template <typename T>
  struct is_grpc_stream : std::false_type
  {};

  template <typename T>
  struct is_grpc_stream<Stream<T>> : public std::true_type
  {};

  template <typename T>
  struct is_grpc_stream<DetachedStream<T>> : public std::true_type
  {};

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