// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/http_header_map.h"
#include "message.h"
#include "types.h"

#include <memory>

namespace ccf::grpc
{
  // Note: ccf::grpc::Stream and ccf::grpc::DetachedStream are not currently
  // thread safe

  template <typename T>
  class Stream;

  template <typename T>
  using StreamPtr = std::unique_ptr<Stream<T>>;

  template <typename T>
  class Stream
  {
  private:
    std::shared_ptr<http::HTTPResponder> http_responder;

  protected:
    bool stream_data(std::vector<uint8_t>&& data)
    {
      return http_responder->stream_data(std::move(data));
    }

    bool close_stream(const GrpcAdapterEmptyResponse& resp)
    {
      // TODO: Refactor with set_grpc_response
      http::HeaderMap trailers;
      auto success_response = std::get_if<EmptySuccessResponse>(&resp);
      if (success_response != nullptr)
      {
        trailers[TRAILER_STATUS] =
          std::to_string(success_response->status.code());
        trailers[TRAILER_MESSAGE] = success_response->status.message();
      }
      else
      {
        auto error_response = std::get<ErrorResponse>(resp);

        trailers[TRAILER_STATUS] = std::to_string(error_response.status.code());
        trailers[TRAILER_MESSAGE] = error_response.status.message();
      }
      return http_responder->close_stream(std::move(trailers));
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

    bool stream_msg(const T& msg)
    {
      return stream_data(make_grpc_message(msg));
    }
  };

  template <typename T>
  class DetachedStream : public Stream<T>
  {
  public:
    DetachedStream(StreamPtr<T>&& s) : Stream<T>(std::move(s)) {}

    bool stream_msg(const T& msg)
    {
      return this->stream_data(make_grpc_message(msg));
    }

    bool close(const GrpcAdapterEmptyResponse& resp)
    {
      return this->close_stream(resp);
    }
  };

  template <typename T>
  using DetachedStreamPtr = std::unique_ptr<DetachedStream<T>>;

  template <typename T>
  static DetachedStreamPtr<T> detach_stream(StreamPtr<T>&& stream)
  {
    return std::make_unique<DetachedStream<T>>(std::move(stream));
  }

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
    return std::make_unique<Stream<T>>(get_http_responder(rpc_ctx));
  }

  template <typename T>
  static DetachedStreamPtr<T> make_detached_stream(
    const std::shared_ptr<ccf::RpcContext>& rpc_ctx)
  {
    return std::make_unique<DetachedStream<T>>(get_http_responder(rpc_ctx));
  }
}