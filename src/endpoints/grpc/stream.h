// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/http_header_map.h"
#include "message.h"
#include "types.h"

#include <memory>

namespace ccf::grpc
{
  // Note: Streams are not currently thread safe

  // Vanilla HTTP/2 stream
  class BaseStream
  {
  private:
    std::shared_ptr<http::HTTPResponder> http_responder;

  protected:
    BaseStream(const std::shared_ptr<http::HTTPResponder>& r) :
      http_responder(r)
    {}

    BaseStream(const BaseStream&) = default;

    bool stream_data(std::vector<uint8_t>&& data)
    {
      return http_responder->stream_data(std::move(data));
    }

    bool close_stream(http::HeaderMap&& trailers)
    {
      return http_responder->close_stream(std::move(trailers));
    }
  };

  template <typename T>
  class Stream : public BaseStream
  {
  public:
    Stream(const std::shared_ptr<http::HTTPResponder>& r) : BaseStream(r) {}
    Stream(const Stream& s) : BaseStream(s) {}

    Stream(Stream&&) = delete;

    bool stream_msg(const T& msg)
    {
      return stream_data(make_grpc_message(msg));
    }
  };

  template <typename T>
  class DetachedStream : public Stream<T>
  {
  public:
    DetachedStream(const Stream<T>& s) : Stream<T>(s) {}

    ~DetachedStream()
    {
      close(make_grpc_status_ok());
    }

    bool close(const GrpcAdapterEmptyResponse& resp)
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

      return this->close_stream(std::move(trailers));
    }
  };

  template <typename T>
  using StreamPtr = std::unique_ptr<Stream<T>>;

  template <typename T>
  using DetachedStreamPtr = std::unique_ptr<DetachedStream<T>>;

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
  static DetachedStreamPtr<T> detach_stream(StreamPtr<T>&& stream)
  {
    return std::make_unique<DetachedStream<T>>(*stream.get());
  }
}