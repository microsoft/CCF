// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/http_header_map.h"
#include "ccf/http_responder.h"
#include "message.h"
#include "status.h"
#include "types.h"

#include <functional>
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

    void start_stream(
      http_status status = HTTP_STATUS_OK,
      const http::HeaderMap& headers = default_response_headers)
    {
      http_responder->start_stream(status, headers);
    }

    bool stream_data(std::span<const uint8_t> data)
    {
      return http_responder->stream_data(data);
    }

    bool close_stream(http::HeaderMap&& trailers)
    {
      return http_responder->close_stream(std::move(trailers));
    }

    void set_on_close_callback(http::StreamOnCloseCallback close_cb)
    {
      http_responder->set_on_stream_close_callback(close_cb);
    }
  };

  template <typename T>
  class Stream : public BaseStream
  {
  public:
    Stream(
      const std::shared_ptr<http::HTTPResponder>& r,
      http_status s = HTTP_STATUS_OK,
      const http::HeaderMap& h = default_response_headers) :
      BaseStream(r)
    {
      start_stream(s, h);
    }
    Stream(const Stream& s) : BaseStream(s) {}

    Stream(Stream&&) = delete;

    bool stream_msg(const T& msg)
    {
      return stream_data(serialise_grpc_message(msg));
    }
  };

  template <typename T>
  class DetachedStream : public Stream<T>
  {
  public:
    DetachedStream(
      const Stream<T>& s, http::StreamOnCloseCallback close_cb_ = nullptr) :
      Stream<T>(s)
    {
      BaseStream::set_on_close_callback(close_cb_);
    }

    ~DetachedStream()
    {
      close(make_grpc_status_ok());
    }

    bool close(const GrpcAdapterEmptyResponse& resp)
    {
      http::HeaderMap trailers;
      auto success_response = std::get_if<EmptySuccessResponse>(&resp);
      if (success_response != nullptr)
      {
        trailers.emplace(make_status_trailer(success_response->status.code()));
        trailers.emplace(
          make_message_trailer(success_response->status.message()));
      }
      else
      {
        auto error_response = std::get<ErrorResponse>(resp);

        trailers.emplace(make_status_trailer(error_response.status.code()));
        trailers.emplace(make_message_trailer(error_response.status.message()));
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
    const std::shared_ptr<ccf::RpcContext>& rpc_ctx,
    http_status status = HTTP_STATUS_OK,
    const http::HeaderMap& headers = default_response_headers)
  {
    return std::make_unique<Stream<T>>(
      get_http_responder(rpc_ctx), status, headers);
  }

  template <typename T>
  static DetachedStreamPtr<T> detach_stream(
    StreamPtr<T>&& stream, http::StreamOnCloseCallback close_cb = nullptr)
  {
    return std::make_unique<DetachedStream<T>>(*stream.get(), close_cb);
  }
}