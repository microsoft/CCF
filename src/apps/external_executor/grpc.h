// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/odata_error.h"
#include "ds/serialized.h"
#include "grpc_status.h"
#include "node/rpc/rpc_exception.h"
#include "status.pb.h"

#include <arpa/inet.h>
#include <variant>
#include <vector>

namespace ccf::grpc
{
  namespace impl
  {
    using CompressedFlag = uint8_t;
    using MessageLength = uint32_t;

    static constexpr size_t message_frame_length =
      sizeof(CompressedFlag) + sizeof(MessageLength);

    MessageLength read_message_frame(const uint8_t*& data, size_t& size)
    {
      auto compressed_flag = serialized::read<CompressedFlag>(data, size);
      if (compressed_flag >= 1)
      {
        throw std::logic_error(fmt::format(
          "gRPC compressed flag has unexpected value {} - currently only "
          "support "
          "unencoded gRPC payloads",
          compressed_flag));
      }
      return ntohl(serialized::read<MessageLength>(data, size));
    }

    void write_message_frame(uint8_t*& data, size_t& size, size_t message_size)
    {
      CompressedFlag compressed_flag = 0;
      serialized::write(data, size, compressed_flag);
      serialized::write(data, size, htonl(message_size));
    }
  }

  struct EmptyResponse
  {};

  template <typename T>
  struct SuccessResponse
  {
    T body;
    ccf::Status status;

    SuccessResponse(const T& body_, ccf::Status status_) :
      body(body_),
      status(status_)
    {}
  };

  struct ErrorResponse
  {
    ccf::Status status;
    ErrorResponse(ccf::Status status_) : status(status_) {}
  };

  template <typename T>
  using GrpcAdapterResponse = std::variant<ErrorResponse, SuccessResponse<T>>;

  template <typename T>
  GrpcAdapterResponse<T> make_success(T t)
  {
    ccf::Status s;
    s.set_code(static_cast<int32_t>(grpc_status::OK));
    s.set_message("Ok");
    return SuccessResponse(t, s);
  }

  GrpcAdapterResponse<EmptyResponse> make_success()
  {
    ccf::Status s;
    s.set_code(0);
    s.set_message("Ok");
    return SuccessResponse(EmptyResponse{}, s);
  }

  ErrorResponse make_error(
    grpc_status code, const std::string& details, const std::string& msg)
  {
    ccf::Status s;
    s.set_code(static_cast<int32_t>(code));
    s.set_message(msg);
    return ErrorResponse(s);
  }

  template <typename T>
  GrpcAdapterResponse<T> make_error(
    grpc_status code, const std::string& details, const std::string& msg)
  {
    ccf::Status s;
    s.set_code(static_cast<int32_t>(code));
    s.set_message(msg);
    return ErrorResponse(s);
  }

  template <typename In>
  In get_grpc_payload(const std::shared_ptr<ccf::RpcContext>& ctx)
  {
    auto& request_body = ctx->get_request_body();
    auto request_content_type =
      ctx->get_request_header(http::headers::CONTENT_TYPE);

    auto data = request_body.data();
    auto size = request_body.size();

    if (request_content_type != http::headervalues::contenttype::GRPC)
    {
      throw RpcException(
        HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE,
        ccf::errors::UnsupportedContentType,
        fmt::format(
          "Unsupported content type. Only {} is supported ",
          http::headervalues::contenttype::GRPC));
    }

    auto message_length = impl::read_message_frame(data, size);
    if (size != message_length)
    {
      throw std::logic_error(fmt::format(
        "Error in gRPC frame: frame size is {} but messages is {} bytes",
        size,
        message_length));
    }
    ctx->set_response_header(
      http::headers::CONTENT_TYPE, http::headervalues::contenttype::GRPC);

    In in;
    if (!in.ParseFromArray(data, size))
    {
      throw std::logic_error(
        fmt::format("Error deserialising protobuf payload of size {}", size));
    }
    return in;
  }

  template <typename Out>
  void set_grpc_response(
    const GrpcAdapterResponse<Out>& r,
    const std::shared_ptr<ccf::RpcContext>& ctx)
  {
    auto r_ = std::get_if<SuccessResponse<Out>>(&r);
    if (r_ != nullptr)
    {
      const auto& resp = r_->body;
      if constexpr (!std::is_same_v<Out, EmptyResponse>)
      {
        size_t r_size = impl::message_frame_length + resp.ByteSizeLong();
        std::vector<uint8_t> r(r_size);
        auto r_data = r.data();

        impl::write_message_frame(r_data, r_size, resp.ByteSizeLong());
        ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::GRPC);

        if (!resp.SerializeToArray(r_data, r_size))
        {
          throw std::logic_error(fmt::format(
            "Error serialising protobuf response of size {}",
            resp.ByteSizeLong()));
        }
        ctx->set_response_body(r);
        ctx->set_response_header(http::headers::CONTENT_LENGTH, r_size);
      }
      ctx->set_response_trailer("grpc-status", r_->status.code());
      ctx->set_response_trailer("grpc-message", r_->status.message());
    }
    else
    {
      auto r_ = std::get<ErrorResponse>(r);
      ctx->set_response_trailer("grpc-status", r_.status.code());
      ctx->set_response_trailer("grpc-message", r_.status.message());
    }
  }
}

namespace ccf
{
  template <typename In, typename Out>
  using GrpcEndpoint = std::function<grpc::GrpcAdapterResponse<Out>(
    endpoints::EndpointContext& ctx, In&& payload)>;

  template <typename In, typename Out>
  using GrpcReadOnlyEndpoint = std::function<grpc::GrpcAdapterResponse<Out>(
    endpoints::ReadOnlyEndpointContext& ctx, In&& payload)>;

  template <typename In, typename Out>
  endpoints::EndpointFunction grpc_adapter(const GrpcEndpoint<In, Out>& f)
  {
    return [f](endpoints::EndpointContext& ctx) {
      grpc::set_grpc_response<Out>(
        f(ctx, grpc::get_grpc_payload<In>(ctx.rpc_ctx)), ctx.rpc_ctx);
    };
  }

  template <typename In, typename Out>
  endpoints::ReadOnlyEndpointFunction grpc_read_only_adapter(
    const GrpcReadOnlyEndpoint<In, Out>& f)
  {
    return [f](endpoints::ReadOnlyEndpointContext& ctx) {
      grpc::set_grpc_response<Out>(
        f(ctx, grpc::get_grpc_payload<In>(ctx.rpc_ctx)), ctx.rpc_ctx);
    };
  }
}
