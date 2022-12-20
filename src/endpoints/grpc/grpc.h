// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/odata_error.h"
#include "message.h"
#include "node/rpc/rpc_context_impl.h"
#include "node/rpc/rpc_exception.h"
#include "stream.h"
#include "types.h"

#include <memory>

namespace ccf::grpc
{
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

    if constexpr (nonstd::is_std_vector<In>::value)
    {
      using Message = typename In::value_type;
      In messages;
      while (size != 0)
      {
        const auto message_length = impl::read_message_frame(data, size);
        if (message_length > size)
        {
          throw std::logic_error(fmt::format(
            "Error in gRPC frame: only {} bytes remaining but message header "
            "says messages is {} bytes",
            size,
            message_length));
        }

        Message& msg = messages.emplace_back();
        if (!msg.ParseFromArray(data, message_length))
        {
          throw std::logic_error(fmt::format(
            "Error deserialising protobuf payload of type {}, size {} (message "
            "{} in "
            "stream)",
            msg.GetTypeName(),
            size,
            messages.size()));
        }
        data += message_length;
        size -= message_length;
      }
      return messages;
    }
    else
    {
      const auto message_length = impl::read_message_frame(data, size);
      if (size != message_length)
      {
        throw std::logic_error(fmt::format(
          "Error in gRPC frame: frame size is {} but messages is {} bytes",
          size,
          message_length));
      }

      In in;
      if (!in.ParseFromArray(data, message_length))
      {
        throw std::logic_error(fmt::format(
          "Error deserialising protobuf payload of type {}, size {}",
          in.GetTypeName(),
          size));
      }
      return in;
    }
  }

  inline void set_grpc_default_headers(
    const std::shared_ptr<ccf::RpcContext>& ctx)
  {
    for (auto const& h : default_response_headers)
    {
      ctx->set_response_header(h.first, h.second);
    }
  }

  inline void set_grpc_response_trailers(
    const std::shared_ptr<ccf::RpcContext>& ctx,
    const ccf::protobuf::Status& status)
  {
    ctx->set_response_trailer(make_status_trailer(status.code()));
    ctx->set_response_trailer(make_message_trailer(status.message()));
  }

  template <typename Out>
  void set_grpc_response(
    const GrpcAdapterResponse<Out>& r,
    const std::shared_ptr<ccf::RpcContext>& ctx)
  {
    set_grpc_default_headers(ctx);

    if (auto success_response = std::get_if<SuccessResponse<Out>>(&r))
    {
      std::vector<uint8_t> v;

      if constexpr (nonstd::is_std_vector<Out>::value)
      {
        v = serialise_grpc_messages(success_response->body);
      }
      else
      {
        v = serialise_grpc_message(success_response->body);
      }

      ctx->set_response_body(v);

      set_grpc_response_trailers(ctx, success_response->status);
    }
    else if (std::get_if<ErrorResponse>(&r))
    {
      auto error_response = std::get<ErrorResponse>(r);

      set_grpc_response_trailers(ctx, error_response.status);
    }
  }
}

namespace ccf
{
  template <typename In, typename Out>
  using GrpcEndpoint = std::function<grpc::GrpcAdapterResponse<Out>(
    endpoints::EndpointContext&, In&&)>;

  template <typename In, typename Out>
  using GrpcReadOnlyEndpoint = std::function<grpc::GrpcAdapterResponse<Out>(
    endpoints::ReadOnlyEndpointContext&, In&&)>;

  template <typename In, typename Out>
  using GrpcCommandEndpoint = std::function<grpc::GrpcAdapterResponse<Out>(
    endpoints::CommandEndpointContext&, In&&)>;

  template <typename In, typename Out>
  using GrpcCommandUnaryStreamEndpoint =
    std::function<grpc::GrpcAdapterStreamingResponse(
      endpoints::CommandEndpointContext&, In&&, grpc::StreamPtr<Out>&&)>;

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

  template <typename In, typename Out>
  endpoints::CommandEndpointFunction grpc_command_adapter(
    const GrpcCommandEndpoint<In, Out>& f)
  {
    return [f](endpoints::CommandEndpointContext& ctx) {
      grpc::set_grpc_response<Out>(
        f(ctx, grpc::get_grpc_payload<In>(ctx.rpc_ctx)), ctx.rpc_ctx);
    };
  }

  // Note: For now, only command endpoints (i.e. with no kv::Tx) support gRPC
  // server streaming.
  template <typename In, typename Out>
  endpoints::CommandEndpointFunction grpc_command_unary_stream_adapter(
    const GrpcCommandUnaryStreamEndpoint<In, Out>& f)
  {
    return [f](endpoints::CommandEndpointContext& ctx) {
      grpc::set_grpc_default_headers(ctx.rpc_ctx);
      const auto result =
        f(ctx,
          grpc::get_grpc_payload<In>(ctx.rpc_ctx),
          grpc::make_stream<Out>(ctx.rpc_ctx));

      if (auto error_response = std::get_if<grpc::ErrorResponse>(&result))
      {
        grpc::set_grpc_response_trailers(ctx.rpc_ctx, error_response->status);
      }
    };
  }
}
