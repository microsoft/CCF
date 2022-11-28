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

    // Set response header here rather than in set_grpc_response as data stream
    // may be sent to client before endpoint returns
    for (auto const& h : default_response_headers)
    {
      ctx->set_response_header(h.first, h.second);
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

  template <typename Out>
  void set_grpc_response(
    const GrpcAdapterResponse<Out>& r,
    const std::shared_ptr<ccf::RpcContext>& ctx)
  {
    auto success_response = std::get_if<SuccessResponse<Out>>(&r);
    if (success_response != nullptr)
    {
      std::vector<uint8_t> r;

      if constexpr (nonstd::is_std_vector<Out>::value)
      {
        r = make_grpc_messages(success_response->body);
      }
      else
      {
        r = make_grpc_message(success_response->body);
      }

      ctx->set_response_body(r);

      ctx->set_response_trailer(
        make_status_trailer(success_response->status.code()));
      ctx->set_response_trailer(
        make_message_trailer(success_response->status.message()));
    }
    else if (std::get_if<ErrorResponse>(&r)) // TODO: Cleanup
    {
      auto error_response = std::get<ErrorResponse>(r);
      ctx->set_response_trailer(
        make_status_trailer(error_response.status.code()));
      ctx->set_response_trailer(
        make_message_trailer(error_response.status.message()));
    }
    else /* Pending */
    {
      LOG_FAIL_FMT("Pending!"); // TODO: Remove
      auto rpc_ctx_impl = dynamic_cast<ccf::RpcContextImpl*>(ctx.get());
      if (rpc_ctx_impl == nullptr)
      {
        throw std::logic_error("Unexpected type for RpcContext");
      }

      rpc_ctx_impl->response_is_pending = true;
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
    std::function<grpc::GrpcAdapterEmptyResponse(
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
      grpc::set_grpc_response<grpc::EmptyResponse>(
        f(ctx,
          grpc::get_grpc_payload<In>(ctx.rpc_ctx),
          grpc::make_stream<Out>(ctx.rpc_ctx)),
        ctx.rpc_ctx);
    };
  }
}
