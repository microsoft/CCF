// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/odata_error.h"
#include "ds/serialized.h"
#include "node/rpc/rpc_exception.h"

#include <arpa/inet.h>
#include <variant>
#include <vector>

namespace ccf::grpc
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
        "gRPC compressed flag has unexpected value {} - currently only support "
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

    auto message_length = grpc::read_message_frame(data, size);
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
    const Out& resp, const std::shared_ptr<ccf::RpcContext>& ctx)
  {
    size_t r_size = resp.ByteSizeLong();
    std::vector<uint8_t> r(r_size);

    auto r_data = r.data();

    auto request_content_type =
      ctx->get_request_header(http::headers::CONTENT_TYPE);
    if (request_content_type == http::headervalues::contenttype::GRPC)
    {
      r_size += grpc::message_frame_length;
      r.resize(r_size);
      r_data = r.data();
      grpc::write_message_frame(r_data, r_size, resp.ByteSizeLong());
      ctx->set_response_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::GRPC);
    }

    if (!resp.SerializeToArray(r_data, r_size))
    {
      throw std::logic_error(fmt::format(
        "Error serialising protobuf response of size {}", resp.ByteSizeLong()));
    }
    ctx->set_response_body(r);
    ctx->set_response_header(http::headers::CONTENT_LENGTH, r_size);
    ctx->set_response_trailer("grpc-status", 0);
    ctx->set_response_trailer("grpc-message", "Ok");
  }
}

namespace ccf
{
  template <typename In, typename Out = void>
  using GrpcEndpoint =
    std::function<Out(endpoints::EndpointContext& ctx, In&& payload)>;

  template <typename In, typename Out = void>
  using GrpcReadOnlyEndpoint =
    std::function<Out(endpoints::ReadOnlyEndpointContext& ctx, In&& payload)>;

  template <typename In, typename Out = void>
  endpoints::EndpointFunction grpc_adapter(const GrpcEndpoint<In, Out>& f)
  {
    if constexpr (std::is_same_v<Out, void>)
    {
      return [f](endpoints::EndpointContext& ctx) {
        f(ctx, grpc::get_grpc_payload<In>(ctx.rpc_ctx));
        ctx.rpc_ctx->set_response_trailer("grpc-status", 0);
        ctx.rpc_ctx->set_response_trailer("grpc-message", "Ok");
      };
    }
    else
    {
      return [f](endpoints::EndpointContext& ctx) {
        grpc::set_grpc_response<Out>(
          f(ctx, grpc::get_grpc_payload<In>(ctx.rpc_ctx)), ctx.rpc_ctx);
      };
    }
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