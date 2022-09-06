// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/odata_error.h"
#include "ds/serialized.h"
#include "grpc_status.h"
#include "node/rpc/rpc_exception.h"

#include <arpa/inet.h>
#include <variant>
#include <vector>

namespace ccf::grpc
{
  // As per https://cloud.google.com/apis/design/errors#error_model
  struct ErrorDetails
  {
    grpc_status code;
    std::string message;
    std::string details;
  };

  template <typename T>
  using GrpcAdapterResponse = std::variant<ErrorDetails, T>;
  using EmptyResponse = std::monostate;

  template <typename T>
  GrpcAdapterResponse<T> make_success(T t)
  {
    return t;
  }

  GrpcAdapterResponse<EmptyResponse> make_success()
  {
    return EmptyResponse{};
  }

  template <typename T>
  GrpcAdapterResponse<T> make_error(
    grpc_status status, const std::string& code, const std::string& msg)
  {
    return ErrorDetails{status, code, msg};
  }

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
    const GrpcAdapterResponse<Out>& r,
    const std::shared_ptr<ccf::RpcContext>& ctx)
  {
    auto error = std::get_if<ErrorDetails>(&r);
    if (error != nullptr)
    {
      // TODO: Handle errors
    }
    else
    {
      const auto resp = std::get_if<Out>(&r);

      if constexpr (std::is_same_v<Out, void>)
      {
        // TODO: Do we set this in the HTTP status or in the grpc-status??
        ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
      }
      else if constexpr (std::is_same_v<Out, EmptyResponse>)
      {
        // TODO: Fix
        ctx->set_response_status(HTTP_STATUS_OK);
      }
      else
      {
        // TODO: Check that Out is protobuf-able type (for better compile-time
        // error message)

        size_t r_size = grpc::message_frame_length + resp->ByteSizeLong();
        std::vector<uint8_t> r(r_size);
        auto r_data = r.data();

        grpc::write_message_frame(r_data, r_size, resp->ByteSizeLong());
        ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::GRPC);

        if (!resp->SerializeToArray(r_data, r_size))
        {
          throw std::logic_error(fmt::format(
            "Error serialising protobuf response of size {}",
            resp->ByteSizeLong()));
        }
        ctx->set_response_body(r);
        ctx->set_response_header(http::headers::CONTENT_LENGTH, r_size);
      }
      ctx->set_response_trailer("grpc-status", 0);
      ctx->set_response_trailer("grpc-message", "Ok");
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