// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/odata_error.h"
#include "ds/serialized.h"
#include "grpc_status.h"
#include "node/rpc/rpc_exception.h"

#include <arpa/inet.h>
#include <google/protobuf/empty.pb.h>
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

  template <typename T>
  struct SuccessResponse
  {
    T body;
    ccf::protobuf::Status status;

    SuccessResponse(const T& body_, ccf::protobuf::Status status_) :
      body(body_),
      status(status_)
    {}
  };

  struct ErrorResponse
  {
    ccf::protobuf::Status status;
    ErrorResponse(ccf::protobuf::Status status_) : status(status_) {}
  };

  template <typename T>
  using GrpcAdapterResponse = std::variant<ErrorResponse, SuccessResponse<T>>;

  template <typename T>
  GrpcAdapterResponse<T> make_success(const T& t)
  {
    return SuccessResponse(t, make_grpc_status_ok());
  }

  GrpcAdapterResponse<google::protobuf::Empty> make_success()
  {
    return SuccessResponse(google::protobuf::Empty{}, make_grpc_status_ok());
  }

  ErrorResponse make_error(
    grpc_status code,
    const std::string& msg,
    const std::optional<std::string>& details = std::nullopt)
  {
    return ErrorResponse(make_grpc_status(code, msg, details));
  }

  template <typename T>
  GrpcAdapterResponse<T> make_error(
    grpc_status code,
    const std::string& msg,
    const std::optional<std::string>& details = std::nullopt)
  {
    return ErrorResponse(make_grpc_status(code, msg, details));
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
        using Message = typename Out::value_type;
        const Out& messages = success_response->body;
        size_t r_size = std::accumulate(
          messages.begin(),
          messages.end(),
          0,
          [](size_t current, const Message& msg) {
            return current + impl::message_frame_length + msg.ByteSizeLong();
          });
        r.resize(r_size);
        auto r_data = r.data();

        for (const Message& msg : messages)
        {
          const auto message_length = msg.ByteSizeLong();
          impl::write_message_frame(r_data, r_size, message_length);

          if (!msg.SerializeToArray(r_data, r_size))
          {
            throw std::logic_error(fmt::format(
              "Error serialising protobuf response of type {}, size {}",
              msg.GetTypeName(),
              message_length));
          }

          r_data += message_length;
          r_size += message_length;
        }
      }
      else
      {
        const Out& resp = success_response->body;
        const auto message_length = resp.ByteSizeLong();
        size_t r_size = impl::message_frame_length + message_length;
        r.resize(r_size);
        auto r_data = r.data();

        impl::write_message_frame(r_data, r_size, message_length);

        if (!resp.SerializeToArray(r_data, r_size))
        {
          throw std::logic_error(fmt::format(
            "Error serialising protobuf response of type {}, size {}",
            resp.GetTypeName(),
            message_length));
        }
      }

      ctx->set_response_body(r);
      ctx->set_response_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::GRPC);

      ctx->set_response_trailer("grpc-status", success_response->status.code());
      ctx->set_response_trailer(
        "grpc-message", success_response->status.message());
    }
    else
    {
      auto error_response = std::get<ErrorResponse>(r);
      ctx->set_response_trailer("grpc-status", error_response.status.code());
      ctx->set_response_trailer(
        "grpc-message", error_response.status.message());
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
  using GrpcCommandEndpoint = std::function<grpc::GrpcAdapterResponse<Out>(
    endpoints::CommandEndpointContext& ctx, In&& payload)>;

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
}
