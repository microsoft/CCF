// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/http_consts.h"
#include "ccf/http_header_map.h"
#include "status.h"

#include <google/protobuf/empty.pb.h>
#include <optional>
#include <string>
#include <variant>

namespace ccf::grpc
{
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

  // Used for server streaming endpoints. Successful response bodies are
  // streamed, not returned by the handler.
  struct PendingResponse
  {};

  using GrpcAdapterStreamingResponse =
    std::variant<ErrorResponse, PendingResponse>;

  using EmptyResponse = google::protobuf::Empty;
  using EmptySuccessResponse = SuccessResponse<EmptyResponse>;
  using GrpcAdapterEmptyResponse = GrpcAdapterResponse<EmptyResponse>;

  template <typename T>
  static GrpcAdapterResponse<T> make_success(const T& t)
  {
    return SuccessResponse(t, make_grpc_status_ok());
  }

  static GrpcAdapterEmptyResponse make_success()
  {
    return SuccessResponse(EmptyResponse{}, make_grpc_status_ok());
  }

  static PendingResponse make_pending()
  {
    return PendingResponse{};
  }

  static ErrorResponse make_error(grpc_status code, const std::string& msg)
  {
    return ErrorResponse(make_grpc_status(code, msg));
  }

  template <typename T>
  static GrpcAdapterResponse<T> make_error(
    grpc_status code, const std::string& msg)
  {
    return ErrorResponse(make_grpc_status(code, msg));
  }
}