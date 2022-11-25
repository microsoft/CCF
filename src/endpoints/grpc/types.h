// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

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

  using EmptyResponse = google::protobuf::Empty;
  using EmptySuccessResponse = SuccessResponse<EmptyResponse>;
  using GrpcAdapterEmptyResponse = GrpcAdapterResponse<EmptyResponse>;

  template <typename T>
  GrpcAdapterResponse<T> make_success(const T& t)
  {
    return SuccessResponse(t, make_grpc_status_ok());
  }

  GrpcAdapterEmptyResponse make_success()
  {
    return SuccessResponse(EmptyResponse{}, make_grpc_status_ok());
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
}