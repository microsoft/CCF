// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "status.pb.h"

#include <optional>
#include <string>

// Mapping to HTTP errors as per
// https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto
#define GRPC_STATUS_MAP(XX) \
  XX(0, OK, "Ok", 200) \
  XX(1, CANCELLED, "Cancelled", 499) \
  XX(2, UNKNOWN, "Unknown", 500) \
  XX(3, INVALID_ARGUMENT, "Invalid Argument", 400) \
  XX(4, DEADLINE_EXCEEDED, "Deadline Exceeded", 504) \
  XX(5, NOT_FOUND, "Not Found", 404) \
  XX(6, ALREADY_EXISTS, "Already Exists", 409) \
  XX(7, PERMISSION_DENIED, "Permission Denied", 403) \
  XX(8, RESOURCE_EXHAUSTED, "Resource Exhausted", 429) \
  XX(9, FAILED_PRECONDITION, "Failed Precondition", 400) \
  XX(10, ABORTED, "Aborted", 409) \
  XX(11, OUT_OF_RANGE, "Out Of Range", 400) \
  XX(12, UNIMPLEMENTED, "Unimplemented", 501) \
  XX(13, INTERNAL, "Internal", 500) \
  XX(14, UNAVAILABLE, "Unavailable", 503) \
  XX(15, DATA_LOSS, "Data Loss", 500) \
  XX(16, UNAUTHENTICATED, "Unauthenticated", 401)

enum grpc_status
{
#define XX(num, name, string, http_eq) GRPC_STATUS_##name = num,
  GRPC_STATUS_MAP(XX)
#undef XX
};

static inline const char* grpc_status_str(enum grpc_status s)
{
  switch (s)
  {
#define XX(num, name, string, http_eq) \
  case GRPC_STATUS_##name: \
    return string;
    GRPC_STATUS_MAP(XX)
#undef XX
    default:
      return "<unknown>";
  }
}

namespace ccf::grpc
{
  int32_t status_to_code(const grpc_status& status)
  {
    return static_cast<int32_t>(status);
  }

  protobuf::Status make_grpc_status(
    enum grpc_status status,
    const std::optional<std::string>& msg = std::nullopt,
    const std::optional<std::string>& details = std::nullopt)
  {
    // Note: details are not currently supported
    protobuf::Status s;
    s.set_code(status_to_code(status));
    if (msg.has_value())
    {
      s.set_message(msg.value());
    }
    else
    {
      s.set_message(grpc_status_str(status));
    }
    if (details.has_value())
    {
      auto* d = s.add_details();
      d->set_value(details.value());
    }
    return s;
  }

  protobuf::Status make_grpc_status_ok()
  {
    return make_grpc_status(GRPC_STATUS_OK);
  }
}