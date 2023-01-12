// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/http_consts.h"
#include "ccf/http_header_map.h"

#include <string>

#define GRPC_STATUS_MAP(XX) \
  XX(0, OK, "Ok") \
  XX(1, CANCELLED, "Cancelled") \
  XX(2, UNKNOWN, "Unknown") \
  XX(3, INVALID_ARGUMENT, "Invalid Argument") \
  XX(4, DEADLINE_EXCEEDED, "Deadline Exceeded") \
  XX(5, NOT_FOUND, "Not Found") \
  XX(6, ALREADY_EXISTS, "Already Exists") \
  XX(7, PERMISSION_DENIED, "Permission Denied") \
  XX(8, RESOURCE_EXHAUSTED, "Resource Exhausted") \
  XX(9, FAILED_PRECONDITION, "Failed Precondition") \
  XX(10, ABORTED, "Aborted") \
  XX(11, OUT_OF_RANGE, "Out Of Range") \
  XX(12, UNIMPLEMENTED, "Unimplemented") \
  XX(13, INTERNAL, "Internal") \
  XX(14, UNAVAILABLE, "Unavailable") \
  XX(15, DATA_LOSS, "Data Loss") \
  XX(16, UNAUTHENTICATED, "Unauthenticated")

enum grpc_status
{
#define XX(num, name, string) GRPC_STATUS_##name = num,
  GRPC_STATUS_MAP(XX)
#undef XX
};

static inline const char* grpc_status_str(enum grpc_status s)
{
  switch (s)
  {
#define XX(num, name, string) \
  case GRPC_STATUS_##name: \
    return string;
    GRPC_STATUS_MAP(XX)
#undef XX
    default:
      return "<unknown>";
  }
}

// CCF is primarily an HTTP framework. However, gRPC clients should be returned
// an appropriate gRPC status code when an error is returned at the framework
// level (e.g. authentication error) so we use the following function to
// automatically convert HTTP errors to gRPC statuses.
// Inspired by
// https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto
static grpc_status http_status_to_grpc(enum http_status s)
{
  // Note: GRPC_STATUS_CANCELLED, GRPC_STATUS_ABORTED and GRPC_STATUS_DATA_LOSS
  // are currently never returned
  switch (s)
  {
    case HTTP_STATUS_UNAUTHORIZED: // 401
      return GRPC_STATUS_UNAUTHENTICATED;
    case HTTP_STATUS_FORBIDDEN: // 404
      return GRPC_STATUS_PERMISSION_DENIED;
    case HTTP_STATUS_NOT_FOUND: // 404
      return GRPC_STATUS_NOT_FOUND;
    case HTTP_STATUS_CONFLICT: // 409
      return GRPC_STATUS_ALREADY_EXISTS;
    case HTTP_STATUS_PRECONDITION_FAILED: // 412
      return GRPC_STATUS_FAILED_PRECONDITION;
    case HTTP_STATUS_RANGE_NOT_SATISFIABLE: // 416
      return GRPC_STATUS_OUT_OF_RANGE;
    case HTTP_STATUS_TOO_MANY_REQUESTS: // 429
      return GRPC_STATUS_RESOURCE_EXHAUSTED;
    case HTTP_STATUS_NOT_IMPLEMENTED: // 501
      return GRPC_STATUS_UNIMPLEMENTED;
    case HTTP_STATUS_SERVICE_UNAVAILABLE: // 503
      return GRPC_STATUS_UNAVAILABLE;
    case HTTP_STATUS_GATEWAY_TIMEOUT: // 504
      return GRPC_STATUS_DEADLINE_EXCEEDED;
    default:
    {
      // For non-specific codes, we approximate to the closest generic code
      if (s >= 200 && s < 300) // 2xx
        return GRPC_STATUS_OK;
      else if (s >= 400 && s < 500) // 4xx
        return GRPC_STATUS_INVALID_ARGUMENT;
      else if (s >= 500) // 5xx
        return GRPC_STATUS_INTERNAL;
      else
        return GRPC_STATUS_UNKNOWN;
    }
  }
}

namespace ccf::grpc
{
  static const http::HeaderMap default_response_headers = {
    {http::headers::CONTENT_TYPE, http::headervalues::contenttype::GRPC}};

  static constexpr auto TRAILER_STATUS = "grpc-status";
  static constexpr auto TRAILER_MESSAGE = "grpc-message";

  static http::HeaderKeyValue make_status_trailer(int32_t code)
  {
    return {TRAILER_STATUS, std::to_string(code)};
  }

  static http::HeaderKeyValue make_message_trailer(const std::string& msg)
  {
    return {TRAILER_MESSAGE, msg};
  }
}