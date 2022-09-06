// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Mapping to HTTP errors are per
// https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto
enum class grpc_status
{
  OK = 0, // HTTP 200
  CANCELLED, // HTTP 499
  UNKNOWN, // HTTP 500
  INVALID_ARGUMENT, // HTTP 400
  DEADLINE_EXCEEDED, // HTTP 504
  NOT_FOUND, // HTTP  404
  ALREADY_EXISTS, // HTTP 409
  PERMISSION_DENIED, // HTTP 403
  RESOURCE_EXHAUSTED, // HTTP 429
  FAILED_PRECONDITION, // HTTP 400
  ABORTED, // HTTP 409
  OUT_OF_RANGE, // HTTP 400
  UNIMPLEMENTED, // HTTP 501
  INTERNAL, // HTTP 500
  UNAVAILABLE, // HTTP 503
  DATA_LOSS, // HTTP 500
  UNAUTHENTICATED // HTTP 401
};