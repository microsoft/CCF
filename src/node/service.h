// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "entities.h"
#include "service_map.h"

#include <msgpack/msgpack.hpp>

namespace ccf
{
  enum class ServiceStatus
  {
    OPENING = 1,
    OPEN = 2,
    WAITING_FOR_RECOVERY_SHARES = 3,
    CLOSED = 4 // For now, unused
  };

  DECLARE_JSON_ENUM(
    ServiceStatus,
    {{ServiceStatus::OPENING, "OPENING"},
     {ServiceStatus::OPEN, "OPEN"},
     {ServiceStatus::WAITING_FOR_RECOVERY_SHARES,
      "WAITING_FOR_RECOVERY_SHARES"},
     {ServiceStatus::CLOSED, "CLOSED"}});
}

MSGPACK_ADD_ENUM(ccf::ServiceStatus);

namespace ccf
{
  struct ServiceInfo
  {
    crypto::Pem cert;
    ServiceStatus status;

    MSGPACK_DEFINE(cert, status);
  };
  DECLARE_JSON_TYPE(ServiceInfo);
  DECLARE_JSON_REQUIRED_FIELDS(ServiceInfo, cert, status);

  // As there is only one service active at a given time, the key for the
  // Service table is always 0.
  using Service = ServiceMap<size_t, ServiceInfo>;
}