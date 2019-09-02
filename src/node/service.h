// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "entities.h"

#include <msgpack.hpp>

namespace ccf
{
  enum class ServiceStatus
  {
    OPENING = 1,
    OPEN = 2,
    CLOSED = 3
  };

  DECLARE_JSON_ENUM(
    ServiceStatus,
    {{ServiceStatus::OPENING, "OPENING"},
     {ServiceStatus::OPEN, "OPEN"},
     {ServiceStatus::CLOSED, "CLOSED"}});
}

MSGPACK_ADD_ENUM(ccf::ServiceStatus);

namespace ccf
{
  struct ServiceInfo
  {
    std::vector<uint8_t> cert;
    ServiceStatus status;

    MSGPACK_DEFINE(cert, status);
  };
  DECLARE_JSON_TYPE(ServiceInfo);
  DECLARE_JSON_REQUIRED_FIELDS(ServiceInfo, cert, status);

  using Service = Store::Map<kv::Version, ServiceInfo>;
}