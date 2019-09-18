// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "entities.h"

#include <msgpack.hpp>

namespace ccf
{
  // ServiceId is used at the key of the SERVICE table. As there is only one
  // service active at a given time, this key is always 0.
  using ServiceId = uint64_t;

  enum class ServiceStatus
  {
    OPENING = 1,
    OPEN = 2,
    CLOSED = 3 // For now, unused
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
    // Version at which the service is applicable from
    kv::Version version;

    std::vector<uint8_t> cert;
    ServiceStatus status;

    MSGPACK_DEFINE(version, cert, status);
  };
  DECLARE_JSON_TYPE(ServiceInfo);
  DECLARE_JSON_REQUIRED_FIELDS(ServiceInfo, version, cert, status);

  using Service = Store::Map<ServiceId, ServiceInfo>;
}