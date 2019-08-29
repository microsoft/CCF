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
    Cert pem_cert;
    ServiceStatus status;

    MSGPACK_DEFINE(pem_cert, status);
  };
  DECLARE_JSON_TYPE(ServiceInfo);
  DECLARE_JSON_REQUIRED_FIELDS(ServiceInfo, pem_cert, status);

  using Service = Store::Map<kv::Version, ServiceInfo>;
}