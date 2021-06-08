// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "entities.h"
#include "service_map.h"

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
    {{ServiceStatus::OPENING, "Opening"},
     {ServiceStatus::OPEN, "Open"},
     {ServiceStatus::WAITING_FOR_RECOVERY_SHARES, "WaitingForRecoveryShares"},
     {ServiceStatus::CLOSED, "Closed"}});

  struct ServiceInfo
  {
    crypto::Pem cert;
    ServiceStatus status;
  };
  DECLARE_JSON_TYPE(ServiceInfo);
  DECLARE_JSON_REQUIRED_FIELDS(ServiceInfo, cert, status);

  // As there is only one service active at a given time, it is stored in single
  // Value in the KV
  using Service = ServiceValue<ServiceInfo>;
}