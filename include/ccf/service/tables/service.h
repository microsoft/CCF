// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/service/map.h"

namespace ccf
{
  enum class ServiceStatus
  {
    OPENING = 1,
    OPEN = 2,
    WAITING_FOR_RECOVERY_SHARES = 3,
    RECOVERING = 4
  };

  DECLARE_JSON_ENUM(
    ServiceStatus,
    {{ServiceStatus::OPENING, "Opening"},
     {ServiceStatus::OPEN, "Open"},
     {ServiceStatus::WAITING_FOR_RECOVERY_SHARES, "WaitingForRecoveryShares"},
     {ServiceStatus::RECOVERING, "Recovering"}});

  struct ServiceInfo
  {
    /// x.509 Service Certificate, as a PEM string
    crypto::Pem cert;
    /// Status of the service
    ServiceStatus status;
    /// Previous service identity, before the last recovery
    std::optional<crypto::Pem> previous_service_identity = std::nullopt;
  };
  DECLARE_JSON_TYPE(ServiceInfo);
  DECLARE_JSON_REQUIRED_FIELDS(ServiceInfo, cert, status);
  DECLARE_JSON_OPTIONAL_FIELDS(ServiceInfo, previous_service_identity);

  // As there is only one service active at a given time, it is stored in single
  // Value in the KV
  using Service = ServiceValue<ServiceInfo>;
  namespace Tables
  {
    static constexpr auto SERVICE = "public:ccf.gov.service.info";
  }
}