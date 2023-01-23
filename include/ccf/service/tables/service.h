// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/ds/json.h"
#include "ccf/service/map.h"
#include "ccf/tx_id.h"

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
    ServiceStatus status = ServiceStatus::OPENING;
    /// Version (seqno) of previous service identity (before the last recovery)
    std::optional<kv::Version> previous_service_identity_version = std::nullopt;
    /// Number of disaster recoveries performed on this service
    std::optional<size_t> recovery_count = std::nullopt;
    /// Free-form user data, can be used by members to store additional
    /// information about service
    nlohmann::json service_data = nullptr;
    /// TxID at which current service was created
    std::optional<ccf::TxID> current_service_create_txid = std::nullopt;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ServiceInfo);
  DECLARE_JSON_REQUIRED_FIELDS(ServiceInfo, cert, status);
  DECLARE_JSON_OPTIONAL_FIELDS(
    ServiceInfo,
    previous_service_identity_version,
    recovery_count,
    service_data,
    current_service_create_txid);

  // As there is only one service active at a given time, it is stored in single
  // Value in the KV
  using Service = ServiceValue<ServiceInfo>;
  namespace Tables
  {
    static constexpr auto SERVICE = "public:ccf.gov.service.info";
  }
}