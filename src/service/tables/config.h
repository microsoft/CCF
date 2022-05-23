// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "enclave/consensus_type.h"
#include "enclave/reconfiguration_type.h"

namespace ccf
{
  static constexpr auto default_node_cert_validity_period_days = 365;
  static constexpr auto default_service_cert_validity_period_days = 365;

  struct ServiceConfiguration
  {
    // Number of recovery shares required to decrypt the latest ledger secret
    size_t recovery_threshold = 0;

    ConsensusType consensus = ConsensusType::CFT;

    /**
     *  Fields below are added in 2.x
     */

    std::optional<size_t> maximum_node_certificate_validity_days = std::nullopt;
    std::optional<size_t> maximum_service_certificate_validity_days =
      std::nullopt;

    std::optional<ReconfigurationType> reconfiguration_type = std::nullopt;

    bool operator==(const ServiceConfiguration& other) const
    {
      return recovery_threshold == other.recovery_threshold &&
        consensus == other.consensus &&
        reconfiguration_type == other.reconfiguration_type &&
        maximum_node_certificate_validity_days ==
        other.maximum_node_certificate_validity_days;
    }
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ServiceConfiguration)
  DECLARE_JSON_REQUIRED_FIELDS(ServiceConfiguration, recovery_threshold)
  DECLARE_JSON_OPTIONAL_FIELDS(
    ServiceConfiguration,
    consensus,
    reconfiguration_type,
    maximum_node_certificate_validity_days,
    maximum_service_certificate_validity_days)

  // The there is always only one active configuration, so this is a single
  // Value
  using Configuration = ServiceValue<ServiceConfiguration>;
  namespace Tables
  {
    static constexpr auto CONFIGURATION = "public:ccf.gov.service.config";
  }
}
