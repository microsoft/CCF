// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/openssl/x509_time.h"
#include "ds/json.h"
#include "enclave/consensus_type.h"
#include "enclave/reconfiguration_type.h"
#include "entities.h"

namespace ccf
{
  static constexpr auto default_node_cert_validity_period_days = 365;
  static constexpr auto default_node_cert_initial_validity_period_days = 1;

  struct ServiceConfiguration
  {
    // Number of recovery shares required to decrypt the latest ledger secret
    size_t recovery_threshold = 0;

    ConsensusType consensus = ConsensusType::CFT;

    std::optional<ReconfigurationType> reconfiguration_type = std::nullopt;

    /**
     *  Fields below are added in 2.x
     */

    size_t node_cert_allowed_validity_period_days =
      default_node_cert_validity_period_days;

    bool operator==(const ServiceConfiguration& other) const
    {
      return recovery_threshold == other.recovery_threshold &&
        consensus == other.consensus &&
        reconfiguration_type == other.reconfiguration_type &&
        node_cert_allowed_validity_period_days ==
        other.node_cert_allowed_validity_period_days;
    }
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ServiceConfiguration)
  DECLARE_JSON_REQUIRED_FIELDS(
    ServiceConfiguration, recovery_threshold, consensus)
  DECLARE_JSON_OPTIONAL_FIELDS(
    ServiceConfiguration,
    reconfiguration_type,
    node_cert_allowed_validity_period_days)

  // The there is always only one active configuration, so this is a single
  // Value
  using Configuration = ServiceValue<ServiceConfiguration>;
}
