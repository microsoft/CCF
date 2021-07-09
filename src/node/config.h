// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "enclave/consensus_type.h"
#include "enclave/reconfiguration_type.h"
#include "entities.h"

namespace ccf
{
  struct ServiceConfiguration
  {
    // Number of recovery shares required to decrypt the latest ledger secret
    size_t recovery_threshold = 0;

    ConsensusType consensus = ConsensusType::CFT;
    std::optional<ReconfigurationType> reconfiguration_type =
      std::nullopt;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ServiceConfiguration)
  DECLARE_JSON_REQUIRED_FIELDS(
    ServiceConfiguration, recovery_threshold, consensus)
  DECLARE_JSON_OPTIONAL_FIELDS(ServiceConfiguration, reconfiguration_type)

  // The there is always only one active configuration, so this is a single
  // Value
  using Configuration = ServiceValue<ServiceConfiguration>;
}
