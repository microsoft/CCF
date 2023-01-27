// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/consensus_type.h"
#include "ccf/service/reconfiguration_type.h"

#include <cstdint>
#include <optional>

namespace ccf
{
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

    /**
     * Fields below are added in 3.x
     */

    /// Size of recent_cose_proposals window
    std::optional<size_t> recent_cose_proposals_window_size = std::nullopt;

    bool operator==(const ServiceConfiguration& other) const
    {
      return recovery_threshold == other.recovery_threshold &&
        consensus == other.consensus &&
        reconfiguration_type == other.reconfiguration_type &&
        maximum_node_certificate_validity_days ==
        other.maximum_node_certificate_validity_days &&
        recent_cose_proposals_window_size ==
        other.recent_cose_proposals_window_size;
    }
  };

}
