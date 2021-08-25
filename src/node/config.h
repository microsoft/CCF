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
  static constexpr auto default_node_certificate_validity_period_days = 365;

  struct ServiceConfiguration
  {
    // Number of recovery shares required to decrypt the latest ledger secret
    size_t recovery_threshold = 0;

    ConsensusType consensus = ConsensusType::CFT;

    std::optional<ReconfigurationType> reconfiguration_type = std::nullopt;

    struct Nodes
    {
      // If true, the service endorses the certificate of new trusted nodes, and
      // records them in the store
      bool node_endorsement_on_trust = true;

      size_t cert_maximum_validity_period_days =
        default_node_certificate_validity_period_days;

      Nodes() {}

      bool operator==(const Nodes& other) const
      {
        return node_endorsement_on_trust == other.node_endorsement_on_trust &&
          cert_maximum_validity_period_days ==
          other.cert_maximum_validity_period_days;
      }

      bool operator!=(const Nodes& other) const
      {
        return !(*this == other);
      }
    };
    std::optional<Nodes> nodes = std::nullopt;

    bool operator==(const ServiceConfiguration& other) const
    {
      return recovery_threshold == other.recovery_threshold &&
        consensus == other.consensus &&
        reconfiguration_type == other.reconfiguration_type &&
        nodes == other.nodes;
    }
  };
  DECLARE_JSON_TYPE(ServiceConfiguration::Nodes)
  DECLARE_JSON_REQUIRED_FIELDS(
    ServiceConfiguration::Nodes,
    node_endorsement_on_trust,
    cert_maximum_validity_period_days)

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ServiceConfiguration)
  DECLARE_JSON_REQUIRED_FIELDS(
    ServiceConfiguration, recovery_threshold, consensus)
  DECLARE_JSON_OPTIONAL_FIELDS(
    ServiceConfiguration, reconfiguration_type, nodes)

  // The there is always only one active configuration, so this is a single
  // Value
  using Configuration = ServiceValue<ServiceConfiguration>;
}
