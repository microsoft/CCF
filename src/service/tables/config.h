// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/service/consensus_type.h"
#include "ccf/service/reconfiguration_type.h"
#include "ccf/service/service_config.h"

namespace ccf
{
  static constexpr auto default_node_cert_validity_period_days = 365;
  static constexpr auto default_service_cert_validity_period_days = 365;
  static constexpr size_t default_recent_cose_proposals_window_size = 100;

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ServiceConfiguration)
  DECLARE_JSON_REQUIRED_FIELDS(ServiceConfiguration, recovery_threshold)
  DECLARE_JSON_OPTIONAL_FIELDS(
    ServiceConfiguration,
    consensus,
    reconfiguration_type,
    maximum_node_certificate_validity_days,
    maximum_service_certificate_validity_days,
    recent_cose_proposals_window_size)

  // The there is always only one active configuration, so this is a single
  // Value
  using Configuration = ServiceValue<ServiceConfiguration>;
  namespace Tables
  {
    static constexpr auto CONFIGURATION = "public:ccf.gov.service.config";
  }
}
