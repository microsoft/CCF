// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "enclave/consensus_type.h"
#include "entities.h"

#include <msgpack/msgpack.hpp>

namespace ccf
{
  struct ServiceConfiguration
  {
    // Number of recovery shares required to decrypt the latest ledger secret
    size_t recovery_threshold = 0;

    ConsensusType consensus = ConsensusType::CFT;

    MSGPACK_DEFINE(recovery_threshold, consensus)
  };
  DECLARE_JSON_TYPE(ServiceConfiguration)
  DECLARE_JSON_REQUIRED_FIELDS(
    ServiceConfiguration, recovery_threshold, consensus)

  // The key for this table is always 0 as there is always only one active
  // configuration.
  using Configuration = kv::Map<size_t, ServiceConfiguration>;
}