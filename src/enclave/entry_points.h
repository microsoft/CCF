// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "common/enclave_interface_types.h"
#include "ds/work_beacon.h"
#include "node/rpc/ledger_interface.h"

#include <cstdint>
#include <memory>

namespace ccf
{
  // ledger_subsystem is the host-owned read-only view of the ledger. It is
  // installed as a node subsystem and must outlive the node.
  CreateNodeStatus enclave_create_node(
    const EnclaveConfig& enclave_config,
    const ccf::StartupConfig& ccf_config,
    std::vector<uint8_t>& node_cert,
    std::vector<uint8_t>& service_cert,
    std::vector<uint8_t>& rpc_addresses,
    StartType start_type,
    ccf::LoggerLevel log_level,
    size_t num_worker_thread,
    const ccf::ds::WorkBeaconPtr& work_beacon,
    const std::shared_ptr<AbstractReadLedgerSubsystemInterface>&
      ledger_subsystem);

  bool enclave_run();
}