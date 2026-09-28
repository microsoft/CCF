// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "common/enclave_interface_types.h"
#include "ds/work_beacon.h"
#include "node/node_transport.h"
#include "node/rpc/ledger_interface.h"
#include "node/runtime_control.h"

#include <cstdint>
#include <memory>

namespace ccf
{
  // ledger_subsystem is the host-owned read-only view of the ledger. It is
  // installed as a node subsystem and must outlive the node. node_transport is
  // the host-owned node-to-node transport, which must also outlive the node.
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
    ccf::AbstractRuntimeControl& runtime_control,
    const std::shared_ptr<AbstractLedgerSubsystemInterface>& ledger_subsystem,
    const std::shared_ptr<AbstractNodeTransport>& node_transport);

  bool enclave_run();
  bool enclave_request_stop();
  bool enclave_request_stop_notice();

  // Terminal cleanup after transports have stopped and enclave threads joined.
  void enclave_shutdown_tasks();
}