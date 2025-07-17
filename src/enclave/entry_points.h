// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "common/enclave_interface_types.h"
#include "ds/work_beacon.h"

#include <cstdint>

extern "C"
{
  CreateNodeStatus enclave_create_node(
    const EnclaveConfig& enclave_config,
    const ccf::StartupConfig& ccf_config,
    std::vector<uint8_t>&& startup_snapshot,
    std::vector<uint8_t>& node_cert,
    std::vector<uint8_t>& service_cert,
    StartType start_type,
    ccf::LoggerLevel log_level,
    size_t num_worker_thread,
    void* time_location,
    const ccf::ds::WorkBeaconPtr& work_beacon);

  bool enclave_run();
}