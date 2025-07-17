// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "common/enclave_interface_types.h"
#include "ds/work_beacon.h"

#include <cstdint>

extern "C"
{
  CreateNodeStatus enclave_create_node(
    void* enclave_config,
    uint8_t* ccf_config,
    size_t ccf_config_size,
    uint8_t* startup_snapshot_data,
    size_t startup_snapshot_size,
    uint8_t* node_cert,
    size_t node_cert_size,
    size_t* node_cert_len,
    uint8_t* service_cert,
    size_t service_cert_size,
    size_t* service_cert_len,
    uint8_t* enclave_version,
    size_t enclave_version_size,
    size_t* enclave_version_len,
    StartType start_type,
    ccf::LoggerLevel log_level,
    size_t num_worker_threads,
    void* time_location,
    const ccf::ds::WorkBeaconPtr& work_beacon);

  bool enclave_run();
}