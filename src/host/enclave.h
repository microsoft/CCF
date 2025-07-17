// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/service/consensus_type.h"
#include "ccf/version.h"
#include "common/enclave_interface_types.h"
#include "enclave/entry_points.h"
#include "enclave/interface.h"

#include <dlfcn.h>
#include <filesystem>

namespace host
{
  class Enclave
  {
  public:
    static CreateNodeStatus create_node(
      const EnclaveConfig& enclave_config,
      const ccf::StartupConfig& ccf_config,
      std::vector<uint8_t>&& startup_snapshot,
      std::vector<uint8_t>& node_cert,
      std::vector<uint8_t>& service_cert,
      StartType start_type,
      ccf::LoggerLevel log_level,
      size_t num_worker_thread,
      void* time_location,
      const ccf::ds::WorkBeaconPtr& work_beacon)
    {
      CreateNodeStatus status = CreateNodeStatus::InternalError;

      status = enclave_create_node(
        enclave_config,
        ccf_config,
        std::move(startup_snapshot),
        node_cert,
        service_cert,
        start_type,
        log_level,
        num_worker_thread,
        time_location,
        work_beacon);

      if (status != CreateNodeStatus::OK)
      {
        // Logs have described the errors already, we just need to allow the
        // host to read them (via read_all()).
        return status;
      }

      return CreateNodeStatus::OK;
    }

    // Run a processor over this circuit inside the enclave - should be called
    // from a thread
    static bool run()
    {
      bool ret = enclave_run();

      if (!ret)
      {
        throw std::logic_error(fmt::format("Failure in enclave_run"));
      }

      return ret;
    }
  };
}
