// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/version.h"
#include "crypto/hash.h"
#include "crypto/key_pair.h"
#include "ds/logger.h"
#include "enclave/interface.h"

#include <dlfcn.h>
#ifdef VIRTUAL_ENCLAVE
#  include "enclave/ccf_v.h"
#else
#  include <ccf_u.h>
#  include <openenclave/bits/result.h>
#  include <openenclave/host.h>
#  include <openenclave/trace.h>
#endif

extern "C"
{
  void nop_oe_logger(
    void* context,
    bool is_enclave,
    const struct tm* t,
    long int usecs,
    oe_log_level_t level,
    uint64_t host_thread_id,
    const char* message)
  {}
}

// Marker to create virtual enclaves, should be distinct from any valid
// OE_ENCLAVE_FLAG combinations
constexpr static uint32_t ENCLAVE_FLAG_VIRTUAL = -1;

namespace host
{
  /**
   * Wraps an oe_enclave and associated ECalls. New ECalls should be added as
   * methods which construct an appropriate EGeneric-derived param type and pass
   * it to call.
   */
  class Enclave
  {
  private:
    bool is_virtual_enclave;

    oe_enclave_t* e;

  public:
    /**
     * Create an uninitialized enclave hosting the given library.
     *
     * @param path Path to signed enclave library file
     * @param flags Flags passed to oe_create_enclave. eg OE_ENCLAVE_FLAG_DEBUG,
     * OE_ENCLAVE_FLAG_SIMULATE. Alternatively, ENCLAVE_FLAG_VIRTUAL will not
     * use OE at all, instead loading a shared library directly
     */
    Enclave(const std::string& path, uint32_t flags) :
      is_virtual_enclave(false),
      e(nullptr)
    {
      if (flags == ENCLAVE_FLAG_VIRTUAL)
      {
#ifdef VIRTUAL_ENCLAVE
        load_virtual_enclave(path.c_str());
#endif
        is_virtual_enclave = true;
      }
      else
      {
#ifndef VERBOSE_LOGGING
        oe_log_set_callback(nullptr, nop_oe_logger);
#endif

        auto err = oe_create_ccf_enclave(
          path.c_str(), OE_ENCLAVE_TYPE_SGX, flags, nullptr, 0, &e);

        if (err != OE_OK)
        {
          throw std::logic_error(
            fmt::format("Could not create enclave: {}", oe_result_str(err)));
        }
      }
    }

    bool create_node(
      const EnclaveConfig& enclave_config,
      const CCFConfig& ccf_config,
      std::vector<uint8_t>& node_cert,
      std::vector<uint8_t>& network_cert,
      StartType start_type,
      ConsensusType consensus_type,
      size_t num_worker_thread,
      void* time_location)
    {
      bool ret;
      size_t node_cert_len = 0;
      size_t network_cert_len = 0;

      auto config = nlohmann::json(ccf_config).dump();

      auto err = enclave_create_node(
        e,
        &ret,
        (void*)&enclave_config,
        config.data(),
        config.size(),
        node_cert.data(),
        node_cert.size(),
        &node_cert_len,
        network_cert.data(),
        network_cert.size(),
        &network_cert_len,
        start_type,
        consensus_type,
        num_worker_thread,
        time_location);

      if (err != OE_OK)
      {
        throw std::logic_error(fmt::format(
          "Failed to call in enclave_create_node: {}", oe_result_str(err)));
      }

      if (!ret)
      {
        throw std::logic_error("An error occurred when creating CCF node");
      }

      node_cert.resize(node_cert_len);
      network_cert.resize(network_cert_len);

      return ret;
    }

    // Run a processor over this circuit inside the enclave - should be called
    // from a thread
    bool run()
    {
      bool ret;
      auto err = enclave_run(e, &ret);

      if (err != OE_OK)
      {
        throw std::logic_error(
          fmt::format("Failed to call in enclave_run: {}", oe_result_str(err)));
      }

      return ret;
    }
  };
}
