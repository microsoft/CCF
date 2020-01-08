// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash.h"
#include "ds/logger.h"
#include "enclave/interface.h"
#include "tls/keypair.h"

#include <dlfcn.h>
#include <msgpack.hpp>
#include <openenclave/bits/report.h>
#include <openenclave/bits/result.h>
#ifdef VIRTUAL_ENCLAVE
#  include "enclave/ccf_v.h"
#else
#  include <ccf_u.h>
#  include <openenclave/host.h>
#endif

// Marker to create virtual enclaves, should be distinct from any valid
// OE_ENCLAVE_FLAG combinations
#define ENCLAVE_FLAG_VIRTUAL -1

#if defined(__clang__)
// Clang UBSan doesn't like calling functions through dlsym
// https://github.com/google/sanitizers/issues/911
#  define NO_SANITIZE_FUNCTION __attribute__((no_sanitize("function")))
#else
#  define NO_SANITIZE_FUNCTION
#endif

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
        auto err = oe_create_ccf_enclave(
          path.c_str(), OE_ENCLAVE_TYPE_SGX, flags, nullptr, 0, &e);

        if (err != OE_OK)
        {
          LOG_FATAL_FMT("Could not create enclave: {}", oe_result_str(err));
        }
      }
    }

    bool create_node(
      const EnclaveConfig& enclave_config,
      const CCFConfig& ccf_config,
      std::vector<uint8_t>& node_cert,
      std::vector<uint8_t>& quote,
      std::vector<uint8_t>& network_cert,
      StartType start_type,
      ConsensusType consensus_type)
    {
      bool ret;
      size_t node_cert_len = 0;
      size_t quote_len = 0;
      size_t network_cert_len = 0;

      msgpack::sbuffer sbuf;
      msgpack::pack(sbuf, ccf_config);

      auto err = enclave_create_node(
        e,
        &ret,
        (void*)&enclave_config,
        sbuf.data(),
        sbuf.size(),
        node_cert.data(),
        node_cert.size(),
        &node_cert_len,
        quote.data(),
        quote.size(),
        &quote_len,
        network_cert.data(),
        network_cert.size(),
        &network_cert_len,
        start_type,
        consensus_type);

      if (err != OE_OK)
      {
        LOG_FATAL_FMT(
          "Failed to call in enclave_create_node: {}", oe_result_str(err));
      }

      node_cert.resize(node_cert_len);
      quote.resize(quote_len);
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
        LOG_FATAL_FMT("Failed to call in enclave_run: {}", oe_result_str(err));
      }

      return ret;
    }
  };
}
