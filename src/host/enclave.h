// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/raft/rafttypes.h"
#include "crypto/hash.h"
#include "ds/logger.h"
#include "enclave/interface.h"

#include <dlfcn.h>
#include <openenclave/bits/report.h>
#include <openenclave/bits/result.h>
#ifdef VIRTUAL_ENCLAVE
#  include "../enclave/ccf_v.h"
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
      const EnclaveConfig& config,
      std::vector<uint8_t>& node_cert,
      std::vector<uint8_t>& quote,
      bool recover)
    {
      bool ret;
      size_t node_cert_len = 0;
      size_t quote_len = 0;

      auto err = enclave_create_node(
        e,
        &ret,
        (void*)&config,
        node_cert.data(),
        node_cert.size(),
        &node_cert_len,
        quote.data(),
        quote.size(),
        &quote_len,
        recover);

      if (err != OE_OK)
      {
        LOG_FATAL_FMT(
          "Failed to call in enclave_create_node: {}", oe_result_str(err));
      }

      node_cert.resize(node_cert_len);
      quote.resize(quote_len);

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

    /**
     * Checks that a quote is valid, the signing authority is trusted, and the
     * quote is over some expected data.
     *
     * Note that without libsgx support, the current verification method is
     * unavailable and this method will throw an unimplemented exception.
     *
     * @return Whether the quote is valid. If it fails, an explanatory error
     * message will be logged.
     */
    bool verify_quote(
      const std::vector<uint8_t>& quote_raw,
      const std::vector<uint8_t>& expected_contents)
    {
      if (is_virtual_enclave)
      {
        return true;
      }

#ifdef GET_QUOTE
      oe_report_t parsed{0};
      oe_result_t result =
        oe_verify_report(e, quote_raw.data(), quote_raw.size(), &parsed);
      if (result != OE_OK)
      {
        LOG_FAIL_FMT("Quote could not be verified: {}", oe_result_str(result));
        return false;
      }

      // Hash the expected contents, check that this matches the data in the
      // quote
      constexpr auto size = crypto::Sha256Hash::SIZE;
      if (parsed.report_data_size < size)
      {
        LOG_FAIL_FMT(
          "Quote data length is too small. Expected: {}, Actual: {}",
          size,
          parsed.report_data_size);
        return false;
      }

      crypto::Sha256Hash hash{expected_contents};
      if (0 != memcmp(hash.h, parsed.report_data, size))
      {
        LOG_FAIL_FMT("Quote does not contain expected data");
        return false;
      }
      LOG_INFO_FMT("Quote verified");
#else
      throw std::logic_error("Quote verification is not implemented");
#endif

      return true;
    }
  };
}
