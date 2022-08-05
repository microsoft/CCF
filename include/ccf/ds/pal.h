// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/attestation_types.h"
#include "ccf/ds/quote_info.h"

#include <cstdint>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include "ccf/ds/logger.h"
#include <sys/ioctl.h>

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
#  include <cstring>
#  include <mutex>
#else
#  include "ccf/ds/ccf_exception.h"

#  include <openenclave/advanced/mallinfo.h>
#  include <openenclave/attestation/attester.h>
#  include <openenclave/bits/defs.h>
#  include <openenclave/bits/security.h>
#  include <openenclave/edger8r/enclave.h> // For oe_lfence
#  include <openenclave/enclave.h>
#  include <openenclave/log.h>
#  include <openenclave/tracee.h>
#  include <pthread.h>
#endif

/**
 * This file implements a platform abstraction layer to enable platforms, such
 * as OpenEnclave to offer custom implementations for certain functionalities.
 * By centralizing the platform-specific code to one file, we can avoid exposing
 * platform-specific types to the rest of the code and have a good overview of
 * all the functionality that is custom to a given platform. The platform
 * abstraction layer can also be used in code shared between the host and the
 * enclave as there is a host implementation for it as well.
 */
namespace ccf
{
  /**
   * Malloc information formatted based on the OE type, but avoiding to expose
   * the actual OE type in non-OE code.
   */
  struct MallocInfo
  {
    size_t max_total_heap_size = 0;
    size_t current_allocated_heap_size = 0;
    size_t peak_allocated_heap_size = 0;
  };

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)

  // Changes on 5.19+ kernel
  constexpr auto SEV_SNP_DEVICE = "/dev/sev";
  #define SEV_GUEST_IOC_TYPE 'S'
  #define SEV_SNP_GUEST_MSG_REPORT \
    _IOWR(SEV_GUEST_IOC_TYPE, 0x1, struct sev_snp_guest_request)

  /**
   * Virtual enclaves and the host code share the same PAL.
   * This PAL takes no dependence on OpenEnclave, but also does not apply
   * security hardening.
   */
  class HostPal
  {
  public:
    using Mutex = std::mutex;

    static inline void* safe_memcpy(void* dest, const void* src, size_t count)
    {
      return ::memcpy(dest, src, count);
    }

    static inline void speculation_barrier() {}

    static inline void redirect_platform_logging() {}

    static inline void initialize_enclave() {}

    static inline void shutdown_enclave() {}

    static inline bool is_outside_enclave(const void* ptr, std::size_t size)
    {
      return true;
    }

    static inline bool get_mallinfo(MallocInfo& info)
    {
      info.max_total_heap_size = std::numeric_limits<size_t>::max();
      info.current_allocated_heap_size = 0;
      info.peak_allocated_heap_size = 0;
      return true;
    }

    static QuoteInfo generate_quote(attestation_report_data&& report_data)
    {
      QuoteInfo node_quote_info = {};
      auto is_sev_snp = access(SEV_SNP_DEVICE, F_OK) == 0;

      // If there is no SEV-SNP device, assume we are using insecure virtual quotes
      if (!is_sev_snp) {
        node_quote_info.format = QuoteFormat::insecure_virtual;
      }

      else {
        node_quote_info.format = QuoteFormat::amd_sev_snp_v1;
        int fd = open(SEV_SNP_DEVICE, O_RDWR | O_CLOEXEC);
        if (fd < 0)
        {
          throw std::logic_error("Failed to open \"/dev/sev\"");
        }

        msg_report_req req = {};
        msg_report_rsp resp = {};

        // Arbitrary report data
        memcpy(req.report_data, report_data.data(), attestation_report_data_size);

        sev_snp_guest_request payload = {
            .req_msg_type = SNP_MSG_REPORT_REQ,
            .rsp_msg_type = SNP_MSG_REPORT_RSP,
            .msg_version = 1,
            .request_len = sizeof(req),
            .request_uaddr = (uint64_t)(void*)&req,
            .response_len = sizeof(resp),
            .response_uaddr = (uint64_t)(void*)&resp,
            .error = 0
        };

        int rc = ioctl(fd, SEV_SNP_GUEST_MSG_REPORT, &payload);
        if (rc < 0)
        {
          CCF_APP_FAIL("IOCTL call failed: {}", strerror(errno));
          CCF_APP_FAIL("Payload error: {}", payload.error);
          throw std::logic_error(
            "Failed to issue ioctl SEV_SNP_GUEST_MSG_REPORT");
        }

        auto quote = reinterpret_cast<uint8_t*>(&resp.report);
        node_quote_info.quote.assign(quote, quote + resp.report_size);
        // TODO: Get endorsements
      }
      return node_quote_info;
    }

    static void verify_quote(
      const QuoteInfo& quote_info,
      attestation_measurement& unique_id,
      attestation_report_data& report_data)
    {
      auto is_sev_snp = access(SEV_SNP_DEVICE, F_OK) == 0;

      if (quote_info.format == QuoteFormat::insecure_virtual)
      {
        if (is_sev_snp) {
          throw std::logic_error(
            "Cannot verify virtual quote if node is SEV-SNP");
        }
        unique_id = {};
        report_data = {};
      }

      else if (quote_info.format == QuoteFormat::amd_sev_snp_v1) {
        if (!is_sev_snp) {
          throw std::logic_error(
            "Cannot verify SEV-SNP quote if node is virtual");
        }
        attestation_report quote = *reinterpret_cast<const attestation_report*>(quote_info.quote.data());
        std::copy(
          std::begin(quote.report_data),
          std::begin(quote.report_data) + attestation_report_data_size, // TODO: Support full size
          report_data.begin()
        );
        std::copy(
          std::begin(quote.measurement),
          std::begin(quote.measurement) + attestation_measurement_size, // TODO: Support full size
          unique_id.begin()
        );
        // TODO: Verify endorsements
      }

      else {
        if (is_sev_snp) {
          throw std::logic_error(
            "Cannot verify non SEV-SNP attestation report");
        }
        else {
          throw std::logic_error(
            "Cannot verify real attestation report on virtual build");
        }
      }
    }
  };

  using Pal = HostPal;

#else
  class OEPal
  {
    /**
     * Temporary workaround until the fix for
     * https://github.com/openenclave/openenclave/issues/4555 is available in a
     * release.
     */
    class MutexImpl
    {
    private:
      pthread_spinlock_t sl;

    public:
      MutexImpl()
      {
        pthread_spin_init(&sl, PTHREAD_PROCESS_PRIVATE);
      }

      ~MutexImpl()
      {
        pthread_spin_destroy(&sl);
      }

      void lock()
      {
        pthread_spin_lock(&sl);
      }

      bool try_lock()
      {
        return pthread_spin_trylock(&sl) == 0;
      }

      void unlock()
      {
        pthread_spin_unlock(&sl);
      }
    };

  public:
    using Mutex = MutexImpl;
    static inline void* safe_memcpy(void* dest, const void* src, size_t count)
    {
      return oe_memcpy_with_barrier(dest, src, count);
    }

    static inline void speculation_barrier()
    {
      oe_lfence();
    }

    static inline void redirect_platform_logging()
    {
      oe_enclave_log_set_callback(nullptr, &open_enclave_logging_callback);
    }

    static inline void initialize_enclave()
    {
      auto rc = oe_attester_initialize();
      if (rc != OE_OK)
      {
        throw ccf::ccf_oe_attester_init_error(fmt::format(
          "Failed to initialise evidence attester: {}", oe_result_str(rc)));
      }
    }

    static inline void shutdown_enclave()
    {
      oe_attester_shutdown();
    }

    static bool is_outside_enclave(const void* ptr, size_t size)
    {
      return oe_is_outside_enclave(ptr, size);
    }

    static bool get_mallinfo(MallocInfo& info)
    {
      oe_mallinfo_t oe_info;
      auto rc = oe_allocator_mallinfo(&oe_info);
      if (rc != OE_OK)
      {
        return false;
      }
      info.max_total_heap_size = oe_info.max_total_heap_size;
      info.current_allocated_heap_size = oe_info.current_allocated_heap_size;
      info.peak_allocated_heap_size = oe_info.peak_allocated_heap_size;
      return true;
    }

    static QuoteInfo generate_quote(std::array<uint8_t, 32>&& report_data)
    {
      QuoteInfo node_quote_info = {};
      node_quote_info.format = QuoteFormat::oe_sgx_v1;

      Evidence evidence;
      Endorsements endorsements;
      SerialisedClaims serialised_custom_claims;

      // Serialise hash of node's public key as a custom claim
      const size_t custom_claim_length = 1;
      oe_claim_t custom_claim;
      custom_claim.name = const_cast<char*>(sgx_report_data_claim_name);
      custom_claim.value = report_data.data();
      custom_claim.value_size = report_data.size();

      auto rc = oe_serialize_custom_claims(
        &custom_claim,
        custom_claim_length,
        &serialised_custom_claims.buffer,
        &serialised_custom_claims.size);
      if (rc != OE_OK)
      {
        throw std::logic_error(fmt::format(
          "Could not serialise node's public key as quote custom claim: {}",
          oe_result_str(rc)));
      }

      rc = oe_get_evidence(
        &oe_quote_format,
        0,
        serialised_custom_claims.buffer,
        serialised_custom_claims.size,
        nullptr,
        0,
        &evidence.buffer,
        &evidence.size,
        &endorsements.buffer,
        &endorsements.size);
      if (rc != OE_OK)
      {
        throw std::logic_error(
          fmt::format("Failed to get evidence: {}", oe_result_str(rc)));
      }

      node_quote_info.quote.assign(
        evidence.buffer, evidence.buffer + evidence.size);
      node_quote_info.endorsements.assign(
        endorsements.buffer, endorsements.buffer + endorsements.size);

      return node_quote_info;
    }

    static void verify_quote(
      const QuoteInfo& quote_info,
      attestation_measurement& unique_id,
      attestation_report_data& report_data)
    {
      if (quote_info.format != QuoteFormat::oe_sgx_v1)
      {
        throw std::logic_error(fmt::format(
          "Cannot verify non OE SGX report: {}", quote_info.format));
      }

      Claims claims;

      auto rc = oe_verify_evidence(
        &oe_quote_format,
        quote_info.quote.data(),
        quote_info.quote.size(),
        quote_info.endorsements.data(),
        quote_info.endorsements.size(),
        nullptr,
        0,
        &claims.data,
        &claims.length);
      if (rc != OE_OK)
      {
        throw std::logic_error(
          fmt::format("Failed to verify evidence: {}", oe_result_str(rc)));
      }

      bool unique_id_found = false;
      bool sgx_report_data_found = false;
      for (size_t i = 0; i < claims.length; i++)
      {
        auto& claim = claims.data[i];
        auto claim_name = std::string(claim.name);
        if (claim_name == OE_CLAIM_UNIQUE_ID)
        {
          std::copy(
            claim.value, claim.value + claim.value_size, unique_id.begin());
          unique_id_found = true;
        }
        else if (claim_name == OE_CLAIM_CUSTOM_CLAIMS_BUFFER)
        {
          // Find sgx report data in custom claims
          CustomClaims custom_claims;
          rc = oe_deserialize_custom_claims(
            claim.value,
            claim.value_size,
            &custom_claims.data,
            &custom_claims.length);
          if (rc != OE_OK)
          {
            throw std::logic_error(fmt::format(
              "Failed to deserialise custom claims", oe_result_str(rc)));
          }

          for (size_t j = 0; j < custom_claims.length; j++)
          {
            auto& custom_claim = custom_claims.data[j];
            if (std::string(custom_claim.name) == sgx_report_data_claim_name)
            {
              if (custom_claim.value_size != report_data.size())
              {
                throw std::logic_error(fmt::format(
                  "Expected {} of size {}, had size {}",
                  sgx_report_data_claim_name,
                  report_data.size(),
                  custom_claim.value_size));
              }

              std::copy(
                custom_claim.value,
                custom_claim.value + custom_claim.value_size,
                report_data.begin());
              sgx_report_data_found = true;
              break;
            }
          }
        }
      }

      if (!unique_id_found)
      {
        throw std::logic_error("Could not find measurement");
      }

      if (!sgx_report_data_found)
      {
        throw std::logic_error("Could not find report data");
      }
    }

  private:
    static void open_enclave_logging_callback(
      void* context,
      oe_log_level_t level,
      uint64_t thread_id,
      const char* message)
    {
      switch (level)
      {
        case OE_LOG_LEVEL_FATAL:
          CCF_LOG_FMT(FATAL, "")("OE: {}", message);
          break;
        case OE_LOG_LEVEL_ERROR:
          CCF_LOG_FMT(FAIL, "")("OE: {}", message);
          break;
        case OE_LOG_LEVEL_WARNING:
          CCF_LOG_FMT(FAIL, "")("OE: {}", message);
          break;
        case OE_LOG_LEVEL_INFO:
          CCF_LOG_FMT(INFO, "")("OE: {}", message);
          break;
        case OE_LOG_LEVEL_VERBOSE:
          CCF_LOG_FMT(DEBUG, "")("OE: {}", message);
          break;
        case OE_LOG_LEVEL_MAX:
        case OE_LOG_LEVEL_NONE:
          CCF_LOG_FMT(TRACE, "")("OE: {}", message);
          break;
      }
    }
  };

  using Pal = OEPal;

#endif
}