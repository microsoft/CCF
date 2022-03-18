// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/ds/json.h"
#include "ccf/ds/logger.h"
#include "ccf/version.h"
#include "common/enclave_interface_types.h"
#include "ds/ccf_exception.h"
#include "enclave.h"
#include "enclave_time.h"
#include "oe_shim.h"
#include "ringbuffer_logger.h"

#include <chrono>
#include <thread>

// the central enclave object
static std::mutex create_lock;
static std::atomic<ccf::Enclave*> e;

std::atomic<uint16_t> num_pending_threads = 0;
std::atomic<uint16_t> num_complete_threads = 0;

threading::ThreadMessaging threading::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> threading::ThreadMessaging::thread_count = 0;

std::chrono::microseconds ccf::Channel::min_gap_between_initiation_attempts(
  2'000'000);

extern "C"
{
  void open_enclave_logging_callback(
    void* context,
    oe_log_level_t level,
    uint64_t thread_id,
    const char* message)
  {
    switch (level)
    {
      case OE_LOG_LEVEL_FATAL:
        LOG_FATAL_FMT("OE: {}", message);
        break;
      case OE_LOG_LEVEL_ERROR:
        LOG_FAIL_FMT("OE: {}", message);
        break;
      case OE_LOG_LEVEL_WARNING:
        LOG_FAIL_FMT("OE: {}", message);
        break;
      case OE_LOG_LEVEL_INFO:
        LOG_INFO_FMT("OE: {}", message);
        break;
      case OE_LOG_LEVEL_VERBOSE:
        LOG_DEBUG_FMT("OE: {}", message);
        break;
      case OE_LOG_LEVEL_MAX:
      case OE_LOG_LEVEL_NONE:
        LOG_TRACE_FMT("OE: {}", message);
        break;
    }
  }

  CreateNodeStatus enclave_create_node(
    void* enclave_config,
    char* ccf_config,
    size_t ccf_config_size,
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
    size_t num_worker_threads,
    void* time_location)
  {
    std::lock_guard<std::mutex> guard(create_lock);

    if (e != nullptr)
    {
      return CreateNodeStatus::NodeAlreadyCreated;
    }

    if (!oe_is_outside_enclave(enclave_config, sizeof(EnclaveConfig)))
    {
      LOG_FAIL_FMT("Memory outside enclave: enclave_config");
      return CreateNodeStatus::MemoryNotOutsideEnclave;
    }

    EnclaveConfig ec = *static_cast<EnclaveConfig*>(enclave_config);

    // Setup logger to allow enclave logs to reach the host before node is
    // actually created
    auto circuit = std::make_unique<ringbuffer::Circuit>(
      ringbuffer::BufferDef{
        ec.to_enclave_buffer_start,
        ec.to_enclave_buffer_size,
        ec.to_enclave_buffer_offsets},
      ringbuffer::BufferDef{
        ec.from_enclave_buffer_start,
        ec.from_enclave_buffer_size,
        ec.from_enclave_buffer_offsets});
    auto basic_writer_factory =
      std::make_unique<ringbuffer::WriterFactory>(*circuit);
    auto writer_factory = std::make_unique<oversized::WriterFactory>(
      *basic_writer_factory, ec.writer_config);

    auto new_logger = std::make_unique<ccf::RingbufferLogger>(
      writer_factory->create_writer_to_outside());
    auto ringbuffer_logger = new_logger.get();
    logger::config::loggers().push_back(std::move(new_logger));

    oe_enclave_log_set_callback(nullptr, &open_enclave_logging_callback);

    {
      // Report enclave version to host
      auto ccf_version_string = std::string(ccf::ccf_version);
      if (ccf_version_string.size() > enclave_version_size)
      {
        LOG_FAIL_FMT(
          "Version mismatch: host {}, enclave {}",
          ccf_version_string,
          enclave_version);
        return CreateNodeStatus::VersionMismatch;
      }

      ::memcpy(
        enclave_version, ccf_version_string.data(), ccf_version_string.size());
      *enclave_version_len = ccf_version_string.size();

      num_pending_threads = (uint16_t)num_worker_threads + 1;

      if (
        num_pending_threads >
        threading::ThreadMessaging::thread_messaging.max_num_threads)
      {
        LOG_FAIL_FMT("Too many threads: {}", num_pending_threads);
        return CreateNodeStatus::TooManyThreads;
      }

      // Check that where we expect arguments to be in host-memory, they really
      // are. lfence after these checks to prevent speculative execution
      if (!oe_is_outside_enclave(time_location, sizeof(ccf::host_time)))
      {
        LOG_FAIL_FMT("Memory outside enclave: time_location");
        return CreateNodeStatus::MemoryNotOutsideEnclave;
      }

      ccf::host_time = static_cast<decltype(ccf::host_time)>(time_location);

      // Check that ringbuffer memory ranges are entirely outside of the enclave
      if (!oe_is_outside_enclave(
            ec.to_enclave_buffer_start, ec.to_enclave_buffer_size))
      {
        LOG_FAIL_FMT("Memory outside enclave: to_enclave buffer start");
        return CreateNodeStatus::MemoryNotOutsideEnclave;
      }

      if (!oe_is_outside_enclave(
            ec.from_enclave_buffer_start, ec.from_enclave_buffer_size))
      {
        LOG_FAIL_FMT("Memory outside enclave: from_enclave buffer start");
        return CreateNodeStatus::MemoryNotOutsideEnclave;
      }

      if (!oe_is_outside_enclave(
            ec.to_enclave_buffer_offsets, sizeof(ringbuffer::Offsets)))
      {
        LOG_FAIL_FMT("Memory outside enclave: to_enclave buffer offset");
        return CreateNodeStatus::MemoryNotOutsideEnclave;
      }

      if (!oe_is_outside_enclave(
            ec.from_enclave_buffer_offsets, sizeof(ringbuffer::Offsets)))
      {
        LOG_FAIL_FMT("Memory outside enclave: from_enclave buffer offset");
        return CreateNodeStatus::MemoryNotOutsideEnclave;
      }

      oe_lfence();
    }

    if (!oe_is_outside_enclave(ccf_config, ccf_config_size))
    {
      LOG_FAIL_FMT("Memory outside enclave: ccf_config");
      return CreateNodeStatus::MemoryNotOutsideEnclave;
    }

    oe_lfence();

    StartupConfig cc =
      nlohmann::json::parse(ccf_config, ccf_config + ccf_config_size);

#ifndef ENABLE_BFT
    // As BFT consensus is currently experimental, disable it in release
    // enclaves
    if (cc.consensus.type != ConsensusType::CFT)
    {
      LOG_FAIL_FMT("BFT consensus disabled in release mode");
      return CreateNodeStatus::ConsensusNotAllowed;
    }
#endif

#ifndef ENABLE_2TX_RECONFIG
    // 2-tx reconfiguration is currently experimental, disable it in release
    // enclaves
    if (
      cc.start.service_configuration.reconfiguration_type.has_value() &&
      cc.start.service_configuration.reconfiguration_type.value() !=
        ReconfigurationType::ONE_TRANSACTION)
    {
      LOG_FAIL_FMT(
        "2TX reconfiguration is experimental, disabled in release mode");
      return CreateNodeStatus::ReconfigurationMethodNotSupported;
    }
#endif

    ccf::Enclave* enclave = nullptr;

    try
    {
      enclave = new ccf::Enclave(
        ec,
        std::move(circuit),
        std::move(basic_writer_factory),
        std::move(writer_factory),
        ringbuffer_logger,
        cc.ledger_signatures.tx_count,
        cc.ledger_signatures.delay.count_ms(),
        cc.consensus,
        cc.node_certificate.curve_id);
    }
    catch (const ccf::ccf_oe_attester_init_error&)
    {
      return CreateNodeStatus::OEAttesterInitFailed;
    }
    catch (const ccf::ccf_oe_verifier_init_error&)
    {
      return CreateNodeStatus::OEVerifierInitFailed;
    }
    catch (const ccf::ccf_openssl_rdrand_init_error&)
    {
      return CreateNodeStatus::OpenSSLRDRANDInitFailed;
    }
    catch (const std::exception&)
    {
      return CreateNodeStatus::EnclaveInitFailed;
    }

    CreateNodeStatus status = EnclaveInitFailed;

    try
    {
      status = enclave->create_new_node(
        start_type,
        std::move(cc),
        node_cert,
        node_cert_size,
        node_cert_len,
        service_cert,
        service_cert_size,
        service_cert_len);
    }
    catch (...)
    {
      delete enclave;
      throw;
    }

    if (status != CreateNodeStatus::OK)
    {
      delete enclave;
      return status;
    }

    e.store(enclave);

    return CreateNodeStatus::OK;
  }

  bool enclave_run()
  {
    if (e.load() != nullptr)
    {
      uint16_t tid;
      {
        std::lock_guard<std::mutex> guard(create_lock);

        tid = threading::ThreadMessaging::thread_count.fetch_add(1);
        threading::thread_ids.emplace(std::pair<std::thread::id, uint16_t>(
          std::this_thread::get_id(), tid));
        num_pending_threads.fetch_sub(1);

        LOG_INFO_FMT("Starting thread: {}", tid);
      }

      while (num_pending_threads != 0)
      {
      }

      LOG_INFO_FMT("All threads are ready!");

      if (tid == threading::MAIN_THREAD_ID)
      {
        auto s = e.load()->run_main();
        while (num_complete_threads !=
               threading::ThreadMessaging::thread_count - 1)
        {
        }
        // All threads are done, we can drop any remaining tasks safely and
        // completely
        threading::ThreadMessaging::thread_messaging.drop_tasks();
        return s;
      }
      else
      {
        auto s = e.load()->run_worker();
        num_complete_threads.fetch_add(1);
        return s;
      }
    }
    else
    {
      return false;
    }
  }
}
