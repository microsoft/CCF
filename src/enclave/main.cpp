// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/ds/ccf_exception.h"
#include "ccf/ds/json.h"
#include "ccf/ds/logger.h"
#include "ccf/pal/enclave.h"
#include "ccf/pal/locking.h"
#include "ccf/version.h"
#include "common/enclave_interface_types.h"
#include "enclave.h"
#include "enclave_time.h"
#include "ringbuffer_logger.h"

#include <chrono>
#include <cstdint>
#include <thread>

// the central enclave object
static ccf::pal::Mutex create_lock;
static std::atomic<ccf::Enclave*> e;

std::atomic<uint16_t> num_pending_threads = 0;
std::atomic<uint16_t> num_complete_threads = 0;

threading::ThreadMessaging threading::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> threading::ThreadMessaging::thread_count = 0;

std::chrono::microseconds ccf::Channel::min_gap_between_initiation_attempts(
  2'000'000);

static bool is_aligned(void* p, size_t align, size_t count = 0)
{
  const auto start = reinterpret_cast<std::uintptr_t>(p);
  const auto end = start + count;
  return (start % align == 0) && (end % align == 0);
}

extern "C"
{
  // Confirming in-enclave behaviour in separate unit tests is tricky, so we
  // do final sanity checks on some basic behaviour here, on every enclave
  // launch.
  void enclave_sanity_checks()
  {
    {
      ccf::pal::Mutex m;
      m.lock();
      if (m.try_lock())
      {
        LOG_FATAL_FMT("Able to lock mutex multiple times");
        abort();
      }
      m.unlock();
    }

    LOG_DEBUG_FMT("All sanity check tests passed");
  }

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
    size_t num_worker_threads,
    void* time_location)
  {
    std::lock_guard<ccf::pal::Mutex> guard(create_lock);

    if (e != nullptr)
    {
      return CreateNodeStatus::NodeAlreadyCreated;
    }

    if (!ccf::pal::is_outside_enclave(enclave_config, sizeof(EnclaveConfig)))
    {
      LOG_FAIL_FMT("Memory outside enclave: enclave_config");
      return CreateNodeStatus::MemoryNotOutsideEnclave;
    }

    if (!is_aligned(enclave_config, 8, sizeof(EnclaveConfig)))
    {
      LOG_FAIL_FMT("Read source memory not aligned: enclave_config");
      return CreateNodeStatus::UnalignedArguments;
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

    // Check that ringbuffer memory ranges are entirely outside of the enclave
    if (
      !ccf::pal::is_outside_enclave(
        ec.from_enclave_buffer_start, ec.from_enclave_buffer_size) ||
      !ccf::pal::is_outside_enclave(
        ec.to_enclave_buffer_start, ec.to_enclave_buffer_size) ||
      !ccf::pal::is_outside_enclave(
        ec.to_enclave_buffer_offsets, sizeof(ringbuffer::Offsets)) ||
      !ccf::pal::is_outside_enclave(
        ec.from_enclave_buffer_offsets, sizeof(ringbuffer::Offsets)))
    {
      return CreateNodeStatus::MemoryNotOutsideEnclave;
    }

    // Note: because logger uses ringbuffer, logger can only be initialised once
    // ringbuffer memory has been verified
    auto new_logger = std::make_unique<ccf::RingbufferLogger>(
      writer_factory->create_writer_to_outside());
    auto ringbuffer_logger = new_logger.get();
    logger::config::loggers().push_back(std::move(new_logger));

    ccf::pal::redirect_platform_logging();

    enclave_sanity_checks();

    {
      auto ccf_version_string = std::string(ccf::ccf_version);
      if (ccf_version_string.size() > enclave_version_size)
      {
        LOG_FAIL_FMT(
          "Version mismatch: host {}, enclave {}",
          ccf_version_string,
          std::string(enclave_version, enclave_version + enclave_version_size));
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

      // Check that where we expect arguments to be in host-memory, they
      // really are. lfence after these checks to prevent speculative
      // execution
      if (!ccf::pal::is_outside_enclave(
            time_location, sizeof(*ccf::host_time_us)))
      {
        LOG_FAIL_FMT("Memory outside enclave: time_location");
        return CreateNodeStatus::MemoryNotOutsideEnclave;
      }

      if (!is_aligned(time_location, 8, sizeof(*ccf::host_time_us)))
      {
        LOG_FAIL_FMT("Read source memory not aligned: time_location");
        return CreateNodeStatus::UnalignedArguments;
      }

      ccf::host_time_us =
        static_cast<decltype(ccf::host_time_us)>(time_location);

      ccf::pal::speculation_barrier();
    }

    if (!ccf::pal::is_outside_enclave(ccf_config, ccf_config_size))
    {
      LOG_FAIL_FMT("Memory outside enclave: ccf_config");
      return CreateNodeStatus::MemoryNotOutsideEnclave;
    }

    if (!is_aligned(ccf_config, 8, ccf_config_size))
    {
      LOG_FAIL_FMT("Read source memory not aligned: ccf_config");
      return CreateNodeStatus::UnalignedArguments;
    }

    if (!ccf::pal::is_outside_enclave(
          startup_snapshot_data, startup_snapshot_size))
    {
      LOG_FAIL_FMT("Memory outside enclave: startup snapshot");
      return CreateNodeStatus::MemoryNotOutsideEnclave;
    }

    if (!is_aligned(startup_snapshot_data, 8, startup_snapshot_size))
    {
      LOG_FAIL_FMT("Read source memory not aligned: startup snapshot");
      return CreateNodeStatus::UnalignedArguments;
    }

    ccf::pal::speculation_barrier();

    StartupConfig cc =
      nlohmann::json::parse(ccf_config, ccf_config + ccf_config_size);

    // Ensure BFT consensus cannot be selected in release enclaves
    if (cc.consensus.type != ConsensusType::CFT)
    {
      LOG_FAIL_FMT("BFT consensus disabled in release mode");
      return CreateNodeStatus::ConsensusNotAllowed;
    }

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
        std::move(circuit),
        std::move(basic_writer_factory),
        std::move(writer_factory),
        ringbuffer_logger,
        cc.ledger_signatures.tx_count,
        cc.ledger_signatures.delay.count_ms(),
        cc.consensus,
        cc.node_certificate.curve_id);
    }
    catch (const ccf::ccf_oe_attester_init_error& e)
    {
      LOG_FAIL_FMT(
        "ccf_oe_attester_init_error during enclave init: {}", e.what());
      return CreateNodeStatus::OEAttesterInitFailed;
    }
    catch (const ccf::ccf_oe_verifier_init_error& e)
    {
      LOG_FAIL_FMT(
        "ccf_oe_verifier_init_error during enclave init: {}", e.what());
      return CreateNodeStatus::OEVerifierInitFailed;
    }
    catch (const ccf::ccf_openssl_rdrand_init_error& e)
    {
      LOG_FAIL_FMT(
        "ccf_openssl_rdrand_init_error during enclave init: {}", e.what());
      return CreateNodeStatus::OpenSSLRDRANDInitFailed;
    }
    catch (const std::exception& e)
    {
      // In most places, logging exception messages directly is unsafe
      // because they may contain confidential information. In this
      // instance the chance of confidential information is extremely low
      // - this is early during node startup, when it has not communicated
      // with any other nodes to retrieve confidential state, and any
      // secrets it may have generated are about to be discarded as this
      // node terminates. The debugging benefit is substantial, while the
      // risk is low, so in this case we promote the generic exception
      // message to FAIL.
      LOG_FAIL_FMT("exception during enclave init: {}", e.what());
      return CreateNodeStatus::EnclaveInitFailed;
    }

    CreateNodeStatus status = EnclaveInitFailed;

    try
    {
      std::vector<uint8_t> startup_snapshot(
        startup_snapshot_data, startup_snapshot_data + startup_snapshot_size);
      status = enclave->create_new_node(
        start_type,
        std::move(cc),
        std::move(startup_snapshot),
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
        std::lock_guard<ccf::pal::Mutex> guard(create_lock);

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
