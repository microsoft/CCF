// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/logger.h"
#include "ds/spin_lock.h"
#include "ds/stacktrace_utils.h"
#include "enclave.h"
#include "enclave_time.h"
#include "oe_shim.h"

#include <chrono>
#include <msgpack/msgpack.hpp>
#include <thread>

// the central enclave object
static SpinLock create_lock;
static std::atomic<enclave::Enclave*> e;

#ifdef DEBUG_CONFIG
static uint8_t* reserved_memory;
#endif
std::atomic<std::chrono::milliseconds> logger::config::ms =
  std::chrono::milliseconds::zero();
std::atomic<uint16_t> num_pending_threads = 0;
std::atomic<uint16_t> num_complete_threads = 0;

threading::ThreadMessaging threading::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> threading::ThreadMessaging::thread_count = 0;

namespace enclave
{
  std::atomic<std::chrono::microseconds>* host_time = nullptr;
  std::chrono::microseconds last_value(0);
}

extern "C"
{
  bool enclave_create_node(
    void* enclave_config,
    char* ccf_config,
    size_t ccf_config_size,
    uint8_t* node_cert,
    size_t node_cert_size,
    size_t* node_cert_len,
    uint8_t* network_cert,
    size_t network_cert_size,
    size_t* network_cert_len,
    StartType start_type,
    ConsensusType consensus_type,
    size_t num_worker_threads,
    void* time_location)
  {
    std::lock_guard<SpinLock> guard(create_lock);

    if (e != nullptr)
    {
      return false;
    }

    num_pending_threads = (uint16_t)num_worker_threads + 1;

    if (
      num_pending_threads >
      threading::ThreadMessaging::thread_messaging.max_num_threads)
    {
      return false;
    }

    // Check that where we expect arguments to be in host-memory, they really
    // are. lfence after these checks to prevent speculative execution
    if (!oe_is_outside_enclave(time_location, sizeof(enclave::host_time)))
    {
      return false;
    }

    enclave::host_time =
      static_cast<decltype(enclave::host_time)>(time_location);

    if (!oe_is_outside_enclave(enclave_config, sizeof(EnclaveConfig)))
    {
      return false;
    }

    EnclaveConfig ec = *static_cast<EnclaveConfig*>(enclave_config);

    {
      // Check that ringbuffer memory ranges are entirely outside of the enclave
      if (!oe_is_outside_enclave(
            ec.to_enclave_buffer_start, ec.to_enclave_buffer_size))
      {
        return false;
      }

      if (!oe_is_outside_enclave(
            ec.from_enclave_buffer_start, ec.from_enclave_buffer_size))
      {
        return false;
      }

      if (!oe_is_outside_enclave(
            ec.to_enclave_buffer_offsets, sizeof(ringbuffer::Offsets)))
      {
        return false;
      }

      if (!oe_is_outside_enclave(
            ec.from_enclave_buffer_offsets, sizeof(ringbuffer::Offsets)))
      {
        return false;
      }

      oe_lfence();
    }

    if (!oe_is_outside_enclave(ccf_config, ccf_config_size))
    {
      return false;
    }

    oe_lfence();

    msgpack::object_handle oh = msgpack::unpack(ccf_config, ccf_config_size);
    msgpack::object obj = oh.get();
    CCFConfig cc;
    obj.convert(cc);

#ifdef DEBUG_CONFIG
    reserved_memory = new uint8_t[ec->debug_config.memory_reserve_startup];
#endif

    auto enclave = new enclave::Enclave(
      ec,
      cc.signature_intervals,
      consensus_type,
      cc.consensus_config,
      cc.curve_id);

    bool result = enclave->create_new_node(
      start_type,
      cc,
      node_cert,
      node_cert_size,
      node_cert_len,
      network_cert,
      network_cert_size,
      network_cert_len);
    e.store(enclave);

    return result;
  }

  bool enclave_run()
  {
    if (e.load() != nullptr)
    {
      uint16_t tid;
      {
        std::lock_guard<SpinLock> guard(create_lock);

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
