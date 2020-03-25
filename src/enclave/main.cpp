// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../ds/logger.h"
#include "../ds/spin_lock.h"
#include "enclave.h"

#include <chrono>
#include <msgpack/msgpack.hpp>
#include <thread>

// the central enclave object
static SpinLock create_lock;
static std::atomic<enclave::Enclave*> e;
static uint8_t* reserved_memory;
std::atomic<std::chrono::milliseconds> logger::config::ms =
  std::chrono::milliseconds::zero();
std::atomic<uint16_t> num_pending_threads = 0;

enclave::ThreadMessaging enclave::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> enclave::ThreadMessaging::thread_count = 0;

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
    uint8_t* network_enc_pubk,
    size_t network_enc_pubk_size,
    size_t* network_enc_pubk_len,
    StartType start_type,
    ConsensusType consensus_type,
    size_t num_worker_threads)
  {
    std::lock_guard<SpinLock> guard(create_lock);

    if (e != nullptr)
    {
      return false;
    }

    num_pending_threads = (uint16_t)num_worker_threads + 1;

    if (
      num_pending_threads >
      enclave::ThreadMessaging::thread_messaging.max_num_threads)
    {
      return false;
    }

    EnclaveConfig* ec = (EnclaveConfig*)enclave_config;

    msgpack::object_handle oh = msgpack::unpack(ccf_config, ccf_config_size);
    msgpack::object obj = oh.get();
    CCFConfig cc;
    obj.convert(cc);

#ifdef DEBUG_CONFIG
    reserved_memory = new uint8_t[ec->debug_config.memory_reserve_startup];
#endif

    auto enclave = new enclave::Enclave(
      ec, cc.signature_intervals, consensus_type, cc.consensus_config);

    bool result = enclave->create_new_node(
      start_type,
      cc,
      node_cert,
      node_cert_size,
      node_cert_len,
      network_cert,
      network_cert_size,
      network_cert_len,
      network_enc_pubk,
      network_enc_pubk_size,
      network_enc_pubk_len);
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

        tid = enclave::ThreadMessaging::thread_count.fetch_add(1);
        num_pending_threads.fetch_sub(1);
        thread_ids.emplace(std::pair<std::thread::id, uint16_t>(
          std::this_thread::get_id(), tid));

        LOG_INFO_FMT("Starting thread: {}", tid);
      }

      while (num_pending_threads != 0)
      {
      }

      LOG_INFO_FMT("All threads are ready!");

      if (tid == 0)
      {
        return e.load()->run_main();
      }
      else
      {
        return e.load()->run_worker();
      }
    }
    else
    {
      return false;
    }
  }
}
