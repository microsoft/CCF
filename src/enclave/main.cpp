// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../ds/logger.h"
#include "../ds/spinlock.h"
#include "enclave.h"

#ifdef PBFT
#  include "../src/consensus/pbft/pbftglobals.h"
#endif

#include <chrono>
#include <msgpack.hpp>
#include <thread>

// the central enclave object
static SpinLock create_lock;
static std::atomic<enclave::Enclave*> e;
static uint8_t* reserved_memory;
std::chrono::milliseconds logger::config::ms =
  std::chrono::milliseconds::zero();
std::atomic<uint32_t> num_pending_threads;

enclave::ThreadMessaging enclave::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> enclave::ThreadMessaging::worker_thread_count = 0;

extern "C"
{
  bool enclave_create_node(
    void* enclave_config,
    char* ccf_config,
    size_t ccf_config_size,
    uint8_t* node_cert,
    size_t node_cert_size,
    size_t* node_cert_len,
    uint8_t* quote,
    size_t quote_size,
    size_t* quote_len,
    uint8_t* network_cert,
    size_t network_cert_size,
    size_t* network_cert_len,
    StartType start_type,
    ConsensusType consensus_type,
    size_t num_worker_thread)
  {
    std::lock_guard<SpinLock> guard(create_lock);

    if (e != nullptr)
      return false;

    EnclaveConfig* ec = (EnclaveConfig*)enclave_config;

    msgpack::object_handle oh = msgpack::unpack(ccf_config, ccf_config_size);
    msgpack::object obj = oh.get();
    CCFConfig cc;
    obj.convert(cc);

#ifdef DEBUG_CONFIG
    reserved_memory = new uint8_t[ec->debug_config.memory_reserve_startup];
#endif

    num_pending_threads = (num_worker_thread + 1);

    auto enclave = new enclave::Enclave(
      ec, cc.signature_intervals, consensus_type, cc.raft_config);

    bool result = enclave->create_new_node(
      start_type,
      cc,
      node_cert,
      node_cert_size,
      node_cert_len,
      quote,
      quote_size,
      quote_len,
      network_cert,
      network_cert_size,
      network_cert_len);
    e.store(enclave);
    return result;
  }

  bool enclave_run()
  {
    uint16_t tid;
    {
      std::lock_guard<SpinLock> guard(create_lock);

      tid = enclave::ThreadMessaging::worker_thread_count.fetch_add(1);
      tls_thread_id.insert(
        std::pair<std::thread::id, uint16_t>(std::this_thread::get_id(), tid));
    }

    LOG_INFO << "Starting thread" << std::endl;

    --num_pending_threads;

    while (num_pending_threads.load() > 0)
    {
    }

    LOG_INFO << "All threads ready!" << std::endl;

    if (e.load() != nullptr)
    {
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
