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

// the central enclave object
static SpinLock create_lock;
static enclave::Enclave* e;
static uint8_t* reserved_memory;
std::chrono::milliseconds logger::config::ms =
  std::chrono::milliseconds::zero();

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
    ConsensusType consensus_type)
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

    e = new enclave::Enclave(
      ec, cc.signature_intervals, consensus_type, cc.raft_config);

    return e->create_new_node(
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
  }

  bool enclave_run()
  {
    if (e != nullptr)
      return e->run();
    else
      return false;
  }
}
