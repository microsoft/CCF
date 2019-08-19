// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../ds/logger.h"
#include "../ds/spinlock.h"
#include "enclave.h"

#include <chrono>

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
    void* ccf_config,
    uint8_t* node_cert,
    size_t node_cert_size,
    size_t* node_cert_len,
    uint8_t* quote,
    size_t quote_size,
    size_t* quote_len,
    uint8_t* network_cert,
    size_t network_cert_size,
    size_t* network_cert_len,
    StartType start_type)
  {
    std::lock_guard<SpinLock> guard(create_lock);

    if (e != nullptr)
      return false;

    EnclaveConfig* ec = (EnclaveConfig*)enclave_config;
    CCFConfig* cc = (CCFConfig*)ccf_config;

#ifdef DEBUG_CONFIG
    reserved_memory = new uint8_t[ec->debug_config.memory_reserve_startup];
#endif

    e = new enclave::Enclave(ec, cc->signature_intervals, cc->raft_config);

    LOG_INFO << "Starting node in starting mode: " << start_type << std::endl;

    bool ret;
    switch (start_type)
    {
      case StartType::Start:
        ret = e->create_new_node(
          *cc,
          node_cert,
          node_cert_size,
          node_cert_len,
          quote,
          quote_size,
          quote_len,
          network_cert,
          network_cert_size,
          network_cert_len);
        break;

      case StartType::Join:
        ret = e->create_join_node(
          *cc,
          node_cert,
          node_cert_size,
          node_cert_len,
          quote,
          quote_size,
          quote_len);
        break;

      case StartType::Recover:
        ret = e->create_recover_node(
          *cc,
          node_cert,
          node_cert_size,
          node_cert_len,
          quote,
          quote_size,
          quote_len,
          network_cert,
          network_cert_size,
          network_cert_len);
        break;

      default:
        return false;
    }
    return ret;
  }

  bool enclave_run()
  {
    if (e != nullptr)
      return e->run();
    else
      return false;
  }
}
