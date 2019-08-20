// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../ds/logger.h"
#include "../ds/spinlock.h"
#include "enclave.h"

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
    StartType start_type)
  {
    std::lock_guard<SpinLock> guard(create_lock);

    if (e != nullptr)
      return false;

    EnclaveConfig* ec = (EnclaveConfig*)enclave_config;

    msgpack::object_handle oh = msgpack::unpack(ccf_config, ccf_config_size);
    msgpack::object obj = oh.get();
    CCFConfig cc;
    obj.convert(cc);

    std::cout << "Raft: " << cc.raft_config.electionTimeout << "/"
              << cc.raft_config.electionTimeout << std::endl;
    std::cout << "node_info: " << cc.node_info.host << "/"
              << cc.node_info.nodeport << "/" << cc.node_info.pubhost << "/"
              << cc.node_info.rpcport << std::endl;
    std::cout << "Signature Intervals: " << cc.signature_intervals.sig_max_ms
              << "/" << cc.signature_intervals.sig_max_tx << std::endl;
    // std::cout << "Genesis: " << cc.genesis.gov_script << std::endl;
    // std::cout << "Joining: " << cc.joining.target_host << "/"
    //           << cc.joining.target_port << std::endl;

#ifdef DEBUG_CONFIG
    reserved_memory = new uint8_t[ec->debug_config.memory_reserve_startup];
#endif

    std::cout << "About to create enclave" << std::endl;
    e = new enclave::Enclave(ec, cc.signature_intervals, cc.raft_config);

    std::cout << "Starting node in mode: " << start_type << std::endl;

    bool ret;
    switch (start_type)
    {
      case StartType::Start:
        ret = e->create_new_node(
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
        break;

      case StartType::Join:
        ret = e->create_join_node(
          cc,
          node_cert,
          node_cert_size,
          node_cert_len,
          quote,
          quote_size,
          quote_len);
        break;

      case StartType::Recover:
        ret = e->create_recover_node(
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
