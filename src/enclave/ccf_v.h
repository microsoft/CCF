// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifdef VIRTUAL_ENCLAVE
#  include "consensus_type.h"
#  include "start_type.h"
#else
#  include <ccf_args.h>
#endif

#define OE_REPORT_DATA_SIZE 64

#define OE_ENCLAVE_FLAG_DEBUG 0x00000001u

static void* virtual_enclave_handle;

template <typename T>
T get_enclave_exported_function(const char* func_name)
{
  void* sym = dlsym(virtual_enclave_handle, func_name);
  if (sym == nullptr)
  {
    throw std::logic_error(
      fmt::format("Failed to find symbol: {}\n  {}", func_name, dlerror()));
  }
  return (T)sym;
}

// Repeat minimal required definitions for virtual build. It should not matter
// if these do not match precisely OE's, so long as they can be used
// consistently by the virtual build
using oe_result_t = int;
constexpr oe_result_t OE_OK = 0;
constexpr oe_result_t OE_FAILURE = 1;

using oe_enclave_t = void;

enum oe_enclave_type_t
{
  OE_ENCLAVE_TYPE_SGX = 2,
};

#ifdef GET_QUOTE
#  error Quotes cannot be retrieved in virtual build. Calls to oe_verify_report should be guarded with GET_QUOTE
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#define oe_result_str(x) x

  typedef void (*oe_ocall_func_t)(
    const uint8_t* input_buffer,
    size_t input_buffer_size,
    uint8_t* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written);

  using create_node_func_t = bool (*)(
    void*,
    char*,
    size_t,
    uint8_t*,
    size_t,
    size_t*,
    uint8_t*,
    size_t,
    size_t*,
    StartType,
    ConsensusType,
    size_t,
    void*);

  using run_func_t = bool (*)();

  using tick_func_t = bool (*)(size_t, size_t);

  /*ocall function table*/
  static oe_ocall_func_t __ccf_ocall_function_table[] = {nullptr};

  inline void load_virtual_enclave(const char* path)
  {
    if (virtual_enclave_handle)
    {
      throw std::logic_error(
        "Current implementation is limited to a single virtual "
        "enclave per process");
    }
    virtual_enclave_handle = dlopen(path, RTLD_NOW);
    if (virtual_enclave_handle == nullptr)
    {
      throw std::logic_error(
        fmt::format("Could not load virtual enclave: {}", dlerror()));
    }
  }

  inline oe_result_t enclave_create_node(
    oe_enclave_t*,
    bool* _retval,
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
    size_t num_worker_thread,
    void* time_location)
  {
    static create_node_func_t create_node_func =
      get_enclave_exported_function<create_node_func_t>("enclave_create_node");

    *_retval = create_node_func(
      enclave_config,
      ccf_config,
      ccf_config_size,
      node_cert,
      node_cert_size,
      node_cert_len,
      network_cert,
      network_cert_size,
      network_cert_len,
      start_type,
      consensus_type,
      num_worker_thread,
      time_location);
    return *_retval ? OE_OK : OE_FAILURE;
  }

  inline oe_result_t enclave_run(oe_enclave_t*, bool* _retval)
  {
    static run_func_t run_func =
      get_enclave_exported_function<run_func_t>("enclave_run");

    *_retval = run_func();
    return *_retval ? OE_OK : OE_FAILURE;
  }

  inline oe_result_t oe_create_ccf_enclave(
    const char*,
    oe_enclave_type_t,
    uint32_t,
    const void*,
    uint32_t,
    oe_enclave_t**)
  {
    // this function is not supposed to be called when using a virtual enclave
    return OE_FAILURE;
  }

  using oe_log_level_t = size_t;
  typedef void (*oe_log_callback_t)(
    void* context,
    bool is_enclave,
    const struct tm* t,
    long int usecs,
    oe_log_level_t level,
    uint64_t host_thread_id,
    const char* message);

  oe_result_t oe_log_set_callback(void* context, oe_log_callback_t callback)
  {
    return OE_OK;
  }

#ifdef __cplusplus
}
#endif
