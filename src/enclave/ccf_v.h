// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <dlfcn.h>
#include <openenclave/bits/report.h>
#include <openenclave/bits/result.h>
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

/**
 * Maximum quote size supported by OE. This is 10 KB.
 */
#define OE_MAX_REPORT_SIZE (10 * 1024)

#define OE_ENCLAVE_FLAG_DEBUG 0x00000001u

static void* virtual_enclave_handle;

template <typename T>
T get_enclave_exported_function(const char* func_name)
{
  void* sym = dlsym(virtual_enclave_handle, func_name);
  if (sym == nullptr)
  {
    LOG_FATAL_FMT("Failed to find symbol: {}\n  {}", func_name, dlerror());
  }
  return (T)sym;
}

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
    uint8_t*,
    size_t,
    size_t*,
    StartType,
    ConsensusType);

  using run_func_t = bool (*)();

  using tick_func_t = bool (*)(size_t, size_t);

  /*ocall function table*/
  static oe_ocall_func_t __ccf_ocall_function_table[] = {NULL};

  inline void load_virtual_enclave(const char* path)
  {
    if (virtual_enclave_handle)
    {
      LOG_FATAL_FMT(
        "Current implementation is limited to a single virtual "
        "enclave per process");
    }
    virtual_enclave_handle = dlopen(path, RTLD_LAZY);
    if (virtual_enclave_handle == nullptr)
    {
      LOG_FATAL_FMT("Could not load virtual enclave: {}", dlerror());
    }
  }

  inline oe_result_t enclave_create_node(
    oe_enclave_t* enclave,
    bool* _retval,
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
    static create_node_func_t create_node_func =
      get_enclave_exported_function<create_node_func_t>("enclave_create_node");

    *_retval = create_node_func(
      enclave_config,
      ccf_config,
      ccf_config_size,
      node_cert,
      node_cert_size,
      node_cert_len,
      quote,
      quote_size,
      quote_len,
      network_cert,
      network_cert_size,
      network_cert_len,
      start_type,
      consensus_type);
    return *_retval ? OE_OK : OE_FAILURE;
  }

  inline oe_result_t enclave_run(oe_enclave_t* enclave, bool* _retval)
  {
    static run_func_t run_func =
      get_enclave_exported_function<run_func_t>("enclave_run");

    *_retval = run_func();
    return *_retval ? OE_OK : OE_FAILURE;
  }

  inline oe_result_t oe_create_ccf_enclave(
    const char* path,
    oe_enclave_type_t type,
    uint32_t flags,
    const void* config,
    uint32_t config_size,
    oe_enclave_t** enclave)
  {
    // this function is not supposed to be called when using a virtual enclave
    return OE_FAILURE;
  }

  inline oe_result_t oe_verify_report(
    oe_enclave_t* e,
    const uint8_t* quote_data,
    size_t quote_size,
    oe_report_t* parsed_quote)
  {
    // this function is not supposed to be called when using a virtual enclave
    return OE_FAILURE;
  }

#ifdef __cplusplus
}
#endif