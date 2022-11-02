// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#if !defined(PLATFORM_VIRTUAL) && !defined(PLATFORM_SNP)
#  error Should only be included in cchost builds with virtual support
#endif

#include "common/enclave_interface_types.h"
#include "consensus_type.h"

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

template <typename T>
T get_enclave_exported_function(
  void* virtual_enclave_handle, const char* func_name)
{
  if (virtual_enclave_handle == nullptr)
  {
    throw std::logic_error(
      "Cannot find symbol - library was not loaded correctly");
  }

  void* sym = dlsym(virtual_enclave_handle, func_name);
  if (sym == nullptr)
  {
    throw std::logic_error(
      fmt::format("Failed to find symbol: {}\n  {}", func_name, dlerror()));
  }
  return (T)sym;
}

#ifndef PLATFORM_SGX
// If this build does not also include OE definitions, then recreate them here.
// It should not matter if these do not match precisely OE's, so long as they
// can be used consistently by the virtual build.
using oe_result_t = int;
constexpr oe_result_t OE_OK = 0;
constexpr oe_result_t OE_FAILURE = 1;

using oe_enclave_t = void;
using oe_log_level_t = size_t;

enum oe_enclave_type_t
{
  OE_ENCLAVE_TYPE_SGX = 2,
};

#  define oe_result_str(x) x
#endif

#ifdef __cplusplus
extern "C"
{
#endif

  typedef void (*oe_ocall_func_t)(
    const uint8_t* input_buffer,
    size_t input_buffer_size,
    uint8_t* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written);

  /*ocall function table*/
  static oe_ocall_func_t __ccf_ocall_function_table[] = {nullptr};

  inline void* load_virtual_enclave(const char* path)
  {
    auto virtual_enclave_handle = dlopen(path, RTLD_NOW);
    if (virtual_enclave_handle == nullptr)
    {
      throw std::logic_error(
        fmt::format("Could not load virtual enclave: {}", dlerror()));
    }
    return virtual_enclave_handle;
  }

  inline oe_result_t virtual_create_node(
    void* virtual_enclave_handle,
    CreateNodeStatus* status,
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
    size_t num_worker_thread,
    void* time_location)
  {
    using create_node_func_t = CreateNodeStatus (*)(
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
      size_t,
      void*);

    static create_node_func_t create_node_func =
      get_enclave_exported_function<create_node_func_t>(
        virtual_enclave_handle, "enclave_create_node");

    *status = create_node_func(
      enclave_config,
      ccf_config,
      ccf_config_size,
      node_cert,
      node_cert_size,
      node_cert_len,
      service_cert,
      service_cert_size,
      service_cert_len,
      enclave_version,
      enclave_version_size,
      enclave_version_len,
      start_type,
      num_worker_thread,
      time_location);

    // Only return OE_OK when the error isn't OE related
    switch (*status)
    {
      case CreateNodeStatus::OEAttesterInitFailed:
      case CreateNodeStatus::OEVerifierInitFailed:
      case CreateNodeStatus::EnclaveInitFailed:
      case CreateNodeStatus::MemoryNotOutsideEnclave:
        return OE_FAILURE;
      default:
        return OE_OK;
    }
  }

  inline oe_result_t virtual_run(void* virtual_enclave_handle, bool* _retval)
  {
    using run_func_t = bool (*)();

    static run_func_t run_func = get_enclave_exported_function<run_func_t>(
      virtual_enclave_handle, "enclave_run");

    *_retval = run_func();
    return *_retval ? OE_OK : OE_FAILURE;
  }

#ifdef __cplusplus
}
#endif
