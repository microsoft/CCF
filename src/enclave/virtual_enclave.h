// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/consensus_type.h"
#include "common/enclave_interface_types.h"

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

#ifdef __cplusplus
extern "C"
{
#endif

  inline void* load_virtual_enclave(const char* path)
  {
    auto virtual_enclave_handle = dlopen(
      path,
      RTLD_NOW
#if defined(__has_feature)
#  if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
        // Avoid unloading on delete under ASAN, so that leak checking can still
        // access symbols
        | RTLD_NODELETE
#  endif
#endif
    );
    if (virtual_enclave_handle == nullptr)
    {
      throw std::logic_error(
        fmt::format("Could not load virtual enclave: {}", dlerror()));
    }
    return virtual_enclave_handle;
  }

  inline void terminate_virtual_enclave(void* handle)
  {
    auto err = dlclose(handle);
    if (err != 0)
    {
      LOG_FAIL_FMT("Error while terminating virtual enclave: {}", dlerror());
    }
  }

  inline CreateNodeStatus virtual_create_node(
    void* virtual_enclave_handle,
    void* enclave_config,
    uint8_t* ccf_config,
    size_t ccf_config_size,
    uint8_t* startup_snapshot,
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
    ccf::LoggerLevel log_level,
    size_t num_worker_thread,
    void* time_location,
    const ccf::ds::WorkBeaconPtr& work_beacon)
  {
    using create_node_func_t = CreateNodeStatus (*)(
      void*,
      uint8_t*,
      size_t,
      uint8_t*,
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
      ccf::LoggerLevel,
      size_t,
      void*,
      const ccf::ds::WorkBeaconPtr&);

    static create_node_func_t create_node_func =
      get_enclave_exported_function<create_node_func_t>(
        virtual_enclave_handle, "enclave_create_node");

    CreateNodeStatus status = create_node_func(
      enclave_config,
      ccf_config,
      ccf_config_size,
      startup_snapshot,
      startup_snapshot_size,
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
      log_level,
      num_worker_thread,
      time_location,
      work_beacon);

    return status;
  }

  inline bool virtual_run(void* virtual_enclave_handle)
  {
    using run_func_t = bool (*)();

    static run_func_t run_func = get_enclave_exported_function<run_func_t>(
      virtual_enclave_handle, "enclave_run");

    bool retval = run_func();
    return retval;
  }

#ifdef __cplusplus
}
#endif
