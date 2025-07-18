// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/version.h"
#include "enclave/interface.h"
#include "enclave/virtual_enclave.h"

#include <dlfcn.h>
#include <filesystem>

namespace host
{
  void expect_enclave_file_suffix(
    const std::string& file, char const* expected_suffix)
  {
    if (!file.ends_with(expected_suffix))
    {
      // Remove possible suffixes to try and get root of filename, to build
      // suggested filename
      auto basename = file;
      for (const char* suffix : {".signed", ".debuggable", ".so", ".enclave"})
      {
        if (basename.ends_with(suffix))
        {
          basename = basename.substr(0, basename.size() - strlen(suffix));
        }
      }
      const auto suggested = fmt::format("{}{}", basename, expected_suffix);
      throw std::logic_error(fmt::format(
        "Given enclave file '{}' does not have suffix expected.. Did you mean "
        "'{}'?",
        file,
        suggested));
    }
  }

  static std::pair<uint8_t*, size_t> allocate_8_aligned(size_t size)
  {
    const auto aligned_size = (size + 7) & ~(7ull);
    auto data = static_cast<uint8_t*>(std::aligned_alloc(8u, aligned_size));
    if (data == nullptr)
    {
      throw std::runtime_error(fmt::format(
        "Unable to allocate {} bytes for aligned data", aligned_size));
    }
    return std::make_pair(data, aligned_size);
  }

  /**
   * Wraps an oe_enclave and associated ECalls. New ECalls should be added as
   * methods which construct an appropriate EGeneric-derived param type and pass
   * it to call.
   */
  class Enclave
  {
  private:
    void* virtual_handle = nullptr;

  public:
    /**
     * Create an uninitialized enclave hosting the given library.
     *
     * @param path Path to library file
     */
    Enclave(const std::string& path)
    {
      if (!std::filesystem::exists(path))
      {
        throw std::logic_error(
          fmt::format("No enclave file found at {}", path));
      }

      switch (ccf::pal::platform)
      {
        case ccf::pal::Platform::SNP:
        case ccf::pal::Platform::Virtual:
        {
          expect_enclave_file_suffix(path, ".so");
          virtual_handle = load_virtual_enclave(path.c_str());
          break;
        }

        default:
        {
          throw std::logic_error(fmt::format(
            "Unsupported enclave type: {}",
            nlohmann::json(ccf::pal::platform).dump()));
        }
      }
    }

    ~Enclave()
    {
      if (virtual_handle != nullptr)
      {
        terminate_virtual_enclave(virtual_handle);
      }
    }

    CreateNodeStatus create_node(
      const EnclaveConfig& enclave_config,
      const ccf::StartupConfig& ccf_config,
      std::vector<uint8_t>&& startup_snapshot,
      std::vector<uint8_t>& node_cert,
      std::vector<uint8_t>& service_cert,
      StartType start_type,
      ccf::LoggerLevel log_level,
      size_t num_worker_thread,
      void* time_location,
      const ccf::ds::WorkBeaconPtr& work_beacon)
    {
      CreateNodeStatus status = CreateNodeStatus::InternalError;
      constexpr size_t enclave_version_size = 256;
      std::vector<uint8_t> enclave_version_buf(enclave_version_size);

      size_t node_cert_len = 0;
      size_t service_cert_len = 0;
      size_t enclave_version_len = 0;

      // Pad config and startup snapshot with NULLs to a multiple of 8, in an
      // 8-byte aligned allocation
      auto config_s = nlohmann::json(ccf_config).dump();

#define CREATE_NODE_ARGS \
  (void*)&enclave_config, (uint8_t*)config_s.data(), config_s.size(), \
    startup_snapshot.data(), startup_snapshot.size(), node_cert.data(), \
    node_cert.size(), &node_cert_len, service_cert.data(), \
    service_cert.size(), &service_cert_len, enclave_version_buf.data(), \
    enclave_version_buf.size(), &enclave_version_len, start_type, log_level, \
    num_worker_thread, time_location, work_beacon

      // Assume that constructor correctly set the appropriate field, and call
      // appropriate function
      if (virtual_handle != nullptr)
      {
        status = virtual_create_node(virtual_handle, CREATE_NODE_ARGS);
      }

      if (status != CreateNodeStatus::OK)
      {
        // Logs have described the errors already, we just need to allow the
        // host to read them (via read_all()).
        return status;
      }

      // Host and enclave versions must match. Otherwise the node may crash much
      // later (e.g. unhandled ring buffer message on either end)
      auto enclave_version = std::string(
        enclave_version_buf.begin(),
        enclave_version_buf.begin() + enclave_version_len);
      if (ccf::ccf_version != enclave_version)
      {
        LOG_FAIL_FMT(
          "Host/Enclave versions mismatch: {} != {}",
          ccf::ccf_version,
          enclave_version);
        return CreateNodeStatus::VersionMismatch;
      }

      node_cert.resize(node_cert_len);
      service_cert.resize(service_cert_len);

      return CreateNodeStatus::OK;
    }

    // Run a processor over this circuit inside the enclave - should be called
    // from a thread
    bool run()
    {
      bool ret = false;

      if (virtual_handle != nullptr)
      {
        ret = virtual_run(virtual_handle);
      }

      if (!ret)
      {
        throw std::logic_error(fmt::format("Failure in virtual_run"));
      }

      return ret;
    }
  };
}
