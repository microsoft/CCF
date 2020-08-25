// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>

namespace fs = std::filesystem;

namespace asynchost
{
  class SnapshotManager
  {
  private:
    const std::string snapshot_dir;
    static constexpr auto snapshot_file_prefix = "snapshot";

    void write_snapshot(
      consensus::Index idx, const uint8_t* snapshot_data, size_t snapshot_size)
    {
      auto snapshot_file_name = fmt::format("{}.{}", snapshot_file_prefix, idx);
      auto full_snapshot_path =
        fs::path(snapshot_dir) / fs::path(snapshot_file_name);

      if (fs::exists(full_snapshot_path))
      {
        throw std::logic_error(fmt::format(
          "Cannot write snapshot at {} since file already exists: {}",
          idx,
          full_snapshot_path));
      }

      LOG_INFO_FMT(
        "Writing new snapshot to {} [{}]", snapshot_file_name, snapshot_size);

      std::ofstream snapshot_file(
        full_snapshot_path, std::ios::out | std::ios::binary);
      snapshot_file.write(
        reinterpret_cast<const char*>(snapshot_data), snapshot_size);
    }

  public:
    SnapshotManager(const std::string& snapshot_dir_) :
      snapshot_dir(snapshot_dir_)
    {
      if (fs::is_directory(snapshot_dir))
      {
        LOG_INFO_FMT(
          "Snapshots will be stored in existing directory: {}", snapshot_dir);
      }
      else if (!fs::create_directory(snapshot_dir))
      {
        throw std::logic_error(fmt::format(
          "Error: Could not create snapshot directory: {}", snapshot_dir));
      }
    }

    std::optional<std::string> find_latest_snapshot()
    {
      std::optional<std::string> snapshot_file = std::nullopt;
      size_t latest_idx = 0;

      for (auto& f : fs::directory_iterator(snapshot_dir))
      {
        auto file_name = f.path().filename().string();
        auto pos = file_name.find(fmt::format("{}.", snapshot_file_prefix));
        if (pos == std::string::npos)
        {
          LOG_FAIL_FMT("File {} does not appear to be a snapshot", file_name);
          continue;
        }

        pos = file_name.find(".");
        size_t snapshot_idx = std::stol(file_name.substr(pos + 1));
        if (snapshot_idx > latest_idx)
        {
          snapshot_file = f.path().string();
          latest_idx = snapshot_idx;
        }
      }

      return snapshot_file;
    }

    void register_message_handlers(
      messaging::Dispatcher<ringbuffer::Message>& disp)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        disp,
        consensus::ledger_snapshot,
        [this](const uint8_t* data, size_t size) {
          auto idx = serialized::read<consensus::Index>(data, size);

          write_snapshot(idx, data, size);
        });
    }
  };
}