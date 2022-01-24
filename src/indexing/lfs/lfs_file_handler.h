// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/indexing/lfs_types.h"

#include <filesystem>

namespace ccf::indexing
{
  struct LFSFileHandler
  {
    const std::filesystem::path root_dir = ".ccf_lfs";

    ringbuffer::WriterPtr writer;

    LFSFileHandler(
      messaging::RingbufferDispatcher& disp, ringbuffer::WriterPtr&& w) :
      writer(w)
    {
      if (std::filesystem::is_directory(root_dir))
      {
        LOG_INFO_FMT("Clearing contents from existing directory {}", root_dir);
        std::filesystem::remove_all(root_dir);
      }

      if (!std::filesystem::create_directory(root_dir))
      {
        throw std::logic_error(
          fmt::format("Could not create directory: {}", root_dir));
      }

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, LFSMsg::store, [&](const uint8_t* data, size_t size) {
          auto [key, encrypted] =
            ringbuffer::read_message<LFSMsg::store>(data, size);

          const auto target_path = root_dir / key;
          std::ofstream f(target_path, std::ios::trunc | std::ios::binary);
          LOG_TRACE_FMT(
            "Writing {} byte file to {}", encrypted.size(), target_path);
          f.write((char const*)encrypted.data(), encrypted.size());
          f.close();
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, LFSMsg::get, [&](const uint8_t* data, size_t size) {
          auto [key] = ringbuffer::read_message<LFSMsg::get>(data, size);

          const auto target_path = root_dir / key;
          if (std::filesystem::is_regular_file(target_path))
          {
            std::ifstream f(target_path, std::ios::binary);
            f.seekg(0, f.end);
            const auto size = f.tellg();
            LOG_TRACE_FMT("Reading {} byte file from {}", size, target_path);
            f.seekg(0, f.beg);

            LFSEncryptedContents blob(size);
            f.read((char*)blob.data(), blob.size());
            f.close();
            RINGBUFFER_WRITE_MESSAGE(LFSMsg::response, writer, key, blob);
          }
          else
          {
            LOG_TRACE_FMT("File {} not found", target_path);
            RINGBUFFER_WRITE_MESSAGE(LFSMsg::not_found, writer, key);
          }
        });
    }
  };
}
