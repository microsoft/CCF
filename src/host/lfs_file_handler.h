// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/messaging.h"
#include "indexing/lfs_ringbuffer_types.h"

#include <filesystem>
#include <fstream>

namespace asynchost
{
  struct LFSFileHandler
  {
    const std::filesystem::path root_dir = ".index";

    ringbuffer::WriterPtr writer;

    LFSFileHandler(ringbuffer::WriterPtr&& w) : writer(w)
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
    }

    void register_message_handlers(messaging::RingbufferDispatcher& disp)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        disp,
        ccf::indexing::LFSMsg::store,
        [&](const uint8_t* data, size_t size) {
          auto [key, encrypted] =
            ringbuffer::read_message<ccf::indexing::LFSMsg::store>(data, size);

          const auto target_path = root_dir / key;
          std::ofstream f(target_path, std::ios::trunc | std::ios::binary);
          LOG_TRACE_FMT(
            "Writing {} byte file to {}", encrypted.size(), target_path);
          f.write(
            reinterpret_cast<char const*>(encrypted.data()), encrypted.size());
          f.close();
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp,
        ccf::indexing::LFSMsg::get,
        [&](const uint8_t* data, size_t size) {
          auto [key] =
            ringbuffer::read_message<ccf::indexing::LFSMsg::get>(data, size);

          const auto target_path = root_dir / key;
          if (std::filesystem::is_regular_file(target_path))
          {
            std::ifstream f(target_path, std::ios::binary);
            f.seekg(0, f.end);
            const auto file_size = f.tellg();
            LOG_TRACE_FMT(
              "Reading {} byte file from {}",
              static_cast<size_t>(file_size),
              target_path);
            f.seekg(0, f.beg);

            ccf::indexing::LFSEncryptedContents blob(file_size);
            f.read(reinterpret_cast<char*>(blob.data()), blob.size());
            f.close();
            RINGBUFFER_WRITE_MESSAGE(
              ccf::indexing::LFSMsg::response, writer, key, blob);
          }
          else
          {
            LOG_TRACE_FMT("File {} not found", target_path);
            RINGBUFFER_WRITE_MESSAGE(
              ccf::indexing::LFSMsg::not_found, writer, key);
          }
        });
    }
  };
}
