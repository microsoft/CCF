// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <filesystem>

namespace indexing::caching
{
  struct HostCache
  {
    const std::filesystem::path root_dir = ".cache";

    ringbuffer::WriterPtr writer;

    HostCache(
      messaging::RingbufferDispatcher& disp, ringbuffer::WriterPtr&& w) :
      writer(w)
    {
      if (std::filesystem::is_directory(root_dir))
      {
        LOG_INFO_FMT("Clearing cache from existing directory {}", root_dir);
        std::filesystem::remove_all(root_dir);
      }

      if (!std::filesystem::create_directory(root_dir))
      {
        throw std::logic_error(
          fmt::format("Could not create cache directory: {}", root_dir));
      }

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, BlobMsg::store, [&](const uint8_t* data, size_t size) {
          auto [key, encrypted_blob] =
            ringbuffer::read_message<BlobMsg::store>(data, size);

          const auto blob_path = root_dir / key;
          std::ofstream f(blob_path, std::ios::trunc | std::ios::binary);
          f.write((char const*)encrypted_blob.data(), encrypted_blob.size());
          f.close();
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, BlobMsg::get, [&](const uint8_t* data, size_t size) {
          auto [key] = ringbuffer::read_message<BlobMsg::get>(data, size);

          const auto blob_path = root_dir / key;
          if (std::filesystem::is_regular_file(blob_path))
          {
            std::ifstream f(blob_path, std::ios::binary);
            f.seekg(0, f.end);
            const auto size = f.tellg();
            f.seekg(0, f.beg);

            EncryptedBlob blob(size);
            f.read((char*)blob.data(), blob.size());
            f.close();
            RINGBUFFER_WRITE_MESSAGE(BlobMsg::response, writer, key, blob);
          }
          else
          {
            RINGBUFFER_WRITE_MESSAGE(BlobMsg::not_found, writer, key);
          }
        });
    }
  };
}
