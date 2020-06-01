// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "ds/logger.h"
#include "ds/messaging.h"

#include <cstdint>
#include <cstdio>
#include <errno.h>
#include <filesystem>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;

namespace asynchost
{
  class MultipleLedger
  {
  private:
    static constexpr auto current_ledger = "ledger";
    static constexpr size_t frame_header_size = sizeof(uint32_t);

    ringbuffer::WriterPtr to_enclave;

    // Ledger directory
    const std::string ledger_dir;

    // This uses C stdio instead of fstream because an fstream
    // cannot be truncated.

    // Keep tracks of all ledger files. Current ledger file is always the last
    // one?
    // TODO: Use shared pointer instead?
    std::vector<FILE*> files;

    // TODO: To be split per file
    std::vector<size_t> positions;
    const size_t chunk_threshold;

    FILE* file; // active chunk
    size_t start_idx = 1; // Start index on the active chunk
    size_t total_len = 0; // Length of the active chunk

  public:
    MultipleLedger(
      const std::string& ledger_dir,
      ringbuffer::AbstractWriterFactory& writer_factory,
      size_t chunk_threshold) :
      ledger_dir(ledger_dir),
      chunk_threshold(chunk_threshold),
      to_enclave(writer_factory.create_writer_to_inside())
    {
      // For now, enforce that the ledger directory is empty on startup
      if (fs::is_directory(ledger_dir))
      {
        throw std::logic_error(
          fmt::format("Error: Ledger directory {} already exists", ledger_dir));
      }

      if (!fs::create_directory(ledger_dir))
      {
        throw std::logic_error(fmt::format(
          "Error: Could not create ledger directory: {}", ledger_dir));
      }

      file =
        fopen((fs::path(ledger_dir) / fs::path(current_ledger)).c_str(), "w+b");
      fseeko(file, 0, SEEK_SET);
      files.emplace_back(file);

      // TODO: Reserve offset

      LOG_INFO_FMT("File created");
    }

    MultipleLedger(const MultipleLedger& that) = delete;

    ~MultipleLedger()
    {
      for (auto const f : files)
      {
        fflush(f);
        fclose(f);
      }
    }

    size_t get_last_idx()
    {
      return positions.size();
    }

    const std::vector<uint8_t> read_entry(size_t idx)
    {
      if ((idx == 0) || (idx > positions.size()))
        return {};

      auto len = entry_size(idx);
      std::vector<uint8_t> entry(len);
      fseeko(file, positions.at(idx - 1) + frame_header_size, SEEK_SET);

      if (fread(entry.data(), len, 1, file) != 1)
      {
        throw std::logic_error(
          fmt::format("Failed to read entry {} from file", idx));
      }

      return entry;
    }

    const std::vector<uint8_t> read_framed_entries(size_t from, size_t to)
    {
      auto framed_size = framed_entries_size(from, to);

      LOG_DEBUG_FMT(
        "Ledger read entries from {} to {}, size: {}", from, to, framed_size);

      std::vector<uint8_t> framed_entries(framed_size);
      if (framed_size == 0)
        return framed_entries;

      fseeko(file, positions.at(from - 1), SEEK_SET);

      if (fread(framed_entries.data(), framed_size, 1, file) != 1)
      {
        throw std::logic_error(fmt::format(
          "Failed to read entries from {} to {} from file", from, to));
      }

      return framed_entries;
    }

    size_t framed_entries_size(size_t from, size_t to)
    {
      if ((from == 0) || (to < from) || (to > positions.size()))
        return 0;

      if (to == positions.size())
      {
        return total_len - positions.at(from - 1);
      }
      else
      {
        return positions.at(to) - positions.at(from - 1);
      }
    }

    size_t entry_size(size_t idx)
    {
      auto framed_size = framed_entries_size(idx, idx);

      return framed_size ? framed_size - frame_header_size : 0;
    }

    // TODO: Only applies to latest chunk
    void write_entry(const uint8_t* data, size_t size, bool committable)
    {
      fseeko(file, total_len, SEEK_SET);
      positions.push_back(total_len);

      // LOG_DEBUG_FMT(
      //   "Ledger write {}: {} bytes. Signature {}",
      //   positions.size(),
      //   size,
      //   committable);

      uint32_t frame = (uint32_t)size;
      total_len += (size + frame_header_size);

      if (fwrite(&frame, frame_header_size, 1, file) != 1)
      {
        throw std::logic_error("Failed to write entry header to ledger");
      }

      if (fwrite(data, size, 1, file) != 1)
      {
        throw std::logic_error("Failed to write entry to ledger");
      }

      LOG_FAIL_FMT(
        "Size of current chunk is {}",
        framed_entries_size(start_idx, positions.size()));

      if (
        committable &&
        framed_entries_size(start_idx, positions.size()) >= chunk_threshold)
      {
        LOG_FAIL_FMT("Creating new chunk at {}", positions.size());

        // TODO:
        // 1. Rename existing file
        // 2. Write offset and positions table
        // 3. Create new file
        // 4. New file becomes current

        fs::rename(
          fs::path(ledger_dir) / fs::path(current_ledger),
          fs::path(ledger_dir) /
            fs::path(fmt::format("{}.{}", current_ledger, start_idx)));

        start_idx = positions.size() + 1;

        // TODO: Write offset and positions table

        FILE* new_file = fopen(
          (fs::path(ledger_dir) / fs::path(current_ledger)).c_str(), "w+b");
        files.emplace_back(new_file);

        file = new_file;
        fseeko(file, 0, SEEK_SET);
      }
    }

    void truncate(size_t last_idx)
    {
      LOG_DEBUG_FMT("Ledger truncate: {}/{}", last_idx, positions.size());

      // positions[last_idx - 1] is the position of the specified
      // final index. Truncate the ledger at position[last_idx].
      if (last_idx >= positions.size())
      {
        LOG_FAIL_FMT(
          "Cannot truncate active ledger at {}: active ledger ends at {}",
          last_idx,
          start_idx);
        return;
      }

      total_len = positions.at(last_idx);
      positions.resize(last_idx);

      if (fflush(file) != 0)
      {
        throw std::logic_error(
          fmt::format("Failed to flush active ledger: {}", strerror(errno)));
      }

      if (ftruncate(fileno(file), total_len))
      {
        throw std::logic_error("Failed to truncate ledger");
      }

      fseeko(file, total_len, SEEK_SET);
    }

    void register_message_handlers(
      messaging::Dispatcher<ringbuffer::Message>& disp)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        disp,
        consensus::ledger_append,
        [this](const uint8_t* data, size_t size) {
          auto committable = serialized::read<bool>(data, size);
          write_entry(data, size, committable);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp,
        consensus::ledger_truncate,
        [this](const uint8_t* data, size_t size) {
          auto idx = serialized::read<consensus::Index>(data, size);

          // TODO: This has to become more complex to handle truncation over a
          // collection of ledger files
          truncate(idx);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp,
        consensus::ledger_compact,
        [this](const uint8_t* data, size_t size) {
          auto idx = serialized::read<consensus::Index>(data, size);
          LOG_FAIL_FMT("Compacting ledger at {}", idx);

          size_t chunk_size = framed_entries_size(start_idx, idx);
          LOG_FAIL_FMT(
            "Size of last chunk: {}/{}", chunk_size, chunk_threshold);

          if (chunk_size > chunk_threshold)
          {
            // archive_chunk(idx);
          }
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, consensus::ledger_get, [&](const uint8_t* data, size_t size) {
          // The enclave has asked for a ledger entry.
          auto [idx] =
            ringbuffer::read_message<consensus::ledger_get>(data, size);

          auto& entry = read_entry(idx);

          if (entry.size() > 0)
          {
            RINGBUFFER_WRITE_MESSAGE(
              consensus::ledger_entry, to_enclave, entry);
          }
          else
          {
            RINGBUFFER_WRITE_MESSAGE(consensus::ledger_no_entry, to_enclave);
          }
        });
    }
  };
}