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
  class LedgerFile
  {
  private:
    size_t start_idx = 1;
    size_t total_len = 0;
    std::vector<size_t> positions;

    FILE* file;

  public:
    std::string get_file_name(FILE* f)
    {
      int fd = fileno(f);
      auto path = fmt::format("/proc/self/fd/{}", fd);
      char result[128];
      ::memset(result, 0, sizeof(result));
      readlink(path.c_str(), result, sizeof(result) - 1);

      return fs::path(result).filename();
    }

    LedgerFile() : {}
  };

  class MultipleLedger
  {
  private:
    static constexpr auto current_ledger = "ledger";
    static constexpr auto ledger_start_idx_delimiter = ".";
    static constexpr size_t frame_header_size = sizeof(uint32_t);

    ringbuffer::WriterPtr to_enclave;

    // Ledger directory
    const std::string ledger_dir;

    // This uses C stdio instead of fstream because an fstream
    // cannot be truncated.

    // Keep tracks of all ledger files. Current ledger file is always the last
    // one?
    // TODO: Use shared pointer instead?
    std::map<size_t, FILE*> files;

    // TODO: To be split per file
    std::vector<size_t> positions;
    const size_t chunk_threshold;

    FILE* file; // active chunk
    size_t start_idx = 1; // Start index on the active chunk
    size_t total_len = 0; // Length of the active chunk

    size_t get_start_idx(FILE* file)
    {
      auto file_name = get_file_name(file);

      auto pos = file_name.find(ledger_start_idx_delimiter);
      if (pos == std::string::npos)
      {
        throw std::logic_error(fmt::format(
          "Error: cannot find delimiter {} in file name {}",
          ledger_start_idx_delimiter,
          file_name));
      }
      return std::stoul(file_name.substr(pos + 1, file_name.size()));
    }

    void dump_files()
    {
      LOG_FAIL_FMT("****** Active files: ");
      for (auto const& f : files)
      {
        LOG_FAIL_FMT("{}: {}", f.first, get_file_name(f.second));
      }
      LOG_FAIL_FMT("******");
    }

  public:
    MultipleLedger(
      const std::string& ledger_dir,
      ringbuffer::AbstractWriterFactory& writer_factory,
      size_t chunk_threshold) :
      ledger_dir(ledger_dir),
      chunk_threshold(chunk_threshold),
      to_enclave(writer_factory.create_writer_to_inside())
    {
      if (chunk_threshold == 0)
      {
        throw std::logic_error(
          "Error: Cannot create ledger with chunk threshold of 0");
      }

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

      // First 8 bytes are reserved for the offset to the position table
      fseeko(file, sizeof(uint64_t), SEEK_SET);
      total_len = sizeof(uint64_t);
      files.emplace(1, file);

      LOG_INFO_FMT("File created");
    }

    MultipleLedger(const MultipleLedger& that) = delete;

    ~MultipleLedger()
    {
      for (auto const f : files)
      {
        fflush(f.second);
        fclose(f.second);
      }
    }

    size_t get_last_idx()
    {
      return positions.size();
    }

    size_t framed_entries_size(size_t from, size_t to)
    {
      LOG_TRACE_FMT(
        "fes: from {} -> to {} [start: {} - last: {}]",
        from,
        to,
        start_idx,
        start_idx + positions.size() - 1);

      if ((from == 0) || (to < from) || (to > start_idx + positions.size() - 1))
      {
        return 0;
      }

      // TODO: It might be much easier to record start_idx as (start_idx - 1)??
      if (to == (start_idx + positions.size() - 1))
      {
        LOG_TRACE_FMT(
          "here, total len {} - start {}",
          total_len,
          positions.at(from - start_idx));
        return total_len - positions.at(from - start_idx);
      }
      else
      {
        // TODO: This is not really tested for now
        // TODO: We need to access previous chunks here
        dump_files();

        // TODO: Handle entries over multiple chunks!! Hard!!

        // Find file with largest offset that is less than from
        auto search = std::upper_bound(
          files.rbegin(),
          files.rend(),
          from,
          [](size_t idx, std::pair<size_t, FILE*> v) {
            LOG_FAIL_FMT("{} >= {} ? {}", idx, v.first, (idx >= v.first));
            return idx >= v.first;
          });
        if (search == files.rend())
        {
          // TODO: Refine this
          throw std::logic_error(
            fmt::format("Could not find anything at {}", from));
        }

        LOG_FAIL_FMT(
          "Found file \"{}\" for {}", get_file_name(search->second), from);

        // TODO: Load file and positions within it
        if (search->second == files.rbegin()->second)
        {
          // TODO: This can be optimised: we know we can look up the last file
          // if from and to are within positions
          LOG_FAIL_FMT("Current file!");
          return positions.at(to - start_idx) - positions.at(from - start_idx);
        }
        else
        {
          size_t start_idx_ = get_start_idx(search->second);
          LOG_FAIL_FMT("Start idx is {}", start_idx_);

          // Load positions
          // First, get full size of file
          fseeko(search->second, 0, SEEK_END);
          size_t total_size = ftello(search->second);

          // Second, read offset at end of file
          fseeko(search->second, 0, SEEK_SET);
          size_t table_offset;
          if (
            fread(&table_offset, sizeof(table_offset), 1, search->second) != 1)
          {
            throw std::logic_error("Failed to read positions offset from file");
          }

          LOG_FAIL_FMT("table offset is {}", table_offset);

          // Finally, read positions
          fseeko(search->second, table_offset, SEEK_SET);

          std::vector<size_t> positions_;
          positions_.resize(
            (total_size - table_offset) / sizeof(positions_.at(0)));
          LOG_FAIL_FMT("len of positions_ is {}", positions_.size());

          if (
            fread(
              positions_.data(),
              sizeof(positions_.at(0)),
              positions_.size(),
              search->second) != positions_.size())
          {
            throw std::logic_error("Failed to read positions_ table from file");
          }

          for (auto const& p : positions_)
          {
            LOG_FAIL_FMT("Positions: {}", p);
          }

          return positions_.at() - positions_.()
        }
      }
    }

    size_t entry_size(size_t idx)
    {
      auto framed_size = framed_entries_size(idx, idx);

      return framed_size ? framed_size - frame_header_size : 0;
    }

    const std::vector<uint8_t> read_entry(size_t idx)
    {
      if ((idx == 0) || (idx > (start_idx + positions.size() - 1)))
      {
        return {};
      }

      auto len = entry_size(idx);
      std::vector<uint8_t> entry(len);
      fseeko(file, positions.at(idx - start_idx) + frame_header_size, SEEK_SET);

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

    // TODO: Only applies to latest chunk
    size_t write_entry(const uint8_t* data, size_t size, bool committable)
    {
      fseeko(file, total_len, SEEK_SET);
      positions.push_back(total_len);
      size_t new_idx = start_idx + positions.size() - 1;

      // LOG_DEBUG_FMT(
      //   "Ledger write {}: {} bytes. Signature {}",
      //   positions.size(),
      //   size,
      //   committable);

      uint32_t frame = (uint32_t)size;
      if (fwrite(&frame, frame_header_size, 1, file) != 1)
      {
        throw std::logic_error("Failed to write entry header to ledger");
      }

      if (fwrite(data, size, 1, file) != 1)
      {
        throw std::logic_error("Failed to write entry to ledger");
      }

      total_len +=
        (size + frame_header_size); // TODO: Not sure we still need this

      LOG_FAIL_FMT(
        "[{}] Size of current chunk, from {} to {}, is {}",
        committable,
        start_idx,
        new_idx,
        total_len);

      auto chunk_size = framed_entries_size(start_idx, new_idx);
      LOG_FAIL_FMT("entry size so far: {}", chunk_size);

      if (committable && chunk_size >= chunk_threshold)
      {
        LOG_FAIL_FMT(
          ">>>>> Creating new chunk which will start at {}, positions size of "
          "{}",
          new_idx + 1,
          positions.size());

        size_t table_offset = ftello(file);
        // TODO: Retry if didn't write everything
        if (
          fwrite(
            reinterpret_cast<uint8_t*>(positions.data()),
            sizeof(positions.at(0)),
            positions.size(),
            file) != positions.size())
        {
          throw std::logic_error("Failed to write positions table to ledger");
        }

        // Write positions table offset at start of file
        if (fseeko(file, 0, SEEK_SET) != 0)
        {
          throw std::logic_error("Failed to set file offset to 0");
        }

        if (fwrite(&table_offset, sizeof(table_offset), 1, file) != 1)
        {
          throw std::logic_error("Failed to write positions table to ledger");
        }

        fs::rename(
          fs::path(ledger_dir) / fs::path(current_ledger),
          fs::path(ledger_dir) /
            fs::path(fmt::format("{}.{}", current_ledger, start_idx)));

        start_idx = new_idx + 1;
        positions.clear();
        total_len = sizeof(uint64_t);

        FILE* new_file = fopen(
          (fs::path(ledger_dir) / fs::path(current_ledger)).c_str(), "w+b");
        fseeko(new_file, sizeof(uint64_t), SEEK_SET);

        // files.emplace_back(new_file);
        files.emplace(start_idx, new_file);

        file = new_file;
      }

      return new_idx;
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