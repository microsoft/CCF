// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "ds/logger.h"
#include "ds/messaging.h"

// TODO: Check which includes are necessary
#include <cstdint>
#include <cstdio>
#include <errno.h> // TODO: Use this for better error messages
#include <filesystem>
#include <list>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;

namespace asynchost
{
  static constexpr auto ledger_final_indicator_delimiter = ".final";

  static inline bool is_ledger_file_complete(const std::string& file_name)
  {
    auto pos = file_name.find(ledger_final_indicator_delimiter);
    return !(pos == std::string::npos);
  }

  // TODO: Unit test this class on its own (probably similar to existing tests)
  class LedgerFile
  {
  private:
    using positions_offset_header_t = size_t;

    static constexpr auto file_name_prefix = "ledger";
    static constexpr auto ledger_start_idx_delimiter = "_";

    static constexpr size_t frame_header_size = sizeof(uint32_t);

    const std::string dir;

    size_t start_idx = 1;
    size_t total_len = 0;
    std::vector<size_t>
      positions; // TODO: Should this be uint32_t as this
                 // makes the positions table big at the end of the file?

    // This uses C stdio instead of fstream because an fstream
    // cannot be truncated.
    FILE* file;
    bool prepared = false;
    bool complete = false;

  public:
    LedgerFile(const std::string& dir, size_t start_idx = 1) :
      dir(dir),
      start_idx(start_idx)
    {
      file = fopen(
        (fs::path(dir) /
         fs::path(fmt::format("{}_{}", file_name_prefix, start_idx)))
          .c_str(),
        "w+b");

      // Header reserved for the offset to the position table
      fseeko(file, sizeof(positions_offset_header_t), SEEK_SET);
      total_len = sizeof(positions_offset_header_t);
    }

    LedgerFile(const std::string& dir, const std::string& file_name) : dir(dir)
    {
      auto full_path = (fs::path(dir) / fs::path(file_name));
      file = fopen(full_path.c_str(), "r+b");
      if (!file)
      {
        throw std::logic_error(
          fmt::format("Unable to open ledger file {}", full_path));
      }

      complete = is_ledger_file_complete(file_name);

      auto pos = file_name.find(ledger_start_idx_delimiter);
      if (pos == std::string::npos)
      {
        throw std::logic_error(fmt::format(
          "Ledger file name {} does not contain a start idx", full_path));
      }

      start_idx = std::stol(file_name.substr(pos + 1));

      // First, get full size of file
      fseeko(file, 0, SEEK_END);
      size_t total_file_size = ftello(file);

      // Second, read offset to header table
      fseeko(file, 0, SEEK_SET);
      positions_offset_header_t table_offset;
      if (fread(&table_offset, sizeof(positions_offset_header_t), 1, file) != 1)
      {
        throw std::logic_error(fmt::format(
          "Failed to read positions offset from ledger file {}", full_path));
      }

      if (table_offset != 0)
      {
        // If the chunk was finalised, read positions table from file directly
        total_len = table_offset;
        fseeko(file, table_offset, SEEK_SET);

        positions.resize(
          (total_file_size - table_offset) / sizeof(positions.at(0)));

        if (
          fread(
            positions.data(),
            sizeof(positions.at(0)),
            positions.size(),
            file) != positions.size())
        {
          throw std::logic_error(fmt::format(
            "Failed to read positions table from ledger file {}", full_path));
        }
      }
      else
      {
        // If the chunk was not finalised, read all entries to reconstruct
        // positions table
        total_len = total_file_size;

        auto len = total_len - sizeof(positions_offset_header_t);
        size_t pos = sizeof(positions_offset_header_t);
        uint32_t entry_size = 0;

        while (len >= frame_header_size)
        {
          if (fread(&entry_size, frame_header_size, 1, file) != 1)
          {
            throw std::logic_error(fmt::format(
              "Failed to read frame from ledger file {}", full_path));
          }

          len -= frame_header_size;

          if (len < entry_size)
          {
            throw std::logic_error(
              fmt::format("Malformed ledger file {}", full_path));
          }

          fseeko(file, entry_size, SEEK_CUR);
          len -= entry_size;

          positions.push_back(pos);
          pos += (entry_size + frame_header_size);
        }
      }
    }

    ~LedgerFile()
    {
      LOG_INFO_FMT("File {} closed", get_file_name());
      fflush(file);
      fclose(file);
    }

    std::string get_file_name() const
    {
      int fd = fileno(file);
      auto path = fmt::format("/proc/self/fd/{}", fd);
      char result[1024];
      ::memset(result, 0, sizeof(result));
      readlink(path.c_str(), result, sizeof(result) - 1);

      return fs::path(result).filename();
    }

    size_t get_start_idx() const
    {
      return start_idx;
    }

    size_t get_last_idx() const
    {
      return start_idx + positions.size() - 1;
    }

    size_t get_current_size() const
    {
      return total_len;
    }

    bool is_complete() const
    {
      return complete;
    }

    size_t write_entry(const uint8_t* data, size_t size)
    {
      fseeko(file, total_len, SEEK_SET);
      positions.push_back(total_len);
      size_t new_idx = start_idx + positions.size() - 1;

      uint32_t frame = (uint32_t)size;
      if (fwrite(&frame, frame_header_size, 1, file) != 1)
      {
        throw std::logic_error("Failed to write entry header to ledger");
      }

      if (fwrite(data, size, 1, file) != 1)
      {
        throw std::logic_error("Failed to write entry to ledger");
      }

      total_len += (size + frame_header_size);

      return new_idx;
    }

    size_t framed_entries_size(size_t from, size_t to) const
    {
      LOG_TRACE_FMT(
        "fes: from {} -> to {} [start: {} - last: {}]",
        from,
        to,
        start_idx,
        start_idx + positions.size() - 1);

      if ((from < start_idx) || (to < from) || (to > get_last_idx()))
      {
        return 0;
      }

      if (to == get_last_idx())
      {
        return total_len - positions.at(from - start_idx);
      }
      else
      {
        return positions.at(to - start_idx + 1) -
          positions.at(from - start_idx);
      }
    }

    size_t entry_size(size_t idx) const
    {
      auto framed_size = framed_entries_size(idx, idx);
      return (framed_size != 0) ? framed_size - frame_header_size : 0;
    }

    const std::vector<uint8_t> read_entry(size_t idx) const
    {
      if ((idx < start_idx) || (idx > get_last_idx()))
      {
        LOG_FAIL_FMT("Unknown entry idx: {}", idx);
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

    const std::vector<uint8_t> read_framed_entries(size_t from, size_t to) const
    {
      if ((from < start_idx) || (to > get_last_idx()))
      {
        LOG_FAIL_FMT("Unknown entries range: {} - {}", from, to);
        return {};
      }

      auto framed_size = framed_entries_size(from, to);
      std::vector<uint8_t> framed_entries(framed_size);
      fseeko(file, positions.at(from - start_idx), SEEK_SET);

      if (fread(framed_entries.data(), framed_size, 1, file) != 1)
      {
        throw std::logic_error(fmt::format(
          "Failed to read entry range {} - {} from file", from, to));
      }

      return framed_entries;
    }

    bool truncate(size_t idx)
    {
      if (complete || (idx < start_idx - 1) || (idx >= get_last_idx()))
      {
        return false;
      }

      LOG_FAIL_FMT("Truncating {} at {}", get_file_name(), idx);

      if (idx == start_idx - 1)
      {
        // Truncating everything triggers file deletion
        if (!fs::remove(fs::path(dir) / fs::path(get_file_name())))
        {
          throw std::logic_error(
            fmt::format("Could not remove file {}", get_file_name()));
        }
        return true;
      }

      // TODO: Only if prepared??

      // Reset positions offset header
      fseeko(file, 0, SEEK_SET);
      positions_offset_header_t table_offset = 0;
      if (fwrite(&table_offset, sizeof(table_offset), 1, file) != 1)
      {
        throw std::logic_error("Failed to reset positions table offset");
      }

      prepared = false;
      total_len = positions.at(idx - start_idx + 1);
      positions.resize(idx - start_idx + 1);

      if (fflush(file) != 0)
      {
        throw std::logic_error(fmt::format(
          "Failed to flush active ledger: {}",
          strerror(errno))); // TODO: Use strerror everywhere or explain_...()?
      }

      if (ftruncate(fileno(file), total_len))
      {
        throw std::logic_error("Failed to truncate ledger");
      }

      fseeko(file, total_len, SEEK_SET);
      return false;
    }

    void prepare()
    {
      if (prepared)
      {
        return;
      }

      fseeko(file, total_len, SEEK_SET);
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

      if (fflush(file) != 0)
      {
        throw std::logic_error(fmt::format(
          "Failed to flush active ledger: {}",
          strerror(errno))); // TODO: Use strerror everywhere or explain_...()?
      }

      prepared = true;
    }

    void compact(size_t idx)
    {
      if (
        !prepared || complete || (idx < get_last_idx()) ||
        (idx > get_last_idx()))
      {
        return;
      }

      LOG_DEBUG_FMT("Compacting file at {}", idx);

      if (fflush(file) != 0)
      {
        throw std::logic_error(fmt::format(
          "Failed to flush active ledger: {}",
          strerror(errno))); // TODO: Use strerror everywhere or explain_...()?
      }

      fs::rename(
        fs::path(dir) / fs::path(get_file_name()),
        fs::path(dir) / fs::path(fmt::format("{}.final", get_file_name())));

      complete = true;
    }
  };

  // TODO: Test with 4 GB files!!!
  class MultipleLedger
  {
  private:
    ringbuffer::WriterPtr to_enclave;

    // Ledger directory
    const std::string ledger_dir;

    // Keep tracks of all ledger files. Current ledger file is always the last
    // one?
    // TODO: Might change once there is a cache
    std::list<std::shared_ptr<LedgerFile>> files;

    const size_t chunk_threshold;
    size_t last_idx = 0;
    size_t compacted_idx = 0;

    // TODO: Delete when necessary
    void dump_files() const
    {
      LOG_FAIL_FMT("****** Active files: ");
      for (auto const& f : files)
      {
        LOG_FAIL_FMT(
          "{} -> {}: {}",
          f->get_file_name(),
          f->get_start_idx(),
          f->get_last_idx());
      }
      LOG_FAIL_FMT("******");
    }

    auto get_it_contains_idx(size_t idx) const
    {
      if (idx == 0)
      {
        return files.end();
      }

      auto f = std::upper_bound(
        files.begin(),
        files.end(),
        idx,
        [](size_t idx, const std::shared_ptr<LedgerFile>& f) {
          return (idx <= f->get_last_idx());
        });

      return f;
    }

    std::shared_ptr<LedgerFile> find_ledger_containing_idx(size_t idx) const
    {
      auto it = get_it_contains_idx(idx);

      // If idx is not known (i.e. in the future), the first ledger file is
      // returned, which will not contain idx
      return ((it == files.end()) ? *files.begin() : *it);
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

      if (fs::is_directory(ledger_dir))
      {
        for (auto const& f : fs::directory_iterator(ledger_dir))
        {
          LOG_FAIL_FMT("Restore, {}", f.path().string());

          files.push_back(std::make_shared<LedgerFile>(
            f.path().parent_path(), f.path().filename()));
        }

        // TODO: Perhaps using a different struct (e.g. unordered map) might
        // help here. The caching strategy will solve this.
        files.sort([](
                     const std::shared_ptr<LedgerFile>& a,
                     const std::shared_ptr<LedgerFile>& b) {
          return a->get_last_idx() < b->get_last_idx();
        });
        dump_files();

        // TODO: Early fail if the ledger idx don't follow each other!!

        for (auto const& f : files)
        {
          if (f->is_complete())
          {
            compacted_idx = f->get_last_idx();
          }
        }
        last_idx = get_latest_file()->get_last_idx();
      }
      else
      {
        if (!fs::create_directory(ledger_dir))
        {
          throw std::logic_error(fmt::format(
            "Error: Could not create ledger directory: {}", ledger_dir));
        }

        files.push_back(std::make_shared<LedgerFile>(ledger_dir));
      }
    }

    MultipleLedger(const MultipleLedger& that) = delete;

    std::shared_ptr<LedgerFile> get_latest_file() const
    {
      if (files.empty())
      {
        return nullptr;
      }
      return *(files.rbegin()++);
    }

    const std::vector<uint8_t> read_entry(size_t idx) const
    {
      return find_ledger_containing_idx(idx)->read_entry(idx);
    }

    const std::vector<uint8_t> read_framed_entries(size_t from, size_t to) const
    {
      if ((from < 0) || (to > last_idx))
      {
        return {};
      }

      auto f_from = get_it_contains_idx(from);
      auto f_to = get_it_contains_idx(to);

      if ((f_from == files.end()) || (f_to == files.end()))
      {
        return {};
      }

      std::vector<std::vector<uint8_t>> entries;
      entries.reserve(std::distance(f_from, f_to) + 1);

      if (f_from == f_to)
      {
        // If the framed entries are only read over one chunk, read framed
        // entries from that chunk and return
        entries.emplace_back((*f_from)->read_framed_entries(from, to));
        return entries.at(0);
      }

      for (auto it = f_from; it != std::next(f_to); it++)
      {
        if (it == f_from)
        {
          entries.emplace_back(
            (*it)->read_framed_entries(from, (*it)->get_last_idx()));
        }
        else if (it == f_to)
        {
          entries.emplace_back(
            (*it)->read_framed_entries((*it)->get_start_idx(), to));
        }
        else
        {
          entries.emplace_back((*it)->read_framed_entries(
            (*it)->get_start_idx(), (*it)->get_last_idx()));
        }
      }

      size_t total_size = 0;
      for (auto const& e : entries)
      {
        total_size += e.size();
      }

      std::vector<uint8_t> flatten_vector;
      flatten_vector.reserve(total_size);

      for (auto const& e : entries)
      {
        flatten_vector.insert(
          flatten_vector.end(),
          std::make_move_iterator(e.begin()),
          std::make_move_iterator(e.end()));
      }

      return flatten_vector;
    }

    size_t write_entry(const uint8_t* data, size_t size, bool committable)
    {
      auto f = get_latest_file();
      if (f == nullptr)
      {
        f = std::make_shared<LedgerFile>(ledger_dir);
        files.push_back(f);
      }

      if (committable && f->get_current_size() >= chunk_threshold)
      {
        f->prepare();

        LOG_FAIL_FMT(
          ">>>>> Creating new chunk which will start at {}", last_idx + 1);

        files.push_back(std::make_shared<LedgerFile>(ledger_dir, last_idx + 1));
      }

      last_idx = get_latest_file()->write_entry(data, size);

      // LOG_FAIL_FMT(
      //   "[{}] Size of current chunk, from {} to {}, is {}",
      //   committable,
      //   f->get_start_idx(),
      //   new_idx,
      //   f->get_current_size());

      return last_idx;
    }

    void truncate(size_t idx)
    {
      LOG_DEBUG_FMT("Ledger truncate: {}/{}", idx, last_idx);

      if (idx >= last_idx || idx < compacted_idx)
      {
        return;
      }

      auto f_from = get_it_contains_idx(idx + 1);
      auto f_to = get_it_contains_idx(last_idx);
      LOG_FAIL_FMT("Number of ledgers: {}", std::distance(f_from, f_to) + 1);

      for (auto it = f_from; it != std::next(f_to);)
      {
        // Truncate the first file to the truncation index while the more recent
        // files are deleted entirely
        auto truncate_idx = (it == f_from) ? idx : (*it)->get_start_idx() - 1;
        LOG_FAIL_FMT("Truncate idx: {}", truncate_idx);
        if ((*it)->truncate(truncate_idx))
        {
          auto it_ = it;
          it++;
          files.erase(it_);
        }
        else
        {
          it++;
        }
      }

      last_idx = idx;
    }

    void compact(size_t idx)
    {
      LOG_DEBUG_FMT("Ledger compact: {}/{}", idx, last_idx);

      if (idx <= compacted_idx)
      {
        return;
      }

      auto f_from = (compacted_idx == 0) ? get_it_contains_idx(1) :
                                           get_it_contains_idx(compacted_idx);
      auto f_to = get_it_contains_idx(idx);
      LOG_FAIL_FMT("Number of ledgers: {}", std::distance(f_from, f_to) + 1);

      for (auto it = f_from; it != std::next(f_to);)
      {
        // Compact all historical files to their latest index while the latest
        // file is compacted to the compaction index
        auto compact_idx = (it == f_to) ? idx : (*it)->get_last_idx();
        (*it)->compact(compact_idx);

        it++;
      }

      compacted_idx = idx;
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
          truncate(idx);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp,
        consensus::ledger_compact,
        [this](const uint8_t* data, size_t size) {
          auto idx = serialized::read<consensus::Index>(data, size);
          compact(idx);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, consensus::ledger_get, [&](const uint8_t* data, size_t size) {
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