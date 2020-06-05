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
  // TODO: Unit test this class on its own (probably similar to existing tests)
  class LedgerFile
  {
  private:
    static constexpr auto file_name_prefix = "ledger";
    static constexpr auto ledger_start_idx_delimiter = ".";
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
    bool is_complete = false;

  public:
    LedgerFile(const std::string& dir, size_t start_idx = 1) :
      dir(dir),
      start_idx(start_idx)
    {
      file = fopen((fs::path(dir) / fs::path(file_name_prefix)).c_str(), "w+b");

      // First 8 bytes are reserved for the offset to the position table
      fseeko(file, sizeof(uint64_t), SEEK_SET);
      total_len = sizeof(uint64_t);

      LOG_INFO_FMT("File {} created", get_file_name());
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
      char result[128];
      ::memset(result, 0, sizeof(result));
      readlink(path.c_str(), result, sizeof(result) - 1);

      return fs::path(result).filename();
    }

    size_t get_start_idx() const
    {
      // auto file_name = get_file_name();
      // auto pos = file_name.find(ledger_start_idx_delimiter);
      // if (pos == std::string::npos)
      // {
      //   throw std::logic_error(fmt::format(
      //     "Error: cannot find delimiter {} in file name {}",
      //     ledger_start_idx_delimiter,
      //     file_name));
      // }
      // return std::stoul(file_name.substr(pos + 1, file_name.size()));
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

    size_t write_entry(const uint8_t* data, size_t size)
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
        LOG_TRACE_FMT(
          "here, total len {} - start {}",
          total_len,
          positions.at(from - start_idx));

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
      return framed_size ? framed_size - frame_header_size : 0;
    }

    const std::vector<uint8_t> read_entry(size_t idx) const
    {
      if ((idx < start_idx) || (idx > get_last_idx()))
      {
        LOG_FAIL_FMT("Unknown entry!");
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
        LOG_FAIL_FMT("Unknown entries range!");
        return {};
      }

      auto framed_size = framed_entries_size(from, to);
      std::vector<uint8_t> framed_entries(framed_size);
      fseeko(file, positions.at(from - start_idx), SEEK_SET);

      if (fread(framed_entries.data(), framed_size, 1, file) != 1)
      {
        throw std::logic_error(
          fmt::format("Failed to read entry range {}-{} from file", from, to));
      }

      return framed_entries;
    }

    bool truncate(size_t idx)
    {
      if (is_complete || (idx < start_idx - 1) || (idx >= get_last_idx()))
      {
        return false;
      }

      LOG_FAIL_FMT("Truncating {} at {}", get_file_name(), idx);

      if (idx == start_idx - 1)
      {
        LOG_FAIL_FMT("Removing {}", get_file_name());
        if (!fs::remove(fs::path(dir) / fs::path(get_file_name())))
        {
          throw std::logic_error(
            fmt::format("Could not remove file {}", get_file_name()));
        }
        return true;
      }

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

      fs::rename(
        fs::path(dir) / fs::path(get_file_name()),
        fs::path(dir) /
          fs::path(fmt::format("{}.{}", file_name_prefix, start_idx)));
    }

    void complete()
    {
      // TODO: To be called when the last index in the chunk has been globally
      // committed
      // 1. fflush
      // 2. Rename file
      is_complete = true;
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
    std::list<std::shared_ptr<LedgerFile>> files;

    const size_t chunk_threshold;
    size_t last_idx = 0;

    void dump_files() const
    {
      LOG_FAIL_FMT("****** Active files: ");
      for (auto const& f : files)
      {
        LOG_FAIL_FMT("{}: {}", f->get_start_idx(), f->get_file_name());
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

      files.push_back(std::make_shared<LedgerFile>(ledger_dir));

      LOG_FAIL_FMT("Multiple ledger created");
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

    size_t framed_entries_size(size_t from, size_t to) const
    {
      auto f = get_latest_file();
      return f->framed_entries_size(from, to);

      // LOG_TRACE_FMT(
      //   "fes: from {} -> to {} [start: {} - last: {}]",
      //   from,
      //   to,
      //   start_idx,
      //   start_idx + positions.size() - 1);

      // if ((from == 0) || (to < from) || (to > start_idx + positions.size() -
      // 1))
      // {
      //   return 0;
      // }

      // // TODO: It might be much easier to record start_idx as (start_idx -
      // 1)?? if (to == (start_idx + positions.size() - 1))
      // {
      //   LOG_TRACE_FMT(
      //     "here, total len {} - start {}",
      //     total_len,
      //     positions.at(from - start_idx));
      //   return total_len - positions.at(from - start_idx);
      // }
      // else
      // {
      // TODO: This is not really tested for now
      // TODO: We need to access previous chunks here
      dump_files();

      // TODO: Handle entries over multiple chunks!! Hard!!

      // // Find file with largest offset that is less than from
      // auto search = std::upper_bound(
      //   files.rbegin(),
      //   files.rend(),
      //   from,
      //   [](size_t idx, std::pair<size_t, FILE*> v) {
      //     LOG_FAIL_FMT("{} >= {} ? {}", idx, v.first, (idx >= v.first));
      //     return idx >= v.first;
      //   });
      // if (search == files.rend())
      // {
      //   // TODO: Refine this
      //   throw std::logic_error(
      //     fmt::format("Could not find anything at {}", from));
      // }

      // LOG_FAIL_FMT(
      //   "Found file \"{}\" for {}", get_file_name(search->second), from);

      // // TODO: Load file and positions within it
      // if (search->second == files.rbegin()->second)
      // {
      //   // TODO: This can be optimised: we know we can look up the last
      //   file
      //     // if from and to are within positions
      //     LOG_FAIL_FMT("Current file!");
      //   return positions.at(to - start_idx) - positions.at(from - start_idx);
      // }
      // else
      // {
      //   size_t start_idx_ = get_start_idx(search->second);
      //   LOG_FAIL_FMT("Start idx is {}", start_idx_);

      //   // Load positions
      //   // First, get full size of file
      //   fseeko(search->second, 0, SEEK_END);
      //   size_t total_size = ftello(search->second);

      //   // Second, read offset at end of file
      //   fseeko(search->second, 0, SEEK_SET);
      //   size_t table_offset;
      //   if (
      //     fread(&table_offset, sizeof(table_offset), 1, search->second) != 1)
      //   {
      //     throw std::logic_error("Failed to read positions offset from
      //     file");
      //   }

      //   LOG_FAIL_FMT("table offset is {}", table_offset);

      //   // Finally, read positions
      //   fseeko(search->second, table_offset, SEEK_SET);

      //   std::vector<size_t> positions_;
      //   positions_.resize(
      //     (total_size - table_offset) / sizeof(positions_.at(0)));
      //   LOG_FAIL_FMT("len of positions_ is {}", positions_.size());

      //   if (
      //     fread(
      //       positions_.data(),
      //       sizeof(positions_.at(0)),
      //       positions_.size(),
      //       search->second) != positions_.size())
      //   {
      //     throw std::logic_error("Failed to read positions_ table from
      //     file");
      //   }

      //   for (auto const& p : positions_)
      //   {
      //     LOG_FAIL_FMT("Positions: {}", p);
      //   }

      //   return positions_.at() - positions_.()
      // }
      // }
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

      LOG_FAIL_FMT("Size of framed entries: {}", entries.size());
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

      if (idx >= last_idx)
      {
        return;
      }

      auto f_from = get_it_contains_idx(idx + 1);
      auto f_to = get_it_contains_idx(last_idx + 1);
      if (f_to == files.end())
      {
        f_to = --f_to;
      }

      LOG_FAIL_FMT("Number of ledgers: {}", std::distance(f_from, f_to) + 1);

      for (auto it = f_from; it != std::next(f_to);)
      {
        auto truncate_idx = (it == f_from) ? idx : (*it)->get_start_idx() - 1;
        LOG_FAIL_FMT("Truncate idx: {}", truncate_idx);

        // Do not delete the last file if it is the only active one
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

    // void register_message_handlers(
    //   messaging::Dispatcher<ringbuffer::Message>& disp)
    // {
    //   DISPATCHER_SET_MESSAGE_HANDLER(
    //     disp,
    //     consensus::ledger_append,
    //     [this](const uint8_t* data, size_t size) {
    //       auto committable = serialized::read<bool>(data, size);
    //       write_entry(data, size, committable);
    //     });

    //   DISPATCHER_SET_MESSAGE_HANDLER(
    //     disp,
    //     consensus::ledger_truncate,
    //     [this](const uint8_t* data, size_t size) {
    //       auto idx = serialized::read<consensus::Index>(data, size);

    //       // TODO: This has to become more complex to handle truncation over
    //       a
    //       // collection of ledger files
    //       truncate(idx);
    //     });

    //   DISPATCHER_SET_MESSAGE_HANDLER(
    //     disp,
    //     consensus::ledger_compact,
    //     [this](const uint8_t* data, size_t size) {
    //       auto idx = serialized::read<consensus::Index>(data, size);
    //       LOG_FAIL_FMT("Compacting ledger at {}", idx);

    //       size_t chunk_size = framed_entries_size(start_idx, idx);
    //       LOG_FAIL_FMT(
    //         "Size of last chunk: {}/{}", chunk_size, chunk_threshold);

    //       if (chunk_size > chunk_threshold)
    //       {
    //         // archive_chunk(idx);
    //       }
    //     });

    //   DISPATCHER_SET_MESSAGE_HANDLER(
    //     disp, consensus::ledger_get, [&](const uint8_t* data, size_t size) {
    //       // The enclave has asked for a ledger entry.
    //       auto [idx] =
    //         ringbuffer::read_message<consensus::ledger_get>(data, size);

    //       auto& entry = read_entry(idx);

    //       if (entry.size() > 0)
    //       {
    //         RINGBUFFER_WRITE_MESSAGE(
    //           consensus::ledger_entry, to_enclave, entry);
    //       }
    //       else
    //       {
    //         RINGBUFFER_WRITE_MESSAGE(consensus::ledger_no_entry, to_enclave);
    //       }
    //     });
    // }
  };
}