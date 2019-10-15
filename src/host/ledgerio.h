// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledgerenclavetypes.h"
#include "ds/logger.h"

#include <cstdint>
#include <cstdio>
#include <errno.h>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace asynchost
{
  class LedgerIO
  {
  private:
    static constexpr size_t frame_header_size = sizeof(uint32_t);

    // This uses C stdio instead of fstream because an fstream
    // cannot be truncated.
    FILE* file;
    std::vector<size_t> positions;
    size_t total_len;

  public:
    LedgerIO(const std::string& filename) : file(NULL)
    {
      file = fopen(filename.c_str(), "r+b");

      if (!file)
        file = fopen(filename.c_str(), "w+b");

      if (!file)
        throw std::logic_error("Unable to open or create ledger file");

      fseeko(file, 0, SEEK_END);
      auto len = ftello(file);
      if (len == 1)
      {
        std::stringstream ss;
        ss << "Failed to tell file size: " << strerror(errno);
        throw std::logic_error(ss.str());
      }
      fseeko(file, 0, SEEK_SET);
      size_t pos = 0;
      uint32_t size = 0;

      while (len >= frame_header_size)
      {
        if (fread(&size, frame_header_size, 1, file) != 1)
          throw std::logic_error("Failed to read from file");

        len -= frame_header_size;

        if (len < size)
          throw std::logic_error("Malformed ledger file");

        fseeko(file, size, SEEK_CUR);
        len -= size;

        positions.push_back(pos);
        pos += (size + frame_header_size);
      }

      total_len = pos;

      if (len != 0)
        throw std::logic_error("Malformed ledger file");
    }

    LedgerIO(const LedgerIO& that) = delete;

    ~LedgerIO()
    {
      if (file)
      {
        fflush(file);
        fclose(file);
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
        throw std::logic_error("Failed to read from file");

      return entry;
    }

    const std::vector<uint8_t> read_framed_entries(size_t from, size_t to)
    {
      auto framed_size = framed_entries_size(from, to);

      std::vector<uint8_t> framed_entries(framed_size);
      if (framed_size == 0)
        return framed_entries;

      fseeko(file, positions.at(from - 1), SEEK_SET);

      if (fread(framed_entries.data(), framed_size, 1, file) != 1)
        throw std::logic_error("Failed to read from file");

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

    void write_entry(const uint8_t* data, size_t size)
    {
      fseeko(file, total_len, SEEK_SET);
      positions.push_back(total_len);

      LOG_DEBUG_FMT("Ledger write {}: {} bytes", positions.size(), size);

      total_len += (size + frame_header_size);

      uint32_t frame = (uint32_t)size;

      if (fwrite(&frame, frame_header_size, 1, file) != 1)
        throw std::logic_error("Failed to write to file");

      if (fwrite(data, size, 1, file) != 1)
        throw std::logic_error("Failed to write to file");
    }

    void truncate(size_t last_idx)
    {
      LOG_DEBUG_FMT("Ledger truncate: {}/{}", last_idx, positions.size());

      // positions[last_idx - 1] is the position of the specified
      // final index. Truncate the ledger at position[last_idx].
      if (last_idx >= positions.size())
        return;

      total_len = positions.at(last_idx);
      positions.resize(last_idx);

      if (fflush(file) != 0)
      {
        std::stringstream ss;
        ss << "Failed to flush file: " << strerror(errno);
        throw std::logic_error(ss.str());
      }

      if (ftruncate(fileno(file), total_len))
        throw std::logic_error("Failed to truncate file");

      fseeko(file, total_len, SEEK_SET);
    }
  };
}
