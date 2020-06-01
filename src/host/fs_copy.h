// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <ds/logger.h>
#include <uv.h>

namespace asynchost
{
  class FileCopy
  {
  private:
    // const std::string src;
    // const std::string dst;
    // const size_t max_offset;

  public:
    static FILE* copy(
      const FILE* src,
      const std::string& dst,
      size_t start_offset, // TODO: Once the original ledger file is truncated
                           // from the start, this should go
      size_t end_offset)
    // src(src),
    // dst(dst),
    // max_offset(max_offset)
    {
      LOG_INFO_FMT(
        "Attempting to copy a file until from offset {} to {}",
        start_offset,
        end_offset);

      // TODO: What permissions?
      FILE* file = fopen(dst.c_str(), "w+b");

      // TODO:
      // 1. Create new dst
      // 2. Start copying to it...
      // 3. Callback to check everything has been written to it, retry
      // otherwise.
      // 4. Provide multiple_ledger a callback to call here when writing to file
      // is finished. This callback will initiate the next copy.

      return file;
    }

    ~FileCopy()
    {
      LOG_INFO_FMT("FileCopy deleted!!");
    }
  };

}