// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/nonstd.h"
#include "ds/internal_logger.h.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

namespace ccf::ds::system
{
  std::optional<std::string> exec(const std::string& cmd)
  {
    std::array<char, 4096> buffer;
    std::string result;

    LOG_TRACE_FMT("Opening pipe to execute command: {}", cmd);
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe)
    {
      LOG_FAIL_FMT("Error opening pipe: {}", strerror(errno));
      return std::nullopt;
    }

    while (fgets(buffer.data(), buffer.size(), pipe) != NULL)
    {
      result += buffer.data();
    }

    auto return_code = pclose(pipe);
    if (return_code != 0)
    {
      LOG_TRACE_FMT("Command returned error: {}", return_code);
    }

    result = ccf::nonstd::trim(result);

    LOG_TRACE_FMT("Result is: {}", result);

    return result;
  }
}
