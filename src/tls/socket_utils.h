// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/internal_logger.h"

#include <cerrno>
#include <system_error>
#include <unistd.h>

namespace ccf::tls::details
{
  // Closes a socket owned by the caller, logging any failure. close() is
  // deliberately not retried, including on EINTR, since the descriptor may
  // already have been reused.
  inline void close_socket(int fd)
  {
    if (::close(fd) != 0)
    {
      const auto err = errno;
      LOG_FAIL_FMT(
        "Failed to close socket {}: {}",
        fd,
        std::generic_category().message(err));
    }
  }
}
