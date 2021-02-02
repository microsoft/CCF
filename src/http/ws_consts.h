// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstddef>

namespace ws
{
  static constexpr size_t INITIAL_READ = 2;
  static constexpr size_t OUT_CCF_HEADER_SIZE =
    sizeof(uint16_t) /* return code */ + sizeof(size_t) /* seqno */ +
    sizeof(size_t) /* view */;

  enum Verb
  {
    WEBSOCKET = -1
  };
}