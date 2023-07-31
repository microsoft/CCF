// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <string>
#include <vector>

class ParquetData
{
public:
  ParquetData() {}

  std::vector<std::string> ids;
  std::vector<std::vector<uint8_t>> request;
  std::vector<std::vector<uint8_t>> raw_response;
  std::vector<int64_t> send_time;
  std::vector<int64_t> response_time;
};