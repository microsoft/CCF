// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <arrow/array/array_binary.h>
#pragma GCC diagnostic pop
#include <memory>
#include <string>
#include <vector>

class ParquetData
{
public:
  std::shared_ptr<arrow::StringArray> ids;
  std::shared_ptr<arrow::BinaryArray> requests;
  std::vector<int64_t> send_time;
};