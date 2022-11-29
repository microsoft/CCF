// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

class ParquetData
{
public:
  ParquetData() {}

  std::vector<std::string> ids;
  std::vector<std::string> request;
  std::vector<std::string> raw_response;
  std::vector<double> send_time;
  std::vector<double> response_time;
};