// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#ifndef PARQUET_DATA_H
#define PARQUET_DATA_H

class ParquetData
{
public:
  ParquetData() {}

  std::vector<std::string> IDS;
  std::vector<std::string> REQUEST;
  std::vector<std::string> RAW_RESPONSE;
  std::vector<double> SEND_TIME;
  std::vector<double> RESPONSE_TIME;
};

#endif