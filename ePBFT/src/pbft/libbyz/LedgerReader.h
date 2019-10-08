// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <string>
#include <vector>

class LedgerReader
{
private:
  std::string file_path;
  size_t file_size;
  FILE* file;

public:
  LedgerReader(const std::string& file_path_);
  virtual ~LedgerReader();
  std::vector<uint8_t> read_next_entry(size_t start_from);
};
