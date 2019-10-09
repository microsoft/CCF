// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#include "LedgerReader.h"

#include "ds/logger.h"

#include <errno.h>

LedgerReader::LedgerReader(const std::string& file_path_) :
  file_path(file_path_)
{
  file = fopen(file_path.c_str(), "r");
  if (!file)
  {
    throw std::logic_error("Could not open ledger file");
  }
  fseeko(file, 0, SEEK_END);
  file_size = ftello(file);
  if (file_size == -1)
  {
    throw std::logic_error("File could not tell its size");
  }

  fseeko(file, 0, SEEK_SET);
}

LedgerReader::~LedgerReader()
{
  if (file)
  {
    fclose(file);
  }
}

std::vector<uint8_t> LedgerReader::read_next_entry(size_t start_from)
{
  if (start_from >= file_size)
  {
    LOG_INFO << "Reached end of ledger file" << std::endl;
    return {};
  }

  if (fseeko(file, start_from, SEEK_SET) == -1)
  {
    throw std::logic_error(
      "Failed to seek from file, errno: " + std::to_string(errno));
  }

  size_t entry_size;
  size_t res;
  if ((res = fread(&entry_size, sizeof(entry_size), 1, file)) != 1)
  {
    throw std::logic_error(
      "Failed to read next entry size from file, fread returned: " +
      std::to_string(res));
  }

  std::vector<uint8_t> entry(entry_size);

  if ((res = fread(entry.data(), entry_size, 1, file)) != 1)
  {
    throw std::logic_error(
      "Failed to read entry of size: " + std::to_string(entry_size) +
      " from file, fread returned: " + std::to_string(res));
  }

  return entry;
}
