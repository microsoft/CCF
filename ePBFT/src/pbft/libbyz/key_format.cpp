// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "key_format.h"

#include <sstream>

void format::from_hex(std::string key, uint8_t* dst, size_t dst_size)
{
  size_t j = 0;
  for (size_t i = 0; i < key.length(); i += 2)
  {
    std::string byte_string = key.substr(i, 2);
    uint8_t byte = (uint8_t)strtol(byte_string.c_str(), NULL, 16);
    dst[j] = byte;
    ++j;
    if (j > dst_size)
    {
      throw std::logic_error(
        "Wrong key size, expected: " + std::to_string(dst_size) +
        " and got: " + std::to_string(j));
    }
  }
}

std::string format::to_hex(uint8_t* key, size_t size)
{
  std::stringstream ss;
  ss.setf(std::ios_base::hex, std::ios::basefield);
  ss.fill('0');

  for (size_t i = 0; i < size; ++i)
  {
    ss << std::setw(2) << static_cast<int>(key[i]);
  }
  return ss.str();
}
