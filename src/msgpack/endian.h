// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <bit>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <vector>

namespace ccf::msgpack::utils
{
  // The msgpack wire format is big-endian. The byte-swap below assumes
  // a little-endian host; on a big-endian host it would silently no-op
  // and produce wrong output. The static_assert fires loudly if that
  // changes.
  static_assert(
    std::endian::native == std::endian::little,
    "ccf::msgpack::utils::write_be assumes a little-endian host; "
    "rework the byte-swap to support a big-endian platform.");

  // Append `value` to `buf` in big-endian byte order. Only unsigned
  // integer widths are accepted; callers wanting to write a signed
  // value reinterpret it through the matching unsigned type at the
  // call site, so the byte-swap logic here doesn't need a signed
  // overload.
  template <typename T>
  void write_be(std::vector<uint8_t>& buf, T value)
  {
    static_assert(std::is_unsigned_v<T>, "write_be expects an unsigned type");
    static_assert(
      sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8,
      "write_be supports 1/2/4/8-byte unsigned integers");

    if constexpr (sizeof(T) == 1)
    {
      buf.push_back(static_cast<uint8_t>(value));
      return;
    }
    else
    {
      // std::byteswap is C++23-only; this hand-rolled swap keeps the
      // file C++20-compatible.
      const auto swapped = [&]() -> T {
        if constexpr (sizeof(T) == 2)
        {
          return static_cast<T>(
            (static_cast<uint16_t>(value) << 8) |
            (static_cast<uint16_t>(value) >> 8));
        }
        else if constexpr (sizeof(T) == 4)
        {
          const auto v = static_cast<uint32_t>(value);
          return static_cast<T>(
            ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
            ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24));
        }
        else
        {
          const auto v = static_cast<uint64_t>(value);
          return static_cast<T>(
            ((v & 0x00000000000000FFull) << 56) |
            ((v & 0x000000000000FF00ull) << 40) |
            ((v & 0x0000000000FF0000ull) << 24) |
            ((v & 0x00000000FF000000ull) << 8) |
            ((v & 0x000000FF00000000ull) >> 8) |
            ((v & 0x0000FF0000000000ull) >> 24) |
            ((v & 0x00FF000000000000ull) >> 40) |
            ((v & 0xFF00000000000000ull) >> 56));
        }
      }();

      const auto offset = buf.size();
      buf.resize(offset + sizeof(T));
      std::memcpy(buf.data() + offset, &swapped, sizeof(T));
    }
  }
} // namespace ccf::msgpack::utils
