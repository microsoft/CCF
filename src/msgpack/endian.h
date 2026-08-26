// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <bit>
#include <cstddef>
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

  // Write `value` to `out` in big-endian byte order. Only unsigned integer
  // widths are accepted; callers wanting to write a signed value reinterpret
  // it through the matching unsigned type at the call site.
  template <typename T>
  void write_be(uint8_t* out, T value)
  {
    static_assert(std::is_unsigned_v<T>, "write_be expects an unsigned type");
    static_assert(
      sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8,
      "write_be supports 1/2/4/8-byte unsigned integers");

    if constexpr (sizeof(T) == 1)
    {
      *out = static_cast<uint8_t>(value);
    }
    else
    {
      const auto swapped = std::byteswap(value);
      std::memcpy(out, &swapped, sizeof(T));
    }
  }

  inline uint8_t* append_space(std::vector<uint8_t>& buf, size_t size)
  {
    const auto offset = buf.size();
    buf.resize(offset + size);
    return buf.data() + offset;
  }

  template <typename T>
  void append_tagged_be(std::vector<uint8_t>& buf, uint8_t tag, T value)
  {
    auto* out = append_space(buf, 1 + sizeof(T));
    *out = tag;
    write_be(out + 1, value);
  }
} // namespace ccf::msgpack::utils
