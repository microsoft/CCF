// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

// C++ port of reference implementation
// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
namespace ccf::siphash
{
  using SipState = uint64_t[4];
  using SipKey = uint64_t[2];

  constexpr uint64_t rotl(uint64_t x, size_t b)
  {
    return (x << b) | (x >> (64 - b));
  }

  inline void u32_to_bytes_le(uint32_t v, uint8_t* out)
  {
    out[0] = (uint8_t)(v);
    out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
  }

  inline void u64_to_bytes_le(uint64_t v, uint8_t* out)
  {
    u32_to_bytes_le((uint32_t)v, out);
    u32_to_bytes_le((uint32_t)(v >> 32), out + 4);
  }

  template <typename ConstRandomIterator>
  constexpr uint64_t bytes_to_64_le(const ConstRandomIterator in)
  {
    return ((uint64_t)in[0]) | ((uint64_t)in[1] << 8) |
      ((uint64_t)in[2] << 16) | ((uint64_t)in[3] << 24) |
      ((uint64_t)in[4] << 32) | ((uint64_t)in[5] << 40) |
      ((uint64_t)in[6] << 48) | ((uint64_t)in[7] << 56);
  }

  inline void sip_rounds(SipState& s, size_t rounds)
  {
    for (size_t i = 0; i < rounds; ++i)
    {
      s[0] += s[1];
      s[1] = rotl(s[1], 13);
      s[1] ^= s[0];
      s[0] = rotl(s[0], 32);
      s[2] += s[3];
      s[3] = rotl(s[3], 16);
      s[3] ^= s[2];
      s[0] += s[3];
      s[3] = rotl(s[3], 21);
      s[3] ^= s[0];
      s[2] += s[1];
      s[1] = rotl(s[1], 17);
      s[1] ^= s[2];
      s[2] = rotl(s[2], 32);
    }
  }

  enum class OutputLength : uint8_t
  {
    EightBytes = 8,
    SixteenBytes = 16,
  };

  template <
    size_t CompressionRounds,
    size_t FinalizationRounds,
    OutputLength out_size>
  void siphash_raw(
    const uint8_t* in, size_t in_len, const SipKey& key, uint8_t* out)
  {
    SipState s{
      0x736f6d6570736575ULL,
      0x646f72616e646f6dULL,
      0x6c7967656e657261ULL,
      0x7465646279746573ULL};

    SipKey k{key[0], key[1]};

    s[0] ^= k[0];
    s[1] ^= k[1];
    s[2] ^= k[0];
    s[3] ^= k[1];

    const uint8_t* end = in + in_len - (in_len % 8);
    const size_t left = in_len & 7;

    if constexpr (out_size == OutputLength::SixteenBytes)
    {
      s[1] ^= 0xee;
    }

    uint64_t m = 0;
    for (; in != end; in += 8)
    {
      m = bytes_to_64_le(in);
      s[3] ^= m;

      sip_rounds(s, CompressionRounds);

      s[0] ^= m;
    }

    uint64_t b = (uint64_t)in_len << 56;

    // Deliberate fall through
    switch (left)
    {
      case 7:
        b |= (uint64_t)in[6] << 48;
      case 6:
        b |= (uint64_t)in[5] << 40;
      case 5:
        b |= (uint64_t)in[4] << 32;
      case 4:
        b |= (uint64_t)in[3] << 24;
      case 3:
        b |= (uint64_t)in[2] << 16;
      case 2:
        b |= (uint64_t)in[1] << 8;
      case 1:
        b |= (uint64_t)in[0];
      case 0:
        break;
      default:
        throw std::logic_error("unreachable");
    }

    s[3] ^= b;

    sip_rounds(s, CompressionRounds);

    s[0] ^= b;

    if constexpr (out_size == OutputLength::SixteenBytes)
    {
      s[2] ^= 0xee;
    }
    else
    {
      s[2] ^= 0xff;
    }

    sip_rounds(s, FinalizationRounds);

    b = s[0] ^ s[1] ^ s[2] ^ s[3];
    u64_to_bytes_le(b, out);

    if constexpr (out_size == OutputLength::EightBytes)
    {
      return;
    }

    s[1] ^= 0xdd;

    sip_rounds(s, FinalizationRounds);

    b = s[0] ^ s[1] ^ s[2] ^ s[3];
    u64_to_bytes_le(b, out + 8);
  }

  template <size_t CompressionRounds, size_t FinalizationRounds>
  uint64_t siphash(const uint8_t* data, size_t size, const SipKey& key)
  {
    uint64_t out = 0;

    siphash_raw<
      CompressionRounds,
      FinalizationRounds,
      OutputLength::EightBytes>(
      data, size, key, reinterpret_cast<uint8_t*>(&out));

    return out;
  }

  template <size_t CompressionRounds, size_t FinalizationRounds>
  uint64_t siphash(const std::vector<uint8_t>& in, const SipKey& key)
  {
    return siphash<CompressionRounds, FinalizationRounds>(
      in.data(), in.size(), key);
  }
}
// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
