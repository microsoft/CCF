// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Tiny generator combinator for property-based testing.
//
// Deliberately small (no shrinking, no third-party dep).
//
// Usage:
//   gen::Rng rng(12345);
//   auto g = gen::uint64_in_range(0, 0xFFFFFFFFULL);
//   for (int i = 0; i < 100; ++i) {
//     auto v = g(rng);
//     ...
//   }
//
// Failure reproducibility: each test fixes the seed and prints it via
// INFO(...) so a failing run can be re-run deterministically. Size
// generators bias toward smaller inputs (most iterations) but include
// boundary thresholds at lower frequency.

#include "msgpack/encode.h"

#include <cassert>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <random>
#include <string>
#include <vector>

namespace ccf::msgpack::test::gen
{
  using Rng = std::mt19937_64;

  template <typename T>
  using Gen = std::function<T(Rng&)>;

  // ===== Primitive generators =====

  inline Gen<uint64_t> uint64_in_range(uint64_t lo, uint64_t hi)
  {
    return [lo, hi](Rng& rng) {
      std::uniform_int_distribution<uint64_t> d(lo, hi);
      return d(rng);
    };
  }

  inline Gen<int64_t> int64_in_range(int64_t lo, int64_t hi)
  {
    return [lo, hi](Rng& rng) {
      std::uniform_int_distribution<int64_t> d(lo, hi);
      return d(rng);
    };
  }

  inline Gen<int64_t> int64_exp_with_mean(int64_t mean)
  {
    return [mean](Rng& rng) {
      std::exponential_distribution<double> d(1.0 / mean);
      return static_cast<int64_t>(d(rng));
    };
  }

  inline Gen<size_t> size_in_range(size_t lo, size_t hi)
  {
    return [lo, hi](Rng& rng) {
      std::uniform_int_distribution<size_t> d(lo, hi);
      return d(rng);
    };
  }

  inline Gen<bool> boolean()
  {
    return [](Rng& rng) {
      std::uniform_int_distribution<int> d(0, 1);
      return d(rng) == 1;
    };
  }

  inline Gen<double> finite_double()
  {
    // Avoid NaN/inf: nlohmann's JSON-as-msgpack-oracle handling of
    // non-finite values is configurable, which makes structural
    // equality comparisons against the oracle ambiguous. Tests
    // exercise non-finite values explicitly via the boundary table.
    return [](Rng& rng) {
      std::uniform_real_distribution<double> d(-1e9, 1e9);
      return d(rng);
    };
  }

  // Choose one of `n` generators uniformly. Caller must supply at
  // least one alternative.
  template <typename T>
  Gen<T> one_of(std::vector<Gen<T>> alternatives)
  {
    assert(!alternatives.empty() && "gen::one_of requires >= 1 alternative");
    return [alts = std::move(alternatives)](Rng& rng) {
      std::uniform_int_distribution<size_t> d(0, alts.size() - 1);
      return alts[d(rng)](rng);
    };
  }

  // ===== Helpers for the size distribution =====
  //
  // Bias toward small sizes (cheap iteration) but include boundary
  // crossings in roughly 1-in-N runs.
  inline Gen<size_t> size_biased(
    size_t small_max, std::vector<size_t> boundary_picks)
  {
    return [small_max, picks = std::move(boundary_picks)](Rng& rng) -> size_t {
      // 80% small uniform, 20% pick from boundaries.
      std::uniform_int_distribution<int> coin(0, 99);
      if (coin(rng) < 80 || picks.empty())
      {
        std::uniform_int_distribution<size_t> d(0, small_max);
        return d(rng);
      }
      std::uniform_int_distribution<size_t> d(0, picks.size() - 1);
      return picks[d(rng)];
    };
  }

  // ===== String / bytes generators =====

  inline Gen<std::string> string_of_size(Gen<size_t> size_gen)
  {
    return [size_gen = std::move(size_gen)](Rng& rng) {
      const auto n = size_gen(rng);
      std::string s(n, '\0');
      // Full byte range: msgpack's str format is byte-array, not text.
      // The encoder is binary-safe; tests should exercise that.
      std::uniform_int_distribution<int> ch(0, 255);
      for (auto& c : s)
      {
        c = static_cast<char>(static_cast<unsigned char>(ch(rng)));
      }
      return s;
    };
  }

  // ASCII-only variant: keeps payload comparisons through nlohmann's
  // JSON oracle unambiguous (no UTF-8 normalisation surprises). Use
  // this for the differential test, not for the encoder's own
  // length-prefix property tests.
  inline Gen<std::string> ascii_string_of_size(Gen<size_t> size_gen)
  {
    return [size_gen = std::move(size_gen)](Rng& rng) {
      const auto n = size_gen(rng);
      std::string s(n, '\0');
      std::uniform_int_distribution<int> ch(32, 126);
      for (auto& c : s)
      {
        c = static_cast<char>(ch(rng));
      }
      return s;
    };
  }

  inline Gen<std::vector<uint8_t>> bytes_of_size(Gen<size_t> size_gen)
  {
    return [size_gen = std::move(size_gen)](Rng& rng) {
      const auto n = size_gen(rng);
      std::vector<uint8_t> v(n);
      std::uniform_int_distribution<int> b(0, 255);
      for (auto& x : v)
      {
        x = static_cast<uint8_t>(b(rng));
      }
      return v;
    };
  }

  using nlohmann::json;
  using namespace ccf::msgpack;

  class StreamReader
  {
  public:
    StreamReader(const uint8_t* d, size_t n) : data_(d), size_(n), pos_(0) {}

    bool eof() const
    {
      return pos_ >= size_;
    }

    uint8_t u8()
    {
      if (eof())
      {
        return 0;
      }
      return data_[pos_++];
    }

    uint64_t u64()
    {
      uint64_t v = 0;
      for (int i = 0; i < 8; ++i)
      {
        v = (v << 8) | u8();
      }
      return v;
    }

    void take(std::vector<uint8_t>& out, size_t n)
    {
      while (n-- && !eof())
      {
        out.push_back(u8());
      }
    }

  private:
    const uint8_t* data_;
    size_t size_;
    size_t pos_;
  };

  // A composite (array or object) currently being filled. Leaves are
  // not frames; they are spliced directly into the top-of-stack
  // composite by the loop body.
  //
  // Invariant: `root` is always either json::array() or json::object();
  // `remaining` counts the children still to splice into it.
  // `pending_key` is set only for objects, and only between the moment
  // the loop reads the next key (and writes it to the wire) and the
  // moment the corresponding value is spliced in.
  struct OpenFrame
  {
    json root;
    uint32_t remaining;
    std::optional<std::string> pending_key;
  };

  // Cap the depth of the work stack. Once reached, further composite
  // opcodes are forced to nil so an adversarial script cannot drive
  // unbounded allocation through repeated array/map opcodes.
  constexpr size_t MAX_STACK_DEPTH = 4;

  // Length of map keys generated from the input stream. Keys are
  // [a-z]^KEY_LEN strings; each character consumes one byte from the
  // input. The exact mapping is chosen so the JSON oracle compares
  // cleanly against the mirror.
  constexpr size_t KEY_LEN = 32;

  inline std::string read_key(StreamReader& r)
  {
    std::string key(KEY_LEN, '\0');
    for (auto& c : key)
    {
      c = static_cast<char>((r.u8() % 26) + 'a');
    }
    return key;
  }

  inline std::vector<uint8_t> event_time_payload(FluentdEventTime t)
  {
    std::vector<uint8_t> payload;
    payload.reserve(8);
    auto append_u32_be = [&payload](uint32_t v) {
      payload.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
      payload.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
      payload.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
      payload.push_back(static_cast<uint8_t>(v & 0xFFu));
    };
    append_u32_be(t.seconds());
    append_u32_be(t.nanoseconds());
    return payload;
  }

  // Splice a value into the top-of-stack composite, consuming any
  // pending object key. The caller must guarantee the stack is
  // non-empty; the top-of-stack `root` must be an array or object.
  inline void splice_into(OpenFrame& parent, json value)
  {
    if (parent.root.is_array())
    {
      parent.root.push_back(std::move(value));
    }
    else
    {
      // Object. The pending key was set when the loop body started this
      // child's iteration (so that write_str(buf, key) preceded the
      // value's bytes on the wire).
      parent.root[*parent.pending_key] = std::move(value);
      parent.pending_key.reset();
    }
  }

  // Drive the script and return the produced json mirror, writing
  // encoded bytes into `buf`.
  inline json encode_one(StreamReader& r, std::vector<uint8_t>& buf)
  {
    // The root frame is a 1-slot array that receives the user's
    // top-level value via splice. After the loop drains, the array's
    // single element is the result.
    std::vector<std::shared_ptr<OpenFrame>> stack;
    stack.push_back(
      std::make_shared<OpenFrame>(OpenFrame{json::array(), 1, std::nullopt}));

    while (!stack.empty())
    {
      auto& frame = *stack.back();

      // If the top-of-stack composite is full, pop it. If popping
      // empties the stack, we've finished; return the root frame's
      // single child. Otherwise, splice the popped composite into the
      // new top.
      if (frame.remaining == 0)
      {
        json finished = std::move(frame.root);
        stack.pop_back();
        if (stack.empty())
        {
          // Root frame just popped. `finished` is json::array of size 1
          // holding the user's tree.
          return std::move(finished[0]);
        }
        splice_into(*stack.back(), std::move(finished));
        continue;
      }

      // About to produce one more child of `frame`. If `frame` is an
      // object, the key must be on the wire before the child's bytes,
      // so read and write it now and stash for the eventual splice.
      if (frame.root.is_object())
      {
        auto key = read_key(r);
        write_str(buf, key);
        frame.pending_key = std::move(key);
      }

      --frame.remaining;

      // EOF mid-script: emit nil so the wire and mirror stay in sync,
      // and splice it as this child.
      if (r.eof())
      {
        write_nil(buf);
        splice_into(frame, json(nullptr));
        continue;
      }

      const uint8_t op = r.u8() % 10;
      switch (op)
      {
        case 0: // nil
        {
          write_nil(buf);
          splice_into(frame, json(nullptr));
          break;
        }
        case 1: // bool
        {
          const bool v = (r.u8() & 1u) != 0u;
          write_bool(buf, v);
          splice_into(frame, json(v));
          break;
        }
        case 2: // uint64
        {
          const uint64_t v = r.u64();
          write_uint(buf, v);
          splice_into(frame, json(v));
          break;
        }
        case 3: // int64 (delegates to write_uint for v >= 0)
        {
          const int64_t v = static_cast<int64_t>(r.u64());
          write_int(buf, v);
          // For non-negative values write_int delegates to write_uint,
          // so the wire carries an unsigned format and from_msgpack
          // will produce json(uint64_t). Reflect that here so the
          // round-trip comparison succeeds.
          if (v >= 0)
          {
            splice_into(frame, json(static_cast<uint64_t>(v)));
          }
          else
          {
            splice_into(frame, json(v));
          }
          break;
        }
        case 4: // float64 (raw bits)
        {
          const uint64_t bits = r.u64();
          double v;
          std::memcpy(&v, &bits, sizeof(v));
          // The encoder is bit-exact for non-finite doubles, but the
          // JSON oracle's handling of NaN / +inf / -inf is configurable
          // (encodes as nil in some configurations), so the round-trip
          // comparison is not unambiguous. Drop non-finite trials to
          // nil to keep the harness self-consistent; the dedicated
          // float test exercises the bit-pattern passthrough.
          if (!std::isfinite(v))
          {
            write_nil(buf);
            splice_into(frame, json(nullptr));
            break;
          }
          write_float(buf, v);
          splice_into(frame, json(v));
          break;
        }
        case 5: // str
        {
          const size_t n = r.u8(); // 0..255
          std::vector<uint8_t> bytes;
          r.take(bytes, n);
          // Map to printable ASCII so the JSON oracle compares cleanly
          // (no UTF-8 normalisation surprises).
          std::string s;
          s.reserve(bytes.size());
          for (auto b : bytes)
          {
            s.push_back(static_cast<char>((b % 95) + 32));
          }
          write_str(buf, s);
          splice_into(frame, json(s));
          break;
        }
        case 6: // bin
        {
          const size_t n = r.u8();
          std::vector<uint8_t> bytes;
          r.take(bytes, n);
          write_bin(buf, bytes);
          splice_into(frame, json::binary(bytes));
          break;
        }
        case 7: // FluentdEventTime
        {
          using namespace std::chrono;
          // Seconds: keep within uint32_t so make() doesn't reject the
          // trial on range. Nanoseconds: keep below 1e9 so the sub-
          // second component is well-formed.
          const uint32_t s = static_cast<uint32_t>(r.u64() & 0xFFFFFFFFu);
          const uint32_t ns =
            static_cast<uint32_t>(r.u64() & 0xFFFFFFFFu) % 1'000'000'000u;
          // Build the time_point through system_clock::duration, since
          // its tick period is implementation-defined (nanoseconds on
          // libstdc++, microseconds on libc++). The mirror below is
          // built from the validated EventTime, not from raw `ns`, so it
          // reflects any precision loss from duration_cast.
          const auto since_epoch = duration_cast<system_clock::duration>(
            seconds{static_cast<int64_t>(s)} + nanoseconds{ns});
          const auto tp = system_clock::time_point{since_epoch};
          const auto et = FluentdEventTime::make(tp);
          write_event_time(buf, et);
          splice_into(frame, json::binary(event_time_payload(et), 0));
          break;
        }
        case 8: // Array
        {
          // Once the stack is at the depth cap, force a nil to bound
          // adversarial inputs.
          const uint32_t n = r.u8() % 5;
          write_array_header(buf, n);
          stack.push_back(std::make_shared<OpenFrame>(
            OpenFrame{json::array(), n, std::nullopt}));
          // The new frame will be popped (when its `remaining` hits 0)
          // and then spliced into `frame` by the pop branch above.
          break;
        }
        case 9: // Map
        {
          const uint32_t n = r.u8() % 5;
          write_map_header(buf, n);
          stack.push_back(std::make_shared<OpenFrame>(
            OpenFrame{json::object(), n, std::nullopt}));
          break;
        }
      }
    }

    // Unreachable: the loop only exits via `return std::move(finished[0])`
    // above, when the root frame pops.
    __builtin_unreachable();
  }
} // namespace ccf::msgpack::test::gen
