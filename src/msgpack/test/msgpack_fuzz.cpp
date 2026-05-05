// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
//
// libFuzzer harness for the msgpack encoder.
//
// Strategy: treat the input bytes as a "script" of write operations.
// Each opcode picks a writer; operands are consumed from the rest of
// the stream. The harness builds an in-memory mirror (nlohmann::json)
// of what the encoder wrote, then runs the round-trip check:
//
//   bytes  = encode(script)
//   value  = nlohmann::from_msgpack(bytes)
//   value should == mirror
//
// If the encoded bytes don't round-trip through the nlohmann oracle
// into a value equal to the mirror, we've produced something
// non-canonical (wrong format family) or non-deterministic, and the
// harness traps.
//
// Binary and ext values are mirrored using nlohmann::json::binary, matching
// the representation produced by from_msgpack.
//
// `encode_one` and `StreamReader` live in `gen.h` so the canned tests in
// `fuzz_script_test.cpp` can exercise the same code paths as this harness.

#include "msgpack/encode.h"
#include "msgpack/test/gen.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <nlohmann/json.hpp>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  using nlohmann::json;
  namespace gen = ccf::msgpack::test::gen;

  gen::StreamReader r(data, size);
  std::vector<uint8_t> buf;
  json mirror;
  try
  {
    mirror = gen::encode_one(r, buf);
  }
  catch (const ccf::msgpack::MsgpackEncodeError&)
  {
    // Expected: e.g. MAP_TOO_LARGE if the script asks for one. Not a bug.
    return 0;
  }
  // Round-trip check: oracle must decode our bytes into a value equal
  // to the JSON mirror we built alongside the encoding.
  json decoded;
  try
  {
    decoded = json::from_msgpack(buf);
  }
  catch (const json::exception& e)
  {
    // We produced bytes the JSON oracle can't decode. That's a bug.
    std::fprintf(
      stderr,
      "[msgpack_fuzz] from_msgpack failed: %s; encoded %zu bytes\n",
      e.what(),
      buf.size());
    __builtin_trap();
  }
  if (decoded != mirror)
  {
    std::fprintf(
      stderr,
      "[msgpack_fuzz] round-trip mismatch:\n"
      "  mirror : %s\n"
      "  decoded: %s\n",
      mirror.dump().c_str(),
      decoded.dump().c_str());
    __builtin_trap();
  }
  return 0;
}
