// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/cbor_tags.h"
#include "crypto/test/cbor_printer.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <tav/cbor.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  tav::cbor::Value value;
  try
  {
    value = tav::cbor::nondet_parse({data, size});
  }
  catch (const tav::cbor::DecodeError&)
  {
    return 0;
  }

  // If parse succeeded, exercise serialization round-trip and string
  // rendering. Any failure here is a real bug - let the fuzzer surface it.
  std::ignore = ccf::cbor::test::to_string(value);
  auto serialized = value.nondet_serialize();
  auto reparsed = tav::cbor::nondet_parse(serialized);
  auto reserialized = reparsed.nondet_serialize();

  if (serialized != reserialized)
  {
    __builtin_trap();
  }

  return 0;
}
