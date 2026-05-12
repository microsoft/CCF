// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/cbor.h"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  ccf::cbor::Value value;
  try
  {
    value = ccf::cbor::parse({data, size});
  }
  catch (const ccf::cbor::CBORDecodeError&)
  {
    return 0;
  }

  // If parse succeeded, exercise serialization round-trip and string
  // rendering. Any failure here is a real bug — let the fuzzer surface it.
  std::ignore = ccf::cbor::to_string(value);
  auto serialized = ccf::cbor::serialize(value);
  auto reparsed = ccf::cbor::parse(serialized);
  auto reserialized = ccf::cbor::serialize(reparsed);

  if (serialized != reserialized)
  {
    __builtin_trap();
  }

  return 0;
}
