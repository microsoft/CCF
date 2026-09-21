// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "crypto/cbor_tags.h"

#include <tav/cbor.hpp>

namespace ccf::cose::utils
{
  inline std::vector<std::vector<uint8_t>> parse_x5chain(
    const tav::cbor::Value& x5chain_value)
  {
    std::vector<std::vector<uint8_t>> chain;
    // x5chain can be either an array of byte strings or a single byte string
    try
    {
      for (size_t i = 0; i < x5chain_value.size(); ++i)
      {
        const auto x5chain_ctx = "x5chain[" + std::to_string(i) + "]";
        const auto& bytes = tav::cbor::rethrow_with_msg(
          [&]() { return x5chain_value.array_at(i).as_bytes(); }, x5chain_ctx);
        chain.emplace_back(bytes.begin(), bytes.end());
      }
    }
    catch (const tav::cbor::DecodeError&)
    {
      auto bytes = tav::cbor::rethrow_with_msg(
        [&]() { return x5chain_value.as_bytes(); }, "x5chain");
      chain.emplace_back(bytes.begin(), bytes.end());
    }
    return chain;
  }
}
