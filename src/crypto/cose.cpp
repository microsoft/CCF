// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/cose.h"

#include "crypto/cbor.h"

#include <stdexcept>
#include <vector>

namespace ccf::cose::edit
{
  std::vector<uint8_t> set_unprotected_header(
    const std::span<const uint8_t>& cose_input, const desc::Type& descriptor)
  {
    using namespace ccf::cbor;

    auto cose_cbor = rethrow_with_msg(
      [&]() { return parse(cose_input); }, "Failed to parse COSE_Sign1");

    const auto& cose_envelope = rethrow_with_msg(
      [&]() -> auto& { return cose_cbor->tag_at(18); },
      "Failed to parse COSE_Sign1 tag");

    const auto& phdr = rethrow_with_msg(
      [&]() -> auto& { return cose_envelope->array_at(0); },
      "Failed to parse COSE_Sign1 protected header");

    const auto& payload = rethrow_with_msg(
      [&]() -> auto& { return cose_envelope->array_at(2); },
      "Failed to parse COSE_Sign1 payload");

    const auto& signature = rethrow_with_msg(
      [&]() -> auto& { return cose_envelope->array_at(3); },
      "Failed to parse COSE_Sign1 signature");

    std::vector<Value> edited;
    edited.push_back(phdr);

    if (std::holds_alternative<desc::Empty>(descriptor))
    {
      edited.push_back(make_map({}));
    }
    else if (std::holds_alternative<desc::Value>(descriptor))
    {
      const auto& [pos, key, value] = std::get<desc::Value>(descriptor);
      std::vector<MapItem> uhdr;

      if (std::holds_alternative<pos::InArray>(pos))
      {
        std::vector<Value> items{make_bytes(value)};
        uhdr.emplace_back(make_signed(key), make_array(std::move(items)));
      }
      else if (std::holds_alternative<pos::AtKey>(pos))
      {
        auto subkey = std::get<pos::AtKey>(pos).key;

        std::vector<Value> items{make_bytes(value)};
        std::vector<MapItem> submap{
          {make_signed(subkey), make_array(std::move(items))}};

        uhdr.emplace_back(make_signed(key), make_map(std::move(submap)));
      }
      else
      {
        throw std::logic_error("Invalid COSE_Sign1 edit operation");
      }

      edited.push_back(make_map(std::move(uhdr)));
    }
    else
    {
      throw std::logic_error("Invalid COSE_Sign1 edit descriptor");
    }

    edited.push_back(payload);
    edited.push_back(signature);

    auto edited_envelope = make_tagged(18, make_array(std::move(edited)));
    return serialize(edited_envelope);
  }
}