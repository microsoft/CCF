// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/cose.h"

#include "crypto/cbor_tags.h"
#include "crypto/cose.h"

#include <stdexcept>
#include <tav/cbor.hpp>
#include <vector>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ccf::cose::edit
{
  std::vector<uint8_t> set_unprotected_header(
    const std::span<const uint8_t>& cose_input, const desc::Type& descriptor)
  {
    using namespace tav::cbor;

    const Value cose_cbor = rethrow_with_msg(
      [&]() { return nondet_parse(cose_input); }, "Failed to parse COSE_Sign1");

    const Value cose_envelope = rethrow_with_msg(
      [&]() { return cose_cbor.tag_at(ccf::cbor::tag::COSE_SIGN_1); },
      "Failed to parse COSE_Sign1 tag");

    const Value phdr = rethrow_with_msg(
      [&]() { return cose_envelope.array_at(0); },
      "Failed to parse COSE_Sign1 protected header");

    const Value payload = rethrow_with_msg(
      [&]() { return cose_envelope.array_at(2); },
      "Failed to parse COSE_Sign1 payload");

    const Value signature = rethrow_with_msg(
      [&]() { return cose_envelope.array_at(3); },
      "Failed to parse COSE_Sign1 signature");

    std::vector<Value> edited;
    edited.push_back(shallow_copy(phdr));

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
        std::vector<Value> items;
        items.push_back(make_bytes(value));
        uhdr.emplace_back(make_signed(key), make_array(std::move(items)));
      }
      else if (std::holds_alternative<pos::AtKey>(pos))
      {
        auto subkey = std::get<pos::AtKey>(pos).key;

        std::vector<Value> items;
        items.push_back(make_bytes(value));
        std::vector<MapItem> submap;
        submap.emplace_back(make_signed(subkey), make_array(std::move(items)));

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

    edited.push_back(shallow_copy(payload));
    edited.push_back(shallow_copy(signature));

    const Value edited_envelope =
      make_tagged(ccf::cbor::tag::COSE_SIGN_1, make_array(std::move(edited)));
    return edited_envelope.nondet_serialize();
  }

  std::vector<uint8_t> detach_payload(
    const std::span<const uint8_t>& cose_input)
  {
    using namespace tav::cbor;

    const Value cose_cbor = rethrow_with_msg(
      [&]() { return nondet_parse(cose_input); }, "Failed to parse COSE_Sign1");

    const Value cose_envelope = rethrow_with_msg(
      [&]() { return cose_cbor.tag_at(ccf::cbor::tag::COSE_SIGN_1); },
      "Failed to parse COSE_Sign1 tag");

    // COSE_Sign1 is exactly [protected, unprotected, payload, signature]
    // (RFC 9052 section 4.2). Reading the first four elements alone would
    // silently drop any extra element, so reject rather than rewrite.
    constexpr size_t cose_sign1_size = 4;
    const size_t envelope_size = rethrow_with_msg(
      [&]() { return cose_envelope.size(); },
      "Failed to parse COSE_Sign1 structure");
    if (envelope_size != cose_sign1_size)
    {
      throw DecodeError(
        Error::TYPE_MISMATCH,
        fmt::format(
          "COSE_Sign1 must be an array of {} elements, found {}",
          cose_sign1_size,
          envelope_size));
    }

    const Value phdr = rethrow_with_msg(
      [&]() { return cose_envelope.array_at(0); },
      "Failed to parse COSE_Sign1 protected header");

    const Value uhdr = rethrow_with_msg(
      [&]() { return cose_envelope.array_at(1); },
      "Failed to parse COSE_Sign1 unprotected header");

    const Value payload = rethrow_with_msg(
      [&]() { return cose_envelope.array_at(2); },
      "Failed to parse COSE_Sign1 payload");

    const bool payload_is_nil = payload.kind() == Kind::SIMPLE &&
      payload.as_simple() == SimpleValue::Null;
    if (payload.kind() != Kind::BYTES && !payload_is_nil)
    {
      throw DecodeError(
        Error::TYPE_MISMATCH,
        "COSE_Sign1 payload must be a byte string or nil");
    }

    const Value signature = rethrow_with_msg(
      [&]() { return cose_envelope.array_at(3); },
      "Failed to parse COSE_Sign1 signature");

    std::vector<Value> edited;
    edited.push_back(shallow_copy(phdr));
    edited.push_back(shallow_copy(uhdr));
    edited.push_back(make_simple(SimpleValue::Null));
    edited.push_back(shallow_copy(signature));

    const Value edited_envelope =
      make_tagged(ccf::cbor::tag::COSE_SIGN_1, make_array(std::move(edited)));
    return edited_envelope.nondet_serialize();
  }
}