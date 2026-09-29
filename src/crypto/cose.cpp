// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/cose.h"

#include "ccf/crypto/ec_key_pair.h"
#include "ccf/crypto/ecdsa.h"
#include "crypto/cbor_tags.h"
#include "crypto/cose.h"

#include <stdexcept>
#include <tav/cbor.hpp>
#include <vector>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ccf::cose
{
  std::vector<uint8_t> make_cose_sign1_tbs(
    std::span<const uint8_t> protected_header, std::span<const uint8_t> payload)
  {
    using namespace tav::cbor;
    std::vector<Value> fields;
    fields.reserve(4);
    fields.push_back(make_string("Signature1"));
    fields.push_back(make_bytes(protected_header));
    fields.push_back(make_bytes({}));
    fields.push_back(make_bytes(payload));
    return make_array(std::move(fields)).det_serialize();
  }

  std::vector<uint8_t> make_cose_sign1_envelope(
    std::span<const uint8_t> protected_header,
    std::span<const uint8_t> payload,
    std::span<const uint8_t> signature,
    bool detached)
  {
    using namespace tav::cbor;
    std::vector<Value> fields;
    fields.push_back(make_bytes(protected_header));
    fields.push_back(make_map({}));
    fields.push_back(
      detached ? make_simple(SimpleValue::Null) : make_bytes(payload));
    fields.push_back(make_bytes(signature));
    return make_tagged(
             ccf::cbor::tag::COSE_SIGN_1, make_array(std::move(fields)))
      .det_serialize();
  }

  namespace
  {
    std::vector<uint8_t> sign1(
      const crypto::ECKeyPair& key,
      crypto::MDType md,
      const tav::cbor::Value& protected_header,
      std::span<const uint8_t> payload,
      bool detached)
    {
      const auto protected_bytes = protected_header.det_serialize();
      const auto tbs = make_cose_sign1_tbs(protected_bytes, payload);
      const auto der_signature = key.sign(tbs, md);
      if (der_signature.empty())
      {
        throw std::runtime_error("COSE signing returned an empty signature");
      }
      const auto signature =
        crypto::ecdsa_sig_der_to_p1363(der_signature, key.get_curve_id());

      return make_cose_sign1_envelope(
        protected_bytes, payload, signature, detached);
    }

    struct SigningAlgorithm
    {
      int64_t alg;
      crypto::MDType md;
    };

    SigningAlgorithm algorithm_for_curve(crypto::CurveID curve)
    {
      switch (curve)
      {
        case crypto::CurveID::SECP256R1:
          return {alg::ES256, crypto::MDType::SHA256};
        case crypto::CurveID::SECP384R1:
          return {alg::ES384, crypto::MDType::SHA384};
        case crypto::CurveID::SECP521R1:
          return {alg::ES512, crypto::MDType::SHA512};
        case crypto::CurveID::NONE:
        case crypto::CurveID::CURVE25519:
        case crypto::CurveID::X25519:
        default:
          throw std::runtime_error("Unsupported COSE signing curve");
      }
    }
  }

  std::vector<uint8_t> sign_ledger(
    const crypto::ECKeyPair& key,
    std::string_view kid,
    int64_t iat,
    std::string_view issuer,
    std::string_view subject,
    std::string_view txid,
    std::span<const uint8_t> payload)
  {
    using namespace tav::cbor;
    const auto algorithm = algorithm_for_curve(key.get_curve_id());
    std::vector<MapItem> cwt_entries;
    cwt_entries.emplace_back(
      make_signed(cwt::header::iana::IAT), make_signed(iat));
    cwt_entries.emplace_back(
      make_signed(cwt::header::iana::ISS), make_string(issuer));
    cwt_entries.emplace_back(
      make_signed(cwt::header::iana::SUB), make_string(subject));
    std::vector<MapItem> ccf_entries;
    ccf_entries.emplace_back(
      make_string(header::custom::TX_ID), make_string(txid));
    std::vector<MapItem> phdr;
    phdr.emplace_back(
      make_signed(header::iana::ALG), make_signed(algorithm.alg));
    phdr.emplace_back(
      make_signed(header::iana::KID),
      make_bytes({reinterpret_cast<const uint8_t*>(kid.data()), kid.size()}));
    phdr.emplace_back(
      make_signed(header::iana::VDS), make_signed(value::CCF_LEDGER_SHA256));
    phdr.emplace_back(
      make_signed(header::iana::CWT_CLAIMS), make_map(std::move(cwt_entries)));
    phdr.emplace_back(
      make_string(header::custom::CCF_V1), make_map(std::move(ccf_entries)));
    return sign1(key, algorithm.md, make_map(std::move(phdr)), payload, true);
  }

  std::vector<uint8_t> sign_endorsement(
    const crypto::ECKeyPair& key,
    int64_t iat,
    std::string_view epoch_begin,
    std::string_view epoch_end,
    std::span<const uint8_t> previous_merkle_root,
    std::span<const uint8_t> payload)
  {
    using namespace tav::cbor;
    const auto algorithm = algorithm_for_curve(key.get_curve_id());
    std::vector<MapItem> cwt_entries;
    cwt_entries.emplace_back(
      make_signed(cwt::header::iana::IAT), make_signed(iat));
    std::vector<MapItem> ccf_entries;
    ccf_entries.emplace_back(
      make_string(header::custom::TX_RANGE_BEGIN), make_string(epoch_begin));
    if (!epoch_end.empty())
    {
      ccf_entries.emplace_back(
        make_string(header::custom::TX_RANGE_END), make_string(epoch_end));
    }
    if (!previous_merkle_root.empty())
    {
      ccf_entries.emplace_back(
        make_string(header::custom::EPOCH_LAST_MERKLE_ROOT),
        make_bytes(previous_merkle_root));
    }
    std::vector<MapItem> phdr;
    phdr.emplace_back(
      make_signed(header::iana::ALG), make_signed(algorithm.alg));
    phdr.emplace_back(
      make_signed(header::iana::CWT_CLAIMS), make_map(std::move(cwt_entries)));
    phdr.emplace_back(
      make_string(header::custom::CCF_V1), make_map(std::move(ccf_entries)));
    return sign1(key, algorithm.md, make_map(std::move(phdr)), payload, false);
  }
}

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