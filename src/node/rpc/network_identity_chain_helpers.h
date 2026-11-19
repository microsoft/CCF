// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose_verifier.h"
#include "ccf/ds/hex.h"
#include "ccf/tx_id.h"
#include "consensus/aft/cft_types.h"
#include "crypto/cbor_tags.h"
#include "crypto/cose.h"
#include "ds/internal_logger.h"
#include "service/tables/previous_service_identity.h"

#include <algorithm>
#include <fmt/format.h>
#include <span>
#include <stdexcept>
#include <string>
#include <tav/cbor.hpp>
#include <vector>

namespace ccf
{
  struct CollectedCoseEndorsement
  {
    ccf::kv::Version write_version = ccf::kv::NoVersion;
    ccf::CoseEndorsement endorsement;
  };

  inline std::string format_epoch(const std::optional<ccf::TxID>& epoch_end)
  {
    return epoch_end.has_value() ? epoch_end->to_str() : "null";
  }

  inline bool is_self_endorsement(const ccf::CoseEndorsement& endorsement)
  {
    return !endorsement.previous_version.has_value();
  }

  inline bool has_ill_formed_epoch_range(
    const ccf::CoseEndorsement& endorsement)
  {
    return endorsement.endorsement_epoch_end.has_value() &&
      endorsement.endorsement_epoch_end->seqno <
      endorsement.endorsement_epoch_begin.seqno;
  }

  inline void validate_fetched_endorsement(
    const ccf::CoseEndorsement& endorsement)
  {
    LOG_INFO_FMT(
      "Validating fetched endorsement from {} to {}",
      endorsement.endorsement_epoch_begin.to_str(),
      format_epoch(endorsement.endorsement_epoch_end));

    if (!is_self_endorsement(endorsement))
    {
      const auto [from, to] =
        ccf::crypto::extract_cose_endorsement_validity(endorsement.endorsement);

      const auto from_txid = ccf::TxID::from_str(from);
      if (!from_txid.has_value())
      {
        throw std::logic_error(fmt::format(
          "Cannot parse COSE endorsement header: {}",
          ccf::cose::header::custom::TX_RANGE_BEGIN));
      }

      const auto to_txid = ccf::TxID::from_str(to);
      if (!to_txid.has_value())
      {
        throw std::logic_error(fmt::format(
          "Cannot parse COSE endorsement header: {}",
          ccf::cose::header::custom::TX_RANGE_END));
      }

      if (!endorsement.endorsement_epoch_end.has_value())
      {
        throw std::logic_error(
          "COSE endorsement does not contain epoch end in the table entry");
      }
      if (
        endorsement.endorsement_epoch_begin != *from_txid ||
        *endorsement.endorsement_epoch_end != *to_txid)
      {
        throw std::logic_error(fmt::format(
          "COSE endorsement fetched but range is invalid, epoch begin {}, "
          "epoch end {}, header epoch begin: {}, header epoch end: {}",
          endorsement.endorsement_epoch_begin.to_str(),
          endorsement.endorsement_epoch_end->to_str(),
          from,
          to));
      }
    }
  }

  inline std::vector<uint8_t> verify_cose_endorsement_signature(
    std::span<const uint8_t> endorsement,
    std::span<const uint8_t> endorsing_key)
  {
    auto verifier = ccf::crypto::make_cose_verifier_from_key(endorsing_key);
    std::span<uint8_t> endorsed_key;
    if (!verifier->verify(endorsement, endorsed_key))
    {
      throw std::logic_error("COSE endorsement failed signature verification");
    }

    if (endorsed_key.empty())
    {
      throw std::logic_error("COSE endorsement contains an empty public key");
    }

    return {endorsed_key.begin(), endorsed_key.end()};
  }

  // Signed start of the validity range of an endorsement. Unlike
  // extract_cose_endorsement_validity, this does not require a signed end,
  // which a self-endorsement does not have.
  inline std::string extract_cose_endorsement_epoch_begin(
    std::span<const uint8_t> cose_msg)
  {
    using namespace tav::cbor;

    auto cose_cbor = rethrow_with_msg(
      [&]() { return nondet_parse(cose_msg); }, "Parse COSE CBOR");

    const auto cose_envelope = rethrow_with_msg(
      [&]() { return cose_cbor.tag_at(ccf::cbor::tag::COSE_SIGN_1); },
      "Parse COSE tag");

    const auto phdr_raw = rethrow_with_msg(
      [&]() { return cose_envelope.array_at(0); },
      "Parse raw protected header");

    auto phdr = rethrow_with_msg(
      [&]() { return nondet_parse(phdr_raw.as_bytes()); },
      "Decode protected header");

    const auto ccf_claims = rethrow_with_msg(
      [&]() {
        return phdr.map_at(make_string(ccf::cose::header::custom::CCF_V1));
      },
      "Retrieve CCF claims");

    const auto from = rethrow_with_msg(
      [&]() {
        return ccf_claims
          .map_at(make_string(ccf::cose::header::custom::TX_RANGE_BEGIN))
          .as_string();
      },
      "Retrieve epoch range begin");

    return std::string(from);
  }

  // A chain stops at the self-endorsement of its oldest service, which is not
  // part of the chain. Checks that it starts at expected_from, the oldest
  // epoch which the chain covers, and that expected_key, the key which the
  // chain trusts for that epoch, signed it over itself.
  inline void validate_self_endorsement(
    const ccf::CoseEndorsement& endorsement,
    const ccf::TxID& expected_from,
    std::span<const uint8_t> expected_key)
  {
    const auto from_str = endorsement.endorsement_epoch_begin.to_str();

    if (!is_self_endorsement(endorsement))
    {
      throw std::logic_error(
        fmt::format("Endorsement at {} is not a self-endorsement", from_str));
    }

    if (endorsement.endorsement_epoch_begin != expected_from)
    {
      throw std::logic_error(fmt::format(
        "Self-endorsement at {} does not start at the oldest endorsed epoch "
        "{}",
        from_str,
        expected_from.to_str()));
    }

    if (!std::equal(
          endorsement.endorsing_key.begin(),
          endorsement.endorsing_key.end(),
          expected_key.begin(),
          expected_key.end()))
    {
      throw std::logic_error(fmt::format(
        "Self-endorsement at {} is signed by public key {}, which is not the "
        "key {} trusted from that epoch",
        from_str,
        ccf::ds::to_hex(endorsement.endorsing_key),
        ccf::ds::to_hex(expected_key)));
    }

    std::vector<uint8_t> endorsed_key;
    try
    {
      endorsed_key = verify_cose_endorsement_signature(
        endorsement.endorsement, endorsement.endorsing_key);
    }
    catch (const std::exception&)
    {
      throw std::logic_error(fmt::format(
        "Self-endorsement at {} failed signature verification", from_str));
    }

    if (endorsed_key != endorsement.endorsing_key)
    {
      throw std::logic_error(fmt::format(
        "Self-endorsement at {} endorses public key {}, which is not the key "
        "which signed it",
        from_str,
        ccf::ds::to_hex(endorsed_key)));
    }

    // The signature is verified, so the header is safe to trust
    const auto signed_from =
      extract_cose_endorsement_epoch_begin(endorsement.endorsement);
    if (signed_from != from_str)
    {
      throw std::logic_error(fmt::format(
        "Self-endorsement at {} is signed for another epoch begin {}",
        from_str,
        signed_from));
    }
  }

  inline void verify_endorsements_connected(
    const ccf::CoseEndorsement& newer, const ccf::CoseEndorsement& older)
  {
    if (!older.endorsement_epoch_end.has_value())
    {
      throw std::logic_error(fmt::format(
        "COSE endorsement chain integrity is violated, previous endorsement "
        "from {} does not have an epoch end",
        older.endorsement_epoch_begin.to_str()));
    }

    if (
      newer.endorsement_epoch_begin.view - aft::starting_view_change !=
        older.endorsement_epoch_end->view ||
      newer.endorsement_epoch_begin.seqno - 1 !=
        older.endorsement_epoch_end->seqno)
    {
      throw std::logic_error(fmt::format(
        "COSE endorsement chain integrity is violated, previous endorsement "
        "epoch end {} is not chained with newer endorsement epoch begin {}",
        older.endorsement_epoch_end->to_str(),
        newer.endorsement_epoch_begin.to_str()));
    }
  }

  // Verify the newest endorsement immediately precedes the current service.
  inline void validate_chain_front_connection(
    const ccf::CoseEndorsement& newest, const ccf::TxID& current_service_from)
  {
    if (!newest.endorsement_epoch_end.has_value())
    {
      throw std::logic_error(fmt::format(
        "The last fetched endorsement at {} has no epoch end",
        newest.endorsement_epoch_begin.to_str()));
    }
    if (
      current_service_from.view - aft::starting_view_change !=
        newest.endorsement_epoch_end->view ||
      current_service_from.seqno - 1 != newest.endorsement_epoch_end->seqno)
    {
      throw std::logic_error(fmt::format(
        "COSE endorsement chain integrity is violated, the current service "
        "start at {} is not chained with previous endorsement ending at {}",
        current_service_from.to_str(),
        newest.endorsement_epoch_end->to_str()));
    }
  }
}
