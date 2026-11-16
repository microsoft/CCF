// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose.h"
#include "ccf/crypto/cose_verifier.h"
#include "ccf/crypto/pem.h"
#include "crypto/cose.h"
#include "ds/internal_logger.h"
#include "ds/serialized.h"
#include "kv/kv_types.h"
#include "kv/serialised_entry_format.h"
#include "kv/store.h"
#include "node/cose_common.h"
#include "node/history.h"
#include "node/rpc/network_identity_chain_helpers.h"

#include <nlohmann/json.hpp>

namespace ccf
{
  struct StartupSnapshotInfo
  {
    ccf::kv::Version seqno;
    std::vector<uint8_t> raw;

    StartupSnapshotInfo(ccf::kv::Version s, std::vector<uint8_t>&& r) :
      seqno(s),
      raw(std::move(r))
    {}
  };

  struct SnapshotSegments
  {
    std::span<const uint8_t> header_and_body;
    std::span<const uint8_t> receipt;
  };

  static SnapshotSegments separate_segments(
    const std::vector<uint8_t>& snapshot)
  {
    const auto* data = snapshot.data();
    auto size = snapshot.size();

    auto tx_hdr = serialized::peek<ccf::kv::SerialisedEntryHeader>(data, size);
    auto store_snapshot_size =
      sizeof(ccf::kv::SerialisedEntryHeader) + tx_hdr.size;

    if (tx_hdr.size == 0)
    {
      throw std::logic_error("Snapshot transaction size should not be zero");
    }

    if (store_snapshot_size > size)
    {
      throw std::invalid_argument(fmt::format(
        "Snapshot transaction header claims size {} which exceeds available "
        "buffer size {}",
        store_snapshot_size,
        size));
    }

    const auto* receipt_data = data + store_snapshot_size;
    auto receipt_size = size - store_snapshot_size;

    if (receipt_size == 0)
    {
      throw std::logic_error("No receipt included in snapshot");
    }

    std::span<const uint8_t> header_and_body{data, store_snapshot_size};
    std::span<const uint8_t> receipt{receipt_data, receipt_size};

    return SnapshotSegments{header_and_body, receipt};
  }

  static void verify_snapshot_seqno(
    const SnapshotSegments& segments,
    const std::shared_ptr<ccf::kv::AbstractTxEncryptor>& encryptor,
    ccf::kv::Version expected_seqno)
  {
    auto deserialiser = ccf::kv::RawKvStoreDeserialiser(
      encryptor, ccf::kv::SecurityDomain::PUBLIC);
    ccf::kv::Term term = 0;
    ccf::kv::EntryFlags flags = {};
    const auto snapshot_seqno = deserialiser.init(
      segments.header_and_body.data(),
      segments.header_and_body.size(),
      term,
      flags,
      false);
    if (!snapshot_seqno.has_value())
    {
      throw std::logic_error("Failed to read version from recovery snapshot");
    }
    if (*snapshot_seqno != expected_seqno)
    {
      throw std::logic_error(fmt::format(
        "Recovery snapshot body is at seqno {}, but its file name claims {}",
        *snapshot_seqno,
        expected_seqno));
    }
  }

  // Validates the collected COSE endorsement chain against the configured
  // previous service identity (target_key) and returns the snapshot signer
  // key: the identity, active at snapshot_seqno, that signed the snapshot
  // receipt. The oldest endorsement covers snapshot_seqno and endorses that
  // key, so it is captured as the endorsed key of the first (oldest) link.
  static std::vector<uint8_t> validate_recovery_snapshot_endorsement_chain(
    const std::vector<CollectedCoseEndorsement>& collected,
    std::span<const uint8_t> target_key,
    ccf::kv::Version snapshot_seqno)
  {
    if (collected.empty())
    {
      throw std::logic_error(
        "No previous service identity endorsements were found after the "
        "snapshot");
    }

    std::vector<uint8_t> snapshot_signer_key;
    std::vector<uint8_t> previous_endorsing_key;
    for (size_t i = 0; i < collected.size(); ++i)
    {
      const auto& [write_version, endorsement] = collected[i];
      if (write_version <= snapshot_seqno)
      {
        throw std::logic_error(fmt::format(
          "Collected endorsement write at {} is not after snapshot seqno {}",
          write_version,
          snapshot_seqno));
      }
      if (is_self_endorsement(endorsement))
      {
        throw std::logic_error(fmt::format(
          "Unexpected self-endorsement after snapshot at {}",
          endorsement.endorsement_epoch_begin.to_str()));
      }
      if (has_ill_formed_epoch_range(endorsement))
      {
        throw std::logic_error(fmt::format(
          "Collected endorsement has an ill-formed epoch range {} - {}",
          endorsement.endorsement_epoch_begin.to_str(),
          format_epoch(endorsement.endorsement_epoch_end)));
      }

      validate_fetched_endorsement(endorsement);

      if (i == 0)
      {
        if (
          !endorsement.previous_version.has_value() ||
          endorsement.previous_version.value() > snapshot_seqno)
        {
          throw std::logic_error(fmt::format(
            "Oldest collected endorsement at {} does not point to an "
            "endorsement at or before snapshot seqno {}",
            write_version,
            snapshot_seqno));
        }
      }
      else
      {
        const auto& previous = collected[i - 1];
        if (
          !endorsement.previous_version.has_value() ||
          endorsement.previous_version.value() != previous.write_version)
        {
          throw std::logic_error(fmt::format(
            "Collected endorsement at {} does not point to the previous "
            "collected endorsement at {}",
            write_version,
            previous.write_version));
        }
        verify_endorsements_connected(endorsement, previous.endorsement);
      }

      const auto endorsed_key = verify_cose_endorsement_signature(
        endorsement.endorsement, endorsement.endorsing_key);
      if (i == 0)
      {
        // The oldest endorsement covers snapshot_seqno; the key it endorses is
        // the identity that signed the snapshot receipt.
        snapshot_signer_key = endorsed_key;
      }
      if (
        !previous_endorsing_key.empty() &&
        endorsed_key != previous_endorsing_key)
      {
        throw std::logic_error(fmt::format(
          "Collected endorsement at {} does not endorse the preceding service "
          "identity",
          write_version));
      }
      previous_endorsing_key = endorsement.endorsing_key;
    }

    if (
      previous_endorsing_key.size() != target_key.size() ||
      !std::equal(
        previous_endorsing_key.begin(),
        previous_endorsing_key.end(),
        target_key.begin()))
    {
      throw std::logic_error(
        "Newest collected endorsement is not signed by the configured "
        "previous service identity");
    }

    const auto& oldest = collected.front().endorsement;
    if (
      !oldest.endorsement_epoch_end.has_value() ||
      oldest.endorsement_epoch_begin.seqno > snapshot_seqno ||
      oldest.endorsement_epoch_end->seqno < snapshot_seqno)
    {
      throw std::logic_error(fmt::format(
        "Oldest collected endorsement range {} - {} does not cover snapshot "
        "seqno {}",
        oldest.endorsement_epoch_begin.to_str(),
        format_epoch(oldest.endorsement_epoch_end),
        snapshot_seqno));
    }

    return snapshot_signer_key;
  }

  static auto decode_and_verify_cose_snapshot_receipt(
    const SnapshotSegments& segments)
  {
    if (segments.receipt.empty())
    {
      throw std::logic_error("Empty snapshot receipt");
    }

    constexpr uint8_t ENCODED_COSE_SIGN1_TAG = 0xD2;
    if (segments.receipt[0] != ENCODED_COSE_SIGN1_TAG)
    {
      throw std::logic_error("Snapshot receipt is not a COSE_Sign1 receipt");
    }

    auto receipt = ccf::cose::decode_ccf_receipt(
      {segments.receipt.begin(), segments.receipt.end()},
      /* recompute_root */ true);

    auto snapshot_digest = ccf::crypto::Sha256Hash(
      segments.header_and_body.data(), segments.header_and_body.size());
    if (
      receipt.claims_digest.size() != ccf::crypto::Sha256Hash::SIZE ||
      std::memcmp(
        snapshot_digest.h.data(),
        receipt.claims_digest.data(),
        ccf::crypto::Sha256Hash::SIZE) != 0)
    {
      throw std::logic_error(fmt::format(
        "Snapshot digest ({}) does not match receipt claim ({})",
        snapshot_digest,
        ds::to_hex(receipt.claims_digest)));
    }

    return receipt;
  }

  static void verify_snapshot(
    const SnapshotSegments& segments,
    const std::optional<std::vector<uint8_t>>& prev_service_identity =
      std::nullopt)
  {
    LOG_INFO_FMT(
      "Deserialising snapshot receipt (size: {}).", segments.receipt.size());
    constexpr size_t max_printed_size = 1024;
    if (segments.receipt.size() > max_printed_size)
    {
      LOG_INFO_FMT(
        "Receipt size ({}) exceeds max printed size ({}), only printing "
        "first {} bytes",
        segments.receipt.size(),
        max_printed_size,
        max_printed_size);
    }
    auto printed_size =
      std::min<size_t>(segments.receipt.size(), max_printed_size);
    LOG_INFO_FMT(
      "{}",
      ds::to_hex(
        segments.receipt.data(), segments.receipt.data() + printed_size));

    const auto receipt = decode_and_verify_cose_snapshot_receipt(segments);

    if (prev_service_identity)
    {
      auto verifier = ccf::crypto::make_cose_verifier_from_pem_cert(
        ccf::crypto::Pem(*prev_service_identity));
      if (!verifier->verify_detached(segments.receipt, receipt.merkle_root))
      {
        throw std::logic_error(
          "Previous service identity does not match the service identity that "
          "signed the snapshot");
      }
      LOG_DEBUG_FMT("Previous service identity matches snapshot signer");
    }
  }

  static void deserialise_snapshot(
    const std::shared_ptr<ccf::kv::Store>& store,
    const SnapshotSegments& segments,
    ccf::kv::ConsensusHookPtrs& hooks,
    std::vector<ccf::kv::Version>* view_history = nullptr,
    bool public_only = false)
  {
    const auto* data = segments.header_and_body.data();
    const auto size = segments.header_and_body.size();

    // Log full size as this snapshot appears in file, but after that ignore the
    // receipt segment
    LOG_INFO_FMT(
      "Deserialising snapshot (size: {}, public only: {})",
      size + segments.receipt.size(),
      public_only);

    auto rc =
      store->deserialise_snapshot(data, size, hooks, view_history, public_only);
    if (rc != ccf::kv::ApplyResult::PASS)
    {
      throw std::logic_error(fmt::format("Failed to apply snapshot: {}", rc));
    }

    LOG_INFO_FMT(
      "Snapshot successfully deserialised at seqno {}",
      store->current_version());
  };

  static void deserialise_snapshot(
    const std::shared_ptr<ccf::kv::Store>& store,
    const std::vector<uint8_t>& snapshot,
    ccf::kv::ConsensusHookPtrs& hooks,
    std::vector<ccf::kv::Version>* view_history = nullptr,
    bool public_only = false)
  {
    const auto segments = separate_segments(snapshot);
    deserialise_snapshot(store, segments, hooks, view_history, public_only);
  }

  // As deserialise_snapshot() with public_only, also returning the public maps
  // captured from it, so that the private domain can later be deserialised
  // without a second copy of the public state (see
  // deserialise_snapshot_in_place()).
  static ccf::kv::Store::SnapshotPublicMaps
  deserialise_public_snapshot_capturing(
    const std::shared_ptr<ccf::kv::Store>& store,
    const SnapshotSegments& segments,
    ccf::kv::ConsensusHookPtrs& hooks,
    std::vector<ccf::kv::Version>* view_history)
  {
    const auto* data = segments.header_and_body.data();
    const auto size = segments.header_and_body.size();

    LOG_INFO_FMT(
      "Deserialising snapshot (size: {}, public only: true, capturing public "
      "maps)",
      size + segments.receipt.size());

    std::optional<ccf::kv::Store::SnapshotPublicMaps> captured;
    auto rc = store->deserialise_public_snapshot_capturing(
      data, size, hooks, view_history, captured);
    if (rc != ccf::kv::ApplyResult::PASS || !captured.has_value())
    {
      throw std::logic_error(fmt::format("Failed to apply snapshot: {}", rc));
    }

    LOG_INFO_FMT(
      "Snapshot successfully deserialised at seqno {}",
      store->current_version());
    return std::move(captured.value());
  }

  // As deserialise_snapshot(), for all domains, but decrypts the private
  // domain in place in snapshot, whose contents are unspecified afterwards. If
  // public_maps is set, it must have been captured from this snapshot by
  // deserialise_public_snapshot_capturing(), and its states are installed
  // rather than deserialised again.
  static void deserialise_snapshot_in_place(
    const std::shared_ptr<ccf::kv::Store>& store,
    std::vector<uint8_t>& snapshot,
    ccf::kv::ConsensusHookPtrs& hooks,
    std::vector<ccf::kv::Version>* view_history = nullptr,
    const ccf::kv::Store::SnapshotPublicMaps* public_maps = nullptr)
  {
    const auto segments = separate_segments(snapshot);
    // segments views snapshot, so this is the same range, writable
    const auto header_and_body = std::span<uint8_t>(snapshot).subspan(
      static_cast<size_t>(segments.header_and_body.data() - snapshot.data()),
      segments.header_and_body.size());

    LOG_INFO_FMT(
      "Deserialising snapshot (size: {}, public only: false, in place, "
      "reusing captured public maps: {})",
      snapshot.size(),
      public_maps != nullptr);

    auto rc = store->deserialise_snapshot_in_place(
      header_and_body, hooks, view_history, public_maps);
    if (rc != ccf::kv::ApplyResult::PASS)
    {
      throw std::logic_error(fmt::format("Failed to apply snapshot: {}", rc));
    }

    LOG_INFO_FMT(
      "Snapshot successfully deserialised at seqno {}",
      store->current_version());
  }

  // Builds the COSE receipt of a snapshot evidence transaction from the
  // signature of the given identity type and the Merkle proof of the evidence
  // transaction in the signed tree
  static std::vector<uint8_t> build_and_serialise_receipt(
    const CoseSignatureMap& cose_sigs,
    IdentityType identity_type,
    const std::vector<uint8_t>& tree,
    ccf::kv::Version seqno,
    const ccf::crypto::Sha256Hash& write_set_digest,
    const std::string& commit_evidence,
    const ccf::crypto::Sha256Hash& claims_digest)
  {
    const auto cose_signature = cose_sigs.find(identity_type);
    if (cose_signature == cose_sigs.end())
    {
      throw std::logic_error(fmt::format(
        "No {} COSE signature available for snapshot receipt",
        nlohmann::json(identity_type).dump()));
    }

    ccf::MerkleTreeHistory history(tree);
    auto proof = history.get_proof(seqno);
    const auto merkle_proof = encode_merkle_proof(
      write_set_digest, commit_evidence, claims_digest, *proof.get_path());

    ccf::cose::edit::desc::Value desc{
      ccf::cose::edit::pos::AtKey{ccf::cose::header::iana::INCLUSION_PROOFS},
      ccf::cose::header::iana::VDP,
      merkle_proof};
    return ccf::cose::edit::set_unprotected_header(
      cose_signature->second, desc);
  }
}
