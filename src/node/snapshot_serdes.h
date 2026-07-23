// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose.h"
#include "ccf/crypto/cose_verifier.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/json.h"
#include "ccf/historical_queries_adapter.h"
#include "ccf/receipt.h"
#include "ccf/service/tables/nodes.h"
#include "crypto/cbor.h"
#include "crypto/cose.h"
#include "ds/files.h"
#include "ds/internal_logger.h"
#include "ds/serialized.h"
#include "kv/kv_types.h"
#include "kv/serialised_entry_format.h"
#include "node/cose_common.h"
#include "node/history.h"
#include "node/rpc/network_identity_chain_helpers.h"
#include "node/tx_receipt_impl.h"
#include "snapshots/filenames.h"

#include <fstream>
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

  static constexpr size_t MAX_SNAPSHOT_ENDORSEMENTS_SIZE = 16 * 1024 * 1024;
  static constexpr size_t MAX_SNAPSHOT_ENDORSEMENTS_COUNT = 64;
  static constexpr size_t MAX_SNAPSHOT_ENDORSEMENT_SIZE = 1024 * 1024;
  static constexpr size_t MAX_SNAPSHOT_ENDORSEMENTS_PAYLOAD_SIZE =
    4 * 1024 * 1024;

  template <typename Endorsements>
  static void validate_cose_endorsement_resource_limits(
    const Endorsements& endorsements)
  {
    if (endorsements.size() > MAX_SNAPSHOT_ENDORSEMENTS_COUNT)
    {
      throw std::logic_error(fmt::format(
        "Snapshot endorsements sidecar contains too many endorsements ({}; "
        "maximum {})",
        endorsements.size(),
        MAX_SNAPSHOT_ENDORSEMENTS_COUNT));
    }

    size_t payload_size = 0;
    for (size_t i = 0; i < endorsements.size(); ++i)
    {
      const auto endorsement_size = endorsements[i].size();
      if (endorsement_size > MAX_SNAPSHOT_ENDORSEMENT_SIZE)
      {
        throw std::logic_error(fmt::format(
          "Snapshot endorsement at index {} is too large ({} bytes; maximum "
          "{} bytes)",
          i,
          endorsement_size,
          MAX_SNAPSHOT_ENDORSEMENT_SIZE));
      }
      if (
        endorsement_size >
        MAX_SNAPSHOT_ENDORSEMENTS_PAYLOAD_SIZE - payload_size)
      {
        throw std::logic_error(fmt::format(
          "Snapshot endorsements payload is too large (maximum {} bytes)",
          MAX_SNAPSHOT_ENDORSEMENTS_PAYLOAD_SIZE));
      }
      payload_size += endorsement_size;
    }
  }

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

  static std::vector<uint8_t> serialise_cose_endorsements(
    const ccf::SerialisedCoseEndorsements& endorsements)
  {
    validate_cose_endorsement_resource_limits(endorsements);

    std::vector<ccf::cbor::Value> items;
    items.reserve(endorsements.size());
    for (const auto& endorsement : endorsements)
    {
      items.emplace_back(ccf::cbor::make_bytes(endorsement));
    }

    return ccf::cbor::serialize(ccf::cbor::make_array(std::move(items)));
  }

  static ccf::SerialisedCoseEndorsements deserialise_cose_endorsements(
    std::span<const uint8_t> serialised)
  {
    const auto parsed = ccf::cbor::rethrow_with_msg(
      [&]() {
        return ccf::cbor::parse(
          serialised, 16, MAX_SNAPSHOT_ENDORSEMENTS_COUNT);
      },
      "Parse snapshot endorsements sidecar");
    if (!std::holds_alternative<ccf::cbor::Array>(parsed->value))
    {
      throw std::logic_error(
        "Snapshot endorsements sidecar must contain a CBOR array");
    }

    std::vector<std::span<const uint8_t>> endorsement_spans;
    endorsement_spans.reserve(parsed->size());
    for (size_t i = 0; i < parsed->size(); ++i)
    {
      const auto bytes = ccf::cbor::rethrow_with_msg(
        [&]() { return parsed->array_at(i)->as_bytes(); },
        fmt::format("Parse snapshot endorsement at index {}", i));
      endorsement_spans.emplace_back(bytes);
    }
    validate_cose_endorsement_resource_limits(endorsement_spans);

    ccf::SerialisedCoseEndorsements endorsements;
    endorsements.reserve(endorsement_spans.size());
    for (const auto endorsement : endorsement_spans)
    {
      endorsements.emplace_back(endorsement.begin(), endorsement.end());
    }
    return endorsements;
  }

  template <typename Prepare, typename Install>
  static std::optional<std::string>
  try_prepare_and_install_recovery_snapshot(
    Prepare&& prepare, Install&& install)
  {
    try
    {
      prepare();
    }
    catch (const std::exception& e)
    {
      return e.what();
    }

    install();
    return std::nullopt;
  }

  static ccf::SerialisedCoseEndorsements read_cose_endorsements_sidecar(
    const std::filesystem::path& path)
  {
    std::error_code ec;
    const auto file_size = std::filesystem::file_size(path, ec);
    if (ec)
    {
      throw std::logic_error(fmt::format(
        "Unable to read snapshot endorsements sidecar size {}: {}",
        path.string(),
        ec.message()));
    }
    if (file_size > MAX_SNAPSHOT_ENDORSEMENTS_SIZE)
    {
      throw std::logic_error(fmt::format(
        "Snapshot endorsements sidecar {} is too large ({} bytes, maximum "
        "{} bytes)",
        path.string(),
        file_size,
        MAX_SNAPSHOT_ENDORSEMENTS_SIZE));
    }

    std::ifstream file(path, std::ios::binary);
    if (!file)
    {
      throw std::logic_error(fmt::format(
        "Unable to open snapshot endorsements sidecar {}", path.string()));
    }

    std::vector<uint8_t> serialised(static_cast<size_t>(file_size));
    if (!serialised.empty())
    {
      file.read(
        reinterpret_cast<char*>(serialised.data()),
        static_cast<std::streamsize>(serialised.size()));
      if (
        !file ||
        file.gcount() != static_cast<std::streamsize>(serialised.size()))
      {
        throw std::logic_error(fmt::format(
          "Unable to read complete snapshot endorsements sidecar {}",
          path.string()));
      }
    }

    return deserialise_cose_endorsements(serialised);
  }

  static void write_cose_endorsements_sidecar(
    const std::filesystem::path& path,
    const ccf::SerialisedCoseEndorsements& endorsements)
  {
    if (std::filesystem::exists(path))
    {
      throw std::logic_error(fmt::format(
        "Refusing to overwrite existing snapshot endorsements sidecar {}",
        path.string()));
    }

    const auto serialised = serialise_cose_endorsements(endorsements);
    if (serialised.size() > MAX_SNAPSHOT_ENDORSEMENTS_SIZE)
    {
      throw std::logic_error(fmt::format(
        "Snapshot endorsements sidecar is too large ({} bytes, maximum {} "
        "bytes)",
        serialised.size(),
        MAX_SNAPSHOT_ENDORSEMENTS_SIZE));
    }
    auto temporary_path = std::filesystem::path(path.string() + ".tmp");
    std::error_code ec;
    std::filesystem::remove(temporary_path, ec);

    try
    {
      files::dump(serialised, temporary_path);
      files::rename(temporary_path, path);
    }
    catch (const std::exception&)
    {
      std::filesystem::remove(temporary_path, ec);
      throw;
    }
  }

  static ccf::CoseEndorsement parse_serialised_cose_endorsement(
    const ccf::SerialisedCoseEndorsement& serialised)
  {
    const auto [from, to] =
      ccf::crypto::extract_cose_endorsement_validity(serialised);
    const auto from_txid = ccf::TxID::from_str(from);
    const auto to_txid = ccf::TxID::from_str(to);
    if (!from_txid.has_value() || !to_txid.has_value())
    {
      throw std::logic_error(
        fmt::format("Invalid COSE endorsement epoch range {} - {}", from, to));
    }

    return ccf::CoseEndorsement{
      .endorsement = serialised,
      .endorsing_key = {},
      .endorsement_epoch_begin = *from_txid,
      .endorsement_epoch_end = *to_txid,
      .previous_version = ccf::kv::Version{0}};
  }

  static std::vector<uint8_t> verify_serialised_cose_endorsements(
    const ccf::SerialisedCoseEndorsements& endorsements,
    std::span<const uint8_t> target_key,
    ccf::kv::Version snapshot_seqno,
    std::optional<ccf::TxID> target_service_from = std::nullopt)
  {
    if (target_key.empty())
    {
      throw std::logic_error(
        "Cannot verify snapshot endorsements with an empty target key");
    }
    if (endorsements.empty())
    {
      return {target_key.begin(), target_key.end()};
    }

    std::vector<uint8_t> current_key(target_key.begin(), target_key.end());
    std::vector<ccf::CoseEndorsement> parsed;
    parsed.reserve(endorsements.size());

    for (const auto& endorsement : endorsements)
    {
      auto parsed_endorsement = parse_serialised_cose_endorsement(endorsement);
      if (has_ill_formed_epoch_range(parsed_endorsement))
      {
        throw std::logic_error(fmt::format(
          "COSE endorsement has an ill-formed epoch range {} - {}",
          parsed_endorsement.endorsement_epoch_begin.to_str(),
          format_epoch(parsed_endorsement.endorsement_epoch_end)));
      }

      current_key = verify_cose_endorsement_signature(endorsement, current_key);
      parsed.emplace_back(std::move(parsed_endorsement));
    }

    for (size_t i = 0; i + 1 < parsed.size(); ++i)
    {
      verify_endorsements_connected(parsed[i], parsed[i + 1]);
    }

    if (target_service_from.has_value())
    {
      validate_chain_front_connection(parsed.front(), *target_service_from);
    }

    const auto& oldest = parsed.back();
    if (
      !oldest.endorsement_epoch_end.has_value() ||
      oldest.endorsement_epoch_begin.seqno > snapshot_seqno ||
      oldest.endorsement_epoch_end->seqno < snapshot_seqno)
    {
      throw std::logic_error(fmt::format(
        "Oldest COSE endorsement range {} - {} does not cover snapshot seqno "
        "{}",
        oldest.endorsement_epoch_begin.to_str(),
        format_epoch(oldest.endorsement_epoch_end),
        snapshot_seqno));
    }

    return current_key;
  }

  static ccf::SerialisedCoseEndorsements
  validate_and_serialise_collected_endorsements(
    const std::vector<CollectedCoseEndorsement>& collected,
    std::span<const uint8_t> target_key,
    ccf::kv::Version snapshot_seqno,
    const ccf::TxID& target_service_from)
  {
    if (collected.empty())
    {
      throw std::logic_error(
        "No previous service identity endorsements were found after the "
        "snapshot");
    }

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
      if (
        !previous_endorsing_key.empty() &&
        endorsed_key != previous_endorsing_key)
      {
        throw std::logic_error(fmt::format(
          "Collected endorsement at {} does not endorse the preceding "
          "service identity",
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

    validate_chain_front_connection(
      collected.back().endorsement, target_service_from);

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

    ccf::SerialisedCoseEndorsements serialised;
    serialised.reserve(collected.size());
    for (auto it = collected.rbegin(); it != collected.rend(); ++it)
    {
      serialised.emplace_back(it->endorsement.endorsement);
    }
    return serialised;
  }

  static auto decode_and_verify_cose_snapshot_receipt(
    const SnapshotSegments& segments)
  {
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

  static void verify_cose_snapshot_receipt(
    const SnapshotSegments& segments,
    const std::optional<std::vector<uint8_t>>& prev_service_identity)
  {
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

  static void verify_json_snapshot_receipt(
    const SnapshotSegments& segments,
    const std::optional<std::vector<uint8_t>>& prev_service_identity)
  {
    auto j =
      ccf::parse_json_safe(segments.receipt.begin(), segments.receipt.end());
    auto receipt_p = j.get<ReceiptPtr>();
    auto receipt = std::dynamic_pointer_cast<ccf::ProofReceipt>(receipt_p);
    if (receipt == nullptr)
    {
      throw std::logic_error(
        "Unexpected receipt type: missing expanded claims");
    }

    auto snapshot_digest = ccf::crypto::Sha256Hash(
      segments.header_and_body.data(), segments.header_and_body.size());
    auto snapshot_digest_claim = receipt->leaf_components.claims_digest.value();
    if (snapshot_digest != snapshot_digest_claim)
    {
      throw std::logic_error(fmt::format(
        "Snapshot digest ({}) does not match receipt claim ({})",
        snapshot_digest,
        snapshot_digest_claim));
    }

    auto root = receipt->calculate_root();

    auto v = ccf::crypto::make_unique_verifier(receipt->cert);
    if (!v->verify_hash(
          root.h.data(),
          root.h.size(),
          receipt->signature.data(),
          receipt->signature.size(),
          ccf::crypto::MDType::SHA256))
    {
      throw std::logic_error(
        "Signature verification failed for snapshot receipt");
    }

    if (prev_service_identity)
    {
      ccf::crypto::Pem prev_pem(*prev_service_identity);
      if (!v->verify_certificate(
            {&prev_pem}, {}, true /* ignore_time */
            ))
      {
        throw std::logic_error(
          "Previous service identity does not endorse the node identity "
          "that signed the snapshot");
      }
      LOG_DEBUG_FMT("Previous service identity endorses snapshot signer");
    }
  }

  static void verify_snapshot(
    const SnapshotSegments& segments,
    std::optional<std::vector<uint8_t>> prev_service_identity = std::nullopt)
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

    if (segments.receipt.empty())
    {
      throw std::logic_error("Empty snapshot receipt");
    }

    auto first_byte = segments.receipt[0];
    constexpr uint8_t ENCODED_COSE_SIGN1_TAG = 0xD2;
    if (first_byte == ENCODED_COSE_SIGN1_TAG)
    {
      LOG_DEBUG_FMT("Snapshot with COSE receipt detected");
      verify_cose_snapshot_receipt(segments, prev_service_identity);
    }
    else if (first_byte == '{')
    {
      LOG_DEBUG_FMT("Snapshot with JSON receipt detected");
      verify_json_snapshot_receipt(segments, prev_service_identity);
    }
    else
    {
      throw std::logic_error(fmt::format(
        "Invalid snapshot receipt: unrecognised format (first byte: "
        "0x{:02X})",
        first_byte));
    }
  }

  static void verify_recovery_snapshot(
    const SnapshotSegments& segments,
    const ccf::crypto::Pem& target_identity,
    const ccf::SerialisedCoseEndorsements& endorsements,
    ccf::kv::Version snapshot_seqno,
    std::optional<ccf::TxID> target_service_from = std::nullopt)
  {
    if (endorsements.empty())
    {
      verify_snapshot(segments, target_identity.raw());
      return;
    }
    if (segments.receipt.empty() || segments.receipt[0] != 0xD2)
    {
      throw std::logic_error(
        "Only snapshots with COSE receipts can use endorsement sidecars");
    }

    const auto target_key = ccf::crypto::public_key_der_from_cert(
      ccf::crypto::cert_pem_to_der(target_identity));
    const auto snapshot_signer_key = verify_serialised_cose_endorsements(
      endorsements, target_key, snapshot_seqno, target_service_from);
    const auto receipt = decode_and_verify_cose_snapshot_receipt(segments);
    const auto verifier =
      ccf::crypto::make_cose_verifier_from_key(snapshot_signer_key);
    if (!verifier->verify_detached(segments.receipt, receipt.merkle_root))
    {
      throw std::logic_error(
        "Snapshot receipt signature verification failed under the endorsed "
        "snapshot service identity");
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

  static std::vector<uint8_t> build_and_serialise_receipt(
    const std::vector<uint8_t>& cose_sig,
    const std::vector<uint8_t>& tree,
    ccf::kv::Version seqno,
    const ccf::crypto::Sha256Hash& write_set_digest,
    const std::string& commit_evidence,
    ccf::crypto::Sha256Hash&& claims_digest)
  {
    ccf::MerkleTreeHistory history(tree);
    auto proof = history.get_proof(seqno);
    ccf::ClaimsDigest cd;
    // NOLINTNEXTLINE(performance-move-const-arg)
    cd.set(std::move(claims_digest));
    ccf::TxReceiptImpl tx_receipt(
      {},
      cose_sig,
      proof.get_root(),
      proof.get_path(),
      {},
      std::nullopt,
      write_set_digest,
      commit_evidence,
      cd);

    // To be replaced with 'describe_cose_receipt' once 7700 is merged.
    auto cose_signature = ccf::describe_cose_signature_v1(tx_receipt);
    if (!cose_signature.has_value())
    {
      throw std::logic_error(
        "No COSE signature available for snapshot receipt");
    }
    auto merkle_proof = ccf::describe_merkle_proof_v1(tx_receipt);
    if (!merkle_proof.has_value())
    {
      return *cose_signature;
    }

    ccf::cose::edit::desc::Value desc{
      ccf::cose::edit::pos::AtKey{ccf::cose::header::iana::INCLUSION_PROOFS},
      ccf::cose::header::iana::VDP,
      *merkle_proof};
    return ccf::cose::edit::set_unprotected_header(*cose_signature, desc);
  }
}
