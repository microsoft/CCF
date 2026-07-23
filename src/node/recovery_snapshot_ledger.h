// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/startup_config.h"
#include "ccf/service/tables/service.h"
#include "ds/internal_logger.h"
#include "host/ledger_filenames.h"
#include "kv/kv_serialiser.h"
#include "kv/serialised_entry_format.h"
#include "node/rpc/network_identity_chain_helpers.h"
#include "node/snapshot_serdes.h"
#include "service/tables/previous_service_identity.h"
#include "service/tables/signatures.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>

namespace ccf
{
  struct RecoverySnapshotLedgerEntry
  {
    ccf::kv::Version version = 0;
    bool is_signature = false;
    std::optional<ccf::CoseEndorsement> endorsement = std::nullopt;
    std::optional<ccf::ServiceInfo> service_info = std::nullopt;
  };

  struct RecoverySnapshotLedgerScan
  {
    ccf::kv::Version last_signed_idx = 0;
    std::vector<CollectedCoseEndorsement> endorsements;
    std::optional<std::pair<ccf::kv::Version, ccf::ServiceInfo>>
      latest_service_info = std::nullopt;
  };

  static RecoverySnapshotLedgerEntry parse_recovery_snapshot_ledger_entry(
    const std::vector<uint8_t>& entry,
    const std::shared_ptr<ccf::kv::AbstractTxEncryptor>& encryptor)
  {
    auto deserialiser = ccf::kv::RawKvStoreDeserialiser(
      encryptor, ccf::kv::SecurityDomain::PUBLIC);
    ccf::kv::Term term = 0;
    ccf::kv::EntryFlags flags = {};
    const auto version =
      deserialiser.init(entry.data(), entry.size(), term, flags, false);
    if (!version.has_value())
    {
      throw std::logic_error(
        "Failed to initialise public ledger entry deserialiser");
    }

    RecoverySnapshotLedgerEntry result;
    result.version = *version;
    size_t map_count = 0;
    bool has_signature = false;
    bool has_cose_signature = false;
    bool has_serialised_tree = false;

    for (auto map_name = deserialiser.start_map(); map_name.has_value();
         map_name = deserialiser.start_map())
    {
      ++map_count;
      std::ignore = deserialiser.deserialise_entry_version();

      const auto read_count = deserialiser.deserialise_read_header();
      for (size_t i = 0; i < read_count; ++i)
      {
        std::ignore = deserialiser.deserialise_read();
      }

      const auto write_count = deserialiser.deserialise_write_header();
      if (write_count > 0)
      {
        has_signature = has_signature || *map_name == ccf::Tables::SIGNATURES;
        has_cose_signature =
          has_cose_signature || *map_name == ccf::Tables::COSE_SIGNATURES;
        has_serialised_tree = has_serialised_tree ||
          *map_name == ccf::Tables::SERIALISED_MERKLE_TREE;
      }

      for (size_t i = 0; i < write_count; ++i)
      {
        auto [key, value] = deserialiser.deserialise_write();
        if (*map_name == ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
        {
          if (
            result.endorsement.has_value() ||
            key != ccf::PreviousServiceIdentityEndorsement::create_unit())
          {
            throw std::logic_error(
              "Invalid previous service identity endorsement table write");
          }
          if (value.size() > MAX_SNAPSHOT_ENDORSEMENT_RECORD_SIZE)
          {
            throw std::logic_error(fmt::format(
              "Serialised previous service identity endorsement is too large "
              "({} bytes; maximum {} bytes)",
              value.size(),
              MAX_SNAPSHOT_ENDORSEMENT_RECORD_SIZE));
          }
          result.endorsement = ccf::PreviousServiceIdentityEndorsement::
            ValueSerialiser::from_serialised(value);
        }
        else if (*map_name == ccf::Tables::SERVICE)
        {
          if (
            result.service_info.has_value() ||
            key != ccf::Service::create_unit())
          {
            throw std::logic_error("Invalid service info table write");
          }
          result.service_info =
            ccf::Service::ValueSerialiser::from_serialised(value);
        }
      }

      const auto remove_count = deserialiser.deserialise_remove_header();
      for (size_t i = 0; i < remove_count; ++i)
      {
        std::ignore = deserialiser.deserialise_remove();
        if (
          *map_name == ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT ||
          *map_name == ccf::Tables::SERVICE)
        {
          throw std::logic_error(fmt::format(
            "Unexpected removal from recovery snapshot scan table {}",
            *map_name));
        }
      }
    }

    if (!deserialiser.end())
    {
      throw std::logic_error(
        "Public ledger entry contains trailing serialised data");
    }

    result.is_signature = has_serialised_tree &&
      ((map_count == 2 && has_signature != has_cose_signature) ||
       (map_count == 3 && has_signature && has_cose_signature));
    return result;
  }

  namespace
  {
    struct RecoverySnapshotLedgerFile
    {
      std::filesystem::path path;
      size_t start_idx;
      std::optional<size_t> end_idx;
      bool committed;
    };

    static std::vector<RecoverySnapshotLedgerFile>
    find_recovery_snapshot_ledger_files(const ccf::CCFConfig::Ledger& config)
    {
      std::vector<RecoverySnapshotLedgerFile> files;

      auto add_directory =
        [&](const std::filesystem::path& directory, bool read_only) {
          std::error_code ec;
          const auto exists = std::filesystem::exists(directory, ec);
          if (ec)
          {
            throw std::logic_error(fmt::format(
              "Unable to inspect ledger directory {}: {}",
              directory.string(),
              ec.message()));
          }
          if (!exists)
          {
            return;
          }

          for (std::filesystem::directory_iterator it(directory, ec), end;
               it != end;
               it.increment(ec))
          {
            if (ec)
            {
              throw std::logic_error(fmt::format(
                "Unable to iterate ledger directory {}: {}",
                directory.string(),
                ec.message()));
            }
            if (!it->is_regular_file())
            {
              continue;
            }

            const auto name = it->path().filename().string();
            if (
              !name.starts_with("ledger_") ||
              asynchost::is_ledger_file_ignored(name))
            {
              continue;
            }

            const auto committed =
              asynchost::is_ledger_file_name_committed(name);
            if (read_only && !committed)
            {
              continue;
            }

            try
            {
              files.push_back(
                {it->path(),
                 asynchost::get_start_idx_from_file_name(name),
                 asynchost::get_last_idx_from_file_name(name),
                 committed});
            }
            catch (const std::exception& e)
            {
              LOG_INFO_FMT(
                "Ignoring invalid ledger file name {} while scanning recovery "
                "snapshot endorsements: {}",
                it->path().string(),
                e.what());
            }
          }
          if (ec)
          {
            throw std::logic_error(fmt::format(
              "Unable to iterate ledger directory {}: {}",
              directory.string(),
              ec.message()));
          }
        };

      add_directory(config.directory, false);
      for (const auto& directory : config.read_only_directories)
      {
        add_directory(directory, true);
      }

      std::sort(
        files.begin(), files.end(), [](const auto& lhs, const auto& rhs) {
          if (lhs.start_idx != rhs.start_idx)
          {
            return lhs.start_idx < rhs.start_idx;
          }
          return lhs.end_idx.has_value() && !rhs.end_idx.has_value();
        });
      return files;
    }
  }

  static RecoverySnapshotLedgerScan scan_recovery_snapshot_ledger_files(
    const ccf::CCFConfig::Ledger& ledger_config,
    const std::shared_ptr<ccf::kv::AbstractTxEncryptor>& encryptor,
    ccf::kv::Version snapshot_seqno)
  {
    if (snapshot_seqno == std::numeric_limits<ccf::kv::Version>::max())
    {
      throw std::logic_error(
        "Snapshot seqno cannot be incremented for ledger scanning");
    }

    RecoverySnapshotLedgerScan scan;
    scan.last_signed_idx = snapshot_seqno;
    auto expected_seqno = snapshot_seqno + 1;
    std::vector<CollectedCoseEndorsement> pending_endorsements;
    size_t committed_endorsements_payload_size = 0;
    size_t pending_endorsements_payload_size = 0;
    std::optional<std::pair<ccf::kv::Version, ccf::ServiceInfo>>
      latest_observed_service_info = std::nullopt;

    for (const auto& ledger_file :
         find_recovery_snapshot_ledger_files(ledger_config))
    {
      if (
        ledger_file.end_idx.has_value() &&
        ledger_file.end_idx.value() < expected_seqno)
      {
        continue;
      }

      std::ifstream file(ledger_file.path, std::ios::binary | std::ios::ate);
      if (!file)
      {
        throw std::logic_error(fmt::format(
          "Unable to open ledger file {}", ledger_file.path.string()));
      }

      const auto file_size = static_cast<std::streamoff>(file.tellg());
      if (file_size < static_cast<std::streamoff>(sizeof(size_t)))
      {
        throw std::logic_error(fmt::format(
          "Ledger file {} is too small", ledger_file.path.string()));
      }
      file.seekg(0);

      size_t positions_offset = 0;
      file.read(
        reinterpret_cast<char*>(&positions_offset), sizeof(positions_offset));
      if (!file)
      {
        throw std::logic_error(fmt::format(
          "Unable to read ledger file header {}", ledger_file.path.string()));
      }
      if (ledger_file.committed && positions_offset == 0)
      {
        throw std::logic_error(fmt::format(
          "Committed ledger file {} has no positions table",
          ledger_file.path.string()));
      }

      const auto entries_end = positions_offset == 0 ?
        file_size :
        static_cast<std::streamoff>(positions_offset);
      if (
        entries_end < static_cast<std::streamoff>(sizeof(size_t)) ||
        entries_end > file_size)
      {
        throw std::logic_error(fmt::format(
          "Ledger file {} has invalid positions table offset {}",
          ledger_file.path.string(),
          positions_offset));
      }

      std::optional<ccf::kv::Version> first_file_version = std::nullopt;
      std::optional<ccf::kv::Version> previous_file_version = std::nullopt;
      while (file.tellg() < entries_end)
      {
        const auto remaining = entries_end - file.tellg();
        if (
          remaining <
          static_cast<std::streamoff>(sizeof(ccf::kv::SerialisedEntryHeader)))
        {
          if (positions_offset == 0)
          {
            break;
          }
          throw std::logic_error(fmt::format(
            "Committed ledger file {} ends with a partial entry header",
            ledger_file.path.string()));
        }

        ccf::kv::SerialisedEntryHeader header{};
        file.read(reinterpret_cast<char*>(&header), sizeof(header));
        if (!file)
        {
          throw std::logic_error(fmt::format(
            "Unable to read entry header from ledger file {}",
            ledger_file.path.string()));
        }

        const auto body_remaining = entries_end - file.tellg();
        if (
          header.size == 0 || header.size > static_cast<size_t>(body_remaining))
        {
          if (positions_offset == 0)
          {
            break;
          }
          throw std::logic_error(fmt::format(
            "Committed ledger file {} contains a truncated entry",
            ledger_file.path.string()));
        }

        std::vector<uint8_t> entry(sizeof(header) + header.size);
        std::memcpy(entry.data(), &header, sizeof(header));
        file.read(
          reinterpret_cast<char*>(entry.data() + sizeof(header)),
          static_cast<std::streamsize>(header.size));
        if (!file)
        {
          throw std::logic_error(fmt::format(
            "Unable to read complete entry from ledger file {}",
            ledger_file.path.string()));
        }

        auto parsed = parse_recovery_snapshot_ledger_entry(entry, encryptor);
        if (!first_file_version.has_value())
        {
          first_file_version = parsed.version;
        }
        if (
          previous_file_version.has_value() &&
          (previous_file_version.value() ==
             std::numeric_limits<ccf::kv::Version>::max() ||
           parsed.version != previous_file_version.value() + 1))
        {
          throw std::logic_error(fmt::format(
            "Ledger file {} contains non-contiguous versions {} and {}",
            ledger_file.path.string(),
            previous_file_version.value(),
            parsed.version));
        }
        previous_file_version = parsed.version;

        if (parsed.version < expected_seqno)
        {
          continue;
        }
        if (parsed.version > expected_seqno)
        {
          throw std::logic_error(fmt::format(
            "Ledger suffix after snapshot is missing seqno {} (next entry is "
            "{})",
            expected_seqno,
            parsed.version));
        }

        if (parsed.endorsement.has_value())
        {
          const auto endorsement_size = parsed.endorsement->endorsement.size();
          if (endorsement_size > MAX_SNAPSHOT_ENDORSEMENT_SIZE)
          {
            throw std::logic_error(fmt::format(
              "Ledger endorsement at {} is too large ({} bytes; maximum {} "
              "bytes)",
              parsed.version,
              endorsement_size,
              MAX_SNAPSHOT_ENDORSEMENT_SIZE));
          }
          if (pending_endorsements.size() >= MAX_SNAPSHOT_ENDORSEMENTS_COUNT)
          {
            throw std::logic_error(fmt::format(
              "Ledger suffix contains too many pending endorsements (maximum "
              "{})",
              MAX_SNAPSHOT_ENDORSEMENTS_COUNT));
          }
          if (
            endorsement_size > MAX_SNAPSHOT_ENDORSEMENTS_PAYLOAD_SIZE -
              pending_endorsements_payload_size)
          {
            throw std::logic_error(fmt::format(
              "Pending ledger endorsements payload is too large (maximum {} "
              "bytes)",
              MAX_SNAPSHOT_ENDORSEMENTS_PAYLOAD_SIZE));
          }
          pending_endorsements_payload_size += endorsement_size;
          pending_endorsements.push_back(
            {parsed.version, std::move(*parsed.endorsement)});
        }
        if (parsed.service_info.has_value())
        {
          latest_observed_service_info.emplace(
            parsed.version, std::move(*parsed.service_info));
        }
        if (parsed.is_signature)
        {
          if (
            pending_endorsements.size() >
            MAX_SNAPSHOT_ENDORSEMENTS_COUNT - scan.endorsements.size())
          {
            throw std::logic_error(fmt::format(
              "Committed ledger suffix contains too many endorsements "
              "(maximum {})",
              MAX_SNAPSHOT_ENDORSEMENTS_COUNT));
          }
          if (
            pending_endorsements_payload_size >
            MAX_SNAPSHOT_ENDORSEMENTS_PAYLOAD_SIZE -
              committed_endorsements_payload_size)
          {
            throw std::logic_error(fmt::format(
              "Committed ledger endorsements payload is too large (maximum {} "
              "bytes)",
              MAX_SNAPSHOT_ENDORSEMENTS_PAYLOAD_SIZE));
          }

          scan.endorsements.insert(
            scan.endorsements.end(),
            std::make_move_iterator(pending_endorsements.begin()),
            std::make_move_iterator(pending_endorsements.end()));
          pending_endorsements.clear();
          committed_endorsements_payload_size +=
            pending_endorsements_payload_size;
          pending_endorsements_payload_size = 0;
          scan.latest_service_info = latest_observed_service_info;
          scan.last_signed_idx = parsed.version;
        }

        if (expected_seqno == std::numeric_limits<ccf::kv::Version>::max())
        {
          throw std::logic_error(
            "Ledger seqno overflow while scanning snapshot endorsements");
        }
        ++expected_seqno;
      }

      if (
        first_file_version.has_value() &&
        first_file_version.value() !=
          static_cast<ccf::kv::Version>(ledger_file.start_idx))
      {
        throw std::logic_error(fmt::format(
          "Ledger file {} does not start at its declared seqno {}",
          ledger_file.path.string(),
          ledger_file.start_idx));
      }
      if (
        ledger_file.end_idx.has_value() &&
        (!previous_file_version.has_value() ||
         previous_file_version.value() !=
           static_cast<ccf::kv::Version>(ledger_file.end_idx.value())))
      {
        throw std::logic_error(fmt::format(
          "Ledger file {} does not end at its declared seqno {}",
          ledger_file.path.string(),
          ledger_file.end_idx.value()));
      }
    }

    return scan;
  }
}
