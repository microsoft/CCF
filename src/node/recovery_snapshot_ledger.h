// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/startup_config.h"
#include "ds/internal_logger.h"
#include "host/ledger_filenames.h"
#include "kv/kv_serialiser.h"
#include "kv/serialised_entry_format.h"
#include "node/rpc/network_identity_chain_helpers.h"
#include "service/tables/previous_service_identity.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>

namespace ccf
{
  static constexpr size_t MAX_RECOVERY_SNAPSHOT_ENDORSEMENTS_COUNT = 64;
  static constexpr size_t MAX_RECOVERY_SNAPSHOT_ENDORSEMENT_SIZE =
    size_t{1024} * 1024;
  static constexpr size_t MAX_RECOVERY_SNAPSHOT_ENDORSEMENT_RECORD_SIZE =
    2 * MAX_RECOVERY_SNAPSHOT_ENDORSEMENT_SIZE;
  static constexpr size_t MAX_RECOVERY_SNAPSHOT_ENDORSEMENTS_SERIALISED_SIZE =
    size_t{4} * 1024 * 1024;
  static constexpr size_t MAX_RECOVERY_SNAPSHOT_LEDGER_ENTRY_SIZE =
    size_t{16} * 1024 * 1024;

  struct RecoverySnapshotLedgerEntry
  {
    ccf::kv::Version version = 0;
    std::optional<ccf::CoseEndorsement> endorsement = std::nullopt;
    size_t endorsement_serialised_size = 0;
  };

  struct RecoverySnapshotLedgerScan
  {
    std::vector<CollectedCoseEndorsement> endorsements;
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

    for (auto map_name = deserialiser.start_map(); map_name.has_value();
         map_name = deserialiser.start_map())
    {
      std::ignore = deserialiser.deserialise_entry_version();

      const auto read_count = deserialiser.deserialise_read_header();
      for (size_t i = 0; i < read_count; ++i)
      {
        std::ignore = deserialiser.deserialise_read();
      }

      const auto write_count = deserialiser.deserialise_write_header();
      for (size_t i = 0; i < write_count; ++i)
      {
        auto [key, value] = deserialiser.deserialise_write();
        if (*map_name != ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
        {
          continue;
        }
        if (
          result.endorsement.has_value() ||
          key != ccf::PreviousServiceIdentityEndorsement::create_unit())
        {
          throw std::logic_error(
            "Invalid previous service identity endorsement table write");
        }
        if (value.size() > MAX_RECOVERY_SNAPSHOT_ENDORSEMENT_RECORD_SIZE)
        {
          throw std::logic_error(
            fmt::format(
              "Serialised previous service identity endorsement is too large "
              "({} bytes; maximum {} bytes)",
              value.size(),
              MAX_RECOVERY_SNAPSHOT_ENDORSEMENT_RECORD_SIZE));
        }
        result.endorsement_serialised_size = value.size();
        result.endorsement = ccf::PreviousServiceIdentityEndorsement::
          ValueSerialiser::from_serialised(value);
      }

      const auto remove_count = deserialiser.deserialise_remove_header();
      for (size_t i = 0; i < remove_count; ++i)
      {
        std::ignore = deserialiser.deserialise_remove();
        if (*map_name == ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
        {
          throw std::logic_error(
            "Unexpected removal from previous service identity endorsement "
            "table");
        }
      }
    }

    if (!deserialiser.end())
    {
      throw std::logic_error(
        "Public ledger entry contains trailing serialised data");
    }
    return result;
  }

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
          throw std::logic_error(
            fmt::format(
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
            throw std::logic_error(
              fmt::format(
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

          const auto committed = asynchost::is_ledger_file_name_committed(name);
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
          throw std::logic_error(
            fmt::format(
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

    std::sort(files.begin(), files.end(), [](const auto& lhs, const auto& rhs) {
      if (lhs.start_idx != rhs.start_idx)
      {
        return lhs.start_idx < rhs.start_idx;
      }
      if (lhs.end_idx.has_value() != rhs.end_idx.has_value())
      {
        return lhs.end_idx.has_value();
      }
      if (lhs.end_idx != rhs.end_idx)
      {
        return lhs.end_idx > rhs.end_idx;
      }
      return lhs.path < rhs.path;
    });
    return files;
  }

  struct RecoverySnapshotLedgerFileReader
  {
    std::ifstream file;
    std::streamoff entries_end;
    bool allow_partial_tail;
  };

  static RecoverySnapshotLedgerFileReader open_recovery_snapshot_ledger_file(
    const RecoverySnapshotLedgerFile& ledger_file)
  {
    std::ifstream file(ledger_file.path, std::ios::binary | std::ios::ate);
    if (!file)
    {
      throw std::logic_error(
        fmt::format(
          "Unable to open ledger file {}", ledger_file.path.string()));
    }

    const auto file_size = static_cast<std::streamoff>(file.tellg());
    if (file_size < static_cast<std::streamoff>(sizeof(size_t)))
    {
      throw std::logic_error(
        fmt::format("Ledger file {} is too small", ledger_file.path.string()));
    }
    file.seekg(0);

    size_t positions_offset = 0;
    file.read(
      reinterpret_cast<char*>(&positions_offset), sizeof(positions_offset));
    if (!file)
    {
      throw std::logic_error(
        fmt::format(
          "Unable to read ledger file header {}", ledger_file.path.string()));
    }
    if (ledger_file.committed && positions_offset == 0)
    {
      throw std::logic_error(
        fmt::format(
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
      throw std::logic_error(
        fmt::format(
          "Ledger file {} has invalid positions table offset {}",
          ledger_file.path.string(),
          positions_offset));
    }

    return {std::move(file), entries_end, positions_offset == 0};
  }

  static std::optional<std::vector<uint8_t>>
  read_recovery_snapshot_ledger_entry(
    RecoverySnapshotLedgerFileReader& reader,
    const RecoverySnapshotLedgerFile& ledger_file)
  {
    if (reader.file.tellg() >= reader.entries_end)
    {
      return std::nullopt;
    }

    const auto remaining = reader.entries_end - reader.file.tellg();
    if (
      remaining <
      static_cast<std::streamoff>(sizeof(ccf::kv::SerialisedEntryHeader)))
    {
      if (reader.allow_partial_tail)
      {
        return std::nullopt;
      }
      throw std::logic_error(
        fmt::format(
          "Committed ledger file {} ends with a partial entry header",
          ledger_file.path.string()));
    }

    ccf::kv::SerialisedEntryHeader header{};
    reader.file.read(reinterpret_cast<char*>(&header), sizeof(header));
    if (!reader.file)
    {
      throw std::logic_error(
        fmt::format(
          "Unable to read entry header from ledger file {}",
          ledger_file.path.string()));
    }

    const auto body_remaining = reader.entries_end - reader.file.tellg();
    if (header.size == 0 || header.size > static_cast<size_t>(body_remaining))
    {
      if (reader.allow_partial_tail)
      {
        return std::nullopt;
      }
      throw std::logic_error(
        fmt::format(
          "Committed ledger file {} contains a truncated entry",
          ledger_file.path.string()));
    }
    if (header.size > MAX_RECOVERY_SNAPSHOT_LEDGER_ENTRY_SIZE)
    {
      throw std::logic_error(
        fmt::format(
          "Ledger entry is too large ({} bytes; maximum {} bytes)",
          static_cast<size_t>(header.size),
          MAX_RECOVERY_SNAPSHOT_LEDGER_ENTRY_SIZE));
    }

    std::vector<uint8_t> entry(sizeof(header) + header.size);
    std::memcpy(entry.data(), &header, sizeof(header));
    reader.file.read(
      reinterpret_cast<char*>(entry.data() + sizeof(header)),
      static_cast<std::streamsize>(header.size));
    if (!reader.file)
    {
      throw std::logic_error(
        fmt::format(
          "Unable to read complete entry from ledger file {}",
          ledger_file.path.string()));
    }
    return entry;
  }

  static void validate_recovery_snapshot_ledger_file_versions(
    const RecoverySnapshotLedgerFile& ledger_file,
    const std::optional<ccf::kv::Version>& first,
    const std::optional<ccf::kv::Version>& last)
  {
    if (
      first.has_value() &&
      *first != static_cast<ccf::kv::Version>(ledger_file.start_idx))
    {
      throw std::logic_error(
        fmt::format(
          "Ledger file {} does not start at its declared seqno {}",
          ledger_file.path.string(),
          ledger_file.start_idx));
    }
    if (
      ledger_file.end_idx.has_value() &&
      (!last.has_value() ||
       *last != static_cast<ccf::kv::Version>(*ledger_file.end_idx)))
    {
      throw std::logic_error(
        fmt::format(
          "Ledger file {} does not end at its declared seqno {}",
          ledger_file.path.string(),
          *ledger_file.end_idx));
    }
  }

  static void append_recovery_snapshot_endorsement(
    RecoverySnapshotLedgerEntry&& parsed,
    RecoverySnapshotLedgerScan& scan,
    size_t& endorsements_serialised_size)
  {
    if (!parsed.endorsement.has_value())
    {
      return;
    }

    const auto endorsement_size = parsed.endorsement->endorsement.size();
    if (endorsement_size > MAX_RECOVERY_SNAPSHOT_ENDORSEMENT_SIZE)
    {
      throw std::logic_error(
        fmt::format(
          "Ledger endorsement at {} is too large ({} bytes; maximum {} bytes)",
          parsed.version,
          endorsement_size,
          MAX_RECOVERY_SNAPSHOT_ENDORSEMENT_SIZE));
    }
    if (scan.endorsements.size() >= MAX_RECOVERY_SNAPSHOT_ENDORSEMENTS_COUNT)
    {
      throw std::logic_error(
        fmt::format(
          "Ledger suffix contains too many endorsements (maximum {})",
          MAX_RECOVERY_SNAPSHOT_ENDORSEMENTS_COUNT));
    }
    if (
      parsed.endorsement_serialised_size >
      MAX_RECOVERY_SNAPSHOT_ENDORSEMENTS_SERIALISED_SIZE -
        endorsements_serialised_size)
    {
      throw std::logic_error(
        fmt::format(
          "Serialised ledger endorsements are too large (maximum {} bytes)",
          MAX_RECOVERY_SNAPSHOT_ENDORSEMENTS_SERIALISED_SIZE));
    }

    endorsements_serialised_size += parsed.endorsement_serialised_size;
    scan.endorsements.push_back(
      {parsed.version, std::move(*parsed.endorsement)});
  }

  static void scan_recovery_snapshot_ledger_file(
    const RecoverySnapshotLedgerFile& ledger_file,
    const std::shared_ptr<ccf::kv::AbstractTxEncryptor>& encryptor,
    ccf::kv::Version& expected_seqno,
    RecoverySnapshotLedgerScan& scan,
    size_t& endorsements_serialised_size)
  {
    if (
      ledger_file.end_idx.has_value() &&
      ledger_file.end_idx.value() < expected_seqno)
    {
      return;
    }

    auto reader = open_recovery_snapshot_ledger_file(ledger_file);

    std::optional<ccf::kv::Version> first_file_version = std::nullopt;
    std::optional<ccf::kv::Version> previous_file_version = std::nullopt;
    while (auto entry =
             read_recovery_snapshot_ledger_entry(reader, ledger_file))
    {
      auto parsed = parse_recovery_snapshot_ledger_entry(*entry, encryptor);
      if (!first_file_version.has_value())
      {
        first_file_version = parsed.version;
      }
      if (const auto previous_version_opt = previous_file_version)
      {
        const auto previous_version = *previous_version_opt;
        if (
          previous_version == std::numeric_limits<ccf::kv::Version>::max() ||
          parsed.version != previous_version + 1)
        {
          throw std::logic_error(
            fmt::format(
              "Ledger file {} contains non-contiguous versions {} and {}",
              ledger_file.path.string(),
              previous_version,
              parsed.version));
        }
      }
      previous_file_version = parsed.version;

      if (parsed.version < expected_seqno)
      {
        continue;
      }
      if (parsed.version > expected_seqno)
      {
        throw std::logic_error(
          fmt::format(
            "Ledger suffix after snapshot is missing seqno {} (next entry is "
            "{})",
            expected_seqno,
            parsed.version));
      }

      append_recovery_snapshot_endorsement(
        std::move(parsed), scan, endorsements_serialised_size);

      if (expected_seqno == std::numeric_limits<ccf::kv::Version>::max())
      {
        throw std::logic_error(
          "Ledger seqno overflow while scanning snapshot endorsements");
      }
      ++expected_seqno;
    }

    validate_recovery_snapshot_ledger_file_versions(
      ledger_file, first_file_version, previous_file_version);
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
    auto expected_seqno = snapshot_seqno + 1;
    size_t endorsements_serialised_size = 0;
    for (const auto& ledger_file :
         find_recovery_snapshot_ledger_files(ledger_config))
    {
      scan_recovery_snapshot_ledger_file(
        ledger_file,
        encryptor,
        expected_seqno,
        scan,
        endorsements_serialised_size);
    }
    return scan;
  }
}
