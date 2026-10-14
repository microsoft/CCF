// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/snapshotter.h"

#include "crypto/openssl/hash.h"
#include "ds/files.h"
#include "ds/internal_logger.h"
#include "kv/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "node/encryptor.h"
#include "node/history.h"
#include "node/recovery_snapshot_ledger.h"
#include "node/snapshot_serdes.h"
#include "snapshots/filenames.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <chrono>
#include <doctest/doctest.h>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <unistd.h>

auto node_kp = ccf::crypto::make_ec_key_pair();

using StringString = ccf::kv::Map<std::string, std::string>;
namespace fs = std::filesystem;

void run_one_task()
{
  auto task = ccf::tasks::get_main_job_board().get_task();
  if (task != nullptr)
  {
    task->do_task();
  }
}

struct ScopedSnapshotDir
{
  fs::path path;

  ScopedSnapshotDir()
  {
    const auto unique_name = fmt::format(
      "ccf-snapshotter-test-{}-{}",
      ::getpid(),
      std::chrono::steady_clock::now().time_since_epoch().count());
    path = fs::temp_directory_path() / unique_name;
    fs::create_directories(path);
  }

  ~ScopedSnapshotDir()
  {
    std::error_code ec;
    fs::remove_all(path, ec);
  }
};

void write_ledger_file(
  const fs::path& path,
  const std::vector<std::vector<uint8_t>>& entries,
  bool completed = false)
{
  std::ofstream ledger_file(path, std::ios::binary);
  REQUIRE(ledger_file);
  size_t positions_offset = 0;
  ledger_file.write(
    reinterpret_cast<const char*>(&positions_offset), sizeof(positions_offset));
  std::vector<uint32_t> positions;
  for (const auto& entry : entries)
  {
    positions.push_back(static_cast<uint32_t>(ledger_file.tellp()));
    ledger_file.write(
      reinterpret_cast<const char*>(entry.data()),
      static_cast<std::streamsize>(entry.size()));
  }
  if (completed)
  {
    positions_offset = static_cast<size_t>(ledger_file.tellp());
    ledger_file.write(
      reinterpret_cast<const char*>(positions.data()),
      static_cast<std::streamsize>(positions.size() * sizeof(uint32_t)));
    ledger_file.seekp(0);
    ledger_file.write(
      reinterpret_cast<const char*>(&positions_offset),
      sizeof(positions_offset));
  }
  REQUIRE(ledger_file);
}

struct RecoverySnapshotLedgerFixture
{
  ScopedSnapshotDir ledger_dir;
  ccf::CCFConfig::Ledger ledger_config;
  std::shared_ptr<ccf::kv::AbstractTxEncryptor> encryptor =
    std::make_shared<ccf::kv::NullTxEncryptor>();
  ccf::CoseEndorsement endorsement{
    .endorsement = {0xd2, 0x01},
    .endorsing_key = {0x02, 0x03},
    .endorsement_epoch_begin = {2, 1},
    .endorsement_epoch_end = ccf::TxID{4, 1},
    .previous_version = 1};

  RecoverySnapshotLedgerFixture()
  {
    ledger_config.directory = ledger_dir.path.string();
  }

  std::vector<uint8_t> entry(
    ccf::kv::Version seqno,
    const std::vector<ccf::IdentityType>& identities = {
      ccf::IdentityType::CLASSICAL}) const
  {
    ccf::kv::RawKvStoreSerialiser serialiser(
      encryptor, ccf::TxID{2, seqno}, ccf::kv::EntryType::WriteSet, 0);
    serialiser.start_map(
      ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT,
      ccf::kv::SecurityDomain::PUBLIC);
    serialiser.serialise_entry_version(ccf::kv::NoVersion);
    serialiser.serialise_count_header(0);
    serialiser.serialise_count_header(identities.size());
    for (const auto identity : identities)
    {
      serialiser.serialise_write(
        ccf::PreviousServiceIdentityEndorsement::KeySerialiser::to_serialised(
          identity),
        ccf::PreviousServiceIdentityEndorsement::ValueSerialiser::to_serialised(
          endorsement));
    }
    serialiser.serialise_count_header(0);
    return serialiser.get_raw_data();
  }

  ccf::RecoverySnapshotLedgerScan scan(
    ccf::kv::Version snapshot_seqno = 0) const
  {
    return ccf::scan_recovery_snapshot_ledger_files(
      ledger_config, encryptor, snapshot_seqno);
  }
};

TEST_CASE("Recovery snapshot endorsement scan reads ledger files directly")
{
  ScopedSnapshotDir ledger_dir;
  ccf::kv::Store source_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  source_store.set_encryptor(encryptor);
  source_store.set_consensus(consensus);
  source_store.initialise_term(2);

  std::vector<std::vector<uint8_t>> entries;
  {
    auto tx = source_store.create_tx();
    tx.rw<StringString>("public:unrelated")->put("key", "value");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    auto latest_entry =
      consensus->get_latest_data().value_or(std::vector<uint8_t>{});
    REQUIRE_FALSE(latest_entry.empty());
    entries.push_back(std::move(latest_entry));
  }
  {
    ccf::CoseEndorsement endorsement;
    endorsement.endorsement = {0xd2, 0x01};
    endorsement.endorsing_key = {0x02, 0x03};
    endorsement.endorsement_epoch_begin = {2, 1};
    endorsement.endorsement_epoch_end = ccf::TxID{4, 1};
    endorsement.previous_version = 1;

    auto tx = source_store.create_tx();
    tx.rw<ccf::PreviousServiceIdentityEndorsement>(
        ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
      ->put(ccf::IdentityType::CLASSICAL, endorsement);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    auto latest_entry =
      consensus->get_latest_data().value_or(std::vector<uint8_t>{});
    REQUIRE_FALSE(latest_entry.empty());
    entries.push_back(std::move(latest_entry));
  }

  const ccf::SnapshotSegments first_entry{
    std::span<const uint8_t>(entries.front()), {}};
  REQUIRE_NOTHROW(ccf::verify_snapshot_seqno(first_entry, encryptor, 1));
  REQUIRE_THROWS(ccf::verify_snapshot_seqno(first_entry, encryptor, 2));

  auto malformed_entry = entries.front();
  const auto public_domain_size_offset =
    sizeof(ccf::kv::SerialisedEntryHeader) + encryptor->get_header_length();
  const auto invalid_public_domain_size = malformed_entry.size();
  std::memcpy(
    malformed_entry.data() + public_domain_size_offset,
    &invalid_public_domain_size,
    sizeof(invalid_public_domain_size));

  const ccf::SnapshotSegments malformed_snapshot{
    std::span<const uint8_t>(malformed_entry), {}};
  REQUIRE_THROWS(ccf::verify_snapshot_seqno(malformed_snapshot, encryptor, 1));

  ScopedSnapshotDir malformed_ledger_dir;
  write_ledger_file(malformed_ledger_dir.path / "ledger_1", {malformed_entry});
  ccf::CCFConfig::Ledger malformed_ledger_config;
  malformed_ledger_config.directory = malformed_ledger_dir.path.string();
  REQUIRE_THROWS(ccf::scan_recovery_snapshot_ledger_files(
    malformed_ledger_config, encryptor, 0));

  write_ledger_file(ledger_dir.path / "ledger_1", entries);

  ccf::CCFConfig::Ledger ledger_config;
  ledger_config.directory = ledger_dir.path.string();
  const auto scan =
    ccf::scan_recovery_snapshot_ledger_files(ledger_config, encryptor, 1);
  REQUIRE(scan.endorsements.size() == 1);
  REQUIRE(scan.endorsements.front().write_version == 2);

  const auto target_key = ccf::crypto::make_ec_key_pair()->public_key_der();
  REQUIRE_THROWS(ccf::validate_recovery_snapshot_endorsement_chain(
    scan.endorsements, target_key, 1));
}

TEST_CASE("Recovery snapshot endorsement scan bounds candidate endorsements")
{
  ScopedSnapshotDir ledger_dir;
  ccf::kv::Store source_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  source_store.set_encryptor(encryptor);
  source_store.set_consensus(consensus);
  source_store.initialise_term(2);

  std::vector<std::vector<uint8_t>> entries;
  for (size_t i = 0; i < ccf::MAX_RECOVERY_SNAPSHOT_ENDORSEMENTS_COUNT + 1; ++i)
  {
    ccf::CoseEndorsement endorsement;
    endorsement.endorsement = {0xd2, 0x01};
    endorsement.endorsing_key = {0x02, 0x03};
    endorsement.endorsement_epoch_begin = {2, i + 1};
    endorsement.endorsement_epoch_end = ccf::TxID{4, i + 1};
    endorsement.previous_version = 1;

    auto tx = source_store.create_tx();
    tx.rw<ccf::PreviousServiceIdentityEndorsement>(
        ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
      ->put(ccf::IdentityType::CLASSICAL, endorsement);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    auto latest_entry =
      consensus->get_latest_data().value_or(std::vector<uint8_t>{});
    REQUIRE_FALSE(latest_entry.empty());
    entries.push_back(std::move(latest_entry));
  }

  write_ledger_file(ledger_dir.path / "ledger_1", entries);

  ccf::CCFConfig::Ledger ledger_config;
  ledger_config.directory = ledger_dir.path.string();
  REQUIRE_THROWS(
    ccf::scan_recovery_snapshot_ledger_files(ledger_config, encryptor, 0));
}

TEST_CASE(
  "Recovery snapshot endorsement scan bounds total serialised record size")
{
  ScopedSnapshotDir ledger_dir;
  ccf::kv::Store source_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  source_store.set_encryptor(encryptor);
  source_store.set_consensus(consensus);
  source_store.initialise_term(2);

  std::vector<std::vector<uint8_t>> entries;
  for (size_t i = 0; i < 3; ++i)
  {
    ccf::CoseEndorsement endorsement;
    endorsement.endorsement = {0xd2, 0x01};
    endorsement.endorsing_key.resize(
      ccf::MAX_RECOVERY_SNAPSHOT_ENDORSEMENTS_SERIALISED_SIZE / 4, 0x02);
    endorsement.endorsement_epoch_begin = {2, i + 1};
    endorsement.endorsement_epoch_end = ccf::TxID{4, i + 1};
    endorsement.previous_version = 1;

    const auto record_size =
      ccf::PreviousServiceIdentityEndorsement::ValueSerialiser::to_serialised(
        endorsement)
        .size();
    REQUIRE(record_size < ccf::MAX_RECOVERY_SNAPSHOT_ENDORSEMENT_RECORD_SIZE);
    REQUIRE(
      record_size * 3 >
      ccf::MAX_RECOVERY_SNAPSHOT_ENDORSEMENTS_SERIALISED_SIZE);

    auto tx = source_store.create_tx();
    tx.rw<ccf::PreviousServiceIdentityEndorsement>(
        ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT)
      ->put(ccf::IdentityType::CLASSICAL, endorsement);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    auto latest_entry =
      consensus->get_latest_data().value_or(std::vector<uint8_t>{});
    REQUIRE_FALSE(latest_entry.empty());
    entries.push_back(std::move(latest_entry));
  }

  write_ledger_file(ledger_dir.path / "ledger_1", entries);

  ccf::CCFConfig::Ledger ledger_config;
  ledger_config.directory = ledger_dir.path.string();
  REQUIRE_THROWS(
    ccf::scan_recovery_snapshot_ledger_files(ledger_config, encryptor, 0));
}

TEST_CASE("Recovery snapshot ledger file ordering is deterministic")
{
  ScopedSnapshotDir root_dir;
  const auto main_dir = root_dir.path / "main";
  const auto read_only_dir = root_dir.path / "read_only";
  fs::create_directories(main_dir);
  fs::create_directories(read_only_dir);

  const auto main_long = main_dir / "ledger_1-5.committed";
  const auto read_only_long = read_only_dir / "ledger_1-5.committed";
  const std::vector<fs::path> paths = {
    main_long,
    read_only_long,
    read_only_dir / "ledger_1-3.committed",
    main_dir / "ledger_1-2.committed",
    main_dir / "ledger_1"};
  for (const auto& path : paths)
  {
    std::ofstream file(path);
    REQUIRE(file);
    file.put(0);
  }

  ccf::CCFConfig::Ledger ledger_config;
  ledger_config.directory = main_dir.string();
  ledger_config.read_only_directories = {read_only_dir.string()};
  const auto files = ccf::find_recovery_snapshot_ledger_files(ledger_config);

  REQUIRE(files.size() == paths.size());
  REQUIRE(files[0].path == std::min(main_long, read_only_long));
  REQUIRE(files[1].path == std::max(main_long, read_only_long));
  REQUIRE(files[2].end_idx == 3);
  REQUIRE(files[3].end_idx == 2);
  REQUIRE_FALSE(files[4].end_idx.has_value());
}

TEST_CASE("Recovery snapshot endorsement scan bounds ledger entry allocation")
{
  ScopedSnapshotDir ledger_dir;
  const auto ledger_path = ledger_dir.path / "ledger_1";
  {
    std::ofstream ledger_file(ledger_path, std::ios::binary);
    REQUIRE(ledger_file);
    const size_t positions_offset = 0;
    ledger_file.write(
      reinterpret_cast<const char*>(&positions_offset),
      sizeof(positions_offset));
    ccf::kv::SerialisedEntryHeader header{};
    header.size = ccf::MAX_RECOVERY_SNAPSHOT_LEDGER_ENTRY_SIZE + 1;
    ledger_file.write(reinterpret_cast<const char*>(&header), sizeof(header));
    ledger_file.seekp(
      static_cast<std::streamoff>(header.size) - 1, std::ios::cur);
    ledger_file.put(0);
    REQUIRE(ledger_file);
  }

  ccf::CCFConfig::Ledger ledger_config;
  ledger_config.directory = ledger_dir.path.string();
  REQUIRE_THROWS(ccf::scan_recovery_snapshot_ledger_files(
    ledger_config, std::make_shared<ccf::kv::NullTxEncryptor>(), 0));
}

TEST_CASE("Recovery snapshot ledger scan filters directory contents")
{
  RecoverySnapshotLedgerFixture fixture;
  const auto missing_dir = fixture.ledger_dir.path / "missing";
  fixture.ledger_config.read_only_directories = {missing_dir.string()};

  SUBCASE("Missing directories contain no candidate entries")
  {
    fixture.ledger_config.directory = missing_dir.string();
    REQUIRE(
      ccf::find_recovery_snapshot_ledger_files(fixture.ledger_config).empty());
    REQUIRE(fixture.scan().endorsements.empty());
  }

  SUBCASE("Only valid writable and committed read-only chunks are scanned")
  {
    const auto read_only_dir = fixture.ledger_dir.path / "read_only";
    fs::create_directories(read_only_dir);
    fixture.ledger_config.read_only_directories.push_back(
      read_only_dir.string());

    const auto committed_path = read_only_dir / "ledger_1-2.committed";
    const auto current_path = fixture.ledger_dir.path / "ledger_3";
    write_ledger_file(
      committed_path, {fixture.entry(1), fixture.entry(2)}, true);
    write_ledger_file(current_path, {fixture.entry(3)});
    write_ledger_file(read_only_dir / "ledger_1", {});
    write_ledger_file(read_only_dir / "ledger_1-4", {}, true);
    fs::create_directory(fixture.ledger_dir.path / "ledger_4");
    for (const auto* name :
         {"notes",
          "ledger_invalid",
          "ledger_1-invalid.committed",
          "ledger_0.recovery",
          "ledger_0.ignored"})
    {
      write_ledger_file(fixture.ledger_dir.path / name, {});
    }

    const auto files =
      ccf::find_recovery_snapshot_ledger_files(fixture.ledger_config);
    REQUIRE(files.size() == 2);
    REQUIRE(files[0].path == committed_path);
    REQUIRE(files[0].start_idx == 1);
    REQUIRE(files[0].end_idx == 2);
    REQUIRE(files[0].committed);
    REQUIRE(files[1].path == current_path);
    REQUIRE(files[1].start_idx == 3);
    REQUIRE_FALSE(files[1].end_idx.has_value());
    REQUIRE_FALSE(files[1].committed);

    const auto scan = fixture.scan(1);
    REQUIRE(scan.endorsements.size() == 2);
    for (size_t i = 0; i < scan.endorsements.size(); ++i)
    {
      REQUIRE(scan.endorsements[i].write_version == i + 2);
      REQUIRE(
        nlohmann::json(scan.endorsements[i].endorsement) ==
        nlohmann::json(fixture.endorsement));
    }
  }

  SUBCASE("A regular file cannot be used as a ledger directory")
  {
    const auto path = fixture.ledger_dir.path / "not_a_directory";
    write_ledger_file(path, {});
    fixture.ledger_config.directory = path.string();
    REQUIRE_THROWS_WITH_AS(
      ccf::find_recovery_snapshot_ledger_files(fixture.ledger_config),
      fmt::format(
        "Unable to iterate ledger directory {}: {}",
        path.string(),
        std::make_error_code(std::errc::not_a_directory).message())
        .c_str(),
      std::logic_error);
  }

  SUBCASE("An unresolvable directory reports the filesystem error")
  {
    const auto path = fixture.ledger_dir.path / "loop";
    fs::create_directory_symlink(path.filename(), path);
    fixture.ledger_config.directory = path.string();
    REQUIRE_THROWS_WITH_AS(
      ccf::find_recovery_snapshot_ledger_files(fixture.ledger_config),
      fmt::format(
        "Unable to inspect ledger directory {}: {}",
        path.string(),
        std::make_error_code(std::errc::too_many_symbolic_link_levels)
          .message())
        .c_str(),
      std::logic_error);
  }
}

TEST_CASE("Recovery snapshot ledger scan validates chunk headers")
{
  RecoverySnapshotLedgerFixture fixture;
  const auto current_path = fixture.ledger_dir.path / "ledger_1";
  const auto committed_path = fixture.ledger_dir.path / "ledger_1-1.committed";

  SUBCASE("A file disappearing after discovery reports an open failure")
  {
    write_ledger_file(current_path, {fixture.entry(1)});
    const auto files =
      ccf::find_recovery_snapshot_ledger_files(fixture.ledger_config);
    REQUIRE(files.size() == 1);
    REQUIRE(fs::remove(current_path));
    REQUIRE_THROWS_WITH_AS(
      ccf::open_recovery_snapshot_ledger_file(files.front()),
      fmt::format("Unable to open ledger file {}", current_path.string())
        .c_str(),
      std::logic_error);
  }

  SUBCASE("Missing and short chunk headers are rejected")
  {
    write_ledger_file(current_path, {});
    for (const auto size : {size_t{0}, sizeof(size_t) - 1})
    {
      fs::resize_file(current_path, size);
      REQUIRE_THROWS_WITH_AS(
        fixture.scan(),
        fmt::format("Ledger file {} is too small", current_path.string())
          .c_str(),
        std::logic_error);
    }
  }

  SUBCASE("Committed chunks must have a positions table")
  {
    write_ledger_file(current_path, {fixture.entry(1)});
    REQUIRE(fixture.scan().endorsements.size() == 1);
    fs::rename(current_path, committed_path);
    REQUIRE_THROWS_WITH_AS(
      fixture.scan(),
      fmt::format(
        "Committed ledger file {} has no positions table",
        committed_path.string())
        .c_str(),
      std::logic_error);
  }

  SUBCASE("Positions table offsets must lie within the chunk")
  {
    write_ledger_file(committed_path, {fixture.entry(1)}, true);
    for (const auto offset :
         {sizeof(size_t) - 1,
          static_cast<size_t>(fs::file_size(committed_path)) + 1,
          std::numeric_limits<size_t>::max()})
    {
      {
        std::fstream file(
          committed_path, std::ios::binary | std::ios::in | std::ios::out);
        REQUIRE(file);
        file.write(reinterpret_cast<const char*>(&offset), sizeof(offset));
        REQUIRE(file);
      }
      REQUIRE_THROWS_WITH_AS(
        fixture.scan(),
        fmt::format(
          "Ledger file {} has invalid positions table offset {}",
          committed_path.string(),
          offset)
          .c_str(),
        std::logic_error);
    }
  }
}

TEST_CASE("Recovery snapshot ledger reader reports truncation after opening")
{
  RecoverySnapshotLedgerFixture fixture;
  const auto path = fixture.ledger_dir.path / "ledger_1";
  write_ledger_file(path, {fixture.entry(1)});
  const ccf::RecoverySnapshotLedgerFile ledger_file{
    path, 1, std::nullopt, false};
  auto reader = ccf::open_recovery_snapshot_ledger_file(ledger_file);
  size_t truncated_size = 0;
  std::string error;

  SUBCASE("Truncated entry header")
  {
    truncated_size = sizeof(size_t);
    error = "entry header";
  }
  SUBCASE("Truncated entry body")
  {
    truncated_size =
      sizeof(size_t) + sizeof(ccf::kv::SerialisedEntryHeader) + 1;
    error = "complete entry";
  }

  fs::resize_file(path, truncated_size);
  // Re-seek to discard bytes buffered while reading the chunk header.
  reader.file.seekg(sizeof(size_t));
  REQUIRE(reader.file);
  REQUIRE_THROWS_WITH_AS(
    ccf::read_recovery_snapshot_ledger_entry(reader, ledger_file),
    fmt::format("Unable to read {} from ledger file {}", error, path.string())
      .c_str(),
    std::logic_error);
}

TEST_CASE("Recovery snapshot ledger scan distinguishes incomplete chunk tails")
{
  RecoverySnapshotLedgerFixture fixture;
  const auto first = fixture.entry(1);
  const auto current_path = fixture.ledger_dir.path / "ledger_1";
  const auto committed_path = fixture.ledger_dir.path / "ledger_1-2.committed";

  SUBCASE("Completed chunks stop at the positions table")
  {
    write_ledger_file(committed_path, {first, fixture.entry(2)}, true);
    const auto scan = fixture.scan();
    REQUIRE(scan.endorsements.size() == 2);
    REQUIRE(scan.endorsements[0].write_version == 1);
    REQUIRE(scan.endorsements[1].write_version == 2);
    REQUIRE(
      nlohmann::json(scan.endorsements[1].endorsement) ==
      nlohmann::json(fixture.endorsement));
  }

  SUBCASE("Incomplete tails are accepted only in mutable chunks")
  {
    auto tail = fixture.entry(2);
    std::string error;
    SUBCASE("Partial entry header")
    {
      tail.resize(sizeof(ccf::kv::SerialisedEntryHeader) - 1);
      error = "ends with a partial entry header";
    }
    SUBCASE("Truncated entry body")
    {
      tail.pop_back();
      error = "contains a truncated entry";
    }
    SUBCASE("Zero-length entry body")
    {
      const ccf::kv::SerialisedEntryHeader header{};
      tail.resize(sizeof(header));
      std::memcpy(tail.data(), &header, sizeof(header));
      error = "contains a truncated entry";
    }

    write_ledger_file(current_path, {first, tail});
    const auto scan = fixture.scan();
    REQUIRE(scan.endorsements.size() == 1);
    REQUIRE(scan.endorsements.front().write_version == 1);
    REQUIRE(
      nlohmann::json(scan.endorsements.front().endorsement) ==
      nlohmann::json(fixture.endorsement));

    REQUIRE(fs::remove(current_path));
    write_ledger_file(committed_path, {first, tail}, true);
    REQUIRE_THROWS_WITH_AS(
      fixture.scan(),
      fmt::format("Committed ledger file {} {}", committed_path.string(), error)
        .c_str(),
      std::logic_error);
  }
}

TEST_CASE("Recovery snapshot ledger scan validates version ranges")
{
  RecoverySnapshotLedgerFixture fixture;
  const auto first = fixture.entry(1);
  const auto second = fixture.entry(2);
  const auto third = fixture.entry(3);

  SUBCASE("An empty mutable chunk contains no endorsements")
  {
    write_ledger_file(fixture.ledger_dir.path / "ledger_1", {});
    REQUIRE(fixture.scan().endorsements.empty());
  }

  SUBCASE("Overlapping chunks and entries before the snapshot are skipped")
  {
    write_ledger_file(
      fixture.ledger_dir.path / "ledger_1-2.committed", {first, second}, true);
    write_ledger_file(
      fixture.ledger_dir.path / "ledger_2-3.committed", {second, third}, true);
    write_ledger_file(
      fixture.ledger_dir.path / "ledger_3", {third, fixture.entry(4)});
    const auto scan = fixture.scan(1);
    REQUIRE(scan.endorsements.size() == 3);
    for (size_t i = 0; i < scan.endorsements.size(); ++i)
    {
      REQUIRE(scan.endorsements[i].write_version == i + 2);
    }
    REQUIRE(fixture.scan(4).endorsements.empty());
  }

  SUBCASE("The first entry must match the filename's start seqno")
  {
    const auto path = fixture.ledger_dir.path / "ledger_2";
    write_ledger_file(path, {first, second});
    REQUIRE_THROWS_WITH_AS(
      fixture.scan(),
      fmt::format(
        "Ledger file {} does not start at its declared seqno 2", path.string())
        .c_str(),
      std::logic_error);
  }

  SUBCASE("The last entry must match the filename's end seqno")
  {
    const auto path = fixture.ledger_dir.path / "ledger_1-3.committed";
    write_ledger_file(path, {first, second}, true);
    REQUIRE_THROWS_WITH_AS(
      fixture.scan(),
      fmt::format(
        "Ledger file {} does not end at its declared seqno 3", path.string())
        .c_str(),
      std::logic_error);
  }

  SUBCASE("A completed chunk cannot claim entries it does not contain")
  {
    const auto path = fixture.ledger_dir.path / "ledger_1-1.committed";
    write_ledger_file(path, {}, true);
    REQUIRE_THROWS_WITH_AS(
      fixture.scan(),
      fmt::format(
        "Ledger file {} does not end at its declared seqno 1", path.string())
        .c_str(),
      std::logic_error);
  }

  SUBCASE("Repeated and skipped versions within a chunk are rejected")
  {
    const auto path = fixture.ledger_dir.path / "ledger_1";
    for (const auto next : {ccf::kv::Version{1}, ccf::kv::Version{3}})
    {
      write_ledger_file(path, {first, fixture.entry(next)});
      REQUIRE_THROWS_WITH_AS(
        fixture.scan(),
        fmt::format(
          "Ledger file {} contains non-contiguous versions 1 and {}",
          path.string(),
          next)
          .c_str(),
        std::logic_error);
    }
  }

  SUBCASE("Gaps between chunks report the missing suffix seqno")
  {
    write_ledger_file(fixture.ledger_dir.path / "ledger_1", {first});
    write_ledger_file(fixture.ledger_dir.path / "ledger_3", {third});
    REQUIRE_THROWS_WITH_AS(
      fixture.scan(),
      "Ledger suffix after snapshot is missing seqno 2 (next entry is 3)",
      std::logic_error);
  }
}

TEST_CASE("Recovery snapshot ledger scan rejects seqno overflow")
{
  RecoverySnapshotLedgerFixture fixture;
  const auto max_seqno = std::numeric_limits<ccf::kv::Version>::max();

  SUBCASE("The snapshot seqno must have a successor")
  {
    REQUIRE_THROWS_WITH_AS(
      fixture.scan(max_seqno),
      "Snapshot seqno cannot be incremented for ledger scanning",
      std::logic_error);
  }

  SUBCASE("The last scanned entry must have a successor")
  {
    write_ledger_file(
      fixture.ledger_dir.path / fmt::format("ledger_{}", max_seqno),
      {fixture.entry(max_seqno)});
    REQUIRE_THROWS_WITH_AS(
      fixture.scan(max_seqno - 1),
      "Ledger seqno overflow while scanning snapshot endorsements",
      std::logic_error);
  }
}

TEST_CASE(
  "Recovery snapshot ledger entries enforce endorsement table semantics")
{
  RecoverySnapshotLedgerFixture fixture;
  const auto path = fixture.ledger_dir.path / "ledger_1";

  SUBCASE("PQ records do not count as classical endorsements")
  {
    write_ledger_file(
      path,
      {fixture.entry(1, {ccf::IdentityType::PQ}),
       fixture.entry(
         2, {ccf::IdentityType::CLASSICAL, ccf::IdentityType::PQ})});
    const auto scan = fixture.scan();
    REQUIRE(scan.endorsements.size() == 1);
    REQUIRE(scan.endorsements.front().write_version == 2);
    REQUIRE(
      nlohmann::json(scan.endorsements.front().endorsement) ==
      nlohmann::json(fixture.endorsement));
  }

  SUBCASE("Duplicate classical writes in an entry are rejected")
  {
    write_ledger_file(
      path,
      {fixture.entry(
        1, {ccf::IdentityType::CLASSICAL, ccf::IdentityType::CLASSICAL})});
    REQUIRE_THROWS_WITH_AS(
      fixture.scan(),
      "Invalid previous service identity endorsement table write",
      std::logic_error);
  }

  SUBCASE(
    "Removals from the endorsement table are rejected for either identity")
  {
    for (const auto identity :
         {ccf::IdentityType::CLASSICAL, ccf::IdentityType::PQ})
    {
      ccf::kv::RawKvStoreSerialiser serialiser(
        fixture.encryptor, ccf::TxID{2, 1}, ccf::kv::EntryType::WriteSet, 0);
      serialiser.start_map(
        ccf::Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT,
        ccf::kv::SecurityDomain::PUBLIC);
      serialiser.serialise_entry_version(ccf::kv::NoVersion);
      serialiser.serialise_count_header(0);
      serialiser.serialise_count_header(0);
      serialiser.serialise_count_header(1);
      serialiser.serialise_remove(
        ccf::PreviousServiceIdentityEndorsement::KeySerialiser::to_serialised(
          identity));
      write_ledger_file(path, {serialiser.get_raw_data()});
      REQUIRE_THROWS_WITH_AS(
        fixture.scan(),
        "Unexpected removal from previous service identity endorsement table",
        std::logic_error);
    }
  }

  SUBCASE("Legacy reads and unrelated removals preserve entry traversal")
  {
    ccf::kv::RawKvStoreSerialiser serialiser(
      fixture.encryptor, ccf::TxID{2, 1}, ccf::kv::EntryType::WriteSet, 0);
    serialiser.start_map("public:unrelated", ccf::kv::SecurityDomain::PUBLIC);
    serialiser.serialise_entry_version(0);
    serialiser.serialise_count_header(1);
    // A legacy read consists of a size-prefixed key and its previous version.
    serialiser.serialise_raw({0x01});
    serialiser.serialise_entry_version(0);
    serialiser.serialise_count_header(0);
    serialiser.serialise_count_header(1);
    serialiser.serialise_remove({0x02});
    write_ledger_file(path, {serialiser.get_raw_data(), fixture.entry(2)});
    const auto scan = fixture.scan();
    REQUIRE(scan.endorsements.size() == 1);
    REQUIRE(scan.endorsements.front().write_version == 2);
    REQUIRE(
      nlohmann::json(scan.endorsements.front().endorsement) ==
      nlohmann::json(fixture.endorsement));
  }
}

TEST_CASE("Recovery snapshot ledger scan bounds individual endorsement sizes")
{
  RecoverySnapshotLedgerFixture fixture;
  const auto path = fixture.ledger_dir.path / "ledger_1";

  SUBCASE("The endorsement byte limit is inclusive")
  {
    const auto limit = ccf::MAX_RECOVERY_SNAPSHOT_ENDORSEMENT_SIZE;
    for (const auto extra : {size_t{0}, size_t{1}})
    {
      fixture.endorsement.endorsement.resize(limit + extra, 0x01);
      REQUIRE(
        ccf::PreviousServiceIdentityEndorsement::ValueSerialiser::to_serialised(
          fixture.endorsement)
          .size() < ccf::MAX_RECOVERY_SNAPSHOT_ENDORSEMENT_RECORD_SIZE);
      write_ledger_file(path, {fixture.entry(1)});
      if (extra == 0)
      {
        const auto scan = fixture.scan();
        REQUIRE(scan.endorsements.size() == 1);
        REQUIRE(scan.endorsements.front().write_version == 1);
        REQUIRE(
          scan.endorsements.front().endorsement.endorsement ==
          fixture.endorsement.endorsement);
      }
      else
      {
        REQUIRE_THROWS_WITH_AS(
          fixture.scan(),
          fmt::format(
            "Ledger endorsement at 1 is too large ({} bytes; maximum {} bytes)",
            limit + extra,
            limit)
            .c_str(),
          std::logic_error);
      }
    }
  }

  SUBCASE("The serialised record byte limit is inclusive")
  {
    const auto limit = ccf::MAX_RECOVERY_SNAPSHOT_ENDORSEMENT_RECORD_SIZE;
    fixture.endorsement.endorsing_key.clear();
    const auto record_overhead =
      ccf::PreviousServiceIdentityEndorsement::ValueSerialiser::to_serialised(
        fixture.endorsement)
        .size();
    REQUIRE(record_overhead < limit);
    REQUIRE((limit - record_overhead) % 4 == 0);
    // The key is base64-encoded in JSON: three bytes produce four characters.
    const auto key_size = (limit - record_overhead) / 4 * 3;
    for (const auto extra : {size_t{0}, size_t{1}})
    {
      fixture.endorsement.endorsing_key.resize(key_size + extra, 0x02);
      REQUIRE(
        ccf::PreviousServiceIdentityEndorsement::ValueSerialiser::to_serialised(
          fixture.endorsement)
          .size() == limit + 4 * extra);
      write_ledger_file(path, {fixture.entry(1)});
      if (extra == 0)
      {
        const auto scan = fixture.scan();
        REQUIRE(scan.endorsements.size() == 1);
        REQUIRE(scan.endorsements.front().write_version == 1);
        REQUIRE(
          scan.endorsements.front().endorsement.endorsing_key ==
          fixture.endorsement.endorsing_key);
      }
      else
      {
        REQUIRE_THROWS_WITH_AS(
          fixture.scan(),
          fmt::format(
            "Serialised previous service identity endorsement is too large "
            "({} bytes; maximum {} bytes)",
            limit + 4 * extra,
            limit)
            .c_str(),
          std::logic_error);
      }
    }
  }
}

std::optional<fs::path> latest_committed_snapshot_path(const fs::path& dir)
{
  return ccf::snapshots::find_latest_committed_snapshot_in_directory(dir);
}

std::optional<::consensus::Index> latest_committed_snapshot_idx(
  const fs::path& dir)
{
  auto path = latest_committed_snapshot_path(dir);
  if (!path.has_value())
  {
    return std::nullopt;
  }

  return ccf::snapshots::get_snapshot_idx_from_file_name(path->filename());
}

std::optional<::consensus::Index> latest_committed_snapshot_evidence_idx(
  const fs::path& dir)
{
  auto path = latest_committed_snapshot_path(dir);
  if (!path.has_value())
  {
    return std::nullopt;
  }

  return ccf::snapshots::get_snapshot_evidence_idx_from_file_name(
    path->filename());
}

std::vector<uint8_t> read_latest_committed_snapshot_data(const fs::path& dir)
{
  auto path = latest_committed_snapshot_path(dir);
  if (!path.has_value())
  {
    throw std::logic_error("No committed snapshot");
  }

  return files::slurp(path.value());
}

void issue_transactions(ccf::NetworkState& network, size_t tx_count)
{
  for (size_t i = 0; i < tx_count; i++)
  {
    auto tx = network.tables->create_tx();
    auto map = tx.rw<StringString>("public:map");
    map->put("foo", "bar");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
}

size_t read_latest_snapshot_evidence(
  const std::shared_ptr<ccf::kv::Store>& store)
{
  auto tx = store->create_read_only_tx();
  auto h = tx.ro<ccf::SnapshotEvidence>(ccf::Tables::SNAPSHOT_EVIDENCE);
  auto evidence = h->get();
  if (!evidence.has_value())
  {
    throw std::logic_error("No snapshot evidence");
  }
  return evidence->version;
}

bool record_signature(
  const std::shared_ptr<ccf::MerkleTxHistory>& history,
  const std::shared_ptr<ccf::Snapshotter>& snapshotter,
  size_t idx)
{
  std::vector<uint8_t> dummy_cose_sig = ccf::ds::from_hex(
    "d28451a301382219012c440102030419012d1822a0f6586026a27ea4c9f067a0e6716c779b"
    "80f78b1366b3dec549423f06a2b56f1f25fd45a21e9e6295aed0b05ebca639eac103a68967"
    "e7eb6ef9f7603741960b6fca20841b9730921220e9ec1d0897e424bb4290c5abe498b67373"
    "b96881e8c6f9265af8");

  bool requires_snapshot = snapshotter->record_committable(idx);
  snapshotter->record_cose_signatures(
    idx, {{ccf::IdentityType::CLASSICAL, dummy_cose_sig}});
  snapshotter->record_serialised_tree(idx, history->serialise_tree(idx));

  return requires_snapshot;
}

void record_snapshot_evidence(
  const std::shared_ptr<ccf::Snapshotter>& snapshotter,
  size_t snapshot_idx,
  size_t evidence_idx)
{
  snapshotter->record_snapshot_evidence_idx(
    evidence_idx, ccf::SnapshotHash{.hash = {}, .version = snapshot_idx});
}

TEST_CASE("Regular snapshotting")
{
  ccf::logger::config::default_init();

  ccf::NetworkState network;

  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto history = std::make_shared<ccf::MerkleTxHistory>(
    *network.tables.get(), ccf::kv::test::PrimaryNodeId, *node_kp);
  network.tables->set_history(history);
  network.tables->initialise_term(2);
  network.tables->set_consensus(consensus);
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  network.tables->set_encryptor(encryptor);

  ScopedSnapshotDir snapshot_dir;

  size_t snapshot_tx_interval = 10;

  issue_transactions(network, snapshot_tx_interval);

  auto snapshotter = std::make_shared<ccf::Snapshotter>(
    snapshot_dir.path.string(), network.tables, snapshot_tx_interval);

  size_t commit_idx = 0;
  size_t snapshot_idx = snapshot_tx_interval;
  size_t snapshot_evidence_idx = snapshot_idx + 1;
  size_t last_committed_snapshot_idx = 0;

  INFO("Generate snapshot before interval has no effect");
  {
    REQUIRE_FALSE(record_signature(history, snapshotter, snapshot_idx - 1));
    commit_idx = snapshot_idx - 1;
    snapshotter->commit(commit_idx, true);
    run_one_task();

    REQUIRE_THROWS_AS(
      read_latest_snapshot_evidence(network.tables), std::logic_error);
    REQUIRE_FALSE(latest_committed_snapshot_idx(snapshot_dir.path).has_value());
  }

  INFO("Generate first snapshot");
  {
    issue_transactions(network, snapshot_tx_interval);
    snapshot_idx = 2 * snapshot_idx;
    REQUIRE(record_signature(history, snapshotter, snapshot_idx));

    // Note: even if commit_idx > snapshot_tx_interval, the snapshot is
    // generated at snapshot_idx
    commit_idx = snapshot_idx + 1;
    snapshotter->commit(commit_idx, true);

    run_one_task();
    // Snapshot evidence is committed to the KV, but the snapshot is not
    // released to the host until its evidence is globally committed
    REQUIRE(read_latest_snapshot_evidence(network.tables) == snapshot_idx);
    REQUIRE_FALSE(latest_committed_snapshot_idx(snapshot_dir.path).has_value());
  }

  INFO("Commit first snapshot");
  {
    issue_transactions(network, 1);
    record_snapshot_evidence(snapshotter, snapshot_idx, snapshot_evidence_idx);
    commit_idx = snapshot_idx + 2;
    REQUIRE_FALSE(record_signature(history, snapshotter, commit_idx));
    snapshotter->commit(commit_idx, true);
    // The persist action runs on the task system once commit evidence is
    // durable
    run_one_task();
    REQUIRE(latest_committed_snapshot_idx(snapshot_dir.path) == snapshot_idx);
    REQUIRE(
      latest_committed_snapshot_evidence_idx(snapshot_dir.path) ==
      snapshot_evidence_idx);
    last_committed_snapshot_idx = snapshot_idx;
  }

  INFO("Subsequent commit before next snapshot idx has no effect");
  {
    commit_idx = snapshot_idx + 2;
    snapshotter->commit(commit_idx, true);
    run_one_task();
    REQUIRE(
      latest_committed_snapshot_idx(snapshot_dir.path) ==
      last_committed_snapshot_idx);
  }

  issue_transactions(network, snapshot_tx_interval - 2);

  INFO("Generate second snapshot");
  {
    snapshot_idx = snapshot_tx_interval * 3;
    snapshot_evidence_idx = snapshot_idx + 1;
    REQUIRE(record_signature(history, snapshotter, snapshot_idx));
    // Note: Commit exactly on snapshot idx
    commit_idx = snapshot_idx;
    snapshotter->commit(commit_idx, true);

    run_one_task();
    REQUIRE(read_latest_snapshot_evidence(network.tables) == snapshot_idx);
    REQUIRE(
      latest_committed_snapshot_idx(snapshot_dir.path) ==
      last_committed_snapshot_idx);
  }

  INFO("Commit second snapshot");
  {
    issue_transactions(network, 1);
    record_snapshot_evidence(snapshotter, snapshot_idx, snapshot_evidence_idx);
    // Signature after evidence is recorded
    commit_idx = snapshot_idx + 2;
    REQUIRE_FALSE(record_signature(history, snapshotter, commit_idx));

    snapshotter->commit(commit_idx, true);
    run_one_task();
    REQUIRE(latest_committed_snapshot_idx(snapshot_dir.path) == snapshot_idx);
    REQUIRE(
      latest_committed_snapshot_evidence_idx(snapshot_dir.path) ==
      snapshot_evidence_idx);
    last_committed_snapshot_idx = snapshot_idx;
  }
}

TEST_CASE("Rollback before snapshot is committed")
{
  ccf::NetworkState network;
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto history = std::make_shared<ccf::MerkleTxHistory>(
    *network.tables.get(), ccf::kv::test::PrimaryNodeId, *node_kp);
  network.tables->set_history(history);
  network.tables->initialise_term(2);
  network.tables->set_consensus(consensus);
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  network.tables->set_encryptor(encryptor);

  ScopedSnapshotDir snapshot_dir;

  size_t snapshot_tx_interval = 10;
  issue_transactions(network, snapshot_tx_interval);

  auto snapshotter = std::make_shared<ccf::Snapshotter>(
    snapshot_dir.path.string(), network.tables, snapshot_tx_interval);

  size_t snapshot_idx = 0;
  size_t commit_idx = 0;
  size_t last_committed_snapshot_idx = 0;

  INFO("Generate snapshot");
  {
    snapshot_idx = snapshot_tx_interval;
    REQUIRE(record_signature(history, snapshotter, snapshot_idx));
    snapshotter->commit(snapshot_idx, true);

    run_one_task();
    REQUIRE(read_latest_snapshot_evidence(network.tables) == snapshot_idx);
    REQUIRE_FALSE(latest_committed_snapshot_idx(snapshot_dir.path).has_value());
  }

  INFO("Rollback evidence and commit past it");
  {
    snapshotter->rollback(snapshot_idx);

    // ... More transactions are committed, passing the idx at which the
    // evidence was originally committed

    snapshotter->commit(snapshot_tx_interval + 1, true);

    // Snapshot previously generated is not committed
    REQUIRE_FALSE(latest_committed_snapshot_idx(snapshot_dir.path).has_value());

    snapshotter->commit(snapshot_tx_interval + 2, true);
    REQUIRE_FALSE(latest_committed_snapshot_idx(snapshot_dir.path).has_value());
  }

  INFO("Snapshot again and commit evidence");
  {
    issue_transactions(network, snapshot_tx_interval);
    size_t new_snapshot_idx = network.tables->current_version();

    REQUIRE(record_signature(history, snapshotter, new_snapshot_idx));
    snapshotter->commit(new_snapshot_idx, true);

    run_one_task();
    REQUIRE(read_latest_snapshot_evidence(network.tables) == new_snapshot_idx);
    REQUIRE_FALSE(latest_committed_snapshot_idx(snapshot_dir.path).has_value());

    // Commit evidence
    issue_transactions(network, 1);
    commit_idx = new_snapshot_idx + 2;
    record_snapshot_evidence(
      snapshotter, new_snapshot_idx, new_snapshot_idx + 1);
    REQUIRE_FALSE(record_signature(history, snapshotter, commit_idx));
    snapshotter->commit(commit_idx, true);
    run_one_task();
    REQUIRE(
      latest_committed_snapshot_idx(snapshot_dir.path) == new_snapshot_idx);
    last_committed_snapshot_idx = new_snapshot_idx;
  }

  INFO("Force a snapshot");
  {
    size_t new_snapshot_idx = network.tables->current_version();

    network.tables->set_flag(
      ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE);

    REQUIRE(record_signature(history, snapshotter, new_snapshot_idx));
    snapshotter->commit(new_snapshot_idx, true);

    run_one_task();
    REQUIRE(read_latest_snapshot_evidence(network.tables) == new_snapshot_idx);
    REQUIRE(
      latest_committed_snapshot_idx(snapshot_dir.path) ==
      last_committed_snapshot_idx);

    REQUIRE(!network.tables->flag_enabled(
      ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE));

    // Commit evidence
    issue_transactions(network, 1);
    commit_idx = new_snapshot_idx + 2;
    record_snapshot_evidence(
      snapshotter, new_snapshot_idx, new_snapshot_idx + 1);
    REQUIRE_FALSE(record_signature(history, snapshotter, commit_idx));
    snapshotter->commit(commit_idx, true);
    run_one_task();
    REQUIRE(
      latest_committed_snapshot_idx(snapshot_dir.path) == new_snapshot_idx);
  }

  INFO("Rollback after forced snapshot uses released forced baseline");
  {
    snapshotter->rollback(0);

    // The released forced snapshot was taken at seqno 24. After rollback, the
    // baseline should remain there rather than falling back to the previous
    // regular snapshot at seqno 22.
    issue_transactions(network, snapshot_tx_interval - 4);
    REQUIRE_FALSE(record_signature(
      history, snapshotter, network.tables->current_version()));
  }
}

TEST_CASE("Snapshot status updates preserve future queued snapshot")
{
  ccf::logger::config::default_init();

  ccf::NetworkState network;

  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto history = std::make_shared<ccf::MerkleTxHistory>(
    *network.tables, ccf::kv::test::PrimaryNodeId, *node_kp);
  network.tables->set_history(history);
  network.tables->initialise_term(2);
  network.tables->set_consensus(consensus);
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  network.tables->set_encryptor(encryptor);

  ScopedSnapshotDir snapshot_dir;

  size_t snapshot_tx_interval = 10;
  issue_transactions(network, snapshot_tx_interval);

  auto snapshotter = std::make_shared<ccf::Snapshotter>(
    snapshot_dir.path.string(), network.tables, snapshot_tx_interval);
  REQUIRE(record_signature(history, snapshotter, snapshot_tx_interval));

  issue_transactions(network, snapshot_tx_interval);
  REQUIRE(
    record_signature(history, snapshotter, network.tables->current_version()));

  // Simulate a node learning that the latest released snapshot baseline has
  // moved forward via the replicated snapshot status table.
  snapshotter->record_snapshot_status({
    .version = snapshot_tx_interval + 4,
    .timestamp = 0,
  });

  issue_transactions(network, 6);
  REQUIRE_FALSE(
    record_signature(history, snapshotter, network.tables->current_version()));

  snapshotter->commit(2 * snapshot_tx_interval, true);
  run_one_task();

  // The snapshot was generated at the expected idx, as confirmed by the
  // snapshot evidence recorded in the KV store.
  REQUIRE(
    read_latest_snapshot_evidence(network.tables) == 2 * snapshot_tx_interval);
}

TEST_CASE("Snapshot status restore uses persisted timestamp baseline")
{
  ccf::logger::config::default_init();

  ccf::NetworkState network;

  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto history = std::make_shared<ccf::MerkleTxHistory>(
    *network.tables, ccf::kv::test::PrimaryNodeId, *node_kp);
  network.tables->set_history(history);
  network.tables->initialise_term(2);
  network.tables->set_consensus(consensus);
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  network.tables->set_encryptor(encryptor);

  ScopedSnapshotDir snapshot_dir;

  auto snapshotter = std::make_shared<ccf::Snapshotter>(
    snapshot_dir.path.string(),
    network.tables,
    100,
    2,
    std::chrono::seconds(1));

  snapshotter->init_from_snapshot_status({
    .version = 0,
    .timestamp = 0,
  });

  issue_transactions(network, 2);
  REQUIRE_FALSE(
    record_signature(history, snapshotter, network.tables->current_version()));

  issue_transactions(network, 1);
  REQUIRE(
    record_signature(history, snapshotter, network.tables->current_version()));
}

// https://github.com/microsoft/CCF/issues/3796
TEST_CASE("Rekey ledger while snapshot is in progress")
{
  ccf::logger::config::default_init();

  ccf::NetworkState network;

  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto history = std::make_shared<ccf::MerkleTxHistory>(
    *network.tables.get(), ccf::kv::test::PrimaryNodeId, *node_kp);
  network.tables->set_history(history);
  network.tables->initialise_term(2);
  network.tables->set_consensus(consensus);
  auto ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
  ledger_secrets->init();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(ledger_secrets);
  network.tables->set_encryptor(encryptor);

  ScopedSnapshotDir snapshot_dir;

  size_t snapshot_tx_interval = 10;

  issue_transactions(network, snapshot_tx_interval);

  auto snapshotter = std::make_shared<ccf::Snapshotter>(
    snapshot_dir.path.string(), network.tables, snapshot_tx_interval);

  size_t snapshot_idx = snapshot_tx_interval + 1;

  INFO("Trigger snapshot");
  {
    // It is necessary to record a signature for the snapshot to be
    // deserialisable by the backup store
    auto tx = network.tables->create_tx();
    auto sigs = tx.rw<ccf::Signatures>(ccf::Tables::SIGNATURES);
    auto trees =
      tx.rw<ccf::SerialisedMerkleTree>(ccf::Tables::SERIALISED_MERKLE_TREE);
    sigs->put({ccf::kv::test::PrimaryNodeId, 0, 0, {}, {}, {}, {}});
    auto tree = history->serialise_tree(snapshot_idx - 1);
    trees->put(tree);
    tx.commit();

    REQUIRE(record_signature(history, snapshotter, snapshot_idx));
    snapshotter->commit(snapshot_idx, true);

    // Do not schedule task just yet so that we can interleave ledger rekey
  }

  INFO("Rekey ledger and commit new transactions");
  {
    ledger_secrets->set_secret(snapshot_idx + 1, ccf::make_ledger_secret());

    // Issue new transactions that make use of new ledger secret
    issue_transactions(network, snapshot_tx_interval);
  }

  INFO("Finally, schedule snapshot creation");
  {
    run_one_task();
    REQUIRE(read_latest_snapshot_evidence(network.tables) == snapshot_idx);

    // Globally commit the snapshot evidence so that the snapshot is released
    // to the host, carrying the serialised snapshot bytes.
    issue_transactions(network, 1);
    record_snapshot_evidence(snapshotter, snapshot_idx, snapshot_idx + 1);
    auto commit_idx = snapshot_idx + 2;
    REQUIRE_FALSE(record_signature(history, snapshotter, commit_idx));
    snapshotter->commit(commit_idx, true);

    // The persist action runs on the task system, writing the serialised
    // snapshot bytes to disk.
    run_one_task();

    REQUIRE(latest_committed_snapshot_idx(snapshot_dir.path) == snapshot_idx);
    auto snapshot_data = read_latest_committed_snapshot_data(snapshot_dir.path);

    // Snapshot can be deserialised to backup store
    ccf::NetworkState backup_network;
    auto backup_history = std::make_shared<ccf::MerkleTxHistory>(
      *backup_network.tables.get(), ccf::kv::test::FirstBackupNodeId, *node_kp);
    backup_network.tables->set_history(backup_history);
    auto tx = network.tables->create_read_only_tx();

    auto backup_ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
    backup_ledger_secrets->init_from_map(ledger_secrets->get(tx));
    auto backup_encryptor =
      std::make_shared<ccf::NodeEncryptor>(backup_ledger_secrets);
    backup_network.tables->set_encryptor(backup_encryptor);

    ccf::kv::ConsensusHookPtrs hooks;
    std::vector<ccf::kv::Version> view_history;
    const auto snapshot_segments = ccf::separate_segments(snapshot_data);
    REQUIRE(
      backup_network.tables->deserialise_snapshot(
        snapshot_segments.header_and_body.data(),
        snapshot_segments.header_and_body.size(),
        hooks,
        &view_history) == ccf::kv::ApplyResult::PASS);
  }
}

int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}
