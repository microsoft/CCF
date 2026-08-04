// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/snapshotter.h"

#include "crypto/openssl/hash.h"
#include "ds/files.h"
#include "ds/internal_logger.h"
#include "kv/test/null_encryptor.h"
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

void write_current_ledger_file(
  const fs::path& path, const std::vector<std::vector<uint8_t>>& entries)
{
  std::ofstream ledger_file(path, std::ios::binary);
  REQUIRE(ledger_file);
  const size_t positions_offset = 0;
  ledger_file.write(
    reinterpret_cast<const char*>(&positions_offset), sizeof(positions_offset));
  for (const auto& entry : entries)
  {
    ledger_file.write(
      reinterpret_cast<const char*>(entry.data()),
      static_cast<std::streamsize>(entry.size()));
  }
  REQUIRE(ledger_file);
}

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
      ->put(endorsement);
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
  write_current_ledger_file(
    malformed_ledger_dir.path / "ledger_1", {malformed_entry});
  ccf::CCFConfig::Ledger malformed_ledger_config;
  malformed_ledger_config.directory = malformed_ledger_dir.path.string();
  REQUIRE_THROWS(ccf::scan_recovery_snapshot_ledger_files(
    malformed_ledger_config, encryptor, 0));

  write_current_ledger_file(ledger_dir.path / "ledger_1", entries);

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
      ->put(endorsement);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    auto latest_entry =
      consensus->get_latest_data().value_or(std::vector<uint8_t>{});
    REQUIRE_FALSE(latest_entry.empty());
    entries.push_back(std::move(latest_entry));
  }

  write_current_ledger_file(ledger_dir.path / "ledger_1", entries);

  ccf::CCFConfig::Ledger ledger_config;
  ledger_config.directory = ledger_dir.path.string();
  REQUIRE_THROWS(
    ccf::scan_recovery_snapshot_ledger_files(ledger_config, encryptor, 0));
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

std::optional<fs::path> latest_committed_snapshot_path(const fs::path& dir)
{
  return snapshots::find_latest_committed_snapshot_in_directory(dir);
}

std::optional<::consensus::Index> latest_committed_snapshot_idx(
  const fs::path& dir)
{
  auto path = latest_committed_snapshot_path(dir);
  if (!path.has_value())
  {
    return std::nullopt;
  }

  return snapshots::get_snapshot_idx_from_file_name(path->filename());
}

std::optional<::consensus::Index> latest_committed_snapshot_evidence_idx(
  const fs::path& dir)
{
  auto path = latest_committed_snapshot_path(dir);
  if (!path.has_value())
  {
    return std::nullopt;
  }

  return snapshots::get_snapshot_evidence_idx_from_file_name(path->filename());
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
  snapshotter->record_cose_signature(idx, dummy_cose_sig);
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
