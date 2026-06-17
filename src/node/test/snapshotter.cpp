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
#include "snapshots/filenames.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <chrono>
#include <doctest/doctest.h>
#include <filesystem>
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
    evidence_idx, ccf::SnapshotHash{.version = snapshot_idx});
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
    size_t snapshot_idx = network.tables->current_version();

    REQUIRE(record_signature(history, snapshotter, snapshot_idx));
    snapshotter->commit(snapshot_idx, true);

    run_one_task();
    REQUIRE(read_latest_snapshot_evidence(network.tables) == snapshot_idx);
    REQUIRE_FALSE(latest_committed_snapshot_idx(snapshot_dir.path).has_value());

    // Commit evidence
    issue_transactions(network, 1);
    commit_idx = snapshot_idx + 2;
    record_snapshot_evidence(snapshotter, snapshot_idx, snapshot_idx + 1);
    REQUIRE_FALSE(record_signature(history, snapshotter, commit_idx));
    snapshotter->commit(commit_idx, true);
    run_one_task();
    REQUIRE(latest_committed_snapshot_idx(snapshot_dir.path) == snapshot_idx);
    last_committed_snapshot_idx = snapshot_idx;
  }

  INFO("Force a snapshot");
  {
    size_t snapshot_idx = network.tables->current_version();

    network.tables->set_flag(
      ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE);

    REQUIRE(record_signature(history, snapshotter, snapshot_idx));
    snapshotter->commit(snapshot_idx, true);

    run_one_task();
    REQUIRE(read_latest_snapshot_evidence(network.tables) == snapshot_idx);
    REQUIRE(
      latest_committed_snapshot_idx(snapshot_dir.path) ==
      last_committed_snapshot_idx);

    REQUIRE(!network.tables->flag_enabled(
      ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE));

    // Commit evidence
    issue_transactions(network, 1);
    commit_idx = snapshot_idx + 2;
    record_snapshot_evidence(snapshotter, snapshot_idx, snapshot_idx + 1);
    REQUIRE_FALSE(record_signature(history, snapshotter, commit_idx));
    snapshotter->commit(commit_idx, true);
    run_one_task();
    REQUIRE(latest_committed_snapshot_idx(snapshot_dir.path) == snapshot_idx);
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
