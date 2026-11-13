// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/ec_key_pair.h"
#include "ccf/service/tables/nodes.h"
#include "crypto/openssl/hash.h"
#include "kv/claims.h"
#include "kv/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "node/history.h"
#include "node/snapshot_serdes.h"
#include "service/tables/signatures.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#undef FAIL
#include <sstream>
#include <string>

struct CountingSnapshotBuffer : std::stringbuf
{
  size_t bytes_read = 0;

  CountingSnapshotBuffer(const std::string& data) :
    std::stringbuf(data, std::ios::in)
  {}

  std::streamsize xsgetn(char* data, std::streamsize size) override
  {
    const auto count = std::stringbuf::xsgetn(data, size);
    bytes_read += count;
    return count;
  }
};

TEST_CASE("Recovery reads the receipt before the snapshot body")
{
  ccf::kv::SerialisedEntryHeader header;
  header.set_size(1024 * 1024);
  std::string snapshot(sizeof(header), '\0');
  std::memcpy(snapshot.data(), &header, sizeof(header));
  snapshot.append(header.size, 'b');
  const ccf::crypto::Sha256Hash claims_digest(
    reinterpret_cast<const uint8_t*>(snapshot.data()), snapshot.size());
  const std::string receipt = "test receipt";
  snapshot += receipt;

  CountingSnapshotBuffer buffer(snapshot);
  std::istream input(&buffer);
  const auto receipt_bytes = ccf::read_snapshot_receipt(input);
  CHECK(buffer.bytes_read == sizeof(header) + receipt.size());
  CHECK(std::string(receipt_bytes.begin(), receipt_bytes.end()) == receipt);
  const auto body = std::span(
    reinterpret_cast<const uint8_t*>(snapshot.data()),
    sizeof(header) + header.size);

  SUBCASE("The loaded body matches the authenticated digest")
  {
    CHECK_NOTHROW(ccf::verify_snapshot_digest(body, claims_digest));
  }
  SUBCASE("Authenticated receipts do not permit body tampering")
  {
    snapshot[sizeof(header)] ^= 1;
    CHECK_THROWS_WITH_AS(
      ccf::verify_snapshot_digest(body, claims_digest),
      doctest::Contains("does not match receipt claim"),
      std::logic_error);
  }
  SUBCASE("Authenticated receipts do not permit header tampering")
  {
    snapshot[0] ^= 1;
    CHECK_THROWS_WITH_AS(
      ccf::verify_snapshot_digest(body, claims_digest),
      doctest::Contains("does not match receipt claim"),
      std::logic_error);
  }
}

TEST_CASE("Recovery rejects malformed snapshot framing before authentication")
{
  ccf::kv::SerialisedEntryHeader header;
  std::string suffix;
  SUBCASE("Truncated header")
  {
    suffix = "x";
  }
  SUBCASE("Empty body")
  {
    suffix = "receipt";
  }
  SUBCASE("Missing receipt")
  {
    header.set_size(1);
    suffix = "b";
  }
  SUBCASE("Body size exceeds file size")
  {
    header.set_size(
      ccf::kv::SerialisedEntryHeader::max_serialised_entry_body_size);
    suffix = "b";
  }
  std::string snapshot(sizeof(header), '\0');
  std::memcpy(snapshot.data(), &header, sizeof(header));
  snapshot += suffix;
  if (suffix == "x")
  {
    snapshot.resize(sizeof(header) - 1);
  }
  std::istringstream input(snapshot);
  CHECK_THROWS(ccf::read_snapshot_receipt(input));
}

TEST_CASE("Legacy JSON snapshot receipts authenticate before body validation")
{
  auto service_key = ccf::crypto::make_ec_key_pair();
  const auto service_cert = service_key->self_sign(
    "CN=Test Service", "20200101000000Z", "20300101000000Z");
  auto node_key = ccf::crypto::make_ec_key_pair();
  auto receipt = std::make_shared<ccf::ProofReceipt>();
  receipt->cert = service_key->sign_csr(
    service_cert,
    node_key->create_csr("CN=Test Node"),
    "20200101000000Z",
    "20300101000000Z");
  receipt->node_id = ccf::compute_node_id_from_kp(node_key);

  ccf::kv::SerialisedEntryHeader header;
  header.set_size(128);
  std::string snapshot(sizeof(header), '\0');
  std::memcpy(snapshot.data(), &header, sizeof(header));
  snapshot.append(header.size, 'b');
  receipt->leaf_components.claims_digest.set(ccf::crypto::Sha256Hash(
    reinterpret_cast<const uint8_t*>(snapshot.data()), snapshot.size()));
  const auto root = receipt->calculate_root();
  receipt->signature = node_key->sign_hash(root.h.data(), root.h.size());

  auto target = service_cert;
  bool reject = false;
  SUBCASE("Matching identity") {}
  SUBCASE("Wrong identity")
  {
    auto other_key = ccf::crypto::make_ec_key_pair();
    target = other_key->self_sign(
      "CN=Other Service", "20200101000000Z", "20300101000000Z");
    reject = true;
  }
  SUBCASE("Invalid signature")
  {
    receipt->signature.back() ^= 1;
    reject = true;
  }

  const auto receipt_json = nlohmann::json(ccf::ReceiptPtr(receipt)).dump();
  snapshot += receipt_json;
  CountingSnapshotBuffer buffer(snapshot);
  std::istream input(&buffer);
  const auto load = [&]() {
    const auto receipt_bytes = ccf::read_snapshot_receipt(input);
    const auto claims_digest =
      ccf::verify_json_snapshot_receipt_signature(receipt_bytes, target.raw());
    const auto body = std::span(
      reinterpret_cast<const uint8_t*>(snapshot.data()),
      sizeof(header) + header.size);
    ccf::verify_snapshot_digest(body, claims_digest);
  };
  if (reject)
  {
    CHECK_THROWS(load());
    CHECK(buffer.bytes_read == sizeof(header) + receipt_json.size());
  }
  else
  {
    CHECK_NOTHROW(load());
  }
}

TEST_CASE("Snapshot with merkle tree" * doctest::test_suite("snapshot"))
{
  auto source_consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  ccf::kv::Store source_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  source_store.set_encryptor(encryptor);
  source_store.set_consensus(source_consensus);

  auto service_kp = std::dynamic_pointer_cast<ccf::crypto::ECKeyPair_OpenSSL>(
    ccf::crypto::make_ec_key_pair());

  ccf::NodeId source_node_id = ccf::kv::test::PrimaryNodeId;
  auto source_node_kp = ccf::crypto::make_ec_key_pair();

  auto source_history = std::make_shared<ccf::MerkleTxHistory>(
    source_store, source_node_id, *source_node_kp);
  source_history->set_endorsed_certificate({});
  source_history->set_service_signing_identity(
    service_kp, ccf::COSESignaturesConfig{});
  source_store.set_history(source_history);
  source_store.initialise_term(2);

  ccf::kv::Map<std::string, std::string> string_map("public:string_map");

  size_t transactions_count = 3;
  ccf::kv::Version snapshot_version = ccf::kv::NoVersion;

  INFO("Apply transactions to original store");
  {
    for (size_t i = 0; i < transactions_count; i++)
    {
      auto tx = source_store.create_tx();
      auto map = tx.rw(string_map);
      map->put(fmt::format("key#{}", i), "value");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
  }

  auto source_root_before_signature =
    source_history->get_replicated_state_root();

  INFO("Emit signature");
  {
    source_history->emit_signature();
    // Snapshot version is the version of the signature
    snapshot_version = transactions_count + 1;
  }

  INFO("Check tree start from mini-tree and sig hash");
  {
    // No snapshot here, only verify that a fresh tree can be started from the
    // mini-tree in a signature and the hash of the signature
    auto tx = source_store.create_read_only_tx();
    auto signatures = tx.ro<ccf::Signatures>(ccf::Tables::SIGNATURES);
    REQUIRE(signatures->has());
    auto sig = signatures->get().value();
    auto serialised_tree =
      tx.ro<ccf::SerialisedMerkleTree>(ccf::Tables::SERIALISED_MERKLE_TREE);
    REQUIRE(serialised_tree->has());
    auto tree = serialised_tree->get();

    auto serialised_signature = source_consensus->get_latest_data().value();

    ccf::MerkleTreeHistory target_tree(tree.value());
    REQUIRE(source_root_before_signature == target_tree.get_root());

    target_tree.append(ccf::entry_leaf(
      serialised_signature,
      ccf::crypto::Sha256Hash("ce:2.4:"),
      ccf::empty_claims()));
    REQUIRE(
      target_tree.get_root() == source_history->get_replicated_state_root());
  }

  INFO("Snapshot at signature");
  {
    ccf::kv::Store target_store;
    auto target_encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
    target_store.set_encryptor(target_encryptor);
    INFO("Setup target store");
    {
      auto target_node_kp = ccf::crypto::make_ec_key_pair();

      auto target_history = std::make_shared<ccf::MerkleTxHistory>(
        target_store, ccf::kv::test::PrimaryNodeId, *target_node_kp);
      target_history->set_endorsed_certificate({});
      target_history->set_service_signing_identity(
        service_kp, ccf::COSESignaturesConfig{});
      target_store.set_history(target_history);
    }

    auto target_history = target_store.get_history();

    INFO("Apply snapshot taken before any signature was emitted");
    {
      std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot =
        nullptr;
      {
        ccf::kv::ScopedStoreMapsLock maps_lock(&source_store);
        snapshot = source_store.snapshot_unsafe_maps(snapshot_version - 1);
      }
      auto serialised_snapshot =
        source_store.serialise_snapshot(std::move(snapshot));

      // There is no signature to read to seed the target history
      std::vector<ccf::kv::Version> view_history;
      ccf::kv::ConsensusHookPtrs hooks;
      REQUIRE(
        target_store.deserialise_snapshot(
          serialised_snapshot.data(),
          serialised_snapshot.size(),
          hooks,
          &view_history) == ccf::kv::ApplyResult::FAIL);
    }

    INFO("Apply snapshot taken at signature");
    {
      std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot =
        nullptr;
      {
        ccf::kv::ScopedStoreMapsLock maps_lock(&source_store);
        snapshot = source_store.snapshot_unsafe_maps(snapshot_version);
      }
      auto serialised_snapshot =
        source_store.serialise_snapshot(std::move(snapshot));

      std::vector<ccf::kv::Version> view_history;
      ccf::kv::ConsensusHookPtrs hooks;
      REQUIRE(
        target_store.deserialise_snapshot(
          serialised_snapshot.data(),
          serialised_snapshot.size(),
          hooks,
          &view_history) == ccf::kv::ApplyResult::PASS);

      // Merkle history and view history thus far are restored when applying
      // snapshot
      REQUIRE(
        source_history->get_replicated_state_root() ==
        target_history->get_replicated_state_root());
      REQUIRE(
        source_consensus->view_history.get_history_until() == view_history);
    }

    INFO("Deserialise additional transaction after restart");
    {
      auto tx = source_store.create_tx();
      auto map = tx.rw(string_map);
      map->put("key", "value");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

      auto serialised_tx = source_consensus->get_latest_data().value();

      target_store.deserialize(serialised_tx)->apply();

      REQUIRE(
        target_history->get_replicated_state_root() ==
        source_history->get_replicated_state_root());
    }
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
