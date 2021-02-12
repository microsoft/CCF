// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/messaging.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "node/historical_queries.h"
#include "node/history.h"
#include "node/share_manager.h"
#include "tls/rsa_key_pair.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

threading::ThreadMessaging threading::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> threading::ThreadMessaging::thread_count = 0;

struct StubWriter : public ringbuffer::AbstractWriter
{
public:
  struct Write
  {
    ringbuffer::Message m;
    bool finished;
    std::vector<uint8_t> contents;
  };
  std::vector<Write> writes;

  Write& get_write(const WriteMarker& marker)
  {
    REQUIRE(marker.has_value());
    REQUIRE(marker.value() < writes.size());
    return writes[marker.value()];
  }

  Write& get_last_message()
  {
    REQUIRE(writes.size() > 0);
    auto& write = writes.back();
    REQUIRE(write.finished);
    return write;
  }

  WriteMarker prepare(
    ringbuffer::Message m,
    size_t size,
    bool wait = true,
    size_t* identifier = nullptr) override
  {
    const auto index = writes.size();
    writes.push_back(Write{m, false, {}});
    return index;
  }

  void finish(const WriteMarker& marker) override
  {
    get_write(marker).finished = true;
  }

  WriteMarker write_bytes(
    const WriteMarker& marker, const uint8_t* bytes, size_t size) override
  {
    auto& write = get_write(marker);
    write.contents.insert(write.contents.end(), bytes, bytes + size);
    return marker;
  }
};

TEST_CASE("StateCache")
{
  ccf::NetworkState network;

  auto consensus = std::make_shared<kv::StubConsensus>();

  network.tables->set_consensus(consensus);
  auto& store = *network.tables.get();

  // Make history to produce signatures
  const auto node_id = 0;
  auto kp = tls::make_key_pair();
  auto history = std::make_shared<ccf::MerkleTxHistory>(store, node_id, *kp);

  store.set_history(history);

  // Make ledger secrets and share manager to rekey ledger and record previous
  // encrypted ledger secret
  network.ledger_secrets = std::make_shared<ccf::LedgerSecrets>(node_id);
  network.ledger_secrets->init();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(network.ledger_secrets);
  ccf::ShareManager share_manager(network);

  store.set_encryptor(encryptor);

  using NumToString = kv::Map<size_t, std::string>;

  constexpr size_t low_signature_transaction = 3;
  constexpr size_t high_signature_transaction = 100;

  constexpr size_t low_index = low_signature_transaction + 2;
  constexpr size_t high_index = high_signature_transaction - 3;
  constexpr size_t unsigned_index = high_signature_transaction + 5;

  // Rekey the ledger inside the range
  constexpr size_t first_rekey_index = low_index + 10;
  constexpr size_t second_rekey_index = first_rekey_index + 10;
  constexpr size_t third_rekey_index = high_signature_transaction - 1;

  {
    INFO("Build some interesting state in the store");

    {
      auto tx = store.create_tx();

      INFO("Store the signing node's key");
      auto nodes = tx.rw<ccf::Nodes>(ccf::Tables::NODES);
      ccf::NodeInfo ni;
      ni.cert = kp->self_sign("CN=Test node");
      ni.status = ccf::NodeStatus::TRUSTED;
      nodes->put(node_id, ni);

      INFO("Store one recovery member");
      // This is necessary to rekey the ledger and issue recovery shares for the
      // new ledger secret
      auto config = tx.rw<ccf::Configuration>(ccf::Tables::CONFIGURATION);
      size_t recovery_threshold = 1;
      config->put(0, {recovery_threshold});
      auto members = tx.rw<ccf::Members>(ccf::Tables::MEMBERS);
      ccf::MemberInfo mi;
      mi.status = ccf::MemberStatus::ACTIVE;
      mi.encryption_pub_key = tls::make_rsa_key_pair()->public_key_pem();
      members->put(0, mi);

      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    }

    {
      for (size_t i = 1; i < high_signature_transaction; ++i)
      {
        if (
          i == low_signature_transaction - 1 ||
          i == high_signature_transaction - 1)
        {
          history->emit_signature();
          store.compact(store.current_version());
        }
        else if (
          i == first_rekey_index || i == second_rekey_index ||
          i == third_rekey_index)
        {
          LOG_DEBUG_FMT("Ledger rekey at {}", i);

          auto tx = store.create_tx();

          auto new_ledger_secret = ccf::make_ledger_secret();
          share_manager.issue_recovery_shares(tx, new_ledger_secret);
          network.ledger_secrets->set_secret(
            i + 1, std::move(new_ledger_secret.raw_key), i + 1);

          REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
        }
        else
        {
          auto tx = store.create_tx();
          auto public_map = tx.rw<NumToString>("public:data");
          auto private_map = tx.rw<NumToString>("data");
          const auto s = std::to_string(i);
          public_map->put(i, s);
          private_map->put(i, s);

          REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
        }
      }
    }

    REQUIRE(store.current_version() == high_signature_transaction);
  }

  std::map<consensus::Index, std::vector<uint8_t>> ledger;
  {
    INFO("Rebuild ledger as seen by host");
    auto next_ledger_entry = consensus->pop_oldest_entry();
    while (next_ledger_entry.has_value())
    {
      const auto ib = ledger.insert(std::make_pair(
        std::get<0>(next_ledger_entry.value()),
        *std::get<1>(next_ledger_entry.value())));
      REQUIRE(ib.second);
      next_ledger_entry = consensus->pop_oldest_entry();
    }

    REQUIRE(ledger.size() == high_signature_transaction);
  }

  // Now we actually get to the historical queries
  std::vector<consensus::Index> requested_ledger_entries = {};
  messaging::BufferProcessor bp("historical_queries");
  DISPATCHER_SET_MESSAGE_HANDLER(
    bp,
    consensus::ledger_get,
    [&requested_ledger_entries](const uint8_t* data, size_t size) {
      auto [idx, purpose] =
        ringbuffer::read_message<consensus::ledger_get>(data, size);
      REQUIRE(purpose == consensus::LedgerRequestPurpose::HistoricalQuery);
      requested_ledger_entries.push_back(idx);
    });

  constexpr size_t buffer_size = 1 << 12;
  auto buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  ringbuffer::Reader rr(buffer->bd);

  ccf::NetworkState recovered_network;

  {
    INFO("Recover a new service, as if the node had recovered from a snapshot");

    recovered_network.ledger_secrets =
      std::make_shared<ccf::LedgerSecrets>(node_id);

    // Initially, the new service has only access to the very latest ledger
    // secret. The historical ledger secrets will be recovered from the
    // ledger before fetching historical entries.
    auto tx = recovered_network.tables->create_read_only_tx();
    ccf::LedgerSecretsMap recovered_ledger_secrets;
    recovered_ledger_secrets.emplace(network.ledger_secrets->get_latest(tx));
    recovered_network.ledger_secrets->restore_historical(
      std::move(recovered_ledger_secrets));

    auto new_encryptor =
      std::make_shared<ccf::NodeEncryptor>(recovered_network.ledger_secrets);
    recovered_network.tables->set_encryptor(new_encryptor);
  }

  auto rw = std::make_shared<ringbuffer::Writer>(rr);
  ccf::historical::StateCache cache(recovered_network, rw);

  {
    INFO("Start fetching historical entries");
    REQUIRE(cache.get_store_at(low_index) == nullptr);
    // REQUIRE(cache.get_store_at(high_index) == nullptr);
    // REQUIRE(cache.get_store_at(unsigned_index) == nullptr);
  }

  auto provide_ledger_entry = [&](size_t i) {
    bool accepted = cache.handle_ledger_entry(i, ledger.at(i));
    // Pump outbound ringbuffer to clear messages
    bp.read_n(100, rr);
    return accepted;
  };

  {
    INFO(
      "The host sees request for historical ledger secret preceding target "
      "idx");

    size_t request_count = 0;
    const auto read = bp.read_n(100, rr);
    REQUIRE(read == 1);
    REQUIRE(requested_ledger_entries.size() == 1);
    REQUIRE(
      requested_ledger_entries[0] >
      low_index); // TODO: More precise assert. We should be looking at the
                  // index at which the previous ledger secret is stored at

    REQUIRE(provide_ledger_entry(requested_ledger_entries[request_count++]));
    REQUIRE(provide_ledger_entry(requested_ledger_entries[request_count++]));
  }

  // {
  //   INFO("The host sees one request for each index");
  //   const auto read = bp.read_n(100, rr);
  //   REQUIRE(read == 3);
  //   REQUIRE(requested_ledger_entries.size() == 3);
  //   REQUIRE(
  //     requested_ledger_entries ==
  //     std::vector<consensus::Index>{low_index, high_index, unsigned_index});
  // }

  {
    INFO("Cache doesn't accept arbitrary entries");
    REQUIRE(!provide_ledger_entry(high_index - 1));
    REQUIRE(!provide_ledger_entry(high_index + 1));
  }

  {
    INFO(
      "Cache accepts requested entries, and then range of supporting
      entries");
    // REQUIRE(provide_ledger_entry(high_index));

    // Count up to next signature
    for (size_t i = high_index + 1; i < high_signature_transaction; ++i)
    {
      REQUIRE(provide_ledger_entry(i));
      REQUIRE(cache.get_store_at(high_index) == nullptr);
    }

    REQUIRE(provide_ledger_entry(high_signature_transaction));
    REQUIRE(cache.get_store_at(high_index) != nullptr);
  }

  // {
  //   INFO(
  //     "Cache accepts _wrong_ requested entry, and the range of supporting "
  //     "entries");
  //   // NB: This is _a_ valid entry, but not at this index. In fact this stage
  //   // will accept anything that looks quite like a valid entry, even if it
  //   // never came from a legitimate node - they should all fail at the
  //   signature
  //   // check
  //   REQUIRE(cache.get_store_at(low_index) == nullptr);
  //   REQUIRE(cache.handle_ledger_entry(low_index, ledger.at(low_index + 1)));

  //   // Count up to next signature
  //   for (size_t i = low_index + 1; i < high_signature_transaction; ++i)
  //   {
  //     REQUIRE(provide_ledger_entry(i));
  //     REQUIRE(cache.get_store_at(low_index) == nullptr);
  //   }

  //   // Signature is good
  //   REQUIRE(provide_ledger_entry(high_signature_transaction));
  //   // Junk entry is still not available
  //   REQUIRE(cache.get_store_at(low_index) == nullptr);
  // }

  // {
  //   INFO("Historical state can be retrieved from provided entries");
  //   auto store_at_index = cache.get_store_at(high_index);
  //   REQUIRE(store_at_index != nullptr);

  //   {
  //     auto tx = store_at_index->create_tx();
  //     auto public_map = tx.rw<NumToString>("public:data");
  //     auto private_map = tx.rw<NumToString>("data");

  //     const auto k = high_index - 1;
  //     const auto v = std::to_string(k);

  //     auto public_v = public_map->get(k);
  //     REQUIRE(public_v.has_value());
  //     REQUIRE(*public_v == v);

  //     auto private_v = private_map->get(k);
  //     REQUIRE(private_v.has_value());
  //     REQUIRE(*private_v == v);

  //     size_t public_count = 0;
  //     public_map->foreach([&public_count](const auto& k, const auto& v) {
  //       REQUIRE(public_count++ == 0);
  //       return true;
  //     });

  //     size_t private_count = 0;
  //     private_map->foreach([&private_count](const auto& k, const auto& v) {
  //       REQUIRE(private_count++ == 0);
  //       return true;
  //     });
  //   }
  // }

  // {
  //   INFO("Cache doesn't throw when given junk");
  //   REQUIRE(cache.get_store_at(unsigned_index) == nullptr);
  //   bool result;
  //   REQUIRE_NOTHROW(result = cache.handle_ledger_entry(unsigned_index, {}));
  //   REQUIRE(!result);
  //   REQUIRE_NOTHROW(
  //     result = cache.handle_ledger_entry(unsigned_index, {0x1, 0x2, 0x3}));
  //   REQUIRE(!result);
  //   REQUIRE_NOTHROW(
  //     result = cache.handle_ledger_entry(unsigned_index, ledger[low_index]));
  //   REQUIRE(!result);
  //   REQUIRE_NOTHROW(
  //     result = cache.handle_ledger_entry(
  //       unsigned_index, ledger[high_signature_transaction]));
  //   REQUIRE(!result);
  // }

  // {
  //   INFO("Signature transactions can be requested");
  //   for (const auto i : {low_signature_transaction,
  //   high_signature_transaction})
  //   {
  //     auto store_at_index = cache.get_store_at(i);
  //     REQUIRE(store_at_index == nullptr);

  //     REQUIRE(provide_ledger_entry(i));

  //     store_at_index = cache.get_store_at(i);
  //     REQUIRE(store_at_index != nullptr);
  //   }
  // }
}