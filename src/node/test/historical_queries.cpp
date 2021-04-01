// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/historical_queries.h"

#include "crypto/rsa_key_pair.h"
#include "ds/messaging.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "node/history.h"
#include "node/share_manager.h"

#include <algorithm>
#include <random>
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

threading::ThreadMessaging threading::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> threading::ThreadMessaging::thread_count = 0;

using NumToString = kv::Map<size_t, std::string>;

struct StubWriter : public ringbuffer::AbstractWriter
{
public:
  struct Write
  {
    ringbuffer::Message m;
    bool finished;
    std::vector<uint8_t> contents;
  };
  std::mutex writes_mutex;
  std::vector<Write> writes;

  Write& get_write(const WriteMarker& marker)
  {
    REQUIRE(marker.has_value());
    REQUIRE(marker.value() < writes.size());
    return writes[marker.value()];
  }

  WriteMarker prepare(
    ringbuffer::Message m,
    size_t size,
    bool wait = true,
    size_t* identifier = nullptr) override
  {
    std::lock_guard<std::mutex> guard(writes_mutex);
    const auto seqno = writes.size();
    writes.push_back(Write{m, false, {}});
    return seqno;
  }

  void finish(const WriteMarker& marker) override
  {
    std::lock_guard<std::mutex> guard(writes_mutex);
    get_write(marker).finished = true;
  }

  WriteMarker write_bytes(
    const WriteMarker& marker, const uint8_t* bytes, size_t size) override
  {
    std::lock_guard<std::mutex> guard(writes_mutex);
    auto& write = get_write(marker);
    write.contents.insert(write.contents.end(), bytes, bytes + size);
    return marker;
  }
};

struct TestState
{
  std::shared_ptr<kv::Store> kv_store = nullptr;
  std::shared_ptr<ccf::LedgerSecrets> ledger_secrets = nullptr;
};

TestState create_and_init_state(bool initialise_ledger_rekey = true)
{
  TestState ts;

  ts.kv_store =
    std::make_shared<kv::Store>(std::make_shared<kv::test::StubConsensus>());

  // Generate node's keypair once, on first call to this function
  static crypto::KeyPairPtr node_kp = nullptr;
  if (node_kp == nullptr)
  {
    node_kp = crypto::make_key_pair();
  }

  // Make history to produce signatures
  const ccf::NodeId node_id = std::string("node_id");
  ts.kv_store->set_history(
    std::make_shared<ccf::MerkleTxHistory>(*ts.kv_store, node_id, *node_kp));

  {
    INFO("Store the signing node's key");
    auto tx = ts.kv_store->create_tx();
    auto nodes = tx.rw<ccf::Nodes>(ccf::Tables::NODES);
    ccf::NodeInfo ni;
    ni.cert = node_kp->self_sign("CN=Test node");
    ni.status = ccf::NodeStatus::TRUSTED;
    nodes->put(node_id, ni);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  // Create ledger secrets to test decrypting entries across rekeys
  ts.ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
  // NB: Encryptor is deliberately set _after_ adding the signing node. That
  // first transaction needed to be unencrypted
  ts.kv_store->set_encryptor(
    std::make_shared<ccf::NodeEncryptor>(ts.ledger_secrets));

  if (initialise_ledger_rekey)
  {
    ts.ledger_secrets->init();

    INFO("Store one recovery member");
    // This is necessary to rekey the ledger and issue recovery shares for the
    // new ledger secret
    auto tx = ts.kv_store->create_tx();
    auto config = tx.rw<ccf::Configuration>(ccf::Tables::CONFIGURATION);
    size_t recovery_threshold = 1;
    config->put(0, {recovery_threshold});
    auto member_info = tx.rw<ccf::MemberInfo>(ccf::Tables::MEMBER_INFO);
    auto member_public_encryption_keys = tx.rw<ccf::MmeberPublicEncryptionKeys>(
      ccf::Tables::MEMBER_ENCRYPTION_PUBLIC_KEYS);

    auto kp = crypto::make_key_pair();
    auto cert = kp->self_sign("CN=member");
    auto member_id =
      crypto::Sha256Hash(crypto::cert_pem_to_der(cert)).hex_str();

    member_info->put(member_id, {ccf::MemberStatus::ACTIVE});
    member_public_encryption_keys->put(
      member_id, crypto::make_rsa_key_pair()->public_key_pem());
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  return ts;
}

kv::Version write_transactions(kv::Store& kv_store, size_t tx_count)
{
  const auto begin = kv_store.current_version();
  const auto end = begin + tx_count;
  for (size_t i = begin; i < end; ++i)
  {
    auto tx = kv_store.create_tx();
    auto public_map = tx.rw<NumToString>("public:data");
    auto private_map = tx.rw<NumToString>("data");
    const auto s = std::to_string(i);
    public_map->put(i, s);
    private_map->put(i, s);

    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  return kv_store.current_version();
}

kv::Version write_transactions_and_signature(
  kv::Store& kv_store, size_t tx_count)
{
  write_transactions(kv_store, tx_count);

  kv_store.get_history()->emit_signature();
  kv_store.compact(kv_store.current_version());

  return kv_store.current_version();
}

kv::Version rekey(
  kv::Store& kv_store,
  const std::shared_ptr<ccf::LedgerSecrets>& ledger_secrets)
{
  // This isn't really used, but is needed for ShareManager, so can be recreated
  // each time here
  ccf::NetworkState network;
  network.ledger_secrets = ledger_secrets;
  ccf::ShareManager share_manager(network);

  auto tx = kv_store.create_tx();
  auto new_ledger_secret = ccf::make_ledger_secret();
  share_manager.issue_recovery_shares(tx, new_ledger_secret);
  REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);

  auto tx_version = tx.commit_version();

  ledger_secrets->set_secret(
    tx_version + 1,
    std::make_shared<ccf::LedgerSecret>(
      std::move(new_ledger_secret->raw_key), tx_version));

  return tx_version;
}

void validate_business_transaction(
  ccf::historical::StorePtr store, ccf::SeqNo seqno)
{
  REQUIRE(store != nullptr);

  auto tx = store->create_read_only_tx();
  auto public_map = tx.ro<NumToString>("public:data");
  auto private_map = tx.ro<NumToString>("data");

  const auto k = seqno - 1;
  const auto v = std::to_string(k);

  auto public_v = public_map->get(k);
  REQUIRE(public_v.has_value());
  REQUIRE(*public_v == v);

  auto private_v = private_map->get(k);
  REQUIRE(private_v.has_value());
  REQUIRE(*private_v == v);

  size_t public_count = 0;
  public_map->foreach([&public_count](const auto& k, const auto& v) {
    REQUIRE(public_count++ == 0);
    return true;
  });

  size_t private_count = 0;
  private_map->foreach([&private_count](const auto& k, const auto& v) {
    REQUIRE(private_count++ == 0);
    return true;
  });
}

std::map<ccf::SeqNo, std::vector<uint8_t>> construct_host_ledger(
  std::shared_ptr<kv::Consensus> c)
{
  auto consensus = dynamic_cast<kv::test::StubConsensus*>(c.get());
  REQUIRE(consensus != nullptr);

  INFO("Rebuild ledger as seen by host");
  std::map<ccf::SeqNo, std::vector<uint8_t>> ledger;

  auto next_ledger_entry = consensus->pop_oldest_entry();
  while (next_ledger_entry.has_value())
  {
    const auto ib = ledger.insert(std::make_pair(
      std::get<0>(next_ledger_entry.value()),
      *std::get<1>(next_ledger_entry.value())));
    REQUIRE(ib.second);
    next_ledger_entry = consensus->pop_oldest_entry();
  }

  return ledger;
}

TEST_CASE("StateCache point queries")
{
  auto state = create_and_init_state();
  auto& kv_store = *state.kv_store;

  kv::Version low_signature_transaction;
  kv::Version high_signature_transaction;

  {
    INFO("Build some interesting state in the store");
    low_signature_transaction = write_transactions_and_signature(kv_store, 3);
    high_signature_transaction = write_transactions_and_signature(kv_store, 20);
    REQUIRE(kv_store.current_version() == high_signature_transaction);
  }

  const auto low_seqno = low_signature_transaction + 2;
  const auto high_seqno = high_signature_transaction - 3;
  const auto unsigned_seqno = high_signature_transaction + 5;

  auto ledger = construct_host_ledger(state.kv_store->get_consensus());
  REQUIRE(ledger.size() == high_signature_transaction);

  // Now we actually get to the historical queries
  auto stub_writer = std::make_shared<StubWriter>();
  ccf::historical::StateCache cache(
    kv_store, state.ledger_secrets, stub_writer);

  static const ccf::historical::RequestHandle default_handle = 0;
  static const ccf::historical::RequestHandle low_handle = 1;
  static const ccf::historical::RequestHandle high_handle = 2;

  {
    INFO(
      "Initially, no stores are available, even if they're requested multiple "
      "times");
    REQUIRE(cache.get_store_at(low_handle, low_seqno) == nullptr);
    REQUIRE(cache.get_store_at(low_handle, low_seqno) == nullptr);
    REQUIRE(cache.get_store_at(high_handle, high_seqno) == nullptr);
    REQUIRE(cache.get_store_at(low_handle, low_seqno) == nullptr);
    REQUIRE(cache.get_store_at(default_handle, unsigned_seqno) == nullptr);
    REQUIRE(cache.get_store_at(high_handle, high_seqno) == nullptr);
    REQUIRE(cache.get_store_at(low_handle, low_seqno) == nullptr);
  }

  {
    INFO("The host sees requests for these indices");
    REQUIRE(!stub_writer->writes.empty());
    std::set<ccf::SeqNo> expected{low_seqno, high_seqno, unsigned_seqno};
    std::set<ccf::SeqNo> actual;
    for (const auto& write : stub_writer->writes)
    {
      const uint8_t* data = write.contents.data();
      size_t size = write.contents.size();
      auto [seqno, purpose] =
        ringbuffer::read_message<consensus::ledger_get>(data, size);
      REQUIRE(purpose == consensus::LedgerRequestPurpose::HistoricalQuery);
      actual.insert(seqno);
    }
    REQUIRE(actual == expected);
  }

  auto provide_ledger_entry = [&](size_t i) {
    bool accepted = cache.handle_ledger_entry(i, ledger.at(i));
    return accepted;
  };

  {
    INFO("Cache doesn't accept arbitrary entries");
    REQUIRE(!provide_ledger_entry(high_seqno - 1));
    REQUIRE(!provide_ledger_entry(high_seqno + 1));
  }

  {
    INFO(
      "Cache accepts requested entries, and then range of supporting entries");
    REQUIRE(provide_ledger_entry(high_seqno));

    // Count up to next signature
    for (size_t i = high_seqno + 1; i < high_signature_transaction; ++i)
    {
      REQUIRE(provide_ledger_entry(i));
      REQUIRE(cache.get_store_at(high_handle, high_seqno) == nullptr);
    }

    REQUIRE(provide_ledger_entry(high_signature_transaction));
    REQUIRE(cache.get_store_at(high_handle, high_seqno) != nullptr);
  }

  {
    INFO(
      "Cache accepts _wrong_ requested entry, and the range of supporting "
      "entries");
    // NB: This is _a_ valid entry, but not at this seqno. In fact this stage
    // will accept anything that looks quite like a valid entry, even if it
    // never came from a legitimate node - they should all fail at the signature
    // check
    REQUIRE(cache.get_store_at(low_handle, low_seqno) == nullptr);
    REQUIRE(cache.handle_ledger_entry(low_seqno, ledger.at(low_seqno + 1)));

    // Count up to next signature
    for (size_t i = low_seqno + 1; i < high_signature_transaction; ++i)
    {
      REQUIRE(provide_ledger_entry(i));
      REQUIRE(cache.get_store_at(low_handle, low_seqno) == nullptr);
    }

    // Signature is good
    REQUIRE(provide_ledger_entry(high_signature_transaction));
    // Junk entry is still not available
    REQUIRE(cache.get_store_at(low_handle, low_seqno) == nullptr);
  }

  {
    INFO("Historical state can be retrieved from provided entries");
    auto store_at_seqno = cache.get_store_at(high_handle, high_seqno);
    REQUIRE(store_at_seqno != nullptr);

    validate_business_transaction(store_at_seqno, high_seqno);
  }

  {
    INFO("Cache doesn't throw when given junk");
    REQUIRE(cache.get_store_at(default_handle, unsigned_seqno) == nullptr);
    bool result;
    REQUIRE_NOTHROW(result = cache.handle_ledger_entry(unsigned_seqno, {}));
    REQUIRE(!result);
    REQUIRE_NOTHROW(
      result = cache.handle_ledger_entry(unsigned_seqno, {0x1, 0x2, 0x3}));
    REQUIRE(!result);
    REQUIRE_NOTHROW(
      result = cache.handle_ledger_entry(unsigned_seqno, ledger[low_seqno]));
    REQUIRE(!result);
    REQUIRE_NOTHROW(
      result = cache.handle_ledger_entry(
        unsigned_seqno, ledger[high_signature_transaction]));
    REQUIRE(!result);
  }

  {
    INFO("Signature transactions can be requested");
    for (const auto i : {low_signature_transaction, high_signature_transaction})
    {
      auto store_at_seqno = cache.get_store_at(default_handle, i);
      REQUIRE(store_at_seqno == nullptr);

      REQUIRE(provide_ledger_entry(i));

      store_at_seqno = cache.get_store_at(default_handle, i);
      REQUIRE(store_at_seqno != nullptr);
    }

    {
      INFO("Store remains available for future requests using the same handle");
      const auto store1 =
        cache.get_store_at(default_handle, high_signature_transaction);
      REQUIRE(store1 != nullptr);

      const auto store2 =
        cache.get_store_at(default_handle, high_signature_transaction);
      REQUIRE(store2 == store1);
    }

    {
      INFO("Dropping a handle deletes it, and it can no longer be retrieved");
      cache.drop_request(default_handle);
      const auto store =
        cache.get_store_at(default_handle, high_signature_transaction);
      REQUIRE(store == nullptr);
    }

    {
      INFO("Handles are dropped automatically after their expiry duration");

      // Initial requests - low uses default expiry while high gets custom
      // expiry
      cache.set_default_expiry_duration(std::chrono::seconds(60));
      cache.get_store_at(low_handle, low_signature_transaction);
      cache.get_store_at(
        high_handle, high_signature_transaction, std::chrono::seconds(30));

      REQUIRE(provide_ledger_entry(low_signature_transaction));
      REQUIRE(provide_ledger_entry(high_signature_transaction));

      // NB: Calling get_store_at always resets the expiry time, so it must be
      // passed on each retrieval attempt

      // No time has passed, both are available
      REQUIRE(
        cache.get_store_at(low_handle, low_signature_transaction) != nullptr);
      REQUIRE(
        cache.get_store_at(
          high_handle, high_signature_transaction, std::chrono::seconds(30)) !=
        nullptr);

      // Some time passes, but not enough for either expiry
      cache.tick(std::chrono::milliseconds(20'000));
      REQUIRE(
        cache.get_store_at(low_handle, low_signature_transaction) != nullptr);
      REQUIRE(
        cache.get_store_at(
          high_handle, high_signature_transaction, std::chrono::seconds(30)) !=
        nullptr);

      // More time passes, and one request expires
      cache.tick(std::chrono::milliseconds(40'000));
      REQUIRE(
        cache.get_store_at(low_handle, low_signature_transaction) != nullptr);
      REQUIRE(
        cache.get_store_at(
          high_handle, high_signature_transaction, std::chrono::seconds(30)) ==
        nullptr);

      // More time passes, and both requests expire
      cache.tick(std::chrono::milliseconds(60'000));
      REQUIRE(
        cache.get_store_at(low_handle, low_signature_transaction) == nullptr);
      REQUIRE(
        cache.get_store_at(
          high_handle, high_signature_transaction, std::chrono::seconds(30)) ==
        nullptr);
    }
  }
}

TEST_CASE("StateCache range queries")
{
  auto state = create_and_init_state();
  auto& kv_store = *state.kv_store;

  std::vector<kv::Version> signature_versions;

  const auto begin_seqno = kv_store.current_version() + 1;

  {
    INFO("Build some interesting state in the store");
    for (size_t batch_size : {10, 5, 2, 20, 5})
    {
      signature_versions.push_back(
        write_transactions_and_signature(kv_store, batch_size));
    }
  }

  const auto end_seqno = kv_store.current_version();

  ccf::historical::StateCache cache(
    kv_store, state.ledger_secrets, std::make_shared<StubWriter>());
  auto ledger = construct_host_ledger(state.kv_store->get_consensus());

  auto provide_ledger_entry = [&](size_t i) {
    bool accepted = cache.handle_ledger_entry(i, ledger.at(i));
    return accepted;
  };

  auto signing_version = [&signature_versions](kv::Version seqno) {
    const auto begin = signature_versions.begin();
    const auto end = signature_versions.end();

    const auto exact_it = std::find(begin, end, seqno);
    if (exact_it != end)
    {
      return seqno;
    }

    const auto next_sig_it = std::upper_bound(begin, end, seqno);
    REQUIRE(next_sig_it != end);
    return *next_sig_it;
  };

  std::random_device rd;
  std::mt19937 g(rd());
  auto next_handle = 0;
  auto fetch_and_validate_range = [&](
                                    kv::Version range_start,
                                    kv::Version range_end) {
    const auto this_handle = next_handle++;
    {
      auto stores = cache.get_store_range(this_handle, range_start, range_end);
      REQUIRE(stores.empty());
    }

    const auto proof_end = signing_version(range_end);

    // Cache is robust to receiving these out-of-order, so stress that by
    // submitting out-of-order
    std::vector<size_t> to_provide(1 + range_end - range_start);
    std::iota(to_provide.begin(), to_provide.end(), range_start);
    std::shuffle(to_provide.begin(), to_provide.end(), g);

    for (const auto seqno : to_provide)
    {
      // Some of these may be unrequested since they overlapped with the
      // previous range so are already known. Provide them all blindly for
      // simplicity, and make no assertion on the return code.
      provide_ledger_entry(seqno);
    }

    // Then provide trailing proof after the requested indices
    for (auto seqno = range_end + 1; seqno <= proof_end; ++seqno)
    {
      provide_ledger_entry(seqno);
    }

    {
      auto stores = cache.get_store_range(this_handle, range_start, range_end);
      REQUIRE(!stores.empty());

      const auto range_size = (range_end - range_start) + 1;
      REQUIRE(stores.size() == range_size);
      for (size_t i = 0; i < stores.size(); ++i)
      {
        auto& store = stores[i];
        REQUIRE(store != nullptr);
        const auto seqno = range_start + i;

        // Don't validate anything about signature transactions, just the
        // business transactions between them
        if (
          std::find(
            signature_versions.begin(), signature_versions.end(), seqno) ==
          signature_versions.end())
        {
          validate_business_transaction(store, seqno);
        }
      }
    }
  };

  {
    INFO("Fetch a single explicit range");
    const auto range_start = 4;
    const auto range_end = 7;

    fetch_and_validate_range(range_start, range_end);
  }

  {
    INFO("Fetch ranges of various sizes, including across multiple signatures");
    const size_t whole_range = end_seqno - begin_seqno;
    std::vector<size_t> range_sizes{3, 8, whole_range / 2, whole_range};
    for (const size_t range_size : range_sizes)
    {
      for (auto range_start = begin_seqno;
           range_start <= (end_seqno - range_size);
           ++range_start)
      {
        const auto range_end = range_start + range_size;
        fetch_and_validate_range(range_start, range_end);
      }
    }
  }
}

TEST_CASE("StateCache concurrent access")
{
  auto state = create_and_init_state();
  auto& kv_store = *state.kv_store;
  const auto default_handle = 0;

  std::vector<kv::Version> signature_versions;

  const auto begin_seqno = kv_store.current_version() + 1;

  {
    INFO("Build some interesting state in the store");
    for (size_t batch_size : {5, 10, 5})
    {
      signature_versions.push_back(
        write_transactions_and_signature(kv_store, batch_size));
    }
  }

  const auto end_seqno = kv_store.current_version();

  auto random_seqno = [&]() {
    return begin_seqno + (rand() % (end_seqno - begin_seqno - 1));
  };

  auto writer = std::make_shared<StubWriter>();
  ccf::historical::StateCache cache(kv_store, state.ledger_secrets, writer);

  std::atomic<bool> finished = false;
  std::thread host_thread([&]() {
    auto ledger = construct_host_ledger(state.kv_store->get_consensus());

    size_t last_handled_write = 0;
    while (!finished)
    {
      std::vector<StubWriter::Write> writes;
      {
        std::lock_guard<std::mutex> guard(writer->writes_mutex);
        auto finished_write_it = std::partition_point(
          writer->writes.begin() + last_handled_write,
          writer->writes.end(),
          [](const StubWriter::Write& w) { return w.finished; });
        writes.insert(
          writes.end(),
          writer->writes.begin() + last_handled_write,
          finished_write_it);
        last_handled_write = finished_write_it - writer->writes.begin();
      }

      for (const auto& write : writes)
      {
        auto data = write.contents.data();
        auto size = write.contents.size();
        const auto [seqno, purpose] =
          ringbuffer::read_message<consensus::ledger_get>(data, size);
        REQUIRE(purpose == consensus::LedgerRequestPurpose::HistoricalQuery);

        const auto it = ledger.find(seqno);
        REQUIRE(it != ledger.end());
        cache.handle_ledger_entry(seqno, it->second);
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  });

  constexpr auto per_thread_queries = 20;

  using Clock = std::chrono::system_clock;
  // Add a watchdog timeout. Even in Debug+SAN this entire test takes <3 secs,
  // so 10 seconds for any single entry is surely deadlock
  const auto too_long = std::chrono::seconds(10);

  auto query_random_point = [&](size_t handle) {
    for (size_t i = 0; i < per_thread_queries; ++i)
    {
      const auto target_seqno = random_seqno();

      ccf::historical::StorePtr store;
      const auto start_time = Clock::now();
      while (true)
      {
        store = cache.get_store_at(handle, target_seqno);
        if (store != nullptr)
        {
          break;
        }

        if (Clock::now() - start_time > too_long)
        {
          std::cout << fmt::format(
                         "Thread <{}>, i [{}]: {} - still no answer!",
                         handle,
                         i,
                         target_seqno)
                    << std::endl;
          REQUIRE(false);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }

      if (
        std::find(
          signature_versions.begin(), signature_versions.end(), target_seqno) ==
        signature_versions.end())
      {
        validate_business_transaction(store, target_seqno);
      }
    }
  };

  auto query_random_range = [&](size_t handle) {
    std::vector<std::pair<size_t, size_t>> requested;
    for (size_t i = 0; i < per_thread_queries; ++i)
    {
      auto range_start = random_seqno();
      auto range_end = random_seqno();

      if (range_start > range_end)
      {
        std::swap(range_start, range_end);
      }

      requested.push_back(std::make_pair(range_start, range_end));

      std::vector<ccf::historical::StorePtr> stores;
      const auto start_time = Clock::now();
      while (true)
      {
        stores = cache.get_store_range(handle, range_start, range_end);
        if (!stores.empty())
        {
          break;
        }

        if (Clock::now() - start_time > too_long)
        {
          std::cout << fmt::format(
                         "Thread <{}>, i [{}]: {}-{} - still no answer!",
                         handle,
                         i,
                         range_start,
                         range_end)
                    << std::endl;
          std::cout << fmt::format(
                         "I've previously used handle {} to request:", handle)
                    << std::endl;
          for (const auto& [a, b] : requested)
          {
            std::cout << fmt::format("  {} to {}", a, b) << std::endl;
          }
          REQUIRE(false);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }

      REQUIRE(stores.size() == range_end - range_start + 1);
      for (size_t i = 0; i < stores.size(); ++i)
      {
        auto& store = stores[i];
        REQUIRE(store != nullptr);
        const auto seqno = range_start + i;
        if (
          std::find(
            signature_versions.begin(), signature_versions.end(), seqno) ==
          signature_versions.end())
        {
          validate_business_transaction(store, seqno);
        }
      }
    }
  };

  const auto num_threads = 20;
  std::atomic<size_t> next_handle = 0;
  std::vector<std::thread> random_queries;
  for (size_t i = 0; i < num_threads; ++i)
  {
    if (i % 3 == 0)
    {
      random_queries.emplace_back(query_random_range, ++next_handle);
    }
    else
    {
      random_queries.emplace_back(query_random_point, ++next_handle);
    }
  }

  for (auto& thread : random_queries)
  {
    thread.join();
  }

  finished = true;
  host_thread.join();
}

TEST_CASE("Recover historical ledger secrets")
{
  auto state = create_and_init_state();
  auto& kv_store = *state.kv_store;

  INFO("Create entries and populate ledger");

  // Rekey ledger every 10 transactions
  write_transactions(kv_store, 10);
  const auto first_rekey_seqno = rekey(kv_store, state.ledger_secrets);
  write_transactions(kv_store, 10);
  const auto second_rekey_seqno = rekey(kv_store, state.ledger_secrets);
  write_transactions(kv_store, 10);
  const auto third_rekey_seqno = rekey(kv_store, state.ledger_secrets);

  // Only one signature, valid with the latest ledger secret
  const auto signature_seqno = write_transactions_and_signature(kv_store, 5);

  const auto first_seqno = first_rekey_seqno - 3;
  const auto second_seqno = second_rekey_seqno + 1;
  const auto third_seqno = third_rekey_seqno + 2;

  auto ledger = construct_host_ledger(state.kv_store->get_consensus());
  REQUIRE(ledger.size() == signature_seqno);

  // Register node in recovered network (note that this won't be necessary when
  // historical nodes are fetched from snapshot, see
  // https://github.com/microsoft/CCF/issues/1705)
  auto recovered_state = create_and_init_state(false);

  {
    INFO("Recover a new service, as if the node had recovered from a snapshot");

    // Initially, the new service has only access to the very latest ledger
    // secret. The historical ledger secrets will be recovered from the
    // ledger before fetching historical entries.
    auto tx = recovered_state.kv_store->create_read_only_tx();
    ccf::LedgerSecretsMap recovered_ledger_secrets;
    recovered_ledger_secrets.emplace(state.ledger_secrets->get_latest(tx));
    recovered_state.ledger_secrets->restore_historical(
      std::move(recovered_ledger_secrets));
  }

  // Now we actually get to the historical queries
  auto writer = std::make_shared<StubWriter>();
  ccf::historical::StateCache cache(
    *recovered_state.kv_store, recovered_state.ledger_secrets, writer);
  constexpr ccf::historical::RequestHandle default_handle = 42;

  auto provide_ledger_entry = [&](size_t i) {
    bool accepted = cache.handle_ledger_entry(i, ledger.at(i));
    return accepted;
  };

  {
    INFO("Retrieve latest seqno, applicable with latest ledger secret");
    REQUIRE(cache.get_store_at(default_handle, third_seqno) == nullptr);

    // Provide target and subsequent entries until next signature
    for (size_t i = third_seqno; i <= signature_seqno; ++i)
    {
      REQUIRE(provide_ledger_entry(i));
    }

    // Store is now trusted, proceed to recover entries
    auto historical_store = cache.get_store_at(default_handle, third_seqno);
    REQUIRE(historical_store != nullptr);

    validate_business_transaction(historical_store, third_seqno);
  }

  {
    INFO("Retrieve second seqno, requiring one historical ledger secret");
    REQUIRE(cache.get_store_at(default_handle, second_seqno) == nullptr);

    // Request is always in flight
    REQUIRE(cache.get_store_at(default_handle, second_seqno) == nullptr);

    // The encrypted ledger secret applicable for second_seqno was recorded in
    // the store at the next rekey
    REQUIRE(provide_ledger_entry(third_rekey_seqno));

    // Ledger secret has already been fetched
    REQUIRE_FALSE(provide_ledger_entry(third_rekey_seqno));

    // Provide target and subsequent entries until next signature
    for (size_t i = second_seqno; i <= signature_seqno; ++i)
    {
      provide_ledger_entry(i);
    }

    // Store is now trusted, proceed to recover entries
    auto historical_store = cache.get_store_at(default_handle, second_seqno);
    REQUIRE(historical_store != nullptr);

    validate_business_transaction(historical_store, second_seqno);
  }

  {
    INFO("Retrieve first seqno, requiring all historical ledger secrets");
    REQUIRE(cache.get_store_at(default_handle, first_seqno) == nullptr);

    // Recover all ledger secrets since the start of time
    REQUIRE(provide_ledger_entry(second_rekey_seqno));
    REQUIRE(provide_ledger_entry(first_rekey_seqno));

    // Provide target and subsequent entries until next signature
    for (size_t i = first_seqno; i <= signature_seqno; ++i)
    {
      provide_ledger_entry(i);
    }

    // Store is now trusted, proceed to recover entries
    auto historical_store = cache.get_store_at(default_handle, first_seqno);
    REQUIRE(historical_store != nullptr);

    validate_business_transaction(historical_store, first_seqno);
  }
}