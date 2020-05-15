// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define PICOBENCH_IMPLEMENT_WITH_MAIN

#include "kv/kv.h"
#include "kv/test/stub_consensus.h"
#include "node/encryptor.h"

#include <picobench/picobench.hpp>
#include <string>

inline void clobber_memory()
{
  asm volatile("" : : : "memory");
}

// Helper functions to use a dummy encryption key
std::shared_ptr<ccf::LedgerSecrets> create_ledger_secrets()
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  auto new_secret = ccf::LedgerSecret();
  secrets->init();

  return secrets;
}

// Test functions
template <kv::SecurityDomain SD>
static void serialise(picobench::state& s)
{
  logger::config::level() = logger::INFO;

  kv::Store kv_store;
  auto secrets = create_ledger_secrets();
  auto encryptor = std::make_shared<ccf::RaftTxEncryptor>(secrets);
  encryptor->set_iv_id(1);
  kv_store.set_encryptor(encryptor);

  auto& map0 = kv_store.create<std::string, std::string>("map0", SD);
  auto& map1 = kv_store.create<std::string, std::string>("map1", SD);
  kv::Tx tx;
  auto [tx0, tx1] = tx.get_view(map0, map1);

  for (int i = 0; i < s.iterations(); i++)
  {
    auto key = "key" + std::to_string(i);
    tx0->put(key, "value");
    tx1->put(key, "value");
  }

  s.start_timer();
  auto rc = tx.commit();
  if (rc != kv::CommitSuccess::OK)
    throw std::logic_error("Transaction commit failed: " + std::to_string(rc));
  s.stop_timer();
}

template <kv::SecurityDomain SD>
static void deserialise(picobench::state& s)
{
  logger::config::level() = logger::INFO;

  auto consensus = std::make_shared<kv::StubConsensus>();
  kv::Store kv_store(consensus);
  kv::Store kv_store2;

  auto secrets = create_ledger_secrets();
  auto encryptor = std::make_shared<ccf::RaftTxEncryptor>(secrets);
  encryptor->set_iv_id(1);
  kv_store.set_encryptor(encryptor);
  kv_store2.set_encryptor(encryptor);

  auto& map0 = kv_store.create<std::string, std::string>("map0", SD);
  auto& map1 = kv_store.create<std::string, std::string>("map1", SD);
  auto& map0_ = kv_store2.create<std::string, std::string>("map0", SD);
  auto& map1_ = kv_store2.create<std::string, std::string>("map1", SD);
  kv::Tx tx;
  auto [tx0, tx1] = tx.get_view(map0, map1);

  for (int i = 0; i < s.iterations(); i++)
  {
    auto key = "key" + std::to_string(i);
    tx0->put(key, "value");
    tx1->put(key, "value");
  }
  tx.commit();

  s.start_timer();
  auto rc = kv_store2.deserialise(consensus->get_latest_data().first);
  if (rc != kv::DeserialiseSuccess::PASS)
    throw std::logic_error(
      "Transaction deserialisation failed: " + std::to_string(rc));
  s.stop_timer();
}

template <size_t S>
static void commit_latency(picobench::state& s)
{
  logger::config::level() = logger::INFO;

  kv::Store kv_store;
  auto secrets = create_ledger_secrets();
  auto encryptor = std::make_shared<ccf::RaftTxEncryptor>(secrets);
  encryptor->set_iv_id(1);
  kv_store.set_encryptor(encryptor);

  auto& map0 = kv_store.create<std::string, std::string>("map0");
  auto& map1 = kv_store.create<std::string, std::string>("map1");

  for (int i = 0; i < s.iterations(); i++)
  {
    kv::Tx tx;
    auto [tx0, tx1] = tx.get_view(map0, map1);
    for (int iTx = 0; iTx < S; iTx++)
    {
      auto key = "key" + std::to_string(i) + " - " + std::to_string(iTx);
      tx0->put(key, "value");
      tx1->put(key, "value");
    }

    auto rc = tx.commit();
    if (rc != kv::CommitSuccess::OK)
    {
      throw std::logic_error(
        "Transaction commit failed: " + std::to_string(rc));
    }
  }
  s.start_timer();
  kv_store.compact(kv_store.current_version());
  s.stop_timer();
}

const std::vector<int> tx_count = {10, 100, 1000};
const uint32_t sample_size = 100;

using SD = kv::SecurityDomain;

PICOBENCH_SUITE("commit_latency");
PICOBENCH(commit_latency<10>).iterations(tx_count).samples(10).baseline();
PICOBENCH(commit_latency<100>).iterations(tx_count).samples(10);

PICOBENCH_SUITE("serialise");
PICOBENCH(serialise<SD::PUBLIC>)
  .iterations(tx_count)
  .samples(sample_size)
  .baseline();
PICOBENCH(serialise<SD::PRIVATE>).iterations(tx_count).samples(sample_size);

PICOBENCH_SUITE("deserialise");
PICOBENCH(deserialise<SD::PUBLIC>)
  .iterations(tx_count)
  .samples(sample_size)
  .baseline();
PICOBENCH(deserialise<SD::PRIVATE>).iterations(tx_count).samples(sample_size);
