// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define PICOBENCH_IMPLEMENT_WITH_MAIN

#include "kv/store.h"
#include "kv/test/stub_consensus.h"
#include "kv/tx.h"
#include "node/encryptor.h"

#include <msgpack/msgpack.hpp>
#include <picobench/picobench.hpp>
#include <string>

using KeyType = kv::serialisers::SerialisedEntry;
using ValueType = kv::serialisers::SerialisedEntry;
using MapType = kv::untyped::Map;

inline void clobber_memory()
{
  asm volatile("" : : : "memory");
}

KeyType gen_key(size_t i, const std::string& suf = "")
{
  const auto s = "key" + std::to_string(i) + suf;
  msgpack::sbuffer buf;
  msgpack::pack(buf, s);
  const auto raw = reinterpret_cast<const uint8_t*>(buf.data());
  return KeyType(raw, raw + buf.size());
}

ValueType gen_value(size_t i)
{
  const auto s = "value" + std::to_string(i);
  msgpack::sbuffer buf;
  msgpack::pack(buf, s);
  const auto raw = reinterpret_cast<const uint8_t*>(buf.data());
  return ValueType(raw, raw + buf.size());
}

// Helper functions to use a dummy encryption key
std::shared_ptr<ccf::LedgerSecrets> create_ledger_secrets()
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  return secrets;
}

std::string build_map_name(const std::string& core_name, kv::SecurityDomain sd)
{
  if (sd == kv::SecurityDomain::PUBLIC)
  {
    return fmt::format("{}{}", kv::public_domain_prefix, core_name);
  }

  return core_name;
}

// Test functions
template <kv::SecurityDomain SD>
static void serialise(picobench::state& s)
{
  logger::config::level() = logger::INFO;

  kv::Store kv_store;
  auto secrets = create_ledger_secrets();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  kv_store.set_encryptor(encryptor);

  auto map0 = build_map_name("map0", SD);
  auto map1 = build_map_name("map1", SD);

  auto tx = kv_store.create_tx();
  auto tx0 = tx.rw<MapType>(map0);
  auto tx1 = tx.rw<MapType>(map1);

  for (int i = 0; i < s.iterations(); i++)
  {
    const auto key = gen_key(i);
    const auto value = gen_value(i);
    tx0->put(key, value);
    tx1->put(key, value);
  }

  s.start_timer();
  auto rc = tx.commit();
  if (rc != kv::CommitResult::SUCCESS)
    throw std::logic_error("Transaction commit failed: " + std::to_string(rc));
  s.stop_timer();
}

template <kv::SecurityDomain SD>
static void apply(picobench::state& s)
{
  logger::config::level() = logger::INFO;

  auto consensus = std::make_shared<kv::StubConsensus>();
  kv::Store kv_store(consensus);
  kv::Store kv_store2;

  auto secrets = create_ledger_secrets();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  kv_store.set_encryptor(encryptor);
  kv_store2.set_encryptor(encryptor);

  auto map0 = build_map_name("map0", SD);
  auto map1 = build_map_name("map1", SD);

  auto tx = kv_store.create_tx();
  auto tx0 = tx.rw<MapType>(map0);
  auto tx1 = tx.rw<MapType>(map1);

  for (int i = 0; i < s.iterations(); i++)
  {
    const auto key = gen_key(i);
    const auto value = gen_value(i);
    tx0->put(key, value);
    tx1->put(key, value);
  }
  tx.commit();

  s.start_timer();
  auto rc =
    kv_store2.apply(consensus->get_latest_data().value(), ConsensusType::CFT)
      ->execute();
  if (rc != kv::ApplyResult::PASS)
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
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  kv_store.set_encryptor(encryptor);

  auto map0 = "map0";
  auto map1 = "map1";

  for (int i = 0; i < s.iterations(); i++)
  {
    auto tx = kv_store.create_tx();
    auto tx0 = tx.rw<MapType>(map0);
    auto tx1 = tx.rw<MapType>(map1);
    for (int iTx = 0; iTx < S; iTx++)
    {
      const auto key = gen_key(i, std::to_string(iTx));
      const auto value = gen_value(i);
      tx0->put(key, value);
      tx1->put(key, value);
    }

    auto rc = tx.commit();
    if (rc != kv::CommitResult::SUCCESS)
    {
      throw std::logic_error(
        "Transaction commit failed: " + std::to_string(rc));
    }
  }
  s.start_timer();
  kv_store.compact(kv_store.current_version());
  s.stop_timer();
}

template <size_t KEY_COUNT>
static void ser_snap(picobench::state& s)
{
  logger::config::level() = logger::INFO;

  kv::Store kv_store;
  auto secrets = create_ledger_secrets();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  kv_store.set_encryptor(encryptor);

  auto tx = kv_store.create_tx();
  for (int i = 0; i < s.iterations(); i++)
  {
    auto handle = tx.rw<MapType>(fmt::format("map{}", i));
    for (int j = 0; j < KEY_COUNT; j++)
    {
      const auto key = gen_key(j);
      const auto value = gen_value(j);

      handle->put(key, value);
    }
  }

  auto rc = tx.commit();
  if (rc != kv::CommitResult::SUCCESS)
    throw std::logic_error("Transaction commit failed: " + std::to_string(rc));

  s.start_timer();
  auto snap = kv_store.snapshot(tx.commit_version());
  kv_store.serialise_snapshot(std::move(snap));
  s.stop_timer();
}

template <size_t KEY_COUNT>
static void des_snap(picobench::state& s)
{
  logger::config::level() = logger::INFO;

  kv::Store kv_store;
  kv::Store kv_store2;
  auto secrets = create_ledger_secrets();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  kv_store.set_encryptor(encryptor);
  kv_store2.set_encryptor(encryptor);

  auto tx = kv_store.create_tx();
  for (int i = 0; i < s.iterations(); i++)
  {
    auto handle = tx.rw<MapType>(fmt::format("map{}", i));
    for (int j = 0; j < KEY_COUNT; j++)
    {
      const auto key = gen_key(j);
      const auto value = gen_value(j);

      handle->put(key, value);
    }
  }

  auto rc = tx.commit();
  if (rc != kv::CommitResult::SUCCESS)
    throw std::logic_error("Transaction commit failed: " + std::to_string(rc));

  auto snap = kv_store.snapshot(tx.commit_version());
  auto serialised_snap = kv_store.serialise_snapshot(std::move(snap));

  kv::ConsensusHookPtrs hooks;
  s.start_timer();
  kv_store2.deserialise_snapshot(serialised_snap, hooks);
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

PICOBENCH_SUITE("apply");
PICOBENCH(apply<SD::PUBLIC>)
  .iterations(tx_count)
  .samples(sample_size)
  .baseline();
PICOBENCH(apply<SD::PRIVATE>).iterations(tx_count).samples(sample_size);

const uint32_t snapshot_sample_size = 10;
const std::vector<int> map_count = {20, 100};

PICOBENCH_SUITE("serialise_snapshot");
PICOBENCH(ser_snap<100>)
  .iterations(map_count)
  .samples(snapshot_sample_size)
  .baseline();
PICOBENCH(ser_snap<1000>).iterations(map_count).samples(snapshot_sample_size);

PICOBENCH_SUITE("deserialise_snapshot");
PICOBENCH(des_snap<100>)
  .iterations(map_count)
  .samples(snapshot_sample_size)
  .baseline();
PICOBENCH(des_snap<1000>).iterations(map_count).samples(snapshot_sample_size);