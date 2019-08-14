// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define PICOBENCH_IMPLEMENT_WITH_MAIN

#include "enclave/appinterface.h"
#include "kv/kv.h"
#include "node/encryptor.h"
#include "stub_consensus.h"

#include <picobench/picobench.hpp>
#include <string>

using namespace ccfapp;

// Helper functions
ccf::NetworkSecrets create_network_secrets()
{
  // Because the ccf::NetworkSecrets("some_name") calls tls::KeyPair with the
  // old curve (MBEDTLS_ECP_DP_SECP384R1) by default which makes tx.commit() run
  // a lot slower with legacy curves, we use a dummy encryption key for this
  // benchmarks
  auto secrets = ccf::NetworkSecrets();
  auto new_secret = std::make_unique<ccf::NetworkSecrets::Secret>(
    std::vector<uint8_t>(),
    std::vector<uint8_t>(),
    std::vector<uint8_t>(16, 0x1));
  secrets.get_secrets().emplace(
    0, std::move(new_secret)); // Create new secrets valid from version 0

  return secrets;
}

// Test functions
template <kv::SecurityDomain SD>
static void serialise(picobench::state& s)
{
  Store kv_store;
  auto secrets = create_network_secrets();
  auto encryptor = std::make_shared<ccf::TxEncryptor>(0x1, secrets);
  kv_store.set_encryptor(encryptor);

  auto& map0 = kv_store.create<std::string, std::string>("map0", SD);
  auto& map1 = kv_store.create<std::string, std::string>("map1", SD);
  Store::Tx tx;
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
  auto consensus = std::make_shared<kv::StubConsensus>();
  Store kv_store(consensus);
  Store kv_store2;

  auto secrets = create_network_secrets();
  auto encryptor = std::make_shared<ccf::TxEncryptor>(0x1, secrets);
  kv_store.set_encryptor(encryptor);
  kv_store2.set_encryptor(encryptor);

  auto& map0 = kv_store.create<std::string, std::string>("map0", SD);
  auto& map1 = kv_store.create<std::string, std::string>("map1", SD);
  auto& map0_ = kv_store2.create<std::string, std::string>("map0", SD);
  auto& map1_ = kv_store2.create<std::string, std::string>("map1", SD);
  Store::Tx tx;
  auto [tx0, tx1] = tx.get_view(map0, map1);

  for (int i = 0; i < s.iterations(); i++)
  {
    auto key = "key" + std::to_string(i);
    tx0->put(key, "value");
    tx1->put(key, "value");
  }
  tx.commit();

  auto serial = consensus->get_latest_data();
  s.start_timer();
  auto rc = kv_store2.deserialise(serial.first);
  if (rc != kv::DeserialiseSuccess::PASS)
    throw std::logic_error(
      "Transaction deserialisation failed: " + std::to_string(rc));
  s.stop_timer();
}

const std::vector<int> tx_count = {10, 100, 200};
const uint32_t sample_size = 100;

using SD = kv::SecurityDomain;

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
