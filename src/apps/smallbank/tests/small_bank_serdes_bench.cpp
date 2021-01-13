// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define PICOBENCH_IMPLEMENT

#include "consensus/aft/request.h"
#include "node/encryptor.h"
#include "node/history.h"
#include "node/rpc/serdes.h"
#include "node/secrets.h"

#include <nlohmann/json.hpp>
#include <picobench/picobench.hpp>

const std::string account_name = "10";
const int transaction_value = 50;

inline void clobber_memory()
{
  asm volatile("" : : : "memory");
}

ccf::Secrets secrets_map("secrets");

// Helper functions
std::shared_ptr<ccf::LedgerSecrets> create_ledger_secrets()
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>(secrets_map);
  secrets->init();

  return secrets;
}

static std::vector<uint8_t> raw_tx_buffer()
{
  const auto size =
    sizeof(size_t) + account_name.size() + sizeof(transaction_value);
  std::vector<uint8_t> v(size);
  auto data = v.data();
  auto remaining = v.size();

  serialized::write(data, remaining, account_name);
  serialized::write(data, remaining, transaction_value);

  return v;
}

static std::vector<uint8_t> packed_json_tx()
{
  nlohmann::json j;
  j["name"] = account_name;
  j["value"] = transaction_value;
  return serdes::pack(j, serdes::Pack::MsgPack);
}

std::vector<uint8_t> large_payload(size_t size)
{
  std::vector<uint8_t> payload;
  for (size_t i = 0; i < size; i++)
  {
    payload.push_back(i);
  }
  return payload;
}

static std::vector<uint8_t> kv_serialized_data(std::vector<uint8_t>& data)
{
  kv::Store kv_store;
  auto secrets = create_ledger_secrets();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  kv_store.set_encryptor(encryptor);

  aft::RequestsMap map0("map0");

  auto tx = kv_store.create_reserved_tx(kv_store.next_version());
  auto tx0 = tx.get_view(map0);

  tx0->put(0, {{}, data, {}});

  auto pending_tx = tx.commit_reserved();
  return pending_tx.data;
}
// End Helper functions

// Test functions
static void raw_ser(picobench::state& s)
{
  s.start_timer();
  for (int i = 0; i < s.iterations(); i++)
  {
    auto buf = raw_tx_buffer();
    clobber_memory();
  }
  s.stop_timer();
}

static void raw_des(picobench::state& s)
{
  const auto buf = raw_tx_buffer();
  s.start_timer();
  for (int i = 0; i < s.iterations(); i++)
  {
    auto data = buf.data();
    auto size = buf.size();

    auto name =
      serialized::read<std::remove_cv_t<typeof(account_name)>>(data, size);
    auto value =
      serialized::read<std::remove_cv_t<typeof(transaction_value)>>(data, size);
    clobber_memory();
  }
  s.stop_timer();
}

static void json_msgpack_ser(picobench::state& s)
{
  s.start_timer();
  for (int i = 0; i < s.iterations(); i++)
  {
    auto p = packed_json_tx();
    clobber_memory();
  }
  s.stop_timer();
}

static void json_msgpack_des(picobench::state& s)
{
  auto p = packed_json_tx();
  s.start_timer();
  for (int i = 0; i < s.iterations(); i++)
  {
    auto params = serdes::unpack(p, serdes::Pack::MsgPack);
    std::string name = params["name"];
    int64_t value = params["value"];
    clobber_memory();
  }
  s.stop_timer();
}

static void run_mt_benchmark(picobench::state& s, std::vector<uint8_t> data)
{
  ccf::MerkleTreeHistory tree;
  s.start_timer();
  for (int i = 0; i < s.iterations(); i++)
  {
    crypto::Sha256Hash rh({data.data(), data.size()});
    tree.append(rh);
    clobber_memory();
  }
  s.stop_timer();
}

static void raw_mt_append(picobench::state& s)
{
  auto data = raw_tx_buffer();
  auto serialized_data = kv_serialized_data(data);
  run_mt_benchmark(s, serialized_data);
}

static void json_msgpack_mt_append(picobench::state& s)
{
  auto data = packed_json_tx();
  auto serialized_data = kv_serialized_data(data);
  run_mt_benchmark(s, serialized_data);
}

template <size_t S>
static void raw_large_payload(picobench::state& s)
{
  auto payload = large_payload(S);
  auto data = kv_serialized_data(payload);
  run_mt_benchmark(s, data);
}

template <size_t S>
static void jm_large_payload(picobench::state& s)
{
  auto payload = large_payload(S);
  nlohmann::json j;
  j["data"] = payload;
  auto d = serdes::pack(j, serdes::Pack::MsgPack);
  auto data = kv_serialized_data(d);
  run_mt_benchmark(s, data);
}

const std::vector<int> iters = {10, 100, 1000};
const std::vector<int> iter = {100};

PICOBENCH_SUITE("smallbank payload serialize");
PICOBENCH(raw_ser).iterations(iters).samples(10);
PICOBENCH(json_msgpack_ser).iterations(iters).samples(10);

PICOBENCH_SUITE("smallbank payload deserialize");
PICOBENCH(raw_des).iterations(iters).samples(10);
PICOBENCH(json_msgpack_des).iterations(iters).samples(10);

PICOBENCH_SUITE("smallbank payload merkle tree bench");
PICOBENCH(raw_mt_append).iterations(iters).samples(10);
PICOBENCH(json_msgpack_mt_append).iterations(iters).samples(10);

PICOBENCH_SUITE("large payload merkle tree bench");
PICOBENCH(raw_large_payload<10>).iterations(iter).samples(10);
PICOBENCH(jm_large_payload<10>).iterations(iter).samples(10);
PICOBENCH(raw_large_payload<100>).iterations(iter).samples(10);
PICOBENCH(jm_large_payload<100>).iterations(iter).samples(10);
PICOBENCH(raw_large_payload<1000>).iterations(iter).samples(10);
PICOBENCH(jm_large_payload<1000>).iterations(iter).samples(10);
PICOBENCH(raw_large_payload<10000>).iterations(iter).samples(10);
PICOBENCH(jm_large_payload<10000>).iterations(iter).samples(10);

int main(int argc, char* argv[])
{
  picobench::runner runner;
  runner.parse_cmd_line(argc, argv);
  return runner.run();
}