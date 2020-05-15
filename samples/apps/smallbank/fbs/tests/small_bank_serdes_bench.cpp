// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define PICOBENCH_IMPLEMENT

#include "consensus/pbft/pbft_requests.h"
#include "node/encryptor.h"
#include "node/history.h"
#include "node/rpc/json_rpc.h"
#include "tests/flatbuffer_wrapper_test.h"

#include <nlohmann/json.hpp>
#include <picobench/picobench.hpp>

extern "C"
{
#include <evercrypt/EverCrypt_AutoConfig2.h>
}

size_t account_name = 10;
int transaction_value = 50;

inline void clobber_memory()
{
  asm volatile("" : : : "memory");
}

// Helper functions
std::shared_ptr<ccf::LedgerSecrets> create_ledger_secrets()
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();

  return secrets;
}

static std::vector<uint8_t> packed_json_tx()
{
  nlohmann::json j;
  j["name"] = std::to_string(account_name);
  j["value"] = transaction_value;
  return jsonrpc::pack(j, jsonrpc::Pack::MsgPack);
}

static std::unique_ptr<flatbuffers::DetachedBuffer> fb_tx_buffer()
{
  TransactionSerializer ts(std::to_string(account_name), transaction_value);
  return ts.get_detached_buffer();
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
  ccf::Store kv_store;
  auto secrets = create_ledger_secrets();
  auto encryptor = std::make_shared<ccf::RaftTxEncryptor>(secrets);
  kv_store.set_encryptor(encryptor);

  auto& map0 = kv_store.create<pbft::RequestsMap>("map0");

  ccf::Tx tx(kv_store.next_version());
  auto tx0 = tx.get_view(map0);

  tx0->put(0, {0, {}, data, {}});

  auto pending_tx = tx.commit_reserved();
  return pending_tx.data;
}
// End Helper functions

// Test functions
static void flatbuffers_ser(picobench::state& s)
{
  s.start_timer();
  for (int i = 0; i < s.iterations(); i++)
  {
    auto buf = fb_tx_buffer();
    CBuffer b = {buf->data(), buf->size()};
  }
  s.stop_timer();
}

static void flatbuffers_des(picobench::state& s)
{
  auto buf = fb_tx_buffer();
  s.start_timer();
  for (int i = 0; i < s.iterations(); i++)
  {
    TransactionDeserializer td(buf->data());
    std::string name = td.name();
    int64_t value = td.value();
  }
  s.stop_timer();
}

static void json_msgpack_ser(picobench::state& s)
{
  s.start_timer();
  for (int i = 0; i < s.iterations(); i++)
  {
    auto p = packed_json_tx();
  }
  s.stop_timer();
}

static void json_msgpack_des(picobench::state& s)
{
  auto p = packed_json_tx();
  s.start_timer();
  for (int i = 0; i < s.iterations(); i++)
  {
    auto params = jsonrpc::unpack(p, jsonrpc::Pack::MsgPack);
    std::string name = params["name"];
    int64_t value = params["value"];
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

static void flatbuffers_mt_append(picobench::state& s)
{
  auto buf = fb_tx_buffer();
  std::vector<uint8_t> data(buf->data(), buf->data() + buf->size());
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
static void fb_large_payload(picobench::state& s)
{
  auto payload = large_payload(S);
  LargePayloadSerializer lps(payload);
  auto d = lps.get_data();
  auto data = kv_serialized_data(d);
  run_mt_benchmark(s, data);
}

template <size_t S>
static void jm_large_payload(picobench::state& s)
{
  auto payload = large_payload(S);
  nlohmann::json j;
  j["data"] = payload;
  auto d = jsonrpc::pack(j, jsonrpc::Pack::MsgPack);
  auto data = kv_serialized_data(d);
  run_mt_benchmark(s, data);
}

const std::vector<int> iters = {10, 100, 1000};
const std::vector<int> iter = {100};

PICOBENCH_SUITE("smallbank payload serialize");
PICOBENCH(flatbuffers_ser).iterations(iters).samples(10);
PICOBENCH(json_msgpack_ser).iterations(iters).samples(10);

PICOBENCH_SUITE("smallbank payload deserialize");
PICOBENCH(flatbuffers_des).iterations(iters).samples(10);
PICOBENCH(json_msgpack_des).iterations(iters).samples(10);

PICOBENCH_SUITE("smallbank payload merkle tree bench");
PICOBENCH(flatbuffers_mt_append).iterations(iters).samples(10);
PICOBENCH(json_msgpack_mt_append).iterations(iters).samples(10);

PICOBENCH_SUITE("large payload merkle tree bench");
PICOBENCH(fb_large_payload<10>).iterations(iter).samples(10);
PICOBENCH(jm_large_payload<10>).iterations(iter).samples(10);
PICOBENCH(fb_large_payload<100>).iterations(iter).samples(10);
PICOBENCH(jm_large_payload<100>).iterations(iter).samples(10);
PICOBENCH(fb_large_payload<1000>).iterations(iter).samples(10);
PICOBENCH(jm_large_payload<1000>).iterations(iter).samples(10);
PICOBENCH(fb_large_payload<10000>).iterations(iter).samples(10);
PICOBENCH(jm_large_payload<10000>).iterations(iter).samples(10);

// We need an explicit main to initialize kremlib and EverCrypt
int main(int argc, char* argv[])
{
  ::EverCrypt_AutoConfig2_init();
  picobench::runner runner;
  runner.parse_cmd_line(argc, argv);
  return runner.run();
}