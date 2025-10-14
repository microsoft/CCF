// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/hash.h"
#include "kv/test/stub_consensus.h"
#include "node/history.h"

#include <cstdlib>
#include <ctime>
#define PICOBENCH_IMPLEMENT
#include <picobench/picobench.hpp>

using namespace ccf;

class DummyConsensus : public ccf::kv::test::StubConsensus
{
public:
  DummyConsensus() {}
};

template <class A>
inline void do_not_optimize(A const& value)
{
  asm volatile("" : : "r,m"(value) : "memory");
}

inline void clobber_memory()
{
  asm volatile("" : : : "memory");
}

template <size_t S>
static void hash_only(picobench::state& s)
{
  ::srand(42);

  std::vector<std::vector<uint8_t>> txs;
  for (size_t i = 0; i < s.iterations(); i++)
  {
    std::vector<uint8_t> tx;
    for (size_t j = 0; j < S; j++)
    {
      tx.push_back(::rand() % 256);
    }
    txs.push_back(tx);
  }

  size_t idx = 0;
  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    auto data = txs[idx++];
    ccf::crypto::Sha256Hash h(data);
    do_not_optimize(h);
    clobber_memory();
  }
  s.stop_timer();
}

template <size_t S>
static void append(picobench::state& s)
{
  ::srand(42);

  ccf::kv::Store store;
  auto node_kp = ccf::crypto::make_key_pair();

  std::shared_ptr<ccf::kv::Consensus> consensus =
    std::make_shared<DummyConsensus>();
  store.set_consensus(consensus);

  std::shared_ptr<ccf::kv::TxHistory> history =
    std::make_shared<ccf::MerkleTxHistory>(
      store, ccf::kv::test::PrimaryNodeId, *node_kp);
  store.set_history(history);

  std::vector<std::vector<uint8_t>> txs;
  for (size_t i = 0; i < s.iterations(); i++)
  {
    std::vector<uint8_t> tx;
    for (size_t j = 0; j < S; j++)
    {
      tx.push_back(::rand() % 256);
    }
    txs.push_back(tx);
  }

  size_t idx = 0;
  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    history->append(txs[idx++]);
    clobber_memory();
  }
  s.stop_timer();
}

template <size_t S>
static void append_compact(picobench::state& s)
{
  ::srand(42);

  ccf::kv::Store store;
  auto node_kp = ccf::crypto::make_key_pair();

  std::shared_ptr<ccf::kv::Consensus> consensus =
    std::make_shared<DummyConsensus>();
  store.set_consensus(consensus);

  std::shared_ptr<ccf::kv::TxHistory> history =
    std::make_shared<ccf::MerkleTxHistory>(
      store, ccf::kv::test::PrimaryNodeId, *node_kp);
  store.set_history(history);

  std::vector<std::vector<uint8_t>> txs;
  for (size_t i = 0; i < s.iterations(); i++)
  {
    std::vector<uint8_t> tx;
    for (size_t j = 0; j < S; j++)
    {
      tx.push_back(::rand() % 256);
    }
    txs.push_back(tx);
  }

  size_t idx = 0;
  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    history->append(txs[idx++]);
    if (idx % 1000)
      history->compact(idx);
    clobber_memory();
  }
  s.stop_timer();
}

const std::vector<int> sizes = {1000, 10000};

PICOBENCH_SUITE("hash_only");
PICOBENCH(hash_only<10>).iterations(sizes).baseline();
PICOBENCH(hash_only<100>).iterations(sizes);
PICOBENCH(hash_only<1000>).iterations(sizes);

PICOBENCH_SUITE("append");
PICOBENCH(append<10>).iterations(sizes).baseline();
PICOBENCH(append<100>).iterations(sizes);
PICOBENCH(append<1000>).iterations(sizes);

PICOBENCH_SUITE("append_compact");
PICOBENCH(append_compact<10>).iterations(sizes).baseline();
PICOBENCH(append_compact<100>).iterations(sizes);
PICOBENCH(append_compact<1000>).iterations(sizes);

int main(int argc, char* argv[])
{
  ccf::logger::config::level() = ccf::LoggerLevel::FATAL;
  ::threading::ThreadMessaging::init(1);

  picobench::runner runner;
  runner.parse_cmd_line(argc, argv);
  auto ret = runner.run();
  return ret;
}
