// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv/test/stub_consensus.h"
#include "node/history.h"

#include <cstdlib>
#include <ctime>
#define PICOBENCH_IMPLEMENT
#include <picobench/picobench.hpp>

std::unique_ptr<threading::ThreadMessaging>
  threading::ThreadMessaging::singleton = nullptr;

namespace threading
{
  std::map<std::thread::id, uint16_t> thread_ids;
}

using namespace ccf;

class DummyConsensus : public kv::test::StubConsensus
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
    crypto::Sha256Hash h(data);
    do_not_optimize(h);
    clobber_memory();
  }
  s.stop_timer();
}

template <size_t S>
static void append(picobench::state& s)
{
  ::srand(42);

  kv::Store store;
  auto kp = crypto::make_key_pair();

  std::shared_ptr<kv::Consensus> consensus = std::make_shared<DummyConsensus>();
  store.set_consensus(consensus);

  std::shared_ptr<kv::TxHistory> history =
    std::make_shared<ccf::MerkleTxHistory>(store, kv::test::PrimaryNodeId, *kp);
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

  kv::Store store;
  auto kp = crypto::make_key_pair();

  std::shared_ptr<kv::Consensus> consensus = std::make_shared<DummyConsensus>();
  store.set_consensus(consensus);

  std::shared_ptr<kv::TxHistory> history =
    std::make_shared<ccf::MerkleTxHistory>(store, kv::test::PrimaryNodeId, *kp);
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
PICOBENCH(hash_only<10>).iterations(sizes).samples(10).baseline();
PICOBENCH(hash_only<100>).iterations(sizes).samples(10);
PICOBENCH(hash_only<1000>).iterations(sizes).samples(10);

PICOBENCH_SUITE("append");
PICOBENCH(append<10>).iterations(sizes).samples(10).baseline();
PICOBENCH(append<100>).iterations(sizes).samples(10);
PICOBENCH(append<1000>).iterations(sizes).samples(10);

PICOBENCH_SUITE("append_compact");
PICOBENCH(append_compact<10>).iterations(sizes).samples(10).baseline();
PICOBENCH(append_compact<100>).iterations(sizes).samples(10);
PICOBENCH(append_compact<1000>).iterations(sizes).samples(10);

int main(int argc, char* argv[])
{
  logger::config::level() = logger::FATAL;
  threading::ThreadMessaging::init(1);
  
  picobench::runner runner;
  runner.parse_cmd_line(argc, argv);
  return runner.run();
}
