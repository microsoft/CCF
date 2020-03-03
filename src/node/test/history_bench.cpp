// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define PICOBENCH_IMPLEMENT
#include "kv/test/stub_consensus.h"
#include "node/history.h"

#include <cstdlib>
#include <ctime>
#include <picobench/picobench.hpp>

extern "C"
{
#include <evercrypt/EverCrypt_AutoConfig2.h>
}

using namespace ccf;

class DummyConsensus : public kv::StubConsensus
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
    crypto::Sha256Hash h;
    crypto::Sha256Hash::evercrypt_sha256({data}, h.h.data());
    do_not_optimize(h);
    clobber_memory();
  }
  s.stop_timer();
}

template <size_t S>
static void hash_mbedtls_sha256(picobench::state& s)
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
    crypto::Sha256Hash h;
    crypto::Sha256Hash::mbedtls_sha256({data}, h.h.data());
    do_not_optimize(h);
    clobber_memory();
  }
  s.stop_timer();
}

template <size_t S>
static void hash_mbedtls_sha512(picobench::state& s)
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
    std::array<uint8_t, 512 / 8> hash;
    mbedtls_sha512_ret(data.data(), data.size(), hash.begin(), 0);
    do_not_optimize(hash);
    clobber_memory();
  }
  s.stop_timer();
}

template <size_t S>
static void append(picobench::state& s)
{
  ::srand(42);

  Store store;
  auto& nodes = store.create<ccf::Nodes>(ccf::Tables::NODES);
  auto& signatures = store.create<ccf::Signatures>(ccf::Tables::SIGNATURES);

  auto kp = tls::make_key_pair();

  std::shared_ptr<kv::Consensus> consensus = std::make_shared<DummyConsensus>();
  store.set_consensus(consensus);

  std::shared_ptr<kv::TxHistory> history =
    std::make_shared<ccf::MerkleTxHistory>(store, 0, *kp, signatures, nodes);
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

  Store store;
  auto& nodes = store.create<ccf::Nodes>(ccf::Tables::NODES);
  auto& signatures = store.create<ccf::Signatures>(ccf::Tables::SIGNATURES);

  auto kp = tls::make_key_pair();

  std::shared_ptr<kv::Consensus> consensus = std::make_shared<DummyConsensus>();
  store.set_consensus(consensus);

  std::shared_ptr<kv::TxHistory> history =
    std::make_shared<ccf::MerkleTxHistory>(store, 0, *kp, signatures, nodes);
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

PICOBENCH_SUITE("hash_mbedtls_sha256");
PICOBENCH(hash_mbedtls_sha256<10>).iterations(sizes).samples(10).baseline();
PICOBENCH(hash_mbedtls_sha256<100>).iterations(sizes).samples(10);
PICOBENCH(hash_mbedtls_sha256<1000>).iterations(sizes).samples(10);

PICOBENCH_SUITE("hash_mbedtls_sha512");
PICOBENCH(hash_mbedtls_sha512<10>).iterations(sizes).samples(10).baseline();
PICOBENCH(hash_mbedtls_sha512<100>).iterations(sizes).samples(10);
PICOBENCH(hash_mbedtls_sha512<1000>).iterations(sizes).samples(10);

PICOBENCH_SUITE("append");
PICOBENCH(append<10>).iterations(sizes).samples(10).baseline();
PICOBENCH(append<100>).iterations(sizes).samples(10);
PICOBENCH(append<1000>).iterations(sizes).samples(10);

PICOBENCH_SUITE("append_compact");
PICOBENCH(append_compact<10>).iterations(sizes).samples(10).baseline();
PICOBENCH(append_compact<100>).iterations(sizes).samples(10);
PICOBENCH(append_compact<1000>).iterations(sizes).samples(10);

// We need an explicit main to initialize kremlib and EverCrypt
int main(int argc, char* argv[])
{
  ::EverCrypt_AutoConfig2_init();
  logger::config::level() = logger::FATAL;

  picobench::runner runner;
  runner.parse_cmd_line(argc, argv);
  return runner.run();
}