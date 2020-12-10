// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "util.h"

#include <chrono>
#include <iomanip>
#include <iostream>
#include <merklecpp.h>

#define HSZ 32
#define PRNTSZ 3

#ifdef HAVE_EVERCRYPT
#  include <Hacl_Hash.h>
#  include <MerkleTree.h>

void sha256_compress_evercrypt(
  const merkle::HashT<32>& l,
  const merkle::HashT<32>& r,
  merkle::HashT<32>& out)
{
  mt_sha256_compress((uint8_t*)l.bytes, (uint8_t*)r.bytes, (uint8_t*)out.bytes);
}

void sha256_evercrypt(
  const merkle::HashT<32>& l,
  const merkle::HashT<32>& r,
  merkle::HashT<32>& out)
{
  uint8_t block[32 * 2];
  memcpy(&block[0], l.bytes, 32);
  memcpy(&block[32], r.bytes, 32);
  Hacl_Hash_SHA2_hash_256(block, sizeof(block), (uint8_t*)out.bytes);
}

void mt_sha256_evercrypt(uint8_t* src1, uint8_t* src2, uint8_t* dst)
{
  uint8_t block[32 * 2];
  memcpy(&block[0], src1, 32);
  memcpy(&block[32], src2, 32);
  Hacl_Hash_SHA2_hash_256(block, sizeof(block), dst);
}

typedef merkle::TreeT<32, sha256_compress_evercrypt> EverCryptTree;
typedef merkle::TreeT<32, sha256_evercrypt> EverCryptFullTree;
#endif

#ifdef HAVE_OPENSSL
typedef merkle::TreeT<32, merkle::sha256_compress_openssl> OpenSSLTree;
typedef merkle::TreeT<32, merkle::sha256_openssl> OpenSSLFullTree;
#endif

#ifdef HAVE_MBEDTLS
typedef merkle::TreeT<32, merkle::sha256_compress_mbedtls> MbedTLSTree;
typedef merkle::TreeT<32, merkle::sha256_mbedtls> MbedTLSFullTree;
#endif

template <
  void (*HF1)(
    const merkle::HashT<32>& l,
    const merkle::HashT<32>& r,
    merkle::HashT<32>& out),
  void (*HF2)(
    const merkle::HashT<32>& l,
    const merkle::HashT<32>& r,
    merkle::HashT<32>& out)>
void compare_roots(
  merkle::TreeT<32, HF1>& mt1, merkle::TreeT<32, HF2>& mt2, const char* name)
{
  auto mt1_root = mt1.root();
  auto mt2_root = mt2.root();

  if (mt1_root != mt2_root)
  {
    std::cout << mt1.num_leaves() << ": " << mt1_root.to_string()
              << " != " << mt2_root.to_string() << std::endl;
    std::cout << "mt1: " << std::endl;
    std::cout << mt1.to_string(PRNTSZ) << std::endl;
    std::cout << name << ": " << std::endl;
    std::cout << mt2.to_string(PRNTSZ) << std::endl;
    throw std::runtime_error("root hash mismatch");
  }
}

void compare_compression_hashes()
{
#ifndef NDEBUG
  const size_t num_trees = 1024;
  const size_t root_interval = 31;
#else
  const size_t num_trees = 4096;
  const size_t root_interval = 128;
#endif

  size_t total_inserts = 0, total_roots = 0;

  for (size_t k = 0; k < num_trees; k++)
  {
    merkle::Tree mt;

#ifdef HAVE_EVERCRYPT
    EverCryptTree mte;
#endif

#ifdef HAVE_OPENSSL
    OpenSSLTree mto;
#endif

#ifdef HAVE_MBEDTLS
    MbedTLSTree mtm;
#endif

    // Build trees with k+1 leaves
    int j = 0;
    auto hashes = make_hashes(k + 1);

    for (const auto h : hashes)
    {
      mt.insert(h);

#ifdef HAVE_EVERCRYPT
      mte.insert(h);
#endif

#ifdef HAVE_OPENSSL
      mto.insert(h);
#endif

#ifdef HAVE_MBEDTLS
      mtm.insert(h);
#endif

      total_inserts++;

      if ((j++ % root_interval) == 0)
      {
#ifdef HAVE_EVERCRYPT
        compare_roots(mt, mte, "EverCrypt");
#endif

#ifdef HAVE_OPENSSL
        compare_roots(mt, mto, "OpenSSL");
#endif

#ifdef HAVE_MBEDTLS
        compare_roots(mt, mtm, "mbedTLS");
#endif

        total_roots++;
      }
    }

#ifdef HAVE_EVERCRYPT
    compare_roots(mt, mte, "EverCrypt");
#endif

#ifdef HAVE_OPENSSL
    compare_roots(mt, mto, "OpenSSL");
#endif

#ifdef HAVE_MBEDTLS
    compare_roots(mt, mtm, "mbedTLS");
#endif
  }

  static char time_str[256] = "";
  std::time_t t = std::time(nullptr);
  std::strftime(time_str, sizeof(time_str), "%R", std::localtime(&t));
  std::cout << time_str << ": " << num_trees << " trees, " << total_inserts
            << " inserts, " << total_roots
            << " roots with SHA256 compression function: OK" << std::endl;
}

#if defined(HAVE_OPENSSL) && (defined(HAVE_EVERCRYPT) || defined(HAVE_MBEDTLS))
void compare_full_hashes()
{
#  ifndef NDEBUG
  const size_t num_trees = 1024;
  const size_t root_interval = 31;
#  else
  const size_t num_trees = 4096;
  const size_t root_interval = 128;
#  endif

  size_t total_inserts = 0, total_roots = 0;

  for (size_t k = 0; k < num_trees; k++)
  {
    OpenSSLFullTree mto;

#  ifdef HAVE_EVERCRYPT
    merkle::TreeT<32, sha256_evercrypt> mte;
#  endif

#  ifdef HAVE_MBEDTLS
    MbedTLSFullTree mtm;
#  endif

    // Build trees with k+1 leaves
    int j = 0;
    auto hashes = make_hashes(k + 1);

    for (const auto h : hashes)
    {
      mto.insert(h);

#  ifdef HAVE_EVERCRYPT
      mte.insert(h);
#  endif

#  ifdef HAVE_MBEDTLS
      mtm.insert(h);
#  endif

      total_inserts++;

      if ((j++ % root_interval) == 0)
      {
#  ifdef HAVE_EVERCRYPT
        compare_roots(mto, mte, "EverCrypt");
#  endif

#  ifdef HAVE_MBEDTLS
        compare_roots(mto, mtm, "mbedTLS");
#  endif

        total_roots++;
      }
    }

#  ifdef HAVE_EVERCRYPT
    compare_roots(mto, mte, "OpenSSL");
#  endif

#  ifdef HAVE_MBEDTLS
    compare_roots(mto, mtm, "mbedTLS");
#  endif
  }

  static char time_str[256] = "";
  std::time_t t = std::time(nullptr);
  std::strftime(time_str, sizeof(time_str), "%R", std::localtime(&t));
  std::cout << time_str << ": " << num_trees << " trees, " << total_inserts
            << " inserts, " << total_roots << " roots with full SHA256: OK"
            << std::endl;
}
#endif

template <typename T>
void bench(
  const std::vector<merkle::Hash>& hashes,
  const std::string& name,
  size_t root_interval)
{
  size_t j = 0;
  auto start = std::chrono::high_resolution_clock::now();
  T mt;
  for (auto& h : hashes)
  {
    mt.insert(h);
    if ((j++ % root_interval) == 0)
      mt.root();
  }
  mt.root();
  auto stop = std::chrono::high_resolution_clock::now();
  double seconds =
    std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count() /
    1e9;
  std::cout << std::left << std::setw(10) << name << ": "
            << mt.statistics.num_insert << " insertions, "
            << mt.statistics.num_root << " roots in " << seconds << " sec"
            << std::endl;
}

#ifdef HAVE_EVERCRYPT
template <void (*HASH_FUNCTION)(uint8_t* l, uint8_t* r, uint8_t* out)>
void bench_evercrypt(
  const std::vector<uint8_t*>& hashes,
  const std::string& name,
  size_t root_interval)
{
  size_t j = 0, num_inserts = 0, num_roots = 0;
  uint8_t* ec_root = mt_init_hash(32);
  auto start = std::chrono::high_resolution_clock::now();
  merkle_tree* ec_mt = mt_create_custom(32, hashes[0], HASH_FUNCTION);
  for (size_t i = 1; i < hashes.size(); i++)
  {
    mt_insert(ec_mt, hashes[i]);
    num_inserts++;
    if ((j++ % root_interval) == 0)
    {
      mt_get_root(ec_mt, ec_root);
      num_roots++;
    }
  }
  mt_get_root(ec_mt, ec_root);
  num_roots++;
  auto stop = std::chrono::high_resolution_clock::now();
  auto seconds =
    std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count() /
    1e9;
  std::cout << std::left << std::setw(10) << name << ": " << num_inserts
            << " insertions, " << num_roots << " roots in " << seconds << " sec"
            << std::endl;
  mt_free_hash(ec_root);
  mt_free(ec_mt);
}
#endif

int main()
{
  try
  {
    // std::srand(0);
    std::srand(std::time(0));

    compare_compression_hashes();

#if defined(HAVE_EVERCRYPT) && (defined(HAVE_OPENSSL) || defined(HAVE_MBEDTLS))
    compare_full_hashes();
#endif

#ifndef NDEBUG
    const size_t num_leaves = 128 * 1024;
    const size_t root_interval = 128;
#else
    const size_t num_leaves = 16 * 1024 * 1024;
    const size_t root_interval = 1024;
#endif

    auto hashes = make_hashes(num_leaves);

    std::cout << "--- merklecpp trees with SHA256 compression function: "
              << std::endl;

    bench<merkle::Tree>(hashes, "merklecpp", root_interval);

#ifdef HAVE_OPENSSL
    bench<OpenSSLTree>(hashes, "OpenSSL", root_interval);
#endif

#ifdef HAVE_MBEDTLS
    bench<MbedTLSTree>(hashes, "mbedTLS", root_interval);
#endif

#ifdef HAVE_EVERCRYPT
    bench<EverCryptTree>(hashes, "EverCrypt", root_interval);
#endif

    std::cout << "--- merklecpp trees with full SHA256: " << std::endl;

#ifdef HAVE_OPENSSL
    bench<OpenSSLFullTree>(hashes, "OpenSSL", root_interval);
#endif

#ifdef HAVE_MBEDTLS
    bench<MbedTLSFullTree>(hashes, "mbedTLS", root_interval);
#endif

#ifdef HAVE_EVERCRYPT
    bench<EverCryptFullTree>(hashes, "EverCrypt", root_interval);
#endif

#ifdef HAVE_EVERCRYPT
    std::vector<uint8_t*> ec_hashes;
    for (auto& h : hashes)
    {
      ec_hashes.push_back(mt_init_hash(32));
      memcpy(ec_hashes.back(), h.bytes, 32);
    }

    std::cout << "--- EverCrypt trees with SHA256 compression function: "
              << std::endl;
    bench_evercrypt<mt_sha256_compress>(ec_hashes, "EverCrypt", root_interval);

    std::cout << "--- EverCrypt trees with full SHA256: " << std::endl;
    bench_evercrypt<mt_sha256_evercrypt>(ec_hashes, "EverCrypt", root_interval);

    for (auto h : ec_hashes)
      mt_free_hash(h);
#endif
  }
  catch (std::exception& ex)
  {
    std::cout << "Error: " << ex.what() << std::endl;
    return 1;
  }
  catch (...)
  {
    std::cout << "Error" << std::endl;
    return 1;
  }

  return 0;
}