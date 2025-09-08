// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/base64.h"
#include "ccf/crypto/entropy.h"
#include "ccf/crypto/hash_provider.h"
#include "ccf/crypto/hmac.h"
#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/sha256.h"
#include "ccf/crypto/symmetric_key.h"
#include "crypto/openssl/base64.h"
#include "crypto/openssl/hash.h"
#include "crypto/openssl/key_pair.h"
#include "crypto/openssl/rsa_key_pair.h"
#include "crypto/sharing.h"

#define PICOBENCH_UNIQUE_SYM_SUFFIX __COUNTER__
#define PICOBENCH_IMPLEMENT_WITH_MAIN
#include <picobench/picobench.hpp>

using namespace std;
using namespace ccf::crypto;

static const string lorem_ipsum =
  "Lorem ipsum dolor sit amet, consectetur adipiscing "
  "elit, sed do eiusmod tempor incididunt ut labore et"
  " dolore magna aliqua. Ut enim ad minim veniam, quis"
  " nostrud exercitation ullamco laboris nisi ut "
  "aliquip ex ea commodo consequat. Duis aute irure "
  "dolor in reprehenderit in voluptate velit esse "
  "cillum dolore eu fugiat nulla pariatur. Excepteur "
  "sint occaecat cupidatat non proident, sunt in culpa "
  "qui officia deserunt mollit anim id est laborum.";

template <class A>
inline void do_not_optimize(A const& value)
{
  asm volatile("" : : "r,m"(value) : "memory");
}

inline void clobber_memory()
{
  asm volatile("" : : : "memory");
}

template <size_t NBytes>
vector<uint8_t> make_contents()
{
  vector<uint8_t> contents(NBytes);
  size_t written = 0;
  while (written < NBytes)
  {
    const auto write_size = min(lorem_ipsum.size(), NBytes - written);
    memcpy(contents.data() + written, lorem_ipsum.data(), write_size);
    written += write_size;
  }
  return contents;
}

template <typename P, CurveID Curve, size_t NContents>
static void benchmark_sign(picobench::state& s)
{
  P kp(Curve);
  auto contents = make_contents<NContents>();

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    auto signature = kp.sign(contents);
    do_not_optimize(signature);
    clobber_memory();
  }
  s.stop_timer();
}

template <typename T, typename S, CurveID CID, size_t NContents>
static void benchmark_verify(picobench::state& s)
{
  T kp(CID);
  const auto contents = make_contents<NContents>();
  S pubk(kp.public_key_pem());

  auto signature = kp.sign(contents);

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    auto verified = pubk.verify(contents, signature);
    do_not_optimize(verified);
    clobber_memory();
  }
  s.stop_timer();
}

template <MDType M, size_t NContents>
static void benchmark_hmac(picobench::state& s)
{
  const auto contents = make_contents<NContents>();
  const auto key =
    ccf::crypto::get_entropy()->random(ccf::crypto::GCM_DEFAULT_KEY_SIZE);

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    HashBytes hash = ccf::crypto::hmac(M, key, contents);
    do_not_optimize(hash);
    clobber_memory();
  }
  s.stop_timer();
}

template <typename P, MDType M, size_t NContents>
static void benchmark_hash(picobench::state& s)
{
  const auto contents = make_contents<NContents>();

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    P hp;
    HashBytes hash = hp.Hash(contents.data(), contents.size(), M);
    do_not_optimize(hash);
    clobber_memory();
  }
  s.stop_timer();
}

template <typename P, CurveID Curve>
static void benchmark_create(picobench::state& s)
{
  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    P kp(Curve);
    do_not_optimize(kp);
    clobber_memory();
  }
  s.stop_timer();
}

const std::vector<int> sizes = {10};

#define PICO_SUFFIX(CURVE) iterations(sizes).samples(10)

#define PICO_HASH_SUFFIX() iterations(sizes).samples(10)

PICOBENCH_SUITE("create ec keypairs");
namespace CREATE_KEYPAIRS
{
  auto create_256r1 = benchmark_create<KeyPair_OpenSSL, CurveID::SECP256R1>;
  PICOBENCH(create_256r1).iterations({1000}).samples(10);

  auto create_384r1 = benchmark_create<KeyPair_OpenSSL, CurveID::SECP384R1>;
  PICOBENCH(create_384r1).iterations({1000}).samples(10);
}

PICOBENCH_SUITE("sign secp384r1");
namespace SIGN_SECP384R1
{
  auto sign_384_ossl_1byte =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP384R1, 1>;
  PICOBENCH(sign_384_ossl_1byte).PICO_SUFFIX(CurveID::SECP384R1);

  auto sign_384_ossl_1k =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP384R1, 1024>;
  PICOBENCH(sign_384_ossl_1k).PICO_SUFFIX(CurveID::SECP384R1);

  auto sign_384_ossl_100k =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP384R1, 102400>;
  PICOBENCH(sign_384_ossl_100k).PICO_SUFFIX(CurveID::SECP384R1);
}

PICOBENCH_SUITE("sign secp256r1");
namespace SIGN_SECP256R1
{
  auto sign_256r1_ossl_1byte =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP256R1, 1>;
  PICOBENCH(sign_256r1_ossl_1byte).PICO_SUFFIX(CurveID::SECP256R1);

  auto sign_256r1_ossl_1k =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP256R1, 1024>;
  PICOBENCH(sign_256r1_ossl_1k).PICO_SUFFIX(CurveID::SECP256R1);

  auto sign_256r1_ossl_100k =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP256R1, 102400>;
  PICOBENCH(sign_256r1_ossl_100k).PICO_SUFFIX(CurveID::SECP256R1);
}

PICOBENCH_SUITE("verify secp384r1");
namespace SECP384R1
{
  auto verify_384_ossl_1byte =
    benchmark_verify<KeyPair_OpenSSL, PublicKey_OpenSSL, CurveID::SECP384R1, 1>;
  PICOBENCH(verify_384_ossl_1byte).PICO_SUFFIX(CurveID::SECP384R1);

  auto verify_384_ossl_1k = benchmark_verify<
    KeyPair_OpenSSL,
    PublicKey_OpenSSL,
    CurveID::SECP384R1,
    1024>;
  PICOBENCH(verify_384_ossl_1k).PICO_SUFFIX(CurveID::SECP384R1);

  auto verify_384_ossl_100k = benchmark_verify<
    KeyPair_OpenSSL,
    PublicKey_OpenSSL,
    CurveID::SECP384R1,
    102400>;
  PICOBENCH(verify_384_ossl_100k).PICO_SUFFIX(CurveID::SECP384R1);
}

PICOBENCH_SUITE("verify secp256r1");
namespace SECP256R1
{
  auto verify_256r1_ossl_1byte =
    benchmark_verify<KeyPair_OpenSSL, PublicKey_OpenSSL, CurveID::SECP256R1, 1>;
  PICOBENCH(verify_256r1_ossl_1byte).PICO_SUFFIX(CurveID::SECP256R1);

  auto verify_256r1_ossl_1k = benchmark_verify<
    KeyPair_OpenSSL,
    PublicKey_OpenSSL,
    CurveID::SECP256R1,
    1024>;
  PICOBENCH(verify_256r1_ossl_1k).PICO_SUFFIX(CurveID::SECP256R1);

  auto verify_256r1_ossl_100k = benchmark_verify<
    KeyPair_OpenSSL,
    PublicKey_OpenSSL,
    CurveID::SECP256R1,
    102400>;
  PICOBENCH(verify_256r1_ossl_100k).PICO_SUFFIX(CurveID::SECP256R1);
}

PICOBENCH_SUITE("sign RSA-2048");
namespace SIGN_RSA2048
{
  template <typename P, size_t KSZ, size_t NContents>
  static void benchmark_sign(picobench::state& s)
  {
    P kp(KSZ);
    auto contents = make_contents<NContents>();

    s.start_timer();
    for (auto _ : s)
    {
      (void)_;
      auto signature = kp.sign(contents, MDType::SHA256);
      do_not_optimize(signature);
      clobber_memory();
    }
    s.stop_timer();
  }

  auto sign_rsa_ossl_1byte = benchmark_sign<RSAKeyPair_OpenSSL, 2048, 1>;
  PICOBENCH(sign_rsa_ossl_1byte).PICO_SUFFIX();

  auto sign_rsa_ossl_1k = benchmark_sign<RSAKeyPair_OpenSSL, 2048, 1024>;
  PICOBENCH(sign_rsa_ossl_1k).PICO_SUFFIX();

  auto sign_rsa_ossl_100k = benchmark_sign<RSAKeyPair_OpenSSL, 2048, 102400>;
  PICOBENCH(sign_rsa_ossl_100k).PICO_SUFFIX();
}

PICOBENCH_SUITE("verify RSA-2048");
namespace VERIFY_RSA2048
{
  template <typename P, size_t KSZ, size_t NContents>
  static void benchmark_verify(picobench::state& s)
  {
    P kp(KSZ);
    auto contents = make_contents<NContents>();
    auto signature = kp.sign(contents, MDType::SHA256);

    s.start_timer();
    for (auto _ : s)
    {
      (void)_;
      if (!kp.verify(
            contents.data(),
            contents.size(),
            signature.data(),
            signature.size(),
            MDType::SHA256))
      {
        throw std::runtime_error("verification failure");
      }
      do_not_optimize(signature);
      clobber_memory();
    }
    s.stop_timer();
  }

  auto verify_rsa_ossl_1byte = benchmark_verify<RSAKeyPair_OpenSSL, 2048, 1>;
  PICOBENCH(verify_rsa_ossl_1byte).PICO_SUFFIX();

  auto verify_rsa_ossl_1k = benchmark_verify<RSAKeyPair_OpenSSL, 2048, 1024>;
  PICOBENCH(verify_rsa_ossl_1k).PICO_SUFFIX();

  auto verify_rsa_ossl_100k =
    benchmark_verify<RSAKeyPair_OpenSSL, 2048, 102400>;
  PICOBENCH(verify_rsa_ossl_100k).PICO_SUFFIX();
}

PICOBENCH_SUITE("hash");
namespace Hashes
{
  auto sha_384_ossl_1byte =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA384, 1>;
  PICOBENCH(sha_384_ossl_1byte).PICO_HASH_SUFFIX();
  auto sha_256_ossl_1byte =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA256, 1>;
  PICOBENCH(sha_256_ossl_1byte).PICO_HASH_SUFFIX();
  auto sha_512_ossl_1byte =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA512, 1>;
  PICOBENCH(sha_512_ossl_1byte).PICO_HASH_SUFFIX();

  auto sha_384_ossl_1k =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA384, 1024>;
  PICOBENCH(sha_384_ossl_1k).PICO_HASH_SUFFIX();
  auto sha_256_ossl_1k =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA256, 1024>;
  PICOBENCH(sha_256_ossl_1k).PICO_HASH_SUFFIX();
  auto sha_512_ossl_1k =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA512, 1024>;
  PICOBENCH(sha_512_ossl_1k).PICO_HASH_SUFFIX();

  auto sha_384_ossl_100k =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA384, 102400>;
  PICOBENCH(sha_384_ossl_100k).PICO_HASH_SUFFIX();
  auto sha_256_ossl_100k =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA256, 102400>;
  PICOBENCH(sha_256_ossl_100k).PICO_HASH_SUFFIX();
  auto sha_512_ossl_100k =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA512, 102400>;
  PICOBENCH(sha_512_ossl_100k).PICO_HASH_SUFFIX();
}

template <size_t size>
static void sha256_bench(picobench::state& s)
{
  std::vector<uint8_t> v(size);
  for (size_t i = 0; i < size; ++i)
  {
    v[i] = rand();
  }

  ccf::crypto::Sha256Hash h;

  s.start_timer();
  for (size_t i = 0; i < 10; ++i)
  {
    ccf::crypto::openssl_sha256(v, h.h.data());
  }
  s.stop_timer();
}

// Variant of the code above that uses the OpenSSL API
// directly without any MD or CTX caching/pre-creation
// for comparison. This is fine for larger inputs, but
// substantially slower for smaller inputs, such as
// digests in Merkle Trees.
template <size_t size>
static void sha256_noopt_bench(picobench::state& s)
{
  std::vector<uint8_t> v(size);
  for (size_t i = 0; i < size; ++i)
  {
    v[i] = rand();
  }

  std::vector<uint8_t> out(EVP_MD_size(EVP_sha256()));

  s.start_timer();
  for (size_t i = 0; i < 10; ++i)
  {
    auto* md = EVP_MD_fetch(nullptr, "SHA2-256", nullptr);
    auto* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, v.data(), v.size());
    EVP_DigestFinal_ex(ctx, out.data(), nullptr);
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);
  }
  s.stop_timer();
}

#define DEFINE_SHA256_BENCH(SHIFT) \
  PICOBENCH_SUITE("digest sha256 (2 << " #SHIFT ")"); \
  namespace SHA256_bench_##SHIFT \
  { \
    auto openssl_sha256_##SHIFT##_no = sha256_noopt_bench<2 << SHIFT>; \
    PICOBENCH(openssl_sha256_##SHIFT##_no).PICO_HASH_SUFFIX().baseline(); \
    auto openssl_sha256_##SHIFT = sha256_bench<2 << SHIFT>; \
    PICOBENCH(openssl_sha256_##SHIFT).PICO_HASH_SUFFIX(); \
  }

DEFINE_SHA256_BENCH(6)
DEFINE_SHA256_BENCH(8)
DEFINE_SHA256_BENCH(10)
DEFINE_SHA256_BENCH(12)
DEFINE_SHA256_BENCH(14)
DEFINE_SHA256_BENCH(16)

PICOBENCH_SUITE("base64");
namespace Base64_bench
{
  template <size_t size>
  static void base64_bench(picobench::state& s)
  {
    std::vector<uint8_t> v(size);
    for (size_t i = 0; i < size; ++i)
    {
      v[i] = rand();
    }

    s.start_timer();
    for (size_t i = 0; i < 10; ++i)
    {
      // We don't check the outputs as this is done elsewhere
      std::string encoded =
        ccf::crypto::Base64_openssl::b64_from_raw(v.data(), v.size());
      ccf::crypto::Base64_openssl::raw_from_b64(encoded);
    }
    s.stop_timer();
  }

  // Single line is 64 chars (48 bytes)
  auto openssl_base64_base = base64_bench<45>;
  PICOBENCH(openssl_base64_base).PICO_HASH_SUFFIX();

  // Small double line
  auto openssl_base64_50 = base64_bench<50>;
  PICOBENCH(openssl_base64_50).PICO_HASH_SUFFIX();

  auto openssl_base64_100 = base64_bench<100>;
  PICOBENCH(openssl_base64_100).PICO_HASH_SUFFIX();

  auto openssl_base64_500 = base64_bench<500>;
  PICOBENCH(openssl_base64_500).PICO_HASH_SUFFIX();

  auto openssl_base64_1000 = base64_bench<1000>;
  PICOBENCH(openssl_base64_1000).PICO_HASH_SUFFIX();

  auto openssl_base64_5000 = base64_bench<5000>;
  PICOBENCH(openssl_base64_5000).PICO_HASH_SUFFIX();
}

PICOBENCH_SUITE("hmac");
namespace HMAC_bench
{
  auto openssl_hmac_sha256_32 = benchmark_hmac<MDType::SHA256, 32>;
  PICOBENCH(openssl_hmac_sha256_32).PICO_HASH_SUFFIX();

  auto openssl_hmac_sha256_64 = benchmark_hmac<MDType::SHA256, 64>;
  PICOBENCH(openssl_hmac_sha256_64).PICO_HASH_SUFFIX();
}

std::vector<ccf::crypto::sharing::Share> shares;

PICOBENCH_SUITE("share");
namespace SHARE_bench
{
  template <size_t nshares, size_t threshold>
  static void benchmark_share(picobench::state& s)
  {
    shares.resize(nshares);

    s.start_timer();
    for (auto _ : s)
    {
      (void)_;
      ccf::crypto::sharing::Share secret;
      ccf::crypto::sharing::sample_secret_and_shares(secret, shares, threshold);
      do_not_optimize(secret);
      clobber_memory();
    }
    s.stop_timer();
  }

  auto share_10s_d1 = benchmark_share<10, 1>;
  auto share_100s_d1 = benchmark_share<100, 1>;
  auto share_1000s_d1 = benchmark_share<1000, 1>;

  PICOBENCH(share_10s_d1).PICO_SUFFIX();
  PICOBENCH(share_100s_d1).PICO_SUFFIX();
  PICOBENCH(share_1000s_d1).PICO_SUFFIX();

  auto share_10s_d5 = benchmark_share<10, 5>;
  auto share_100s_d5 = benchmark_share<100, 5>;
  auto share_1000s_d5 = benchmark_share<1000, 5>;

  PICOBENCH(share_10s_d5).PICO_SUFFIX();
  PICOBENCH(share_100s_d5).PICO_SUFFIX();
  PICOBENCH(share_1000s_d5).PICO_SUFFIX();

  template <size_t nshares, size_t threshold>
  static void benchmark_share_and_recover(picobench::state& s)
  {
    shares.resize(nshares);

    s.start_timer();
    for (auto _ : s)
    {
      (void)_;
      ccf::crypto::sharing::Share secret;
      ccf::crypto::sharing::sample_secret_and_shares(secret, shares, threshold);
      ccf::crypto::sharing::recover_unauthenticated_secret(
        secret, shares, threshold);
      do_not_optimize(secret);
      clobber_memory();
    }
    s.stop_timer();
  }

  auto share_n_recover_10s_d1 = benchmark_share_and_recover<10, 1>;
  auto share_n_recover_100s_d1 = benchmark_share_and_recover<100, 1>;
  auto share_n_recover_1000s_d1 = benchmark_share_and_recover<1000, 1>;

  PICOBENCH(share_n_recover_10s_d1).PICO_SUFFIX();
  PICOBENCH(share_n_recover_100s_d1).PICO_SUFFIX();
  PICOBENCH(share_n_recover_1000s_d1).PICO_SUFFIX();

  auto share_n_recover_10s_d5 = benchmark_share_and_recover<10, 5>;
  auto share_n_recover_100s_d5 = benchmark_share_and_recover<100, 5>;
  auto share_n_recover_1000s_d5 = benchmark_share_and_recover<1000, 5>;

  PICOBENCH(share_n_recover_10s_d5).PICO_SUFFIX();
  PICOBENCH(share_n_recover_100s_d5).PICO_SUFFIX();
  PICOBENCH(share_n_recover_1000s_d5).PICO_SUFFIX();
}