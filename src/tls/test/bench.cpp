// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../key_pair.h"

#define PICOBENCH_IMPLEMENT_WITH_MAIN
#include <picobench/picobench.hpp>

using namespace std;
using namespace tls;

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
  auto kp = std::make_shared<P>(Curve);
  auto contents = make_contents<NContents>();

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    for (size_t i = 0; i < contents.size(); i++)
      contents[i]++;
    auto signature = kp->sign(contents);
    do_not_optimize(signature);
    clobber_memory();
  }
  s.stop_timer();
}

template <typename T, typename S, CurveID CID, size_t NContents>
static void benchmark_verify(picobench::state& s)
{
  auto kp = std::make_shared<T>(CID);
  const auto contents = make_contents<NContents>();
  auto pubk = std::make_shared<S>(kp->public_key_pem());

  auto signature = kp->sign(contents);

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    auto verified = pubk->verify(contents, signature);
    do_not_optimize(verified);
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

const std::vector<int> sizes = {10};

using namespace tls;

#define PICO_SUFFIX(CURVE) iterations(sizes).samples(10)

#define PICO_HASH_SUFFIX() iterations(sizes).samples(10)

PICOBENCH_SUITE("sign secp384r1");
namespace SIGN_SECP384R1
{
  auto sign_384_mbed_1byte =
    benchmark_sign<KeyPair_mbedTLS, CurveID::SECP384R1, 1>;
  PICOBENCH(sign_384_mbed_1byte).PICO_SUFFIX(CurveID::SECP384R1);
  auto sign_384_ossl_1byte =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP384R1, 1>;
  PICOBENCH(sign_384_ossl_1byte).PICO_SUFFIX(CurveID::SECP384R1);

  auto sign_384_mbed_1k =
    benchmark_sign<KeyPair_mbedTLS, CurveID::SECP384R1, 1024>;
  PICOBENCH(sign_384_mbed_1k).PICO_SUFFIX(CurveID::SECP384R1);
  auto sign_384_ossl_1k =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP384R1, 1024>;
  PICOBENCH(sign_384_ossl_1k).PICO_SUFFIX(CurveID::SECP384R1);

  auto sign_384_mbed_100k =
    benchmark_sign<KeyPair_mbedTLS, CurveID::SECP384R1, 102400>;
  PICOBENCH(sign_384_mbed_100k).PICO_SUFFIX(CurveID::SECP384R1);
  auto sign_384_ossl_100k =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP384R1, 102400>;
  PICOBENCH(sign_384_ossl_100k).PICO_SUFFIX(CurveID::SECP384R1);
}

PICOBENCH_SUITE("sign secp256r1");
namespace SIGN_SECP256R1
{
  auto sign_256r1_mbed_1byte =
    benchmark_sign<KeyPair_mbedTLS, CurveID::SECP256R1, 1>;
  PICOBENCH(sign_256r1_mbed_1byte).PICO_SUFFIX(CurveID::SECP256R1);
  auto sign_256r1_ossl_1byte =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP256R1, 1>;
  PICOBENCH(sign_256r1_ossl_1byte).PICO_SUFFIX(CurveID::SECP256R1);

  auto sign_256r1_mbed_1k =
    benchmark_sign<KeyPair_mbedTLS, CurveID::SECP256R1, 1024>;
  PICOBENCH(sign_256r1_mbed_1k).PICO_SUFFIX(CurveID::SECP256R1);
  auto sign_256r1_ossl_1k =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP256R1, 1024>;
  PICOBENCH(sign_256r1_ossl_1k).PICO_SUFFIX(CurveID::SECP256R1);

  auto sign_256r1_mbed_100k =
    benchmark_sign<KeyPair_mbedTLS, CurveID::SECP256R1, 102400>;
  PICOBENCH(sign_256r1_mbed_100k).PICO_SUFFIX(CurveID::SECP256R1);
  auto sign_256r1_ossl_100k =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP256R1, 102400>;
  PICOBENCH(sign_256r1_ossl_100k).PICO_SUFFIX(CurveID::SECP256R1);
}

PICOBENCH_SUITE("sign secp256k1");
namespace SIGN_SECP256K1
{
  auto sign_256k1_mbed_1byte =
    benchmark_sign<KeyPair_mbedTLS, CurveID::SECP256K1, 1>;
  PICOBENCH(sign_256k1_mbed_1byte).PICO_SUFFIX(CurveID::SECP256K1);
  auto sign_256k1_ossl_1byte =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP256K1, 1>;
  PICOBENCH(sign_256k1_ossl_1byte).PICO_SUFFIX(CurveID::SECP256K1);
  auto sign_256k1_bitc_1byte =
    benchmark_sign<KeyPair_k1Bitcoin, CurveID::SECP256K1, 1>;
  PICOBENCH(sign_256k1_bitc_1byte).PICO_SUFFIX(CurveID::SECP256K1);

  auto sign_256k1_mbed_64b =
    benchmark_sign<KeyPair_mbedTLS, CurveID::SECP256K1, 64>;
  PICOBENCH(sign_256k1_mbed_64b).PICO_SUFFIX(CurveID::SECP256K1);
  auto sign_256k1_ossl_64b =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP256K1, 64>;
  PICOBENCH(sign_256k1_ossl_64b).PICO_SUFFIX(CurveID::SECP256K1);
  auto sign_256k1_bitc_64b =
    benchmark_sign<KeyPair_k1Bitcoin, CurveID::SECP256K1, 64>;
  PICOBENCH(sign_256k1_bitc_64b).PICO_SUFFIX(CurveID::SECP256K1);

  auto sign_256k1_mbed_1k =
    benchmark_sign<KeyPair_mbedTLS, CurveID::SECP256K1, 1024>;
  PICOBENCH(sign_256k1_mbed_1k).PICO_SUFFIX(CurveID::SECP256K1);
  auto sign_256k1_ossl_1k =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP256K1, 1024>;
  PICOBENCH(sign_256k1_ossl_1k).PICO_SUFFIX(CurveID::SECP256K1);
  auto sign_256k1_bitc_1k =
    benchmark_sign<KeyPair_k1Bitcoin, CurveID::SECP256K1, 1024>;
  PICOBENCH(sign_256k1_bitc_1k).PICO_SUFFIX(CurveID::SECP256K1);

  auto sign_256k1_mbed_100k =
    benchmark_sign<KeyPair_mbedTLS, CurveID::SECP256K1, 102400>;
  PICOBENCH(sign_256k1_mbed_100k).PICO_SUFFIX(CurveID::SECP256K1);
  auto sign_256k1_ossl_100k =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP256K1, 102400>;
  PICOBENCH(sign_256k1_ossl_100k).PICO_SUFFIX(CurveID::SECP256K1);
  auto sign_256k1_bitc_100k =
    benchmark_sign<KeyPair_k1Bitcoin, CurveID::SECP256K1, 102400>;
  PICOBENCH(sign_256k1_bitc_100k).PICO_SUFFIX(CurveID::SECP256K1);
}

PICOBENCH_SUITE("verify secp384r1");
namespace SECP384R1
{
  auto verify_384_mbed_1byte =
    benchmark_verify<KeyPair_mbedTLS, PublicKey_mbedTLS, CurveID::SECP384R1, 1>;
  PICOBENCH(verify_384_mbed_1byte).PICO_SUFFIX(CurveID::SECP384R1);
  auto verify_384_ossl_1byte =
    benchmark_verify<KeyPair_OpenSSL, PublicKey_OpenSSL, CurveID::SECP384R1, 1>;
  PICOBENCH(verify_384_ossl_1byte).PICO_SUFFIX(CurveID::SECP384R1);

  auto verify_384_mbed_1k = benchmark_verify<
    KeyPair_mbedTLS,
    PublicKey_mbedTLS,
    CurveID::SECP384R1,
    1024>;
  PICOBENCH(verify_384_mbed_1k).PICO_SUFFIX(CurveID::SECP384R1);
  auto verify_256k1_mbed_1k = benchmark_verify<
    KeyPair_mbedTLS,
    PublicKey_mbedTLS,
    CurveID::SECP256K1,
    1024>;
  auto verify_384_ossl_1k = benchmark_verify<
    KeyPair_OpenSSL,
    PublicKey_OpenSSL,
    CurveID::SECP384R1,
    1024>;
  PICOBENCH(verify_384_ossl_1k).PICO_SUFFIX(CurveID::SECP384R1);

  auto verify_384_mbed_100k = benchmark_verify<
    KeyPair_mbedTLS,
    PublicKey_mbedTLS,
    CurveID::SECP384R1,
    102400>;
  PICOBENCH(verify_384_mbed_100k).PICO_SUFFIX(CurveID::SECP384R1);
  auto verify_384_ossl_100k = benchmark_verify<
    KeyPair_OpenSSL,
    PublicKey_OpenSSL,
    CurveID::SECP384R1,
    102400>;
  PICOBENCH(verify_384_ossl_100k).PICO_SUFFIX(CurveID::SECP384R1);
}

PICOBENCH_SUITE("verify secp256k1");
namespace SECP256K1
{
  auto verify_256k1_mbed_1byte =
    benchmark_verify<KeyPair_mbedTLS, PublicKey_mbedTLS, CurveID::SECP256K1, 1>;
  PICOBENCH(verify_256k1_mbed_1byte).PICO_SUFFIX(CurveID::SECP256K1);
  auto verify_256k1_bitc_1byte = benchmark_verify<
    KeyPair_k1Bitcoin,
    PublicKey_k1Bitcoin,
    CurveID::SECP256K1,
    1>;
  PICOBENCH(verify_256k1_bitc_1byte).PICO_SUFFIX(CurveID::SECP256K1);
  auto verify_256k1_ossl_1byte =
    benchmark_verify<KeyPair_OpenSSL, PublicKey_OpenSSL, CurveID::SECP256K1, 1>;
  PICOBENCH(verify_256k1_ossl_1byte).PICO_SUFFIX(CurveID::SECP256K1);

  auto verify_256k1_mbed_1k = benchmark_verify<
    KeyPair_mbedTLS,
    PublicKey_mbedTLS,
    CurveID::SECP256K1,
    1024>;
  PICOBENCH(verify_256k1_mbed_1k).PICO_SUFFIX(CurveID::SECP256K1);
  auto verify_256k1_bitc_1k = benchmark_verify<
    KeyPair_k1Bitcoin,
    PublicKey_k1Bitcoin,
    CurveID::SECP256K1,
    1024>;
  PICOBENCH(verify_256k1_bitc_1k).PICO_SUFFIX(CurveID::SECP256K1);
  auto verify_256k1_ossl_1k = benchmark_verify<
    KeyPair_OpenSSL,
    PublicKey_OpenSSL,
    CurveID::SECP256K1,
    1024>;
  PICOBENCH(verify_256k1_ossl_1k).PICO_SUFFIX(CurveID::SECP256K1);

  auto verify_256k1_mbed_100k = benchmark_verify<
    KeyPair_mbedTLS,
    PublicKey_mbedTLS,
    CurveID::SECP256K1,
    102400>;
  PICOBENCH(verify_256k1_mbed_100k).PICO_SUFFIX(CurveID::SECP256K1);
  auto verify_256k1_bitc_100k = benchmark_verify<
    KeyPair_k1Bitcoin,
    PublicKey_k1Bitcoin,
    CurveID::SECP256K1,
    102400>;
  PICOBENCH(verify_256k1_bitc_100k).PICO_SUFFIX(CurveID::SECP256K1);
  auto verify_256k1_ossl_100k = benchmark_verify<
    KeyPair_OpenSSL,
    PublicKey_OpenSSL,
    CurveID::SECP256K1,
    102400>;
  PICOBENCH(verify_256k1_ossl_100k).PICO_SUFFIX(CurveID::SECP256K1);
}

PICOBENCH_SUITE("verify secp256r1");
namespace SECP256R1
{
  auto verify_256r1_mbed_1byte =
    benchmark_verify<KeyPair_mbedTLS, PublicKey_mbedTLS, CurveID::SECP256R1, 1>;
  PICOBENCH(verify_256r1_mbed_1byte).PICO_SUFFIX(CurveID::SECP256R1);
  auto verify_256r1_ossl_1byte =
    benchmark_verify<KeyPair_OpenSSL, PublicKey_OpenSSL, CurveID::SECP256R1, 1>;
  PICOBENCH(verify_256r1_ossl_1byte).PICO_SUFFIX(CurveID::SECP256R1);

  auto verify_256r1_mbed_1k = benchmark_verify<
    KeyPair_mbedTLS,
    PublicKey_mbedTLS,
    CurveID::SECP256R1,
    1024>;
  PICOBENCH(verify_256r1_mbed_1k).PICO_SUFFIX(CurveID::SECP256R1);
  auto verify_256r1_ossl_1k = benchmark_verify<
    KeyPair_OpenSSL,
    PublicKey_OpenSSL,
    CurveID::SECP256R1,
    1024>;
  PICOBENCH(verify_256r1_ossl_1k).PICO_SUFFIX(CurveID::SECP256R1);

  auto verify_256r1_mbed_100k = benchmark_verify<
    KeyPair_mbedTLS,
    PublicKey_mbedTLS,
    CurveID::SECP256R1,
    102400>;
  PICOBENCH(verify_256r1_mbed_100k).PICO_SUFFIX(CurveID::SECP256R1);
  auto verify_256r1_ossl_100k = benchmark_verify<
    KeyPair_OpenSSL,
    PublicKey_OpenSSL,
    CurveID::SECP256R1,
    102400>;
  PICOBENCH(verify_256r1_ossl_100k).PICO_SUFFIX(CurveID::SECP256R1);
}

PICOBENCH_SUITE("hash");
namespace Hashes
{
  auto sha_384_mbed_1byte = benchmark_hash<MBedHashProvider, MDType::SHA384, 1>;
  PICOBENCH(sha_384_mbed_1byte).PICO_HASH_SUFFIX().baseline();
  auto sha_256_mbed_1byte = benchmark_hash<MBedHashProvider, MDType::SHA256, 1>;
  PICOBENCH(sha_256_mbed_1byte).PICO_HASH_SUFFIX();
  auto sha_512_mbed_1byte = benchmark_hash<MBedHashProvider, MDType::SHA512, 1>;
  PICOBENCH(sha_512_mbed_1byte).PICO_HASH_SUFFIX();

  auto sha_384_ossl_1byte =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA384, 1>;
  PICOBENCH(sha_384_ossl_1byte).PICO_HASH_SUFFIX();
  auto sha_256_ossl_1byte =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA256, 1>;
  PICOBENCH(sha_256_ossl_1byte).PICO_HASH_SUFFIX();
  auto sha_512_ossl_1byte =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA512, 1>;
  PICOBENCH(sha_512_ossl_1byte).PICO_HASH_SUFFIX();

  auto sha_256_bitc_1byte =
    benchmark_hash<BitcoinHashProvider, MDType::SHA256, 1>;
  PICOBENCH(sha_256_bitc_1byte).PICO_HASH_SUFFIX();

  auto sha_384_mbed_1k = benchmark_hash<MBedHashProvider, MDType::SHA384, 1024>;
  PICOBENCH(sha_384_mbed_1k).PICO_HASH_SUFFIX();
  auto sha_256_mbed_1k = benchmark_hash<MBedHashProvider, MDType::SHA256, 1024>;
  PICOBENCH(sha_256_mbed_1k).PICO_HASH_SUFFIX();
  auto sha_512_mbed_1k = benchmark_hash<MBedHashProvider, MDType::SHA512, 1024>;
  PICOBENCH(sha_512_mbed_1k).PICO_HASH_SUFFIX();

  auto sha_384_ossl_1k =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA384, 1024>;
  PICOBENCH(sha_384_ossl_1k).PICO_HASH_SUFFIX();
  auto sha_256_ossl_1k =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA256, 1024>;
  PICOBENCH(sha_256_ossl_1k).PICO_HASH_SUFFIX();
  auto sha_512_ossl_1k =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA512, 1024>;
  PICOBENCH(sha_512_ossl_1k).PICO_HASH_SUFFIX();

  auto sha_256_bitc_1k =
    benchmark_hash<BitcoinHashProvider, MDType::SHA256, 1024>;
  PICOBENCH(sha_256_bitc_1k).PICO_HASH_SUFFIX();

  auto sha_384_mbed_100k =
    benchmark_hash<MBedHashProvider, MDType::SHA384, 102400>;
  PICOBENCH(sha_384_mbed_100k).PICO_HASH_SUFFIX();
  auto sha_256_mbed_100k =
    benchmark_hash<MBedHashProvider, MDType::SHA256, 102400>;
  PICOBENCH(sha_256_mbed_100k).PICO_HASH_SUFFIX();
  auto sha_512_mbed_100k =
    benchmark_hash<MBedHashProvider, MDType::SHA512, 102400>;
  PICOBENCH(sha_512_mbed_100k).PICO_HASH_SUFFIX();

  auto sha_384_ossl_100k =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA384, 102400>;
  PICOBENCH(sha_384_ossl_100k).PICO_HASH_SUFFIX();
  auto sha_256_ossl_100k =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA256, 102400>;
  PICOBENCH(sha_256_ossl_100k).PICO_HASH_SUFFIX();
  auto sha_512_ossl_100k =
    benchmark_hash<OpenSSLHashProvider, MDType::SHA512, 102400>;
  PICOBENCH(sha_512_ossl_100k).PICO_HASH_SUFFIX();

  auto sha_256_bitc_100k =
    benchmark_hash<BitcoinHashProvider, MDType::SHA256, 102400>;
  PICOBENCH(sha_256_bitc_100k).PICO_HASH_SUFFIX();

}