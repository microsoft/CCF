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

#define PICOBENCH_IMPLEMENT_WITH_MAIN
#include <picobench/picobench.hpp>

using namespace std;
using namespace crypto;

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
    crypto::create_entropy()->random(crypto::GCM_DEFAULT_KEY_SIZE);

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    HashBytes hash = crypto::hmac(M, key, contents);
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

const std::vector<int> sizes = {10};

#define PICO_SUFFIX(CURVE) iterations(sizes).samples(10)

#define PICO_HASH_SUFFIX() iterations(sizes).samples(10)

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

PICOBENCH_SUITE("sign secp256k1");
namespace SIGN_SECP256K1
{
  auto sign_256k1_ossl_1byte =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP256K1, 1>;
  PICOBENCH(sign_256k1_ossl_1byte).PICO_SUFFIX(CurveID::SECP256K1);

  auto sign_256k1_ossl_1k =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP256K1, 1024>;
  PICOBENCH(sign_256k1_ossl_1k).PICO_SUFFIX(CurveID::SECP256K1);

  auto sign_256k1_ossl_100k =
    benchmark_sign<KeyPair_OpenSSL, CurveID::SECP256K1, 102400>;
  PICOBENCH(sign_256k1_ossl_100k).PICO_SUFFIX(CurveID::SECP256K1);
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

PICOBENCH_SUITE("verify secp256k1");
namespace SECP256K1
{
  auto verify_256k1_ossl_1byte =
    benchmark_verify<KeyPair_OpenSSL, PublicKey_OpenSSL, CurveID::SECP256K1, 1>;
  PICOBENCH(verify_256k1_ossl_1byte).PICO_SUFFIX(CurveID::SECP256K1);

  auto verify_256k1_ossl_1k = benchmark_verify<
    KeyPair_OpenSSL,
    PublicKey_OpenSSL,
    CurveID::SECP256K1,
    1024>;
  PICOBENCH(verify_256k1_ossl_1k).PICO_SUFFIX(CurveID::SECP256K1);

  auto verify_256k1_ossl_100k = benchmark_verify<
    KeyPair_OpenSSL,
    PublicKey_OpenSSL,
    CurveID::SECP256K1,
    102400>;
  PICOBENCH(verify_256k1_ossl_100k).PICO_SUFFIX(CurveID::SECP256K1);
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

PICOBENCH_SUITE("digest sha256");
namespace SHA256_bench
{
  template <size_t size>
  static void sha256_bench(picobench::state& s)
  {
    std::vector<uint8_t> v(size);
    for (size_t i = 0; i < size; ++i)
    {
      v[i] = rand();
    }

    crypto::Sha256Hash h;

    s.start_timer();
    for (size_t i = 0; i < 10; ++i)
    {
      crypto::openssl_sha256(v, h.h.data());
    }
    s.stop_timer();
  }

  auto openssl_sha256_base = sha256_bench<2 << 6>;
  PICOBENCH(openssl_sha256_base).PICO_HASH_SUFFIX();

  auto openssl_sha256_8 = sha256_bench<2 << 8>;
  PICOBENCH(openssl_sha256_8).PICO_HASH_SUFFIX();

  auto openssl_sha256_12 = sha256_bench<2 << 12>;
  PICOBENCH(openssl_sha256_12).PICO_HASH_SUFFIX();

  auto openssl_sha256_16 = sha256_bench<2 << 16>;
  PICOBENCH(openssl_sha256_16).PICO_HASH_SUFFIX();

  auto openssl_sha256_18 = sha256_bench<2 << 18>;
  PICOBENCH(openssl_sha256_18).PICO_HASH_SUFFIX();
}

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
        crypto::Base64_openssl::b64_from_raw(v.data(), v.size());
      crypto::Base64_openssl::raw_from_b64(encoded);
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