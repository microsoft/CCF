// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "cose/cose_rs_ffi.h"
#include "crypto/cbor.h"
#include "crypto/cose.h"
#include "crypto/openssl/ec_key_pair.h"

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

static const string bench_kid = "bench-kid";
static const string bench_issuer = "bench-issuer";
static const string bench_subject = "bench-subject";
static const string bench_txid = "2.42";
static const int64_t bench_iat = 1700000000;

struct CoseSign1Components
{
  std::span<const uint8_t> phdr;
  std::optional<std::span<const uint8_t>> payload;
  std::span<const uint8_t> sig;
  int64_t alg;
};

static CoseSign1Components decompose(const std::vector<uint8_t>& envelope)
{
  using namespace ccf::cbor;
  auto cose = parse(envelope);
  const auto& env = cose->tag_at(ccf::cbor::tag::COSE_SIGN_1);
  auto phdr = env->array_at(0)->as_bytes();

  std::optional<std::span<const uint8_t>> payload;
  try
  {
    payload = env->array_at(2)->as_bytes();
  }
  catch (const CBORDecodeError&)
  {
    if (env->array_at(2)->as_simple() != ccf::cbor::SimpleValue::Null)
    {
      throw;
    }
  }

  auto sig = env->array_at(3)->as_bytes();

  auto phdr_parsed = parse({phdr.data(), phdr.size()});
  auto alg =
    phdr_parsed->map_at(ccf::cbor::make_signed(ccf::cose::header::iana::ALG))
      ->as_signed();

  return {phdr, payload, sig, alg};
}

template <CurveID Curve, size_t PayloadSize>
static void benchmark_cose_sign(picobench::state& s)
{
  ECKeyPair_OpenSSL kp(Curve);
  auto priv_der = kp.private_key_der();
  CoseBuffer key_err;
  auto cose_key =
    CoseKey::from_private(priv_der.data(), priv_der.size(), key_err);
  auto payload = make_contents<PayloadSize>();

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    CoseBuffer buf;
    CoseBuffer sign_err;
    cose_sign_ledger(
      cose_key,
      reinterpret_cast<const uint8_t*>(bench_kid.data()),
      bench_kid.size(),
      bench_iat,
      reinterpret_cast<const uint8_t*>(bench_issuer.data()),
      bench_issuer.size(),
      reinterpret_cast<const uint8_t*>(bench_subject.data()),
      bench_subject.size(),
      reinterpret_cast<const uint8_t*>(bench_txid.data()),
      bench_txid.size(),
      payload.data(),
      payload.size(),
      buf,
      sign_err);
    do_not_optimize(buf);
    clobber_memory();
  }
  s.stop_timer();
}

template <CurveID Curve, size_t PayloadSize>
static void benchmark_cose_verify(picobench::state& s)
{
  ECKeyPair_OpenSSL kp(Curve);
  auto priv_der = kp.private_key_der();
  auto pub_der = kp.public_key_der();
  CoseBuffer key_err;
  auto cose_key =
    CoseKey::from_private(priv_der.data(), priv_der.size(), key_err);
  CoseBuffer vkey_err;
  auto verify_key =
    CoseKey::from_public(pub_der.data(), pub_der.size(), vkey_err);
  auto payload = make_contents<PayloadSize>();

  // Sign once outside the timed section.
  CoseBuffer buf;
  CoseBuffer sign_err;
  cose_sign_ledger(
    cose_key,
    reinterpret_cast<const uint8_t*>(bench_kid.data()),
    bench_kid.size(),
    bench_iat,
    reinterpret_cast<const uint8_t*>(bench_issuer.data()),
    bench_issuer.size(),
    reinterpret_cast<const uint8_t*>(bench_subject.data()),
    bench_subject.size(),
    reinterpret_cast<const uint8_t*>(bench_txid.data()),
    bench_txid.size(),
    payload.data(),
    payload.size(),
    buf,
    sign_err);
  auto envelope = buf.to_vector();
  auto c = decompose(envelope);

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    CoseBuffer verify_err;
    auto rc = cose_verify1(
      verify_key,
      c.alg,
      c.phdr.data(),
      c.phdr.size(),
      payload.data(),
      payload.size(),
      c.sig.data(),
      c.sig.size(),
      verify_err);
    do_not_optimize(rc);
    clobber_memory();
  }
  s.stop_timer();
}

const std::vector<int> sizes = {10};

#define PICO_SUFFIX() iterations(sizes)

PICOBENCH_SUITE("cose sign secp256r1");
namespace COSE_SIGN_SECP256R1
{
  auto sign_256r1_1byte = benchmark_cose_sign<CurveID::SECP256R1, 1>;
  PICOBENCH(sign_256r1_1byte).PICO_SUFFIX();

  auto sign_256r1_1k = benchmark_cose_sign<CurveID::SECP256R1, 1024>;
  PICOBENCH(sign_256r1_1k).PICO_SUFFIX();

  auto sign_256r1_100k = benchmark_cose_sign<CurveID::SECP256R1, 102400>;
  PICOBENCH(sign_256r1_100k).PICO_SUFFIX();
}

PICOBENCH_SUITE("cose sign secp384r1");
namespace COSE_SIGN_SECP384R1
{
  auto sign_384r1_1byte = benchmark_cose_sign<CurveID::SECP384R1, 1>;
  PICOBENCH(sign_384r1_1byte).PICO_SUFFIX();

  auto sign_384r1_1k = benchmark_cose_sign<CurveID::SECP384R1, 1024>;
  PICOBENCH(sign_384r1_1k).PICO_SUFFIX();

  auto sign_384r1_100k = benchmark_cose_sign<CurveID::SECP384R1, 102400>;
  PICOBENCH(sign_384r1_100k).PICO_SUFFIX();
}

PICOBENCH_SUITE("cose verify secp256r1");
namespace COSE_VERIFY_SECP256R1
{
  auto verify_256r1_1byte = benchmark_cose_verify<CurveID::SECP256R1, 1>;
  PICOBENCH(verify_256r1_1byte).PICO_SUFFIX();

  auto verify_256r1_1k = benchmark_cose_verify<CurveID::SECP256R1, 1024>;
  PICOBENCH(verify_256r1_1k).PICO_SUFFIX();

  auto verify_256r1_100k = benchmark_cose_verify<CurveID::SECP256R1, 102400>;
  PICOBENCH(verify_256r1_100k).PICO_SUFFIX();
}

PICOBENCH_SUITE("cose verify secp384r1");
namespace COSE_VERIFY_SECP384R1
{
  auto verify_384r1_1byte = benchmark_cose_verify<CurveID::SECP384R1, 1>;
  PICOBENCH(verify_384r1_1byte).PICO_SUFFIX();

  auto verify_384r1_1k = benchmark_cose_verify<CurveID::SECP384R1, 1024>;
  PICOBENCH(verify_384r1_1k).PICO_SUFFIX();

  auto verify_384r1_100k = benchmark_cose_verify<CurveID::SECP384R1, 102400>;
  PICOBENCH(verify_384r1_100k).PICO_SUFFIX();
}
