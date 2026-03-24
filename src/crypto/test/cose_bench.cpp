// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/cose_verifier.h"
#include "crypto/cbor.h"
#include "crypto/cose.h"
#include "crypto/openssl/cose_sign.h"
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

static ccf::cbor::Value make_protected_headers()
{
  namespace cbor = ccf::cbor;

  std::vector<cbor::MapItem> ccf_headers;
  ccf_headers.emplace_back(
    cbor::make_string(ccf::cose::header::custom::TX_ID),
    cbor::make_string(bench_txid));

  std::vector<cbor::MapItem> cwt_headers;
  cwt_headers.emplace_back(
    cbor::make_signed(ccf::cwt::header::iana::IAT),
    cbor::make_signed(bench_iat));
  cwt_headers.emplace_back(
    cbor::make_signed(ccf::cwt::header::iana::ISS),
    cbor::make_string(bench_issuer));
  cwt_headers.emplace_back(
    cbor::make_signed(ccf::cwt::header::iana::SUB),
    cbor::make_string(bench_subject));

  std::vector<cbor::MapItem> phdr;
  phdr.emplace_back(
    cbor::make_signed(ccf::cose::header::iana::KID),
    cbor::make_bytes(std::span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(bench_kid.data()),
      bench_kid.size())));
  phdr.emplace_back(
    cbor::make_signed(ccf::cose::header::iana::VDS),
    cbor::make_signed(ccf::cose::value::CCF_LEDGER_SHA256));
  phdr.emplace_back(
    cbor::make_signed(ccf::cose::header::iana::CWT_CLAIMS),
    cbor::make_map(std::move(cwt_headers)));
  phdr.emplace_back(
    cbor::make_string(ccf::cose::header::custom::CCF_V1),
    cbor::make_map(std::move(ccf_headers)));

  return cbor::make_map(std::move(phdr));
}

template <CurveID Curve, size_t PayloadSize>
static void benchmark_cose_sign(picobench::state& s)
{
  ECKeyPair_OpenSSL kp(Curve);
  auto payload = make_contents<PayloadSize>();

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    auto phdr = make_protected_headers();
    auto envelope = cose_sign1(kp, phdr, payload);
    do_not_optimize(envelope);
    clobber_memory();
  }
  s.stop_timer();
}

template <CurveID Curve, size_t PayloadSize>
static void benchmark_cose_verify(picobench::state& s)
{
  ECKeyPair_OpenSSL kp(Curve);
  auto payload = make_contents<PayloadSize>();

  auto phdr = make_protected_headers();
  auto envelope = cose_sign1(kp, phdr, payload);
  auto verifier = make_cose_verifier_from_key(kp.public_key_pem());

  s.start_timer();
  for (auto _ : s)
  {
    (void)_;
    auto ok = verifier->verify_detached(envelope, payload);
    do_not_optimize(ok);
    clobber_memory();
  }
  s.stop_timer();
}

const std::vector<int> sizes = {10};

#define PICO_SUFFIX() iterations(sizes)

PICOBENCH_SUITE("cose sign secp256r1");
namespace COSE_SIGN_SECP256R1
{
  auto sign_256r1_1byte =
    benchmark_cose_sign<CurveID::SECP256R1, 1>;
  PICOBENCH(sign_256r1_1byte).PICO_SUFFIX();

  auto sign_256r1_1k =
    benchmark_cose_sign<CurveID::SECP256R1, 1024>;
  PICOBENCH(sign_256r1_1k).PICO_SUFFIX();

  auto sign_256r1_100k =
    benchmark_cose_sign<CurveID::SECP256R1, 102400>;
  PICOBENCH(sign_256r1_100k).PICO_SUFFIX();
}

PICOBENCH_SUITE("cose sign secp384r1");
namespace COSE_SIGN_SECP384R1
{
  auto sign_384r1_1byte =
    benchmark_cose_sign<CurveID::SECP384R1, 1>;
  PICOBENCH(sign_384r1_1byte).PICO_SUFFIX();

  auto sign_384r1_1k =
    benchmark_cose_sign<CurveID::SECP384R1, 1024>;
  PICOBENCH(sign_384r1_1k).PICO_SUFFIX();

  auto sign_384r1_100k =
    benchmark_cose_sign<CurveID::SECP384R1, 102400>;
  PICOBENCH(sign_384r1_100k).PICO_SUFFIX();
}

PICOBENCH_SUITE("cose verify secp256r1");
namespace COSE_VERIFY_SECP256R1
{
  auto verify_256r1_1byte =
    benchmark_cose_verify<CurveID::SECP256R1, 1>;
  PICOBENCH(verify_256r1_1byte).PICO_SUFFIX();

  auto verify_256r1_1k =
    benchmark_cose_verify<CurveID::SECP256R1, 1024>;
  PICOBENCH(verify_256r1_1k).PICO_SUFFIX();

  auto verify_256r1_100k =
    benchmark_cose_verify<CurveID::SECP256R1, 102400>;
  PICOBENCH(verify_256r1_100k).PICO_SUFFIX();
}

PICOBENCH_SUITE("cose verify secp384r1");
namespace COSE_VERIFY_SECP384R1
{
  auto verify_384r1_1byte =
    benchmark_cose_verify<CurveID::SECP384R1, 1>;
  PICOBENCH(verify_384r1_1byte).PICO_SUFFIX();

  auto verify_384r1_1k =
    benchmark_cose_verify<CurveID::SECP384R1, 1024>;
  PICOBENCH(verify_384r1_1k).PICO_SUFFIX();

  auto verify_384r1_100k =
    benchmark_cose_verify<CurveID::SECP384R1, 102400>;
  PICOBENCH(verify_384r1_100k).PICO_SUFFIX();
}
