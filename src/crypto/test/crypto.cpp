// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ccf/crypto/base64.h"
#include "ccf/crypto/eddsa_key_pair.h"
#include "ccf/crypto/entropy.h"
#include "ccf/crypto/hmac.h"
#include "ccf/crypto/jwk.h"
#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/key_wrap.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/crypto/symmetric_key.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/json.h"
#include "crypto/certs.h"
#include "crypto/csr.h"
#include "crypto/openssl/key_pair.h"
#include "crypto/openssl/rsa_key_pair.h"
#include "crypto/openssl/symmetric_key.h"
#include "crypto/openssl/verifier.h"
#include "crypto/openssl/x509_time.h"
#include "ds/x509_time_fmt.h"
#include "node/uvm_endorsements.h" // TODO: Move elsewhere?

#include <chrono>
#include <cstring>
#include <ctime>
#include <didx509cpp/didx509cpp.h>
#include <doctest/doctest.h>
#include <optional>
#include <span>

using namespace std;
using namespace crypto;

static const string contents_ =
  "Lorem ipsum dolor sit amet, consectetur adipiscing "
  "elit, sed do eiusmod tempor incididunt ut labore et"
  " dolore magna aliqua. Ut enim ad minim veniam, quis"
  " nostrud exercitation ullamco laboris nisi ut "
  "aliquip ex ea commodo consequat. Duis aute irure "
  "dolor in reprehenderit in voluptate velit esse "
  "cillum dolore eu fugiat nulla pariatur. Excepteur "
  "sint occaecat cupidatat non proident, sunt in culpa "
  "qui officia deserunt mollit anim id est laborum.";

vector<uint8_t> contents(contents_.begin(), contents_.end());

template <typename T>
void corrupt(T& buf)
{
  buf[1]++;
  buf[buf.size() / 2]++;
  buf[buf.size() - 2]++;
}

static constexpr CurveID supported_curves[] = {
  CurveID::SECP384R1, CurveID::SECP256R1, CurveID::SECP256K1};

static constexpr char const* labels[] = {"secp384r1", "secp256r1", "secp256k1"};

crypto::Pem generate_self_signed_cert(
  const KeyPairPtr& kp, const std::string& name)
{
  constexpr size_t certificate_validity_period_days = 365;
  using namespace std::literals;
  auto valid_from =
    ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);

  return crypto::create_self_signed_cert(
    kp, name, {}, valid_from, certificate_validity_period_days);
}

TEST_CASE("Sign, verify, with KeyPair")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp->sign(contents);
    CHECK(kp->verify(contents, signature));

    auto kp2 = make_key_pair(kp->private_key_pem());
    CHECK(kp2->verify(contents, signature));

    // Signatures won't necessarily be identical due to entropy, but should be
    // mutually verifiable
    for (auto i = 0; i < 10; ++i)
    {
      const auto new_sig = kp2->sign(contents);
      CHECK(kp->verify(contents, new_sig));
      CHECK(kp2->verify(contents, new_sig));
    }
  }
}

TEST_CASE("Sign, verify, with PublicKey")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp->sign(contents);

    const auto public_key = kp->public_key_pem();
    auto pubk = make_public_key(public_key);
    CHECK(pubk->verify(contents, signature));
  }
}

TEST_CASE("Sign, fail to verify with bad signature")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    vector<uint8_t> signature = kp->sign(contents);

    const auto public_key = kp->public_key_pem();
    auto pubk = make_public_key(public_key);
    corrupt(signature);
    CHECK_FALSE(pubk->verify(contents, signature));
  }
}

TEST_CASE("Sign, fail to verify with bad contents")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    vector<uint8_t> signature = kp->sign(contents);

    const auto public_key = kp->public_key_pem();
    auto pubk = make_public_key(public_key);
    corrupt(contents);
    CHECK_FALSE(pubk->verify(contents, signature));
  }
}

TEST_CASE("Sign, fail to verify with wrong key on correct curve")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    vector<uint8_t> signature = kp->sign(contents);

    auto kp2 = make_key_pair(curve);
    const auto public_key = kp2->public_key_pem();
    auto pubk = make_public_key(public_key);
    CHECK_FALSE(pubk->verify(contents, signature));
  }
}

TEST_CASE("Sign, fail to verify with wrong key on wrong curve")
{
  constexpr size_t num_supported_curves =
    static_cast<size_t>(sizeof(supported_curves) / sizeof(CurveID));
  for (auto i = 0; i < num_supported_curves; ++i)
  {
    const auto curve = supported_curves[i];
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    vector<uint8_t> signature = kp->sign(contents);

    const auto wrong_curve = supported_curves[(i + 1) % num_supported_curves];
    auto kp2 = make_key_pair(wrong_curve);
    const auto public_key = kp2->public_key_pem();
    auto pubk = make_public_key(public_key);
    CHECK_FALSE(pubk->verify(contents, signature));
  }
}

template <typename T, typename S, CurveID CID>
void run_alt()
{
  T kp1(CID);
  vector<uint8_t> contents(contents_.begin(), contents_.end());
  vector<uint8_t> signature = kp1.sign(contents);

  S kp2(kp1.public_key_pem());
  CHECK(kp2.verify(contents, signature));
}

TEST_CASE("Sign, verify with certificate")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp->sign(contents);

    auto cert = generate_self_signed_cert(kp, "CN=name");
    auto verifier = make_verifier(cert);
    CHECK(verifier->verify(contents, signature));
  }
}

TEST_CASE("Sign, verify. Fail to verify with bad contents")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    const vector<uint8_t> signature = kp->sign(contents);

    auto cert = generate_self_signed_cert(kp, "CN=name");
    auto verifier = make_verifier(cert);
    CHECK(verifier->verify(contents, signature));
    corrupt(contents);
    CHECK_FALSE(verifier->verify(contents, signature));
  }
}

crypto::HashBytes bad_manual_hash(const std::vector<uint8_t>& data)
{
  // secp256r1 requires 32-byte hashes, other curves don't care. So use 32 for
  // general hasher
  constexpr auto n = 32;
  crypto::HashBytes hash(n);

  for (size_t i = 0; i < data.size(); ++i)
  {
    hash[i % n] ^= data[i];
  }

  return hash;
}

TEST_CASE("Manually hash, sign, verify, with PublicKey")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    crypto::HashBytes hash = bad_manual_hash(contents);
    const vector<uint8_t> signature = kp->sign_hash(hash.data(), hash.size());

    const auto public_key = kp->public_key_pem();
    auto pubk = make_public_key(public_key);
    CHECK(pubk->verify_hash(hash, signature, MDType::SHA256));
    corrupt(hash);
    CHECK_FALSE(pubk->verify_hash(hash, signature, MDType::SHA256));
  }
}

TEST_CASE("Manually hash, sign, verify, with certificate")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    vector<uint8_t> contents(contents_.begin(), contents_.end());
    crypto::HashBytes hash = bad_manual_hash(contents);
    const vector<uint8_t> signature = kp->sign_hash(hash.data(), hash.size());

    auto cert = generate_self_signed_cert(kp, "CN=name");
    auto verifier = make_verifier(cert);
    CHECK(verifier->verify_hash(hash, signature));
    corrupt(hash);
    CHECK_FALSE(verifier->verify(hash, signature));
  }
}

TEST_CASE("Sign, verify, with KeyPair of EdDSA")
{
  constexpr auto curve = "curve25519";
  constexpr auto curve_id = CurveID::CURVE25519;
  INFO("With curve: " << curve);
  auto kp = make_eddsa_key_pair(curve_id);
  vector<uint8_t> contents(contents_.begin(), contents_.end());
  const vector<uint8_t> signature = kp->sign(contents);
  CHECK(kp->verify(contents, signature));
}

TEST_CASE("Sign, verify, with PublicKey of EdDSA")
{
  constexpr auto curve = "curve25519";
  constexpr auto curve_id = CurveID::CURVE25519;
  INFO("With curve: " << curve);
  auto kp = make_eddsa_key_pair(curve_id);
  vector<uint8_t> contents(contents_.begin(), contents_.end());
  const vector<uint8_t> signature = kp->sign(contents);

  const auto public_key = kp->public_key_pem();
  auto pubk = make_eddsa_public_key(public_key);
  CHECK(pubk->verify(contents, signature));
}

TEST_CASE("Sign, fail to verify with bad signature (EdDSA)")
{
  constexpr auto curve = "curve25519";
  constexpr auto curve_id = CurveID::CURVE25519;
  INFO("With curve: " << curve);
  auto kp = make_eddsa_key_pair(curve_id);
  vector<uint8_t> contents(contents_.begin(), contents_.end());
  vector<uint8_t> signature = kp->sign(contents);

  const auto public_key = kp->public_key_pem();
  auto pubk = make_eddsa_public_key(public_key);
  corrupt(signature);
  CHECK_FALSE(pubk->verify(contents, signature));
}

TEST_CASE("Sign, fail to verify with bad contents (EdDSA)")
{
  constexpr auto curve = "curve25519";
  constexpr auto curve_id = CurveID::CURVE25519;
  INFO("With curve: " << curve);
  auto kp = make_eddsa_key_pair(curve_id);
  vector<uint8_t> contents(contents_.begin(), contents_.end());
  vector<uint8_t> signature = kp->sign(contents);

  const auto public_key = kp->public_key_pem();
  auto pubk = make_eddsa_public_key(public_key);
  corrupt(contents);
  CHECK_FALSE(pubk->verify(contents, signature));
}

TEST_CASE("Sign, fail to verify with wrong key on correct curve (EdDSA)")
{
  constexpr auto curve = "curve25519";
  constexpr auto curve_id = CurveID::CURVE25519;
  INFO("With curve: " << curve);
  auto kp = make_eddsa_key_pair(curve_id);
  vector<uint8_t> contents(contents_.begin(), contents_.end());
  vector<uint8_t> signature = kp->sign(contents);

  auto kp2 = make_eddsa_key_pair(curve_id);
  const auto public_key = kp2->public_key_pem();
  auto pubk = make_eddsa_public_key(public_key);
  CHECK_FALSE(pubk->verify(contents, signature));
}

TEST_CASE("base64")
{
  for (size_t length = 1; length < 20; ++length)
  {
    std::vector<uint8_t> raw(length);
    std::generate(raw.begin(), raw.end(), rand);

    const auto encoded = b64_from_raw(raw.data(), raw.size());
    const auto decoded = raw_from_b64(encoded);
    REQUIRE(decoded == raw);
  }
}

TEST_CASE("base64url")
{
  for (size_t length = 1; length < 20; ++length)
  {
    std::vector<uint8_t> raw(length);
    std::generate(raw.begin(), raw.end(), rand);

    auto encoded = b64_from_raw(raw.data(), raw.size());
    std::replace(encoded.begin(), encoded.end(), '+', '-');
    std::replace(encoded.begin(), encoded.end(), '/', '_');
    encoded.erase(
      std::find(encoded.begin(), encoded.end(), '='), encoded.end());
    const auto decoded = raw_from_b64url(encoded);
    REQUIRE(decoded == raw);
  }
}

TEST_CASE("Wrap, unwrap with RSAKeyPair")
{
  size_t input_len = 64;
  std::vector<uint8_t> input = create_entropy()->random(input_len);

  INFO("Cannot make RSA key from EC key");
  {
    for (const auto curve : supported_curves)
    {
      auto rsa_kp = make_key_pair(curve); // EC Key

      REQUIRE_THROWS_AS(
        make_rsa_public_key(rsa_kp->public_key_pem()), std::logic_error);
    }
  }

  INFO("Without label");
  {
    auto rsa_kp = make_rsa_key_pair();
    auto rsa_pub = make_rsa_public_key(rsa_kp->public_key_pem());

    // Public key can wrap
    auto wrapped = rsa_pub->rsa_oaep_wrap(input);

    // Only private key can unwrap
    auto unwrapped = rsa_kp->rsa_oaep_unwrap(wrapped);
    // rsa_pub->unwrap(wrapped); // Doesn't compile
    REQUIRE(input == unwrapped);

    // Raw data
    wrapped = rsa_pub->rsa_oaep_wrap(input.data(), input.size());
    unwrapped = rsa_kp->rsa_oaep_unwrap(wrapped);
    REQUIRE(input == unwrapped);
  }

  INFO("With label");
  {
    auto rsa_kp = make_rsa_key_pair();
    auto rsa_pub = make_rsa_public_key(rsa_kp->public_key_pem());
    std::string lblstr = "my_label";
    std::vector<uint8_t> label(lblstr.begin(), lblstr.end());
    auto wrapped = rsa_pub->rsa_oaep_wrap(input, label);
    auto unwrapped = rsa_kp->rsa_oaep_unwrap(wrapped, label);
    REQUIRE(input == unwrapped);
  }
}

TEST_CASE("Extract public key from cert")
{
  for (const auto curve : supported_curves)
  {
    INFO("With curve: " << labels[static_cast<size_t>(curve) - 1]);
    auto kp = make_key_pair(curve);
    auto pk = kp->public_key_der();
    auto cert = generate_self_signed_cert(kp, "CN=name");
    auto cert_der = make_verifier(cert.raw())->cert_der();
    auto pubk = public_key_der_from_cert(cert_der);
    REQUIRE(pk == pubk);
  }
}

template <typename T>
void create_csr_and_extract_pubk()
{
  T kp(CurveID::SECP384R1);
  auto pk = kp.public_key_pem();
  auto csr = kp.create_csr("CN=name", {});
  auto pubk = public_key_pem_from_csr(csr);
  REQUIRE(pk == pubk);
}

TEST_CASE("Extract public key from csr")
{
  create_csr_and_extract_pubk<KeyPair_OpenSSL>();
}

template <typename T, typename S>
void run_csr(bool corrupt_csr = false)
{
  T kpm(CurveID::SECP384R1);

  const char* subject_name = "CN=myname";
  std::string valid_from, valid_to;

  std::vector<SubjectAltName> subject_alternative_names;

  subject_alternative_names.push_back({"email:my-other-name", false});
  subject_alternative_names.push_back({"www.microsoft.com", false});
  subject_alternative_names.push_back({"192.168.0.1", true});
  valid_from = "20210311000000Z";
  valid_to = "20230611235959Z";

  auto csr = kpm.create_csr(subject_name, subject_alternative_names);

  if (corrupt_csr)
  {
    constexpr size_t corrupt_byte_pos_from_end = 66;
    auto& corrupt_byte = csr.data()[csr.size() - corrupt_byte_pos_from_end];
    corrupt_byte++;
  }

  auto icrt = kpm.self_sign("CN=issuer", valid_from, valid_to);

  if (corrupt_csr)
  {
    REQUIRE_THROWS(kpm.sign_csr(icrt, csr, valid_from, valid_to));
    return;
  }

  auto crt = kpm.sign_csr(icrt, csr, valid_from, valid_to);
  std::vector<uint8_t> content = {0, 1, 2, 3, 4};
  auto signature = kpm.sign(content);

  S v(crt.raw());
  REQUIRE(v.verify(content, signature));

  std::string valid_from_, valid_to_;
  std::tie(valid_from_, valid_to_) = v.validity_period();
  REQUIRE(valid_from_.find(valid_from) != std::string::npos);
  REQUIRE(valid_to_.find(valid_to) != std::string::npos);
}

TEST_CASE("2-digit years")
{
  auto time_str = "220405175422Z";
  auto tp = ds::time_point_from_string(time_str);
  auto conv = ds::to_x509_time_string(tp);
  REQUIRE(conv == std::string("20") + time_str);
}

TEST_CASE("Non-ASN.1 timepoint formats")
{
  auto time_str = "2022-04-05 18:53:27";
  auto tp = ds::time_point_from_string(time_str);
  auto conv = ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220405185327Z");

  time_str = "2022-04-05 18:53:27.190380";
  tp = ds::time_point_from_string(time_str);
  conv = ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220405185327Z");

  time_str = "2022-04-05 18:53:27 +03:00";
  tp = ds::time_point_from_string(time_str);
  conv = ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220405155327Z");

  time_str = "2022-04-05 18:53:27 +0300";
  tp = ds::time_point_from_string(time_str);
  conv = ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220405155327Z");

  time_str = "2022-04-05 18:53:27.190380+03:00";
  tp = ds::time_point_from_string(time_str);
  conv = ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220405155327Z");

  time_str = "2022-04-05 18:53:27 -03:00";
  tp = ds::time_point_from_string(time_str);
  conv = ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220405215327Z");

  time_str = "2022-04-07T10:37:49.567612";
  tp = ds::time_point_from_string(time_str);
  conv = ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220407103749Z");

  time_str = "2022-04-07T10:37:49.567612+03:00";
  tp = ds::time_point_from_string(time_str);
  conv = ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220407073749Z");

  time_str = "2022-04-07T10:37:49.567612Z";
  tp = ds::time_point_from_string(time_str);
  conv = ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220407103749Z");

  time_str = "220425165619+0000";
  tp = ds::time_point_from_string(time_str);
  conv = ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220425165619Z");

  time_str = "220425165619+0200";
  tp = ds::time_point_from_string(time_str);
  conv = ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220425145619Z");

  time_str = "20220425165619-0300";
  tp = ds::time_point_from_string(time_str);
  conv = ds::to_x509_time_string(tp);
  REQUIRE(conv == "20220425195619Z");
}

TEST_CASE("Create sign and verify certificates")
{
  bool corrupt_csr = false;
  do
  {
    run_csr<KeyPair_OpenSSL, Verifier_OpenSSL>(corrupt_csr);
    corrupt_csr = !corrupt_csr;
  } while (corrupt_csr);
}

static const vector<uint8_t>& get_raw_key()
{
  static const vector<uint8_t> v(16, '$');
  return v;
}

TEST_CASE("ExtendedIv0")
{
  auto k = crypto::make_key_aes_gcm(get_raw_key());

  // setup plain text
  std::vector<uint8_t> plain(100);
  std::iota(plain.begin(), plain.end(), 0);

  // test large IV
  using LargeIVGcmHeader = FixedSizeGcmHeader<1234>;
  LargeIVGcmHeader h;

  SUBCASE("Null IV") {}

  SUBCASE("Random IV")
  {
    h.set_random_iv();
  }

  std::vector<uint8_t> cipher;
  k->encrypt(h.get_iv(), plain, {}, cipher, h.tag);

  auto k2 = crypto::make_key_aes_gcm(get_raw_key());
  std::vector<uint8_t> decrypted_plain;
  REQUIRE(k2->decrypt(h.get_iv(), h.tag, cipher, {}, decrypted_plain));
  REQUIRE(plain == decrypted_plain);
}

TEST_CASE("AES Key wrap with padding")
{
  auto key = get_raw_key();
  std::vector<uint8_t> aad(123, 'y');

  std::vector<uint8_t> key_to_wrap = create_entropy()->random(997);

  auto ossl = std::make_unique<KeyAesGcm_OpenSSL>(key);

  std::vector<uint8_t> wrapped = ossl->ckm_aes_key_wrap_pad(key_to_wrap);
  std::vector<uint8_t> unwrapped = ossl->ckm_aes_key_unwrap_pad(wrapped);

  REQUIRE(wrapped != unwrapped);
  REQUIRE(key_to_wrap == unwrapped);
}

TEST_CASE("CKM_RSA_PKCS_OAEP")
{
  auto key = get_raw_key();

  auto rsa_kp = make_rsa_key_pair();
  auto rsa_pk = make_rsa_public_key(rsa_kp->public_key_pem());

  auto wrapped = crypto::ckm_rsa_pkcs_oaep_wrap(rsa_pk, key);
  auto wrapped_ = crypto::ckm_rsa_pkcs_oaep_wrap(rsa_pk, key);

  // CKM_RSA_PKCS_OAEP wrap is non deterministic
  REQUIRE(wrapped != wrapped_);

  auto unwrapped = crypto::ckm_rsa_pkcs_oaep_unwrap(rsa_kp, wrapped);
  auto unwrapped_ = crypto::ckm_rsa_pkcs_oaep_unwrap(rsa_kp, wrapped_);

  REQUIRE(unwrapped == unwrapped_);
}

TEST_CASE("CKM_RSA_AES_KEY_WRAP")
{
  std::vector<uint8_t> key_to_wrap = create_entropy()->random(256);

  auto rsa_kp = make_rsa_key_pair();
  auto rsa_pk = make_rsa_public_key(rsa_kp->public_key_pem());

  std::vector<uint8_t> wrapped = ckm_rsa_aes_key_wrap(128, rsa_pk, key_to_wrap);
  std::vector<uint8_t> unwrapped = ckm_rsa_aes_key_unwrap(rsa_kp, wrapped);

  REQUIRE(wrapped != unwrapped);
  REQUIRE(unwrapped == key_to_wrap);
}

TEST_CASE("AES-GCM convenience functions")
{
  EntropyPtr entropy = create_entropy();
  std::vector<uint8_t> key = entropy->random(GCM_DEFAULT_KEY_SIZE);
  auto encrypted = aes_gcm_encrypt(key, contents);
  auto decrypted = aes_gcm_decrypt(key, encrypted);
  REQUIRE(decrypted == contents);
}

TEST_CASE("x509 time")
{
  auto time = std::chrono::system_clock::now();

  auto next_minute_time = time + 1min;
  auto next_day_time = time + 24h;
  auto next_year_time = time + 24h * 365;

  INFO("Chronological time");
  {
    struct TimeTest
    {
      struct Input
      {
        std::chrono::system_clock::time_point from;
        std::chrono::system_clock::time_point to;
        std::optional<uint32_t> maximum_validity_period_days = std::nullopt;
      };
      Input input;

      bool expected_verification_result;
    };

    std::vector<TimeTest> test_vector{
      {{time, next_day_time}, true}, // Valid: Next day
      {{time, time}, false}, // Invalid: Same date
      {{next_day_time, time}, false}, // Invalid: to is before from
      {{time, next_day_time, 100}, true}, // Valid: Next day within 100 days
      {{time, next_year_time, 100},
       false}, // Valid: Next day not within 100 days
      {{time, next_minute_time}, true}, // Valid: Next minute
      {{next_minute_time, time}, false}, // Invalid: to is before from
      {{time, next_minute_time, 1}, true} // Valid: Next min within 1 day
    };

    for (auto& data : test_vector)
    {
      const auto& from = data.input.from;
      const auto& to = data.input.to;
      REQUIRE(
        crypto::OpenSSL::validate_chronological_times(
          crypto::OpenSSL::Unique_X509_TIME(from),
          crypto::OpenSSL::Unique_X509_TIME(to),
          data.input.maximum_validity_period_days) ==
        data.expected_verification_result);
    }
  }

  INFO("Adjust time");
  {
    std::vector<std::chrono::system_clock::time_point> times = {
      time, next_day_time, next_day_time};
    size_t days_offset = 100;

    for (auto& t : times)
    {
      auto adjusted_time = t + std::chrono::days(days_offset);

      auto from = crypto::OpenSSL::Unique_X509_TIME(t);
      auto to = crypto::OpenSSL::Unique_X509_TIME(adjusted_time);

      // Convert to string and back to time_points
      auto from_conv =
        ds::time_point_from_string(crypto::OpenSSL::to_x509_time_string(from));
      auto to_conv =
        ds::time_point_from_string(crypto::OpenSSL::to_x509_time_string(to));

      // Diff is still the same amount of days
      auto days_diff =
        std::chrono::duration_cast<std::chrono::days>(to_conv - from_conv)
          .count();
      REQUIRE(days_diff == days_offset);
    }
  }

  INFO("String to time conversion and back");
  {
    std::vector<size_t> days_offsets = {0, 1, 10, 100, 365, 1000, 10000};

    for (auto const& days_offset : days_offsets)
    {
      auto adjusted_time = time + std::chrono::days(days_offset);
      auto adjusted_str = ds::to_x509_time_string(adjusted_time);
      auto asn1_time = crypto::OpenSSL::Unique_X509_TIME(adjusted_str);
      auto converted_str = crypto::OpenSSL::to_x509_time_string(asn1_time);
      REQUIRE(converted_str == adjusted_str);
    }
  }
}

TEST_CASE("hmac")
{
  std::vector<uint8_t> key(32, 0);
  std::vector<uint8_t> zeros(64, 0);
  std::vector<uint8_t> mostly_zeros(64, 0);
  mostly_zeros[0] = 1;

  INFO("Same inputs, same hmac");
  {
    auto r0 = crypto::hmac(MDType::SHA256, key, zeros);
    auto r1 = crypto::hmac(MDType::SHA256, key, zeros);
    REQUIRE(r0 == r1);
  }

  INFO("Different inputs, different hmacs");
  {
    auto r0 = crypto::hmac(MDType::SHA256, key, zeros);
    auto r1 = crypto::hmac(MDType::SHA256, key, mostly_zeros);
    REQUIRE(r0 != r1);
  }
}

TEST_CASE("PEM to JWK and back")
{
  // More complete tests in end-to-end JS modules test
  // to compare with JWK reference implementation.
  auto kid = "my_kid";

  logger::config::default_init(); // TODO: Remove

  INFO("EC");
  {
    auto kp = make_key_pair();
    auto pubk = make_public_key(kp->public_key_pem());

    INFO("Public");
    {
      auto jwk = pubk->public_key_jwk();
      REQUIRE_FALSE(jwk.kid.has_value());
      jwk = pubk->public_key_jwk(kid);
      REQUIRE(jwk.kid.value() == kid);

      auto pubk2 = make_public_key(jwk);
      auto jwk2 = pubk2->public_key_jwk(kid);
      REQUIRE(jwk == jwk2);
    }

    INFO("Private");
    {
      auto jwk = kp->private_key_jwk();
      REQUIRE_FALSE(jwk.kid.has_value());
      jwk = kp->private_key_jwk(kid);
      REQUIRE(jwk.kid.value() == kid);
    }
  }

  INFO("RSA");
  {
    auto kp = make_rsa_key_pair();
    auto pubk = make_rsa_public_key(kp->public_key_pem());

    INFO("Public");
    {
      auto jwk = pubk->public_key_jwk_rsa();
      REQUIRE_FALSE(jwk.kid.has_value());
      jwk = pubk->public_key_jwk_rsa(kid);
      REQUIRE(jwk.kid.value() == kid);
    }

    INFO("Private");
    {
      auto jwk = kp->private_key_jwk_rsa();
      REQUIRE_FALSE(jwk.kid.has_value());
      jwk = kp->private_key_jwk_rsa(kid);
      REQUIRE(jwk.kid.value() == kid);
    }
  }

  INFO("EdDSA");
  {
    auto kp = make_eddsa_key_pair(CurveID::CURVE25519);
    auto pubk = make_eddsa_public_key(kp->public_key_pem());

    INFO("Public");
    {
      auto jwk = pubk->public_key_jwk_eddsa();
      REQUIRE_FALSE(jwk.kid.has_value());
      jwk = pubk->public_key_jwk_eddsa(kid);
      REQUIRE(jwk.kid.value() == kid);
    }

    INFO("Private");
    {
      auto jwk = kp->private_key_jwk_eddsa();
      REQUIRE_FALSE(jwk.kid.has_value());
      jwk = kp->private_key_jwk_eddsa(kid);
      REQUIRE(jwk.kid.value() == kid);
    }
  }
}

TEST_CASE("UVM endorsements")
{
  logger::config::default_init();

  std::string uvm_endorsements_base64 =
    "0oRZBaOlATgiA3gYYXBwbGljYXRpb24vdW5rbm93bitqc29uGCGDWQGNMIIBiTCCAQ8CFGNUWW"
    "ZMDF/"
    "zgiAw9feLSlqOVx37MAoGCCqGSM49BAMCMC4xLDAqBgNVBAMMI1Rlc3QgSW50ZXJtZWRpYXRlI"
    "ENBIChETyBOT1QgVFJVU1QpMB4XDTIyMTIwOTE2MDIzOVoXDTIzMTIwOTE2MDIzOVowIzEhMB8"
    "GA1UEAwwYVGVzdCBMZWFmIChETyBOT1QgVFJVU1QpMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE2"
    "BnAAQrQ4upciOYtuKb8IqMQ7dARTOgcmlaOwEOFKTO/"
    "v8qfEzsdyAS64SC8ZF8eiQzS0Kdccy0N1XW4tBhWvfG8mrWg+rQgHJC/"
    "v0n2V870zUQd07iVtJGPXmwEkorAMAoGCCqGSM49BAMCA2gAMGUCMGSsVGe3Pz6APHlrNUtNKF"
    "YfZkaBdfri/+Abkl12yrxr//X6qR3l5YPVj0wQJkJvOAIxAP/"
    "XC7GSxWWQyqZVdyEgxSpaehsVOAHOy7DKfpBFgI4yPHzYYdYrCCoPW5bMsHWMD1kBuDCCAbQwg"
    "gE5oAMCAQICFCim3MjBw2nSPDFM0mDcSiQeQJylMAoGCCqGSM49BAMCMCYxJDAiBgNVBAMMG1R"
    "lc3QgUm9vdCBDQSAoRE8gTk9UIFRSVVNUKTAeFw0yMjEyMDkxNjAyMzlaFw0yMzEyMDkxNjAyM"
    "zlaMC4xLDAqBgNVBAMMI1Rlc3QgSW50ZXJtZWRpYXRlIENBIChETyBOT1QgVFJVU1QpMHYwEAY"
    "HKoZIzj0CAQYFK4EEACIDYgAEr4oZG/"
    "5HrZRePTY7xTgr7edy7A1jh0b6MWUGAa10Q6yu41HHzyAiFphWxxUFZFXwo4z1RPcNpEWk+"
    "3SW+"
    "ULzSejUjhGfa7uLc4xLmUhvWTCA5AenzrYMFWZxOuxtPEYsoyAwHjAPBgNVHRMBAf8EBTADAQH"
    "/MAsGA1UdDwQEAwIChDAKBggqhkjOPQQDAgNpADBmAjEA5b4iG1JcEHyy/"
    "NRy1754UKnlrgqLNWqypfWgoqB7Mx/"
    "C1tB5bpllE9gnuBNZjUbbAjEA0nrd2hevqjLt8rI10xHUJQYjmff6EEIXDl1hqItoEpsutHk3L"
    "iimJ+"
    "QDMyoOhKVMWQGuMIIBqjCCATGgAwIBAgIUJqI8qUIlzKTzp6nHBJxOrEHkhYgwCgYIKoZIzj0E"
    "AwIwJjEkMCIGA1UEAwwbVGVzdCBSb290IENBIChETyBOT1QgVFJVU1QpMB4XDTIyMTIwOTE2MD"
    "IzOVoXDTIzMTIwOTE2MDIzOVowJjEkMCIGA1UEAwwbVGVzdCBSb290IENBIChETyBOT1QgVFJV"
    "U1QpMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEZrdSBwqnRvlsWBzzWgjrcc6sW88hanWXio/"
    "F7J9rKRB01KT4+51PqHvpsvgwyAL8hv7pwcEmwHKciEodlYv91KF/"
    "g0WoV5TNfl8rb6044U4Bzyi+h+l/5RumEVEzOiwkoyAwHjAPBgNVHRMBAf8EBTADAQH/"
    "MAsGA1UdDwQEAwIChDAKBggqhkjOPQQDAgNnADBkAjAn8SK0fPrCYVeB9qS3/"
    "8jy5vjdDKcZxo5evX74SPh6c0rfvIx4LmHHQ+zQ62zm/JACMG9DY2FUweWhOOQ/"
    "7DkwujnEpRQhEuUjPmKzu8uc1v2IHr8/"
    "RMO7yfp6dsqjZJlwzmNpc3N4bmRpZDp4NTA5OjA6c2hhMjU2OjByZEU3WjhBeWcxZVVIYTZ6UH"
    "V0ZkprZnQ1LVlfOENJSVptbGl2RWxzYjA6OnN1YmplY3Q6Q046VGVzdCUyMExlYWYlMjAlMjhE"
    "TyUyME5PVCUyMFRSVVNUJTI5ZGZlZWRrTVNSQ1Rlc3RVVk2gWNR7CiAgIngtbXMtbWFhLWFwaS"
    "12ZXJzaW9uIjogIjIwMjItMDEtMDEiLAogICJ4LW1zLXNldnNucHZtLWd1ZXN0c3ZuIjogIjAi"
    "LAogICJ4LW1zLXNldnNucHZtLWxhdW5jaG1lYXN1cmVtZW50IjogIjBkNGY5ZmYwZTU0Mjk5ZT"
    "gxZWE4ZjgzMmE4ZWRlY2U2YzNmNGEzMzQ5MjViZWU3MGU1MmEwNDUzMzJjMzY1MjdlNGYxMDdk"
    "MmM3M2RlMjBjNGRiODNiNzlmMWMwZDczOSIKfVhgNGECj0YibtZKcwXlMjFRDY8jcbynTljRWm"
    "girLdzx4SwGTihDoCWbii7twwNrJPQkVnhhA6KhyF0RF7eD9++5mMjymubPs2PVMkw+"
    "rxRFEuqJqcVW8u4IVeWo8baFe6k";

  auto uvm_endorsements_raw = crypto::raw_from_b64(uvm_endorsements_base64);

  auto phdr = ccf::decode_protected_header(uvm_endorsements_raw);

  LOG_FAIL_FMT(
    "phdr:: alg:{},content type:{},x5chain:{},iss:{},feed:{}",
    phdr.alg,
    phdr.content_type,
    phdr.x5_chain.size(),
    phdr.iss,
    phdr.feed);

  //
  // Verify endorsements of certificates
  //

  if (!ccf::is_ecdsa_alg(phdr.alg))
  {
    throw std::logic_error("Algorithm signature is not valid ECDSA");
  }

  const std::string& did = phdr.iss;

  std::string pem_chain;
  for (auto const& c : phdr.x5_chain)
  {
    pem_chain += crypto::cert_der_to_pem(c).str();
  }

  auto jwk = nlohmann::json::parse(didx509::resolve(pem_chain, did));

  crypto::JsonWebKeyECPublic jwk_ec_pub =
    jwk.at("verificationMethod").at(0).at("publicKeyJwk");

  auto pubk = crypto::make_public_key(jwk_ec_pub);

  auto raw_payload =
    ccf::verify_uvm_endorsements_signature(pubk, uvm_endorsements_raw);

  if (phdr.content_type == ccf::COSE_HEADER_CONTENT_TYPE_VALUE)
  {
    ccf::UVMEndorsementsPayload uvm_endorsements_payload =
      nlohmann::json::parse(raw_payload);

    LOG_FAIL_FMT(
      "Payload, api: {} | guestsnv: {} | launch measurement: {}",
      uvm_endorsements_payload.maa_api_version,
      uvm_endorsements_payload.sevsnpvn_guest_svn,
      uvm_endorsements_payload.sevsnpvm_launch_measurement);
  }

  // TODO: Check guest SVN

  return;
}