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
    auto curves = {CurveID::SECP384R1, CurveID::SECP256R1, CurveID::SECP256K1};

    for (auto const& curve : curves)
    {
      auto kp = make_key_pair(curve);
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

        auto kp2 = make_key_pair(jwk);
        auto jwk2 = kp2->private_key_jwk(kid);
        REQUIRE(jwk == jwk2);
      }
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

      auto pubk2 = make_rsa_public_key(jwk);
      auto jwk2 = pubk2->public_key_jwk_rsa(kid);
      REQUIRE(jwk == jwk2);
    }

    INFO("Private");
    {
      auto jwk = kp->private_key_jwk_rsa();
      REQUIRE_FALSE(jwk.kid.has_value());
      jwk = kp->private_key_jwk_rsa(kid);
      REQUIRE(jwk.kid.value() == kid);

      auto kp2 = make_rsa_key_pair(jwk);
      auto jwk2 = kp2->private_key_jwk_rsa(kid);
      REQUIRE(jwk == jwk2);
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

      auto pubk2 = make_eddsa_public_key(jwk);
      auto jwk2 = pubk2->public_key_jwk_eddsa(kid);
      REQUIRE(jwk == jwk2);
    }

    INFO("Private");
    {
      auto jwk = kp->private_key_jwk_eddsa();
      REQUIRE_FALSE(jwk.kid.has_value());
      jwk = kp->private_key_jwk_eddsa(kid);
      REQUIRE(jwk.kid.value() == kid);

      auto kp2 = make_eddsa_key_pair(jwk);
      auto jwk2 = kp2->private_key_jwk_eddsa(kid);
      REQUIRE(jwk == jwk2);
    }
  }
}

TEST_CASE("UVM endorsements")
{
  logger::config::default_init();

  std::string uvm_endorsements_base64 =
    "0oRZEpKnATglA3BhcHBsaWNhdGlvbi9qc29uGCGDWQUKMIIFBjCCA+"
    "6gAwIBAgITMwAABTjoxwoo2TfErAABAAAFODANBgkqhkiG9w0BAQsFADB5MQswCQYDVQQGEwJV"
    "UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm"
    "9zb2Z0IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgVGVzdGluZyBQQ0EgMjAxMDAe"
    "Fw0yMjA1MDUyMDA4MDBaFw0yMzA1MDQyMDA4MDBaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEw"
    "pXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y"
    "YXRpb24xJjAkBgNVBAMTHUNvZGUgU2lnbiBUZXN0IChETyBOT1QgVFJVU1QpMIIBIjANBgkqhk"
    "iG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsL/"
    "j4nCbQ7qI3NQ3v8PRLi0NFz3jZFWqh2IMsydN3isjQ/"
    "5KfRrfNVyYMyq4kL+OkB0uvI1hzlkqBHT8P+iBAM9ab+49vF7u+"
    "FuqVh1XEoDVzvY6uilt6ZSyCy+sKqoDIbiSAys89RSkg84aDwfCdy2T9Npg1Xkp2HrQP1C+"
    "xsOEQpNF8ETfbYG7s1gg5CHEGbOczFWnc4lcKZHXxTWs7hwRT/"
    "C4NytgGBJu1KaaJrLlgbSldNcz9jIp8NBjoN6aMyxa0UQdM79OyyCdPfvhIVMZxW1e0zYetXJf"
    "Imj2qaZ3DpS/9psduI9mE9dxclhI9vRczi/"
    "svuPWUyIkgFUZRwIDAQABo4IBgjCCAX4wEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEF"
    "GpB4gYFDuRtsXqVoIQ6G9tQa1i8MFAGA1UdEQRJMEekRTBDMSkwJwYDVQQLEyBNaWNyb3NvZnQ"
    "gT3BlcmF0aW9ucyBQdWVydG8gUmljbzEWMBQGA1UEBRMNMjMwMDcyKzQ3MDA0NTAfBgNVHSMEG"
    "DAWgBS/"
    "ZaKrb3WjTkWWVwXPOYf0wBUcHDBcBgNVHR8EVTBTMFGgT6BNhktodHRwOi8vd3d3Lm1pY3Jvc2"
    "9mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUZXN0aW5nJTIwUENBJTIwMjAxMCgxKS5j"
    "cmwwaQYIKwYBBQUHAQEEXTBbMFkGCCsGAQUFBzAChk1odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb2"
    "0vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRlc3RpbmclMjBQQ0ElMjAyMDEwKDEpLmNydDAM"
    "BgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCL4T5rGcIhWRICRf7aN4csict/"
    "MSvjO7oDRErfgtlPnvYMoJdMPKHfnH0u9A7bGSluArwffexJhyxnch2sexqqZJTqPAEogQiL5x"
    "OncQuWKcZQySnkHgM/v/"
    "aa1c9NI4iJ+"
    "32BS9lZTwEmxDReEYZnuEz6picExZAnkmi2u3RvbkiMspq2IjhLDeOhVStlmVy5LY4aK/3R/"
    "yFcMd+KGzina2OgLjmQusBmhTS/"
    "y5jH1l3oq4ABEVQMgw7RVxaf9IuVVKUvwRv2uRJbIJXCogdWwkcZTz1VS3yV+"
    "bck3vyR8JbxhqcxiqUXjpp/"
    "GkcwEeoLn4fx9qSNmbmpSldRVtx0WQaXMIIGkzCCBHugAwIBAgITMwAAAC01ekaIyQdx2AAAAA"
    "AALTANBgkqhkiG9w0BAQsFADCBkDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x"
    "EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE6MDgGA1"
    "UEAxMxTWljcm9zb2Z0IFRlc3RpbmcgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAe"
    "Fw0yMDEyMTAyMDQzMjBaFw0zNTA2MTcyMTA0MTFaMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEw"
    "pXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y"
    "YXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBUZXN0aW5nIFBDQSAyMDEwMIIBIjANBgkqhkiG9w"
    "0BAQEFAAOCAQ8AMIIBCgKCAQEAvzxggau+7P/"
    "XF2PypkLRE2KcsBfOukYaeyIuVXOaVLnG1NHKmP53Rw2OnfBezPhU7/"
    "LPKtRi8ak0CgTXxQWG8hD1TdOWCGaF2wJ9GNzieiOnmildrnkYzwxj8Br/"
    "gampQz+pC7lR8bNIOvxELl8RxVY6/"
    "8oOzYgIwf3H1fU+7+pOG3KLI71FN54fcMGnybggc+3zbD2LIQXPdxL+"
    "odwH6Q1beAlsMlUQR9A3yMf3+nP+"
    "RjTkVhaoN2RT1jX7w4C2jraGkaEQ1sFK9uN61BEKst4unhCX4IGuEl2IAV3MpMQoUpxg8ArmiK"
    "9L6VeK7KMPNx4p9l0h09faXQ7JTtuNbQIDAQABo4IB+jCCAfYwDgYDVR0PAQH/"
    "BAQDAgGGMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFOqfXzO20F+"
    "erestpsECu0A4y+e1MB0GA1UdDgQWBBS/"
    "ZaKrb3WjTkWWVwXPOYf0wBUcHDBUBgNVHSAETTBLMEkGBFUdIAAwQTA/"
    "BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaX"
    "RvcnkuaHRtMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMA8GA1UdEwEB/"
    "wQFMAMBAf8wHwYDVR0jBBgwFoAUowEEfjCIM+u5MZzK64V2Z/"
    "xltNEwWQYDVR0fBFIwUDBOoEygSoZIaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv"
    "cHJvZHVjdHMvTWljVGVzUm9vQ2VyQXV0XzIwMTAtMDYtMTcuY3JsMIGNBggrBgEFBQcBAQSBgD"
    "B+"
    "ME0GCCsGAQUFBzAChkFodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Rlc1"
    "Jvb0NlckF1dF8yMDEwLTA2LTE3LmNydDAtBggrBgEFBQcwAYYhaHR0cDovL29uZW9jc3AubWlj"
    "cm9zb2Z0LmNvbS9vY3NwMA0GCSqGSIb3DQEBCwUAA4ICAQAntNCFsp7MD6QqU3PVbdrXMQDI9v"
    "9jyPYBEbUYktrctPmvJuj8Snm9wWewiAN5Zc81NQVYjuKDBpb1un4SWVCb4PDVPZ0J87tGzYe9"
    "dOJ30EYGeiIaaStkLLmLOYAM6oInIqIwVyIk2SE/"
    "q2lGt8OvwcZevNmPkVYjk6nyJi5EdvS6ciPRmW9bRWRT4pWU8bZIQL938LE4lHOQAixrAQiWes"
    "5Szp2U85E0nLdaDr5w/I28J/"
    "Z1+"
    "4zW1Nao1prVCOqrosnoNUfVf1kvswfW3FY2l1PiAYp8sGyO57GaztXdBoEOBcDLedfcPra9+"
    "NLdEF36NkE0g+"
    "9dbokFY7KxhUJ8WpMiCmN4yj9LKFLvQbctGMJJY9EwHFifm2pgaiaafKF1Gyz+"
    "NruJzEEgpysMo/f9AVBQ/"
    "qCdPQQGEWp3QDIaef4ts9QTx+RmDKCBDMTFLgFmmhbtUY0JWjLkKn7soz/LIcDUle/"
    "p5TiFD4VhfZnAcvYQHXfuslnyp+yuhWzASnAQNnOIO6fc1JFIwkDkcM+k/"
    "TspfAajzHooSAwXkrOWrjRDV6wI0YzMVHrEyQ0hZ5NnIXbL3lrTkOPjf3NBu1naSNEaySduStD"
    "bFVjV3TXoENEnZiugJKYSwmhzoYHM1ngipN5rNdqJiK5ukp6E8LDzi3l5/"
    "7XctJQY3+"
    "ZgHDJoslkGATCCBf0wggPloAMCAQICEHRFyHhODMmWSrQvvNop4bwwDQYJKoZIhvcNAQELBQAw"
    "gZAxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR"
    "4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xOjA4BgNVBAMTMU1pY3Jvc29mdCBUZXN0"
    "aW5nIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNjE3MjA1ODAyWhcNMz"
    "UwNjE3MjEwNDExWjCBkDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV"
    "BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE6MDgGA1UEAxMxTW"
    "ljcm9zb2Z0IFRlc3RpbmcgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDCCAiIwDQYJ"
    "KoZIhvcNAQEBBQADggIPADCCAgoCggIBAJXjqMG5nCZUsJnvJh+sHscwgLv1P/Lku/"
    "j+BmoKpoi8tIxF4HBVGYi0Bcu1waH61HzCQlMHnFRWqJfglGm+EyTv5YopnKbQKy+"
    "Kpuh5RC6L6sm+"
    "uFSGU74HJDRUFSIgAXuKRvvSkQeVCbBWEcx2stAfRHlSNCjsT0nCy2HThtzko35Vnp/uEG/"
    "P4T34t4R5ojuNHLCBfOREB+TORrCYg42Hj+"
    "X1rkB68e09m5p8StG5w5QFe9zauM7cHmzP2Z4378NaNnuQhkXc9i7K3e7eJ9l0mmn12V0JLUVB"
    "zLfCgtQqjBYlkpc9lE6JM35bA1TNsIOgjkG3h43ZBWNS9u7mThOdVM1J/"
    "uOLO1CbSLuy5ZLUq6DFEK8+sUUhNJDcrbn3/"
    "iGu7lBYejrlqtjjgtbPbU3JFaycMRelFqdC9toSeKdmkOz8zQFj//AOuuHN8Ntrmg/"
    "2DwQBCbyfzrdsUXBXCBv/eZpSXbqsFOU7Z88sUt4nmjQDbiVIsBl0/"
    "E2YwkuMkuGIrkgqq6vNFE22YQ6hCY8s20WvfTuBVgjJO0G3ZJ9dLhJ/"
    "uWkpH1JFSiPGr7ayOHKdCDP/"
    "0M+JtupuhUSUPpFZ6++evZucGkcDTqIXlvpiC+"
    "hTtk7j6CpzWeITuPhafsbiCt1KQ8zDdzt6MQQKwYSWOmNuGj4KDCW4frVSDLmrAgMBAAGjUTBP"
    "MAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/"
    "MB0GA1UdDgQWBBSjAQR+MIgz67kxnMrrhXZn/"
    "GW00TAQBgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQsFAAOCAgEASYvB/E/"
    "o5C1nkpp2BbrRvJjkK7ofZl9mI88cJ+u0qt2gFyBVcjOxdt7JbQ08LQoIJC3sOJZ6g/"
    "EnUDyGCd0NQc6qXvOPej4+8fC6i3LdNqFpBVt87OdwY40dbsD9OgPxED6Q13t63Opg7C9T/"
    "RkdOqF0CMJ7POBQrCHXtt3dPEQb9/NEPmyW4MCf5u/d3bGmaGFsXp75/"
    "5oGpGrNnnVDiZvLhfbcDEZKjJusEaZjRfv83iDuzmefPdCT2zn76l5L/"
    "NYg8ZU2CIyys6GXG0EZsKz+"
    "4tWrfdkm1Ny9HzjA44bfJOf1PgnKTaG6FsNKsfxymM8OkvpXRelITcaifDtyY6xO9HTpK1esqz"
    "KIC6kQZ1N+0mLS+mjonVuuzeDl4gaWDDQy9rwlrZjzMmC+FNN40RBv/"
    "zLjnj2I2rMyCs8gZUd4qqVLh2qD3BpaKt9wYa81MuBZoZ8LFHqqq0ILa//"
    "7NMudltcmKhM7498R5oZ9DQkRk0uk9tIHws3IvvVn964Fzhb+kMlKmBskaXiQ+TSON+"
    "huHdzPT+fSZEAdxDC61QiIZ0sPuOVZ6RjYDGBorn/qkVW+6/GnjthdUD6/1WlXlY+n/"
    "+QJPwiAlzJCuIJDgm+LC5PaGb9jTl+f7SwitiBfcET6iVmTsHsSD15iYlERvbpa0M6htu+"
    "AIOZzSxEGVuIYIoIvWCDF/tDLoBkeHhoe/P9Gn/"
    "8HWzsTX7By53fQtEtECmQzF2Npc3N4dWRpZDp4NTA5OjA6c2hhMjU2Okdkd3JaQURYSjlOY2Ez"
    "RUl6VF95Z2ljMjlTTTh0NXhhUUFLUVFHY25qUGc6OnN1YmplY3Q6Q046Q29kZSUyMFNpZ24lMj"
    "BUZXN0JTIwJTI4RE8lMjBOT1QlMjBUUlVTVCUyOWRmZWVkdUNvbnRhaW5lclBsYXQtQU1ELVVW"
    "TWtzaWduaW5ndGltZcEaY8mjFKFpdGltZXN0YW1wWRRdMIIUWQYJKoZIhvcNAQcCoIIUSjCCFE"
    "YCAQMxDzANBglghkgBZQMEAgIFADCCAYAGCyqGSIb3DQEJEAEEoIIBbwSCAWswggFnAgEBBgor"
    "BgEEAYRZCgMBMEEwDQYJYIZIAWUDBAICBQAEMK5zkFWfUX3eyH8qjyu4BllGa+"
    "IY47ZwruXXW0W8gd0iiVOHZI4Crzh3PVdm6+"
    "TCBQIGY8aKvUZ5GBMyMDIzMDExOTIwMDc0OC43MjZaMASAAgH0AhkAkMtE7uvpyJBFarynkGHB"
    "NGGNNRmkGXkZoIHUpIHRMIHOMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA"
    "4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQL"
    "EyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUy"
    "BFU046Rjc3Ri1FMzU2LTVCQUUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZp"
    "Y2Wggg6JMIIHEDCCBPigAwIBAgITMwAAAaqlMZsLy7IIDgABAAABqjANBgkqhkiG9w0BAQsFAD"
    "B8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe"
    "MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS"
    "1TdGFtcCBQQ0EgMjAxMDAeFw0yMjAzMDIxODUxMjZaFw0yMzA1MTExODUxMjZaMIHOMQswCQYD"
    "VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UECh"
    "MVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQ"
    "dWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046Rjc3Ri1FMzU2LTVCQUUxJTAjBg"
    "NVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4IC"
    "DwAwggIKAoICAQCgT+xyudW1h3/"
    "hQ0ofTu2Mq0LZDTL3R8x4ms7znSPTzho8iSGK7NVjjJkgqd6P5r7Lj5xUj+"
    "XNHQngblKuruid9DPNWWjTj/"
    "2m2a08GK2DfjeZ0razhnQrUQbpu+"
    "ocu069wGQ1AKy8L4bBpV4S5Q1NcIqGsTPgVcAjSOy5k2mCqo5ufIRILGLSiB5OfS8zpyOGnp2z"
    "ywT/"
    "1WGIyOmuCiHLp9BGRKwLpLeTwv5ilGjqYVDBmJtD8X6WPQZBubD33MxciHwNdyy0UuLBoW1K3D"
    "OeBLxNhZVgUGiaO36yluwlYyEyxF+BNpccEBvzLmftcA2IPTjhK0+Yfus3nI+"
    "u3np8MXlKGjhGyrYlMWiVGJ8kCsQlk5DXVkV0ykpiMcdLW7D+Yq1o6l70+rf83iSsNOTWPIT0+"
    "er1ttKtA2CtjbXjggw9FA+"
    "mTQBS1fOxjpJdHgal3E6BVXXicMDkxOmgOEamKDa9kFDwSFOiRIlBgbPXOKguZgR02OOlWkf6H"
    "WhQy3MUCODj5J+WpfyD7HfP62g5jHyopOusXDYdqjeMsrWDN7og3p1+"
    "anhXcd6XYuN6WABTf0tf91UTZPvxkVVFGFmAYw2UqsbJYnRPIbMQuyvKi35jaGkNmgLLtd4dX2"
    "kzEmSBFcaLM9W/"
    "ciHl5rTOjZa41d3rcEuyV2MBoRzHVWBC9QIDAQABo4IBNjCCATIwHQYDVR0OBBYEFD+"
    "aFLxThy7YX3dFs94RrZ0FRqSeMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/"
    "Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w"
    "a2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBg"
    "grBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lv"
    "cHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1"
    "UdEwEB/"
    "wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBAN8MgE2QRRAaIK3"
    "MB7OMyO6l9stI2ygiOmYnhgCEfekYjK42b1ht/"
    "WDwPxS9r4RkgrTu3mt4gZcIYU8iRD3sS7oE+IweFtK5XTiz+WxHNM8MbPTbUxUvFJds2ye48+"
    "VsUp4Uh7H2lRVKe0ugdmtW4ypliKP0r3d1tVd5nCGM4W6SyFFZT9wm0yRBPnAt4V/"
    "iYIJ0mERE8qPpiOx8/yjFhWkVgVGCOINAa8IldpWKisnpIzaeq4+2/JejoW4F/"
    "yT9G8zcb+oqNGOIjZSM8/z3SIfxNqY96Vz4kCT0ZRJDJLEXnBPFZxcqoUeH2/"
    "xenOcsGOPphKbISAINmFF7MBaqmyvRb/lPGGHJWD74Sv8EWbPv+WriuBTPkE48sI9Aua5q/"
    "DM4qplBoALsGUGMh0QqKZ1XZWjv8cUmQn2mUe8OwdzgRJfI/"
    "laKH7NSn6vQJpkAFmTo7eA5zZOTZ8U4T740FbjlP8vh0xK8Kg/"
    "8CkQpdACd1D0yfDz2Kfo2xF5CpqBYVOCRnq+"
    "Xmo9tp19fabozWSqqmq7eMi4zVDpKlo1ZOCh6XWERnCTFV5CpEAIpY1J/XB0cDbj8/"
    "07u2Jn4EV1jeB7wnE9ptUAA4pzmT7Dub+Y/2xMcNFpha1tgrQxAKZwpZogCnIRa9MUihORE/"
    "gMrmy2qXoxDa/"
    "b7e0Fzaumj9V1nMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0B"
    "AQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG"
    "1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0"
    "IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOT"
    "MwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH"
    "UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3"
    "NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB"
    "AOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/"
    "1xPx2b3lVNxWuJ+Slr+"
    "uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/"
    "YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/"
    "W7IVWTe/"
    "dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3r"
    "Mvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/"
    "SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6Z"
    "NN3SUHDSCD/"
    "AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC"
    "4jMYctenIPDC+"
    "hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbq"
    "vUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/"
    "eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQ"
    "ABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/"
    "y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI"
    "3TIN9AQEwQTA/"
    "BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaX"
    "RvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBB"
    "MAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/"
    "MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dH"
    "A6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEw"
    "LTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm"
    "9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3"
    "DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/"
    "qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+"
    "2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2"
    "CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/"
    "kpicO8F7BUhUKz/AyeixmJ5/"
    "ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+"
    "ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBH"
    "G/"
    "ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rs"
    "joiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/"
    "g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/"
    "wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+"
    "7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8jGCBB"
    "0wggQZAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH"
    "EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3"
    "Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABqqUxmwvLsggOAAEAAAGqMA0GCWCGSAFl"
    "AwQCAgUAoIIBWjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwPwYJKoZIhvcNAQkEMTIEMJ"
    "fpF0uOTCs5hx5LnTIYEWdwRBueri78MOiRsZTylEO1bQoeb3LE7Z8KYGIt77qoATCB+"
    "gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIFa1AkMcWrwR4HPdNe6AKpGFIj8kJlsBNgQjBMb"
    "xsx7AMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVB"
    "AcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWl"
    "jcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGqpTGbC8uyCA4AAQAAAaowIgQgIttO0"
    "SncgJ3qc/EHtPnzG2fQ7n8opn+LnqMW/4krIEswDQYJKoZIhvcNAQEMBQAEggIAORfI6/"
    "nqjl6ktq8Z6mLQiujNhGN9rSNs0lFgI63m6liH4g9JTUaFJGKcV2uyVuIcEzfqj84zUEEgLsop"
    "xy1OrlH5RRppaevoSesMRPFvBuiWO4jw54AkvOBGxALuR/"
    "6SRfTp3Av1ADREq0MzNKKyZkmlFbk+RGfOCFLTJmHNRVGd4G/"
    "jbX+"
    "e56IcLYTtLIU0InqQ6j25yRjRl63ZUK4ZfK7PPi3NhshIZKcnyspXgAmUwYJgwj1TlXqOMqvSs"
    "PvUu7iA5FUYStfttT5FETdItoIDF4l5sGlFkwEuME1zkjvaFIoRAefe9auKBmXK/"
    "AuxIDJNxEAuao7Xfemgi8loe0TLPrg4mbZ+ycM4sLjKhbgfUL5Dp96KHAFKTieQaXVNqfHH1M+"
    "hx3MudophC94JF9TNQQGu8pW5P5orRAxhEwmpnvVNc+"
    "rXdBon8BG064Ps0SIrGuf3RuEonJcwHMMRbBIQ4KbLBEq2yfKEl1RnqVsPXJwCUiG3nVIR4cy6"
    "pn6oYKmF8MbptSjPP9LhTiM9MKn2Tnhj/"
    "TCvsABjfg49xit9xpsVrZORaknktBbt2YMXYg+knpDCFtrpMuY9AMhh0ZgyNzVA+er+"
    "kBZoGbj6VgPmu4fejrt79xdBbnRJMVJ5qb4X7nqR8bxKygRaou5jU6qb7H0Cc9zq4QGdU8814C"
    "pY1HsKICAieC1tcy1tYWEtYXBpLXZlcnNpb24iOiAiMjAyMi0wMS0wMSIsCiAgIngtbXMtc2V2"
    "c25wdm0tZ3Vlc3Rzdm4iOiAiMCIsCiAgIngtbXMtc2V2c25wdm0tbGF1bmNobWVhc3VyZW1lbn"
    "QiOiAiN2RkYmQyZmJlOTAzMGMzZmVhNTdlMGYxMDhjM2FiMDA1ODFiZjA2OWYxYjI4NGM5YjNk"
    "MGVjNzBhZWRjZmQ3OTEzMzY1ZmM4ZTAwMWNiYTJmYTZlYzUzOGE4ZDg5M2YxIgp9WQEAkBXMgt"
    "YVrJTJ5gvwqw5VxZClVJ4WXDTAW+pV1/Bf4l0XG/"
    "IBcWUAzLviKDee+4NRwxkZBrvuezoE3hr7Rojb5Bl+B5bSZi7IYajNK1KR4QvUjY3q3/"
    "EQAJh0MpKxEZmWZ1SadRN42xvhC46pkrgun78ne4PepzMljEw+"
    "abAS4CnMKFKdMFN2znqanefvTSyEdmS1jqoJ+"
    "wtxCWI5jMrcpPwRehP6pkJ4Q6pi2UMTpxsuzR1ySRdPFu4478lLqpDK9tH5fpGDWySJCgc4hNa"
    "gMQk7nTTRW6+oRvdSp1Ath9Fana0695AOdUdO3V1ghnfb1Pp4WDepFJlrKySVHnwGKg==";

  auto uvm_endorsements_raw = crypto::raw_from_b64(uvm_endorsements_base64);

  auto phdr = ccf::decode_protected_header(uvm_endorsements_raw);

  // for (auto const& c : phdr.x5_chain)
  // {
  //   LOG_DEBUG_FMT("{}", crypto::b64_from_raw(c));
  // }

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

  if (!ccf::is_rsa_alg(phdr.alg))
  {
    throw std::logic_error("Algorithm signature is not valid RSA");
  }

  const std::string& did = phdr.iss;

  std::string pem_chain;
  for (auto const& c : phdr.x5_chain)
  {
    pem_chain += crypto::cert_der_to_pem(c).str();
  }

  auto jwk = nlohmann::json::parse(didx509::resolve(pem_chain, did));

  crypto::JsonWebKeyRSAPublic jwk_ec_pub =
    jwk.at("verificationMethod").at(0).at("publicKeyJwk");

  LOG_FAIL_FMT("{}", nlohmann::json(jwk_ec_pub).dump());

  auto pubk = crypto::make_rsa_public_key(jwk_ec_pub);

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

  // auto phdr = ccf::decode_protected_header(uvm_endorsements_raw);

  // LOG_FAIL_FMT(
  //   "phdr:: alg:{},content type:{},x5chain:{},iss:{},feed:{}",
  //   phdr.alg,
  //   phdr.content_type,
  //   phdr.x5_chain.size(),
  //   phdr.iss,
  //   phdr.feed);

  // //
  // // Verify endorsements of certificates
  // //

  // if (!ccf::is_ecdsa_alg(phdr.alg))
  // {
  //   throw std::logic_error("Algorithm signature is not valid ECDSA");
  // }

  // const std::string& did = phdr.iss;

  // std::string pem_chain;
  // for (auto const& c : phdr.x5_chain)
  // {
  //   pem_chain += crypto::cert_der_to_pem(c).str();
  // }

  // auto jwk = nlohmann::json::parse(didx509::resolve(pem_chain, did));

  // crypto::JsonWebKeyECPublic jwk_ec_pub =
  //   jwk.at("verificationMethod").at(0).at("publicKeyJwk");

  // auto pubk = crypto::make_public_key(jwk_ec_pub);

  // auto raw_payload =
  //   ccf::verify_uvm_endorsements_signature(pubk, uvm_endorsements_raw);

  // if (phdr.content_type == ccf::COSE_HEADER_CONTENT_TYPE_VALUE)
  // {
  //   ccf::UVMEndorsementsPayload uvm_endorsements_payload =
  //     nlohmann::json::parse(raw_payload);

  //   LOG_FAIL_FMT(
  //     "Payload, api: {} | guestsnv: {} | launch measurement: {}",
  //     uvm_endorsements_payload.maa_api_version,
  //     uvm_endorsements_payload.sevsnpvn_guest_svn,
  //     uvm_endorsements_payload.sevsnpvm_launch_measurement);
  // }

  // TODO: Check guest SVN

  return;
}