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

  std::string uvm_endorsements_base64 = "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";

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