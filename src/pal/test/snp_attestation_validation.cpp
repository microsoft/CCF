// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/hex.h"
#include "ccf/ds/logger.h"
#include "ccf/ds/quote_info.h"
#include "ccf/node/quote.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/attestation_sev_snp_endorsements.h"
#include "ccf/pal/measurement.h"
#include "ccf/pal/report_data.h"
#include "ccf/pal/sev_snp_cpuid.h"
#include "ccf/pal/snp_ioctl.h"
#include "crypto/openssl/hash.h"
#include "pal/test/attestation.h"
#include "pal/test/attestation_sev_snp_endorsements.h"
#include "pal/test/snp_attestation_validation_data.h"

#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <type_traits>

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

namespace
{
  std::vector<ccf::crypto::Pem> milan_endorsement_certs()
  {
    return ccf::crypto::split_x509_cert_bundle(
      ccf::pal::snp::testing::milan_endorsements);
  }

  std::vector<uint8_t> endorsement_bundle_with_ark(
    const ccf::crypto::Pem& ark_cert)
  {
    auto certs = milan_endorsement_certs();
    REQUIRE(certs.size() == 3);

    certs[2] = ark_cert;
    std::string bundle;
    for (const auto& cert : certs)
    {
      bundle += cert.str();
    }

    return {bundle.begin(), bundle.end()};
  }

  ccf::QuoteInfo milan_quote_info_with_ark(const ccf::crypto::Pem& ark_cert)
  {
    return {
      .format = ccf::QuoteFormat::amd_sev_snp_v1,
      .quote = ccf::pal::snp::testing::milan_attestation,
      .endorsements = endorsement_bundle_with_ark(ark_cert),
      .uvm_endorsements = std::nullopt,
    };
  }

  ccf::crypto::Pem pem_from_x509(X509* x509)
  {
    ccf::crypto::OpenSSL::CHECKNULL(x509);

    ccf::crypto::OpenSSL::Unique_BIO mem;
    ccf::crypto::OpenSSL::CHECK1(PEM_write_bio_X509(mem, x509));

    BUF_MEM* bptr = nullptr;
    ccf::crypto::OpenSSL::CHECK1(BIO_get_mem_ptr(mem, &bptr));
    ccf::crypto::OpenSSL::CHECKNULL(bptr);

    return ccf::crypto::Pem(
      reinterpret_cast<const uint8_t*>(bptr->data), bptr->length);
  }

  ccf::crypto::Pem ark_with_extra_issuer_entry()
  {
    const auto certs = milan_endorsement_certs();
    REQUIRE(certs.size() == 3);

    ccf::crypto::OpenSSL::Unique_BIO mem_bio(certs[2]);
    ccf::crypto::OpenSSL::Unique_X509 x509(
      mem_bio, true, true /* check_null */);

    std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> issuer(
      X509_NAME_dup(X509_get_issuer_name(x509)), X509_NAME_free);
    ccf::crypto::OpenSSL::CHECKNULL(issuer.get());

    static constexpr auto unexpected_ou = "Unexpected";
    ccf::crypto::OpenSSL::CHECK1(X509_NAME_add_entry_by_txt(
      issuer.get(),
      "OU",
      MBSTRING_ASC,
      reinterpret_cast<const unsigned char*>(unexpected_ou),
      -1,
      -1,
      0));
    ccf::crypto::OpenSSL::CHECK1(X509_set_issuer_name(x509, issuer.get()));

    return pem_from_x509(x509);
  }

  ccf::crypto::Pem ark_with_sha384_rsa_signature_algorithm()
  {
    const auto certs = milan_endorsement_certs();
    REQUIRE(certs.size() == 3);

    auto der = ccf::crypto::cert_pem_to_der(certs[2]);
    static constexpr std::array<uint8_t, 9> rsassa_pss_oid = {
      0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a};
    static constexpr std::array<uint8_t, 9> sha384_rsa_oid = {
      0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c};

    size_t replacements = 0;
    for (size_t i = 0; i + rsassa_pss_oid.size() <= der.size(); ++i)
    {
      auto it = der.begin() + i;
      if (std::equal(rsassa_pss_oid.begin(), rsassa_pss_oid.end(), it))
      {
        std::copy(sha384_rsa_oid.begin(), sha384_rsa_oid.end(), it);
        ++replacements;
      }
    }

    REQUIRE(replacements > 0);

    return ccf::crypto::cert_der_to_pem(der);
  }
}

TEST_CASE("unverified SNP report accessors")
{
  using namespace ccf::pal;
  static_assert(
    std::
      is_same_v<snp::AttestationReport::element_type, TavSnpAttestationReport>);
  static_assert(!std::is_copy_constructible_v<snp::AttestationReport>);
  static_assert(std::is_nothrow_move_constructible_v<snp::AttestationReport>);
  static_assert(std::is_same_v<
                decltype(snp::parse_attestation_report_unverified(
                  std::declval<std::span<const uint8_t>>())),
                snp::AttestationReport>);

  auto report =
    snp::parse_attestation_report_unverified(snp::testing::milan_attestation);

  CHECK(tav_snp_attestation_report_version(report.get()) == 3);
  CHECK(tav_snp_attestation_report_cpuid_fam_id(report.get()) == 25);
  CHECK(tav_snp_attestation_report_cpuid_mod_id(report.get()) == 1);
  const uint8_t* data = nullptr;
  size_t size = 0;
  tav_snp_attestation_report_reported_tcb(report.get(), &data, &size);
  CHECK(
    snp::TcbVersionRaw::from_span({data, size}).to_hex() == "db18000000000004");
  tav_snp_attestation_report_measurement(report.get(), &data, &size);
  const auto measurement = std::span<const uint8_t>{data, size};
  auto moved_report = std::move(report);
  CHECK(measurement.size() == snp_attestation_measurement_size);
  tav_snp_attestation_report_signature_r(moved_report.get(), &data, &size);
  CHECK(size == 72);
}

TEST_CASE("CCF policy is separate from generic TAV verification")
{
  using namespace ccf::pal;
  const auto certs = milan_endorsement_certs();
  REQUIRE(certs.size() == 3);
  TavSnpAttestationReport* raw_report = nullptr;
  const std::unique_ptr<TavError, decltype(&tav_error_free)> error(
    tav_verify_snp_attestation(
      snp::testing::milan_attestation.data(),
      snp::testing::milan_attestation.size(),
      certs[2].data(),
      certs[2].size(),
      certs[1].data(),
      certs[1].size(),
      certs[0].data(),
      certs[0].size(),
      &raw_report),
    tav_error_free);
  const snp::AttestationReport report(raw_report);
  REQUIRE(error == nullptr);
  REQUIRE(report != nullptr);
  CHECK(
    tav_snp_attestation_report_version(report.get()) ==
    snp::minimum_attestation_version);

  PlatformAttestationMeasurement measurement;
  PlatformAttestationReportData report_data;
  const std::vector<uint8_t> endorsements(
    snp::testing::milan_endorsements.begin(),
    snp::testing::milan_endorsements.end());
  const ccf::QuoteInfo quote_info = {
    .format = ccf::QuoteFormat::amd_sev_snp_v1,
    .quote = snp::testing::milan_attestation,
    .endorsements = endorsements,
    .uvm_endorsements = std::nullopt,
    .endorsed_tcb = "0000000000000000"};
  CHECK_THROWS_WITH_AS(
    verify_snp_attestation_report_and_get(quote_info, measurement, report_data),
    doctest::Contains("does not match reported TCB"),
    std::logic_error);
}

TEST_CASE("unverified SNP report rejects invalid sizes")
{
  CHECK_THROWS_WITH_AS(
    static_cast<void>(ccf::pal::snp::parse_attestation_report_unverified(
      std::vector<uint8_t>(100))),
    "SEV-SNP: TAV unverified report parsing failed (1): Invalid "
    "attestation report: expected 1184 bytes, got 100",
    std::logic_error);
}

TEST_CASE("SNP byte accessors borrow report storage")
{
  struct ByteField
  {
    void (*accessor)(const TavSnpAttestationReport*, const uint8_t**, size_t*);
    size_t offset;
    size_t size;
  };
  const ByteField fields[] = {
    {tav_snp_attestation_report_family_id, 0x010, 16},
    {tav_snp_attestation_report_image_id, 0x020, 16},
    {tav_snp_attestation_report_platform_version, 0x038, 8},
    {tav_snp_attestation_report_report_data, 0x050, 64},
    {tav_snp_attestation_report_measurement, 0x090, 48},
    {tav_snp_attestation_report_host_data, 0x0C0, 32},
    {tav_snp_attestation_report_id_key_digest, 0x0E0, 48},
    {tav_snp_attestation_report_author_key_digest, 0x110, 48},
    {tav_snp_attestation_report_report_id, 0x140, 32},
    {tav_snp_attestation_report_report_id_ma, 0x160, 32},
    {tav_snp_attestation_report_reported_tcb, 0x180, 8},
    {tav_snp_attestation_report_chip_id, 0x1A0, 64},
    {tav_snp_attestation_report_committed_tcb, 0x1E0, 8},
    {tav_snp_attestation_report_launch_tcb, 0x1F0, 8},
    {tav_snp_attestation_report_signature_r, 0x2A0, 72},
    {tav_snp_attestation_report_signature_s, 0x2E8, 72}};

  const auto& raw_report = ccf::pal::snp::testing::milan_attestation;
  auto report = ccf::pal::snp::parse_attestation_report_unverified(raw_report);
  for (const auto& [accessor, offset, size] : fields)
  {
    const uint8_t* data = nullptr;
    size_t length = 0;
    accessor(report.get(), &data, &length);
    const auto first = std::span<const uint8_t>{data, length};
    data = nullptr;
    length = 0;
    accessor(report.get(), &data, &length);
    const auto second = std::span<const uint8_t>{data, length};
    CHECK(first.data() == second.data());
    REQUIRE(first.size() == size);
    CHECK(std::equal(first.begin(), first.end(), raw_report.begin() + offset));
  }
}

TEST_CASE("SNP chip ID access rejects empty handles")
{
  ccf::pal::snp::AttestationReport report;
  CHECK_THROWS_WITH_AS(
    ccf::pal::snp::get_chip_id_for_vcek(report),
    "Cannot access an empty SNP attestation report",
    std::logic_error);
}

TEST_CASE("SNP borrowed bytes survive report ownership transfers")
{
  using namespace ccf::pal::snp;
  auto raw_report = testing::milan_attestation;
  std::optional<AttestationReport> original =
    parse_attestation_report_unverified(raw_report);
  const uint8_t* data = nullptr;
  size_t size = 0;
  tav_snp_attestation_report_measurement(original->get(), &data, &size);
  const auto measurement = std::span<const uint8_t>{data, size};
  raw_report[0x090] ^= 0xff;
  CHECK(measurement[0] == testing::milan_attestation[0x090]);

  auto moved = std::move(*original);
  original.reset();
  tav_snp_attestation_report_measurement(moved.get(), &data, &size);
  CHECK(measurement.data() == data);
  CHECK(measurement.size() == size);

  auto assigned =
    parse_attestation_report_unverified(testing::genoa_attestation);
  assigned = std::move(moved);
  tav_snp_attestation_report_measurement(assigned.get(), &data, &size);
  CHECK(measurement.data() == data);
  CHECK(measurement.size() == size);
  CHECK(std::equal(
    measurement.begin(),
    measurement.end(),
    testing::milan_attestation.begin() + 0x090));
}

TEST_CASE("VCEK chip ID borrows the product-specific prefix")
{
  using namespace ccf::pal::snp;
  for (const auto* raw_report :
       {&testing::milan_attestation,
        &testing::genoa_attestation,
        &testing::turin_attestation})
  {
    auto report = parse_attestation_report_unverified(*raw_report);
    const uint8_t* data = nullptr;
    size_t size = 0;
    tav_snp_attestation_report_chip_id(report.get(), &data, &size);
    const auto chip_id = std::span<const uint8_t>{data, size};
    const auto vcek_chip_id = get_chip_id_for_vcek(report);
    CHECK(vcek_chip_id.data() == chip_id.data());
    CHECK(
      vcek_chip_id.size() ==
      (get_sev_snp_product(
         tav_snp_attestation_report_cpuid_fam_id(report.get()),
         tav_snp_attestation_report_cpuid_mod_id(report.get())) ==
           ProductName::Turin ?
         8 :
         64));
  }
}

TEST_CASE("TCB values can be constructed from borrowed bytes")
{
  using ccf::pal::snp::TcbVersionRaw;
  std::array<uint8_t, 8> bytes = {4, 0, 0, 0, 0, 0, 24, 219};
  const auto tcb = TcbVersionRaw::from_span(bytes);
  CHECK(tcb.to_hex() == "db18000000000004");
  CHECK(tcb == TcbVersionRaw(std::vector<uint8_t>(bytes.begin(), bytes.end())));
  bytes.fill(0);
  CHECK(tcb.to_hex() == "db18000000000004");
  CHECK_THROWS_WITH_AS(
    TcbVersionRaw::from_span(std::span(bytes).first(7)),
    "Invalid TCB version raw data size: 7",
    std::logic_error);
}

TEST_CASE("SNP verification preserves invalid size error")
{
  ccf::pal::PlatformAttestationMeasurement measurement;
  ccf::pal::PlatformAttestationReportData report_data;
  const ccf::QuoteInfo quote_info = {
    .format = ccf::QuoteFormat::amd_sev_snp_v1,
    .quote = std::vector<uint8_t>(100),
    .endorsements = {},
    .uvm_endorsements = std::nullopt};
  CHECK_THROWS_WITH_AS(
    ccf::pal::verify_snp_attestation_report_and_get(
      quote_info, measurement, report_data),
    doctest::Contains(
      "Input SEV-SNP attestation report is not of expected size 1184: 100"),
    std::logic_error);
}

TEST_CASE("SNP verification rejects other quote formats before parsing")
{
  for (const auto format :
       {ccf::QuoteFormat::insecure_virtual, ccf::QuoteFormat::oe_sgx_v1})
  {
    const ccf::QuoteInfo quote_info = {
      .format = format,
      .quote = {},
      .endorsements = {},
      .uvm_endorsements = std::nullopt};
    ccf::pal::PlatformAttestationMeasurement measurement;
    ccf::pal::PlatformAttestationReportData report_data;
    const auto expected_error = fmt::format(
      "Unexpected attestation report to verify for SEV-SNP: {}", format);
    CHECK_THROWS_WITH_AS(
      ccf::pal::verify_snp_attestation_report_and_get(
        quote_info, measurement, report_data),
      expected_error.c_str(),
      std::logic_error);
    CHECK_THROWS_WITH_AS(
      ccf::pal::verify_snp_attestation_report(
        quote_info, measurement, report_data),
      expected_error.c_str(),
      std::logic_error);
  }
}

TEST_CASE("SNP ioctl response bytes exclude response headers and padding")
{
  using namespace ccf::pal::snp;
  static_assert(
    std::is_same_v<
      decltype(get_attestation_bytes(
        std::declval<const ccf::pal::PlatformAttestationReportData&>())),
      std::vector<uint8_t>>);

  using Response = ioctl6::detail::AttestationResponse;
  static_assert(sizeof(Response) == 4000);
  static_assert(offsetof(Response, status) == 0);
  static_assert(offsetof(Response, report_size) == 4);
  static_assert(offsetof(Response, reserved) == 8);
  static_assert(offsetof(Response, report) == 0x20);
  static_assert(offsetof(Response, padding) == 0x20 + attestation_report_size);

  ioctl6::IoctlSentinel<Response> response;
  CHECK(response.data.status == 0);
  CHECK(response.data.report_size == 0);
  CHECK(response.data.reserved == decltype(response.data.reserved){});
  CHECK(response.data.report == decltype(response.data.report){});
  CHECK(response.data.padding == decltype(response.data.padding){});
  response.data.status = 0xa5a5a5a5;
  response.data.report_size = attestation_report_size;
  response.data.reserved.fill(0xa5);
  response.data.padding.fill(0xa5);
  std::copy(
    testing::milan_attestation.begin(),
    testing::milan_attestation.end(),
    response.data.report.begin());

  const auto report_bytes =
    ioctl6::detail::extract_attestation_bytes(response.data);
  CHECK(report_bytes == testing::milan_attestation);
  CHECK(response.sentinels_intact());
  response.data = {};
  CHECK(report_bytes == testing::milan_attestation);

  response.post_sentinels[1] ^= 1;
  CHECK_FALSE(response.sentinels_intact());
}

TEST_CASE("SNP ioctl response bytes reject invalid report sizes")
{
  using namespace ccf::pal::snp;
  ioctl6::detail::AttestationResponse response = {};
  for (const uint32_t report_size :
       {0U, 1183U, 1185U, std::numeric_limits<uint32_t>::max()})
  {
    response.report_size = report_size;
    const auto expected_error = fmt::format(
      "Unexpected SEV-SNP attestation report size: {} != {}",
      report_size,
      attestation_report_size);
    CHECK_THROWS_WITH_AS(
      ioctl6::detail::extract_attestation_bytes(response),
      expected_error.c_str(),
      std::logic_error);
  }
}

TEST_CASE("SNP byte acquisition rejects oversized report data before ioctl")
{
  ccf::pal::PlatformAttestationReportData report_data;
  report_data.data.resize(ccf::pal::snp_attestation_report_data_size + 1);
  CHECK_THROWS_WITH_AS(
    ccf::pal::snp::ioctl6::get_attestation_bytes(report_data),
    "User-defined report data is larger than available space",
    std::logic_error);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
TEST_CASE("legacy SNP report layout remains compatible")
{
  using ccf::pal::snp::Attestation;

  static_assert(
    std::is_same_v<
      decltype(std::declval<ccf::pal::snp::AttestationInterface&>().get()),
      const Attestation&>);
  static_assert(
    std::is_same_v<
      decltype(std::declval<ccf::pal::snp::AttestationInterface&>().get_raw()),
      std::vector<uint8_t>>);
  static_assert(
    std::is_same_v<
      decltype(std::declval<ccf::pal::snp::ioctl6::Attestation&>().get_raw()),
      std::vector<uint8_t>>);
  static_assert(std::is_same_v<
                decltype(ccf::AttestationProvider::get_snp_attestation(
                  std::declval<const ccf::QuoteInfo&>())),
                std::optional<Attestation>>);
  static_assert(std::is_same_v<
                decltype(ccf::pal::snp::ioctl6::AttestationResp::report),
                Attestation>);

  CHECK(ccf::pal::snp::amd_root_signing_keys.size() == 3);
  CHECK(
    ccf::pal::snp::amd_root_signing_keys.at(ccf::pal::snp::ProductName::Milan)
      .public_key == ccf::pal::snp::amd_milan_root_signing_public_key);

  Attestation report = {};
  CHECK(sizeof(report) == ccf::pal::snp::attestation_report_size);
  CHECK(offsetof(Attestation, version) == 0x000);
  CHECK(offsetof(Attestation, policy) == 0x008);
  CHECK(offsetof(Attestation, report_data) == 0x050);
  CHECK(offsetof(Attestation, measurement) == 0x090);
  CHECK(offsetof(Attestation, reported_tcb) == 0x180);
  CHECK(offsetof(Attestation, chip_id) == 0x1A0);
  CHECK(offsetof(Attestation, signature) == 0x2A0);

  report.version = ccf::pal::snp::minimum_attestation_version;
  report.cpuid_fam_id = 0x19;
  report.cpuid_mod_id = 0x01;
  const auto config =
    ccf::pal::snp::make_endorsement_endpoint_configuration(report);
  CHECK(config.servers.size() == 1);
}
#pragma clang diagnostic pop

TEST_CASE("milan validation")
{
  using namespace ccf;

  auto milan_quote_info = QuoteInfo{
    .format = QuoteFormat::amd_sev_snp_v1,
    .quote = pal::snp::testing::milan_attestation,
    .endorsements = std::vector<uint8_t>(
      pal::snp::testing::milan_endorsements.begin(),
      pal::snp::testing::milan_endorsements.end()),
    .uvm_endorsements = std::nullopt,
  };

  pal::PlatformAttestationMeasurement measurement;
  pal::PlatformAttestationReportData report_data;

  static_assert(std::is_same_v<
                decltype(pal::verify_snp_attestation_report_and_get(
                  std::declval<const QuoteInfo&>(),
                  std::declval<pal::PlatformAttestationMeasurement&>(),
                  std::declval<pal::PlatformAttestationReportData&>())),
                pal::snp::AttestationReport>);

  const auto report = pal::verify_snp_attestation_report_and_get(
    milan_quote_info, measurement, report_data);
  REQUIRE(report != nullptr);
  const auto verified_measurement = measurement.data;
  const auto verified_report_data = report_data.data;
  pal::verify_snp_attestation_report(
    milan_quote_info, measurement, report_data);
  CHECK(measurement.data == verified_measurement);
  CHECK(report_data.data == verified_report_data);
}

TEST_CASE("genoa validation")
{
  using namespace ccf;

  auto genoa_quote_info = QuoteInfo{
    .format = QuoteFormat::amd_sev_snp_v1,
    .quote = pal::snp::testing::genoa_attestation,
    .endorsements = std::vector<uint8_t>(
      pal::snp::testing::genoa_endorsements.begin(),
      pal::snp::testing::genoa_endorsements.end()),
    .uvm_endorsements = std::nullopt,
  };

  pal::PlatformAttestationMeasurement measurement;
  pal::PlatformAttestationReportData report_data;

  pal::verify_snp_attestation_report(
    genoa_quote_info, measurement, report_data);
}

TEST_CASE("turin validation")
{
  using namespace ccf;

  auto turin_quote_info = QuoteInfo{
    .format = QuoteFormat::amd_sev_snp_v1,
    .quote = pal::snp::testing::turin_attestation,
    .endorsements = std::vector<uint8_t>(
      pal::snp::testing::turin_endorsements.begin(),
      pal::snp::testing::turin_endorsements.end()),
    .uvm_endorsements = std::nullopt,
  };

  pal::PlatformAttestationMeasurement measurement;
  pal::PlatformAttestationReportData report_data;

  pal::verify_snp_attestation_report(
    turin_quote_info, measurement, report_data);
}

TEST_CASE("Invalid attestation signature fails TAV verification")
{
  using namespace ccf;

  auto invalid_attestation = pal::snp::testing::milan_attestation;
  static constexpr size_t signature_offset = 0x2a0;
  invalid_attestation[signature_offset] ^= 1;
  auto quote_info = QuoteInfo{
    .format = QuoteFormat::amd_sev_snp_v1,
    .quote = std::move(invalid_attestation),
    .endorsements = std::vector<uint8_t>(
      pal::snp::testing::milan_endorsements.begin(),
      pal::snp::testing::milan_endorsements.end()),
    .uvm_endorsements = std::nullopt,
  };

  pal::PlatformAttestationMeasurement measurement;
  pal::PlatformAttestationReportData report_data;

  CHECK_THROWS_WITH_AS(
    pal::verify_snp_attestation_report(quote_info, measurement, report_data),
    doctest::Contains("SEV-SNP: TAV verification failed (104):"),
    std::logic_error);
}

TEST_CASE("Mismatched attestation and endorsements fail")
{
  using namespace ccf;

  auto mismatched_quote = QuoteInfo{
    .format = QuoteFormat::amd_sev_snp_v1,
    .quote = pal::snp::testing::milan_attestation,
    .endorsements = std::vector<uint8_t>(
      pal::snp::testing::genoa_endorsements.begin(),
      pal::snp::testing::genoa_endorsements.end()),
    .uvm_endorsements = std::nullopt,
  };

  pal::PlatformAttestationMeasurement measurement;
  pal::PlatformAttestationReportData report_data;

  CHECK_THROWS_WITH_AS(
    pal::verify_snp_attestation_report(
      mismatched_quote, measurement, report_data),
    doctest::Contains("SEV-SNP: TAV verification failed (102):"),
    std::logic_error);
}

TEST_CASE("ARK with unexpected issuer fails")
{
  auto quote_info = milan_quote_info_with_ark(ark_with_extra_issuer_entry());

  ccf::pal::PlatformAttestationMeasurement measurement;
  ccf::pal::PlatformAttestationReportData report_data;

  CHECK_THROWS_WITH_AS(
    ccf::pal::verify_snp_attestation_report(
      quote_info, measurement, report_data),
    doctest::Contains("SEV-SNP: TAV verification failed (102):"),
    std::logic_error);
}

TEST_CASE("Parsing of Tcb versions from strings")
{
  const auto milan_tcb_version_raw =
    ccf::pal::snp::TcbVersionRaw::from_hex("d315000000000004");
  CHECK_EQ(
    nlohmann::json(milan_tcb_version_raw).dump(), "\"d315000000000004\"");

  const auto milan_tcb_policy =
    milan_tcb_version_raw.to_policy(ccf::pal::snp::ProductName::Milan);
  CHECK_EQ(
    nlohmann::json(milan_tcb_policy),
    nlohmann::json::parse(
      "{\"boot_loader\":4,\"hexstring\":\"d315000000000004\",\"microcode\":211,"
      "\"snp\":21,\"tee\":0}"));

  const auto milan_tcb_version = milan_tcb_policy.to_milan_genoa();
  CHECK_EQ(milan_tcb_version.microcode, 0xd3);
  CHECK_EQ(milan_tcb_version.snp, 0x15);
  CHECK_EQ(milan_tcb_version.tee, 0x00);
  CHECK_EQ(milan_tcb_version.boot_loader, 0x04);

  const auto turin_tcb_policy =
    ccf::pal::snp::TcbVersionRaw::from_hex("1100000022334455")
      .to_policy(ccf::pal::snp::ProductName::Turin);
  CHECK_EQ(
    nlohmann::json(turin_tcb_policy),
    nlohmann::json::parse(
      "{\"boot_loader\":68,\"fmc\":85,\"hexstring\":\"1100000022334455\","
      "\"microcode\":17,\"snp\":34,\"tee\":51}"));

  const auto turin_tcb_version = turin_tcb_policy.to_turin();
  CHECK_EQ(turin_tcb_version.microcode, 0x11);
  CHECK_EQ(turin_tcb_version.snp, 0x22);
  CHECK_EQ(turin_tcb_version.tee, 0x33);
  CHECK_EQ(turin_tcb_version.boot_loader, 0x44);
  CHECK_EQ(turin_tcb_version.fmc, 0x55);
}

TEST_CASE("Parsing tcb versions from attestaion")
{
  auto milan_attestation = ccf::pal::snp::parse_attestation_report_unverified(
    ccf::pal::snp::testing::milan_attestation);
  const uint8_t* data = nullptr;
  size_t size = 0;
  tav_snp_attestation_report_reported_tcb(
    milan_attestation.get(), &data, &size);
  auto milan_tcb = ccf::pal::snp::TcbVersionRaw::from_span({data, size})
                     .to_policy(ccf::pal::snp::ProductName::Milan)
                     .to_milan_genoa();
  CHECK_EQ(milan_tcb.microcode, 0xdb);
  CHECK_EQ(milan_tcb.snp, 0x18);
  CHECK_EQ(milan_tcb.tee, 0x00);
  CHECK_EQ(milan_tcb.boot_loader, 0x04);
}

TEST_CASE("CPUID product mapping roundtrip")
{
  const std::vector<ccf::pal::snp::ProductName> products = {
    ccf::pal::snp::ProductName::Milan,
    ccf::pal::snp::ProductName::Genoa,
    ccf::pal::snp::ProductName::Turin,
  };

  for (const auto product : products)
  {
    const auto cpuid_hex = ccf::pal::snp::get_cpuid_of_snp_sev_product(product);
    const auto cpuid = ccf::pal::snp::cpuid_from_hex(cpuid_hex);

    CHECK_EQ(cpuid.hex_str(), cpuid_hex);
    CHECK_EQ(ccf::pal::snp::get_sev_snp_product(cpuid), product);
    CHECK_EQ(
      ccf::pal::snp::get_sev_snp_product(
        cpuid.get_family_id(), cpuid.get_model_id()),
      product);

    switch (product)
    {
      case ccf::pal::snp::ProductName::Milan:
        CHECK_EQ(cpuid.get_family_id(), 0x19);
        CHECK_EQ(cpuid.get_model_id(), 0x01);
        break;
      case ccf::pal::snp::ProductName::Genoa:
        CHECK_EQ(cpuid.get_family_id(), 0x19);
        CHECK_EQ(cpuid.get_model_id(), 0x11);
        break;
      case ccf::pal::snp::ProductName::Turin:
        CHECK_EQ(cpuid.get_family_id(), 0x1A);
        CHECK_EQ(cpuid.get_model_id(), 0x02);
        break;
      default:
        FAIL("Unexpected SNP product");
        break;
    }
  }
}

struct QuoteEndorsementsTestCase
{
  std::vector<uint8_t> attestation;
  ccf::pal::snp::EndorsementsServers servers;
  ccf::pal::snp::EndorsementEndpointsConfiguration expected_urls;
};

TEST_CASE("Quote endorsements url generation")
{
  constexpr size_t max_retries_count = 10;
  std::vector<QuoteEndorsementsTestCase> test_cases{
    {.attestation = ccf::pal::snp::testing::genoa_attestation,
     .servers = {{
       ccf::pal::snp::EndorsementsEndpointType::Azure,
       "invalid.azure.com:12345",
     }},
     .expected_urls =
       {.servers = {{{
          .host = "invalid.azure.com",
          .port = "12345",
          .uri = "/SevSnpVM/certificates/"
                 "b1e24a27bbc3a4d58090d8b89851dce3b8031544be249b9ac17132bb2"
                 "22b027622347ee4d0fe4f689efdfc47a68cefc686cbb448d01436506e"
                 "e1e28010cab7c0/541700000000000a",
          .params =
            {
              {"api-version", "2020-10-15-preview"},
            },
          .headers = {},
          .max_retries_count = max_retries_count,
          .max_client_response_size = ccf::ds::SizeString("100mb"),
        }}}}},
    {.attestation = ccf::pal::snp::testing::milan_attestation,
     .servers = {{
       ccf::pal::snp::EndorsementsEndpointType::AMD,
       "invalid.amd.com:12345",
     }},
     .expected_urls =
       {.servers =
          {
            {{{
                .host = "invalid.amd.com",
                .port = "12345",
                .uri = "/vcek/v1/Milan/"
                       "4ffb5cb4fd594f3fee6528fc3fb10370bb38abe89dcd5ba2cf0ab6a"
                       "11df2ca282add516bef45a890a8c9f9732bdca68f9f3f16c42e8460"
                       "30a800295dbeb19ba5",
                .params =
                  {{"blSPL", "4"},
                   {"teeSPL", "0"},
                   {"snpSPL", "24"},
                   {"ucodeSPL", "219"}},
                .response_is_der = true, // DER response
                .headers = {},
                .max_retries_count = max_retries_count,
                .max_client_response_size = ccf::ds::SizeString("100mb"),
              },
              {
                .host = "invalid.amd.com",
                .port = "12345",
                .uri = "/vcek/v1/Milan/cert_chain",
                .params = {},
                .response_is_der = false, // Not DER response
                .headers = {},
                .max_retries_count = max_retries_count,
                .max_client_response_size = ccf::ds::SizeString("100mb"),
              }}}}}},
    {
      .attestation = ccf::pal::snp::testing::turin_attestation,
      .servers = {{
        ccf::pal::snp::EndorsementsEndpointType::AMD,
        "invalid.amd.com:12345",
      }},
      .expected_urls =
        {.servers =
           {
             {{{
                 .host = "invalid.amd.com",
                 .port = "12345",
                 .uri = "/vcek/v1/Turin/59790fb1c39f35c1",
                 .params =
                   {
                     {"fmcSPL", "1"},
                     {"blSPL", "1"},
                     {"teeSPL", "1"},
                     {"snpSPL", "4"},
                     {"ucodeSPL", "81"},
                   },
                 .response_is_der = true, // DER response
                 .headers = {},
                 .max_retries_count = max_retries_count,
                 .max_client_response_size = ccf::ds::SizeString("100mb"),
               },
               {
                 .host = "invalid.amd.com",
                 .port = "12345",
                 .uri = "/vcek/v1/Turin/cert_chain",
                 .params = {},
                 .response_is_der = false, // Not DER response
                 .headers = {},
                 .max_retries_count = max_retries_count,
                 .max_client_response_size = ccf::ds::SizeString("100mb"),
               }}}}},
    },
    {
      .attestation = ccf::pal::snp::testing::genoa_attestation,
      .servers = {{
        ccf::pal::snp::EndorsementsEndpointType::AMD,
        "invalid.amd.com:12345",
      }},
      .expected_urls =
        {.servers =
           {
             {{{
                 .host = "invalid.amd.com",
                 .port = "12345",
                 .uri =
                   "/vcek/v1/Genoa/"
                   "b1e24a27bbc3a4d58090d8b89851dce3b8031544be249b9ac17132b"
                   "b222b027622347ee4d0fe4f689efdfc47a68cefc686cbb448d01436"
                   "506ee1e28010cab7c0",
                 .params =
                   {{"blSPL", "10"},
                    {"teeSPL", "0"},
                    {"snpSPL", "23"},
                    {"ucodeSPL", "84"}},
                 .response_is_der = true, // DER response
                 .headers = {},
                 .max_retries_count = max_retries_count,
                 .max_client_response_size = ccf::ds::SizeString("100mb"),
               },
               {
                 .host = "invalid.amd.com",
                 .port = "12345",
                 .uri = "/vcek/v1/Genoa/cert_chain",
                 .params = {},
                 .response_is_der = false, // Not DER response
                 .headers = {},
                 .max_retries_count = max_retries_count,
                 .max_client_response_size = ccf::ds::SizeString("100mb"),
               }}}}},
    },
    {.attestation = ccf::pal::snp::testing::genoa_attestation,
     .servers = {{
       ccf::pal::snp::EndorsementsEndpointType::THIM,
       "invalid.thim.azure.com:12345",
     }},
     .expected_urls = {
       .servers = {{{
         .host = "invalid.thim.azure.com",
         .port = "12345",
         .uri = "/metadata/THIM/amd/certification",
         .params =
           {{"platformId",
             "b1e24a27bbc3a4d58090d8b89851dce3b8031544be249b9ac17132bb222b02762"
             "2347ee4d0fe4f689efdfc47a68cefc686cbb448d01436506ee1e28010cab7c0"},
            {"tcbVersion", "541700000000000a"}},
         .response_is_thim_json = true,
         .headers = {{"Metadata", "true"}},
         .tls = false,
         .max_retries_count = max_retries_count,
         .max_client_response_size = ccf::ds::SizeString("100mb"),
       }}}}}};

  for (auto [attestation, servers, expected_url] : test_cases)
  {
    auto quote =
      ccf::pal::snp::parse_attestation_report_unverified(attestation);
    auto config =
      ccf::pal::snp::make_endorsement_endpoint_configuration(quote, servers);

    CHECK_EQ(nlohmann::json(config), nlohmann::json(expected_url));
  }
}

TEST_CASE("Quote endorsements generation for v2 attestation version fails")
{
  auto v2_format_milan_attestation =
    ccf::pal::snp::parse_attestation_report_unverified(
      ccf::pal::snp::testing::v2_format_milan_attestation);

  CHECK_EQ(
    tav_snp_attestation_report_version(v2_format_milan_attestation.get()), 2);
  CHECK_EQ(
    tav_snp_attestation_report_cpuid_fam_id(v2_format_milan_attestation.get()),
    0x0);
  CHECK_EQ(
    tav_snp_attestation_report_cpuid_mod_id(v2_format_milan_attestation.get()),
    0x0);

  CHECK_THROWS_WITH(
    ccf::pal::snp::make_endorsement_endpoint_configuration(
      (v2_format_milan_attestation),
      {{
        ccf::pal::snp::EndorsementsEndpointType::AMD,
        "kdsintf.amd.com:443",
      }}),
    "SEV-SNP: attestation version 2 is not supported. Minimum supported "
    "version is 3");
}

TEST_CASE("Extracting metadata from endorsements")
{
  using namespace ccf;

  auto milan_quote_info = QuoteInfo{
    .format = QuoteFormat::amd_sev_snp_v1,
    .quote = pal::snp::testing::milan_attestation,
    .endorsements = std::vector<uint8_t>(
      pal::snp::testing::milan_endorsements.begin(),
      pal::snp::testing::milan_endorsements.end()),
    .uvm_endorsements = std::nullopt,
  };

  auto attestation =
    pal::snp::parse_attestation_report_unverified(milan_quote_info.quote);

  auto certificates = ccf::crypto::split_x509_cert_bundle(std::string_view(
    reinterpret_cast<const char*>(milan_quote_info.endorsements.data()),
    milan_quote_info.endorsements.size()));

  auto chip_certificate = certificates[0];

  auto endorsed_tcb = pal::get_endorsed_tcb_from_cert(
    pal::snp::ProductName::Milan, chip_certificate);
  REQUIRE(endorsed_tcb.has_value());
  const uint8_t* data = nullptr;
  size_t size = 0;
  tav_snp_attestation_report_reported_tcb(attestation.get(), &data, &size);
  CHECK_EQ(
    nlohmann::json(endorsed_tcb.value()).dump(),
    nlohmann::json(pal::snp::TcbVersionRaw::from_span({data, size})).dump());

  auto endorsed_chip_id = pal::get_endorsed_chip_id_from_cert(chip_certificate);
  REQUIRE(endorsed_chip_id.has_value());
  tav_snp_attestation_report_chip_id(attestation.get(), &data, &size);
  const auto printable_reported_chip_id = std::span<const uint8_t>{data, size};
  CHECK_EQ(
    ds::to_hex(endorsed_chip_id.value()),
    ds::to_hex(printable_reported_chip_id));
}

int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  return res;
}
