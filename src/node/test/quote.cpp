// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// Store-backed SEV-SNP join policy verification (verify_quote_against_store
// and its helpers in src/node/quote.cpp) only runs on SNP hardware in e2e
// tests, so CI coverage (which runs on the virtual platform) never exercises
// it. This test builds an in-memory KV store, populates the join-policy
// tables from real Milan/Genoa/Turin attestation report fixtures (already
// used by snp_attestation_test), and drives the verification functions
// directly.

#include "ccf/node/quote.h"

#include "ccf/crypto/sha256_hash.h"
#include "ccf/ds/hex.h"
#include "ccf/ds/json.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/sev_snp_cpuid.h"
#include "ccf/service/tables/code_id.h"
#include "ccf/service/tables/host_data.h"
#include "ccf/service/tables/node_join_policy.h"
#include "ccf/service/tables/snp_measurements.h"
#include "ccf/service/tables/tcb_verification.h"
#include "ccf/service/tables/uvm_endorsements.h"
#include "ccf/service/tables/virtual_measurements.h"
#include "crypto/certs.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "pal/test/attestation.h"
#include "pal/test/snp_attestation_validation_data.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

// The following functions are implementation details of src/node/quote.cpp.
// They are not declared in the public ccf/node/quote.h header, but have
// external linkage, so (as quote.cpp is compiled directly into this test
// binary, mirroring node_frontend_test) we can forward-declare and exercise
// them directly, the same way
// src/pal/test/verify_uvm_attestation_and_endorsements.h forward-declares
// verify_quoted_node_public_key.
namespace ccf
{
  QuoteVerificationResult verify_enclave_measurement_against_store(
    ccf::kv::ReadOnlyTx& tx,
    const pal::PlatformAttestationMeasurement& quote_measurement,
    const QuoteFormat& quote_format,
    const std::optional<std::vector<uint8_t>>& uvm_endorsements);

  QuoteVerificationResult verify_quoted_node_public_key(
    const std::vector<uint8_t>& expected_node_public_key,
    const ccf::crypto::Sha256Hash& quoted_hash);

  QuoteVerificationResult verify_host_data_against_store(
    ccf::kv::ReadOnlyTx& tx,
    const QuoteInfo& quote_info,
    std::optional<HostData>& host_data);
}

using namespace ccf;

namespace
{
  std::shared_ptr<ccf::kv::Store> make_store()
  {
    auto store = std::make_shared<ccf::kv::Store>();
    store->set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
    return store;
  }

  struct ProductFixture
  {
    std::string name;
    pal::snp::ProductName product;
    const std::vector<uint8_t>& attestation;
    const std::string& endorsements;
  };

  const std::vector<ProductFixture>& all_product_fixtures()
  {
    static const std::vector<ProductFixture> fixtures = {
      {"milan",
       pal::snp::ProductName::Milan,
       pal::snp::testing::milan_attestation,
       pal::snp::testing::milan_endorsements},
      {"genoa",
       pal::snp::ProductName::Genoa,
       pal::snp::testing::genoa_attestation,
       pal::snp::testing::genoa_endorsements},
      {"turin",
       pal::snp::ProductName::Turin,
       pal::snp::testing::turin_attestation,
       pal::snp::testing::turin_endorsements},
    };
    return fixtures;
  }

  QuoteInfo make_snp_quote_info(const ProductFixture& fixture)
  {
    return {
      .format = QuoteFormat::amd_sev_snp_v1,
      .quote = fixture.attestation,
      .endorsements = std::vector<uint8_t>(
        fixture.endorsements.begin(), fixture.endorsements.end()),
      .uvm_endorsements = std::nullopt,
    };
  }

  // Derives the fixture's own measurement/host-data/TCB/CPUID from the
  // (already independently-verified, in snp_attestation_test) attestation
  // report, rather than hard-coding expected values in this file.
  struct FixtureFacts
  {
    pal::PlatformAttestationMeasurement measurement;
    HostData host_data;
    pal::snp::TcbVersionPolicy reported_tcb;
    std::string cpuid_hex;
  };

  FixtureFacts derive_facts(const ProductFixture& fixture)
  {
    auto quote_info = make_snp_quote_info(fixture);
    pal::PlatformAttestationMeasurement measurement;
    pal::PlatformAttestationReportData report_data;
    auto report = pal::verify_snp_attestation_report_and_get(
      quote_info, measurement, report_data);

    const uint8_t* data = nullptr;
    size_t size = 0;
    tav_snp_attestation_report_host_data(report.get(), &data, &size);
    HostData::Representation rep{};
    REQUIRE(size == rep.size());
    std::copy_n(data, size, rep.begin());

    tav_snp_attestation_report_reported_tcb(report.get(), &data, &size);
    auto reported_tcb =
      pal::snp::TcbVersionRaw({data, size}).to_policy(fixture.product);

    return {
      measurement,
      HostData::from_representation(rep),
      reported_tcb,
      pal::snp::get_cpuid_of_snp_sev_product(fixture.product)};
  }

  void populate_store_for_fixture(
    ccf::kv::Store& store,
    const ProductFixture& fixture,
    const FixtureFacts& facts,
    bool with_measurement,
    bool with_host_data,
    std::optional<pal::snp::TcbVersionPolicy> min_tcb_override = std::nullopt,
    bool with_tcb_entry = true)
  {
    auto tx = store.create_tx();
    if (with_measurement)
    {
      tx.rw<SnpMeasurements>(Tables::NODE_SNP_MEASUREMENTS)
        ->put(
          pal::SnpAttestationMeasurement(facts.measurement),
          CodeStatus::ALLOWED_TO_JOIN);
    }
    if (with_host_data)
    {
      tx.rw<SnpHostDataMap>(Tables::HOST_DATA)->put(facts.host_data, "");
    }
    if (with_tcb_entry)
    {
      auto min_tcb = min_tcb_override.value_or(facts.reported_tcb);
      tx.rw<SnpTcbVersionMap>(Tables::SNP_TCB_VERSIONS)
        ->put(facts.cpuid_hex, min_tcb);
    }
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
}

TEST_CASE(
  "TcbVersionRaw helpers" *
  doctest::description(
    "from_hex/to_hex, to_policy, to_milan_genoa/to_turin/as_turin, is_valid "
    "and the CPUID BlitSerialiser round-trip"))
{
  using pal::snp::ProductName;
  using pal::snp::TcbVersionPolicy;
  using pal::snp::TcbVersionRaw;

  SUBCASE("from_hex / to_hex round-trip")
  {
    const std::string hex = "db18000000000004";
    auto tcb = TcbVersionRaw::from_hex(hex);
    CHECK(tcb.to_hex() == hex);
  }

  SUBCASE("to_policy for Milan/Genoa and Turin, and to_milan_genoa/to_turin")
  {
    // Milan/Genoa layout: boot_loader, tee, reserved[4], snp, microcode
    std::array<uint8_t, 8> milan_bytes = {4, 0, 0, 0, 0, 0, 24, 219};
    auto milan_raw = TcbVersionRaw(std::span<const uint8_t>(milan_bytes));
    auto milan_policy = milan_raw.to_policy(ProductName::Milan);
    REQUIRE(milan_policy.boot_loader.has_value());
    CHECK(milan_policy.boot_loader.value() == 4);
    CHECK(milan_policy.snp.value() == 24);
    CHECK(milan_policy.microcode.value() == 219);
    CHECK_FALSE(milan_policy.fmc.has_value());
    auto milan_genoa = milan_policy.to_milan_genoa();
    CHECK(milan_genoa.boot_loader == 4);
    CHECK(milan_genoa.snp == 24);
    CHECK(milan_genoa.microcode == 219);

    // Turin layout: fmc, boot_loader, tee, snp, reserved[3], microcode
    std::array<uint8_t, 8> turin_bytes = {
      0x55, 0x44, 0x33, 0x22, 0, 0, 0, 0x11};
    auto turin_raw = TcbVersionRaw(std::span<const uint8_t>(turin_bytes));
    auto turin_policy = turin_raw.to_policy(ProductName::Turin);
    REQUIRE(turin_policy.fmc.has_value());
    CHECK(turin_policy.fmc.value() == 0x55);
    CHECK(turin_policy.boot_loader.value() == 0x44);
    CHECK(turin_policy.tee.value() == 0x33);
    CHECK(turin_policy.snp.value() == 0x22);
    CHECK(turin_policy.microcode.value() == 0x11);
    auto turin_version = turin_policy.to_turin();
    CHECK(turin_version.fmc == 0x55);
    CHECK(turin_version.boot_loader == 0x44);
    CHECK(turin_version.tee == 0x33);
    CHECK(turin_version.snp == 0x22);
    CHECK(turin_version.microcode == 0x11);

    // as_turin() gives mutable access to the same underlying bytes.
    TcbVersionRaw mutable_raw;
    auto* as_turin = mutable_raw.as_turin();
    as_turin->fmc = 0x55;
    as_turin->boot_loader = 0x44;
    as_turin->tee = 0x33;
    as_turin->snp = 0x22;
    as_turin->microcode = 0x11;
    CHECK(mutable_raw == turin_raw);
  }

  SUBCASE("is_valid")
  {
    TcbVersionPolicy minimum{
      .microcode = 10, .snp = 10, .tee = 10, .boot_loader = 10};
    TcbVersionPolicy equal = minimum;
    CHECK(TcbVersionPolicy::is_valid(minimum, equal));

    TcbVersionPolicy higher = minimum;
    higher.microcode = 11;
    CHECK(TcbVersionPolicy::is_valid(minimum, higher));

    TcbVersionPolicy lower = minimum;
    lower.microcode = 9;
    CHECK_FALSE(TcbVersionPolicy::is_valid(minimum, lower));

    // fmc present in one but not the other must fail.
    TcbVersionPolicy with_fmc = minimum;
    with_fmc.fmc = 1;
    CHECK_FALSE(TcbVersionPolicy::is_valid(minimum, with_fmc));
    CHECK_FALSE(TcbVersionPolicy::is_valid(with_fmc, minimum));
  }

  SUBCASE("CPUID BlitSerialiser round-trip and get_cpuid_of_snp_sev_product")
  {
    for (const auto product :
         {ProductName::Milan, ProductName::Genoa, ProductName::Turin})
    {
      const auto hex = pal::snp::get_cpuid_of_snp_sev_product(product);
      auto cpuid = pal::snp::cpuid_from_hex(hex);
      auto serialised =
        ccf::kv::serialisers::BlitSerialiser<pal::snp::CPUID>::to_serialised(
          cpuid);
      auto round_tripped =
        ccf::kv::serialisers::BlitSerialiser<pal::snp::CPUID>::from_serialised(
          serialised);
      CHECK(round_tripped == cpuid);
      CHECK(pal::snp::get_sev_snp_product(cpuid) == product);
    }
  }
}

TEST_CASE("verify_quoted_node_public_key")
{
  const std::vector<uint8_t> public_key_der = {1, 2, 3, 4, 5};
  const auto matching_hash = ccf::crypto::Sha256Hash(public_key_der);
  CHECK(
    verify_quoted_node_public_key(public_key_der, matching_hash) ==
    QuoteVerificationResult::Verified);

  const auto mismatched_hash =
    ccf::crypto::Sha256Hash(std::vector<uint8_t>{9, 9, 9});
  CHECK(
    verify_quoted_node_public_key(public_key_der, mismatched_hash) ==
    QuoteVerificationResult::FailedInvalidQuotedPublicKey);
}

TEST_CASE("verify_enclave_measurement_against_store: SGX")
{
  auto store = make_store();
  pal::PlatformAttestationMeasurement measurement;
  measurement.data =
    std::vector<uint8_t>(pal::sgx_attestation_measurement_size, 0x11);

  {
    auto tx = store->create_read_only_tx();
    CHECK(
      verify_enclave_measurement_against_store(
        tx, measurement, QuoteFormat::oe_sgx_v1, std::nullopt) ==
      QuoteVerificationResult::FailedMeasurementNotFound);
  }

  {
    auto tx = store->create_tx();
    tx.rw<CodeIDs>(Tables::NODE_CODE_IDS)
      ->put(
        pal::SgxAttestationMeasurement(measurement),
        CodeStatus::ALLOWED_TO_JOIN);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = store->create_read_only_tx();
    CHECK(
      verify_enclave_measurement_against_store(
        tx, measurement, QuoteFormat::oe_sgx_v1, std::nullopt) ==
      QuoteVerificationResult::Verified);
  }
}

TEST_CASE(
  "verify_enclave_measurement_against_store: unexpected quote format throws")
{
  // QuoteFormat only ever takes its three declared enum values in
  // practice, but the underlying switch has a defensive default case for
  // any other (malformed/future) value, which should be reported as a
  // programming error rather than silently accepted or rejected.
  auto store = make_store();
  pal::PlatformAttestationMeasurement measurement;
  auto tx = store->create_read_only_tx();
  CHECK_THROWS_AS(
    verify_enclave_measurement_against_store(
      tx, measurement, static_cast<QuoteFormat>(99), std::nullopt),
    std::logic_error);
}

TEST_CASE("verify_enclave_measurement_against_store: virtual")
{
  auto store = make_store();
  pal::PlatformAttestationMeasurement measurement;
  const std::string measurement_str = "test-virtual-measurement";
  measurement.data =
    std::vector<uint8_t>(measurement_str.begin(), measurement_str.end());

  {
    auto tx = store->create_read_only_tx();
    CHECK(
      verify_enclave_measurement_against_store(
        tx, measurement, QuoteFormat::insecure_virtual, std::nullopt) ==
      QuoteVerificationResult::FailedMeasurementNotFound);
  }

  {
    auto tx = store->create_tx();
    tx.rw<VirtualMeasurements>(Tables::NODE_VIRTUAL_MEASUREMENTS)
      ->put(measurement_str, CodeStatus::ALLOWED_TO_JOIN);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = store->create_read_only_tx();
    CHECK(
      verify_enclave_measurement_against_store(
        tx, measurement, QuoteFormat::insecure_virtual, std::nullopt) ==
      QuoteVerificationResult::Verified);
  }
}

TEST_CASE("verify_enclave_measurement_against_store: SNP")
{
  for (const auto& fixture : all_product_fixtures())
  {
    auto facts = derive_facts(fixture);
    auto store = make_store();

    {
      auto tx = store->create_read_only_tx();
      CHECK(
        verify_enclave_measurement_against_store(
          tx, facts.measurement, QuoteFormat::amd_sev_snp_v1, std::nullopt) ==
        QuoteVerificationResult::FailedMeasurementNotFound);
    }

    {
      auto tx = store->create_tx();
      tx.rw<SnpMeasurements>(Tables::NODE_SNP_MEASUREMENTS)
        ->put(
          pal::SnpAttestationMeasurement(facts.measurement),
          CodeStatus::ALLOWED_TO_JOIN);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      auto tx = store->create_read_only_tx();
      CHECK(
        verify_enclave_measurement_against_store(
          tx, facts.measurement, QuoteFormat::amd_sev_snp_v1, std::nullopt) ==
        QuoteVerificationResult::Verified);
    }

    // UVM endorsements are preferred over the SnpMeasurements table when
    // present, even if the store's measurement table alone would have
    // matched. There is no real UVM endorsements COSE fixture in the repo, so
    // a minimal, hand-crafted COSE_Sign1 envelope is used instead: a
    // protected header with an unsupported signature algorithm (neither
    // RSA nor ECDSA), which is far enough along the parsing path to reach
    // uvm_endorsements.cpp's explicit std::logic_error rejection (caught by
    // verify_enclave_measurement_against_uvm_endorsements and reported as
    // FailedUVMEndorsementsNotFound), rather than an earlier CBOR parse
    // failure that is not caught by that function's narrower
    // catch(std::logic_error&) clause.
    // CBOR layout: tag(18) COSE_Sign1, array(1) [ protected header bstr ]
    // protected header map: {1 (alg): 100 (unsupported),
    //                        3 (content-type): "x",
    //                        33 (x5chain): h'' (empty bstr),
    //                        "iss": "d", "feed": "f"}
    // Also populate a root-of-trust entry in the SNPUVMEndorsements table
    // first, so that verify_enclave_measurement_against_uvm_endorsements's
    // KV-to-vector conversion loop (over the DID -> feed -> svn map) is
    // exercised, even though the crafted envelope above still fails before
    // any comparison against it is made.
    {
      auto write_tx = store->create_tx();
      auto* uvmes =
        write_tx.rw<SNPUVMEndorsements>(Tables::NODE_SNP_UVM_ENDORSEMENTS);
      FeedToEndorsementsDataMap feed_map;
      feed_map["test-feed"] = UVMEndorsementsData{"1"};
      uvmes->put("did:x509:test-issuer", feed_map);
      REQUIRE(write_tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      const std::vector<uint8_t> phdr_map = {
        0xa5, 0x01, 0x18, 0x64, 0x03, 0x61, 0x78, 0x18, 0x21, 0x40, 0x63, 0x69,
        0x73, 0x73, 0x61, 0x64, 0x64, 0x66, 0x65, 0x65, 0x64, 0x61, 0x66};
      std::vector<uint8_t> not_uvm_endorsements = {0xd2, 0x81, 0x57};
      not_uvm_endorsements.insert(
        not_uvm_endorsements.end(), phdr_map.begin(), phdr_map.end());

      auto tx = store->create_read_only_tx();
      CHECK(
        verify_enclave_measurement_against_store(
          tx,
          facts.measurement,
          QuoteFormat::amd_sev_snp_v1,
          not_uvm_endorsements) ==
        QuoteVerificationResult::FailedUVMEndorsementsNotFound);
    }
  }
}

TEST_CASE("verify_host_data_against_store: unsupported platform throws")
{
  // Only SNP and virtual quotes carry a host data digest; anything else
  // (e.g. SGX) is a defensive programming-error case.
  auto store = make_store();
  QuoteInfo quote_info;
  quote_info.format = QuoteFormat::oe_sgx_v1;
  std::optional<HostData> host_data;
  auto tx = store->create_read_only_tx();
  CHECK_THROWS_AS(
    verify_host_data_against_store(tx, quote_info, host_data),
    std::logic_error);
}

TEST_CASE("verify_host_data_against_store: SNP")
{
  for (const auto& fixture : all_product_fixtures())
  {
    auto facts = derive_facts(fixture);
    auto quote_info = make_snp_quote_info(fixture);
    auto store = make_store();

    {
      auto tx = store->create_read_only_tx();
      std::optional<HostData> host_data;
      CHECK(
        verify_host_data_against_store(tx, quote_info, host_data) ==
        QuoteVerificationResult::FailedInvalidHostData);
      REQUIRE(host_data.has_value());
      CHECK(host_data.value() == facts.host_data);
    }

    {
      auto tx = store->create_tx();
      tx.rw<SnpHostDataMap>(Tables::HOST_DATA)->put(facts.host_data, "");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      auto tx = store->create_read_only_tx();
      std::optional<HostData> host_data;
      CHECK(
        verify_host_data_against_store(tx, quote_info, host_data) ==
        QuoteVerificationResult::Verified);
    }
  }

  // A truncated/malformed SNP report cannot be verified at all, so
  // AttestationProvider::get_host_data returns nullopt and the store lookup
  // is never reached.
  {
    auto store = make_store();
    auto tx = store->create_read_only_tx();
    QuoteInfo bad_quote_info = {
      .format = QuoteFormat::amd_sev_snp_v1,
      .quote = std::vector<uint8_t>(100),
      .endorsements = {},
      .uvm_endorsements = std::nullopt,
    };
    std::optional<HostData> host_data;
    CHECK(
      verify_host_data_against_store(tx, bad_quote_info, host_data) ==
      QuoteVerificationResult::FailedHostDataDigestNotFound);
    CHECK_FALSE(host_data.has_value());
  }
}

TEST_CASE("verify_host_data_against_store: virtual")
{
  auto store = make_store();
  const auto host_data_hash = ccf::crypto::Sha256Hash(std::string("policy"));

  auto make_virtual_quote = [&](bool include_host_data) {
    auto j = nlohmann::json::object();
    j["measurement"] = "virtual-measurement";
    j["report_data"] = std::vector<uint8_t>(32, 0);
    if (include_host_data)
    {
      j["host_data"] = host_data_hash.hex_str();
    }
    auto dumped = j.dump();
    return QuoteInfo{
      .format = QuoteFormat::insecure_virtual,
      .quote = std::vector<uint8_t>(dumped.begin(), dumped.end()),
      .endorsements = {},
      .uvm_endorsements = std::nullopt,
    };
  };

  {
    // No "host_data" field in the virtual quote at all.
    auto tx = store->create_read_only_tx();
    auto quote_info = make_virtual_quote(false);
    std::optional<HostData> host_data;
    CHECK(
      verify_host_data_against_store(tx, quote_info, host_data) ==
      QuoteVerificationResult::FailedHostDataDigestNotFound);
    CHECK_FALSE(host_data.has_value());
  }

  auto quote_info = make_virtual_quote(true);
  {
    auto tx = store->create_read_only_tx();
    std::optional<HostData> host_data;
    CHECK(
      verify_host_data_against_store(tx, quote_info, host_data) ==
      QuoteVerificationResult::FailedInvalidHostData);
    REQUIRE(host_data.has_value());
    CHECK(host_data.value() == host_data_hash);
  }

  {
    auto tx = store->create_tx();
    tx.rw<VirtualHostDataMap>(Tables::VIRTUAL_HOST_DATA)
      ->insert(host_data_hash);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = store->create_read_only_tx();
    std::optional<HostData> host_data;
    CHECK(
      verify_host_data_against_store(tx, quote_info, host_data) ==
      QuoteVerificationResult::Verified);
  }
}

TEST_CASE("verify_tcb_version_against_store")
{
  for (const auto& fixture : all_product_fixtures())
  {
    auto facts = derive_facts(fixture);
    auto quote_info = make_snp_quote_info(fixture);

    SUBCASE("CPUID entry missing")
    {
      auto store = make_store();
      auto tx = store->create_read_only_tx();
      CHECK(
        verify_tcb_version_against_store(tx, quote_info) ==
        QuoteVerificationResult::FailedInvalidCPUID);
    }

    SUBCASE("Minimum TCB matches the reported TCB exactly: Verified")
    {
      auto store = make_store();
      populate_store_for_fixture(
        *store, fixture, facts, false, false, facts.reported_tcb);
      auto tx = store->create_read_only_tx();
      CHECK(
        verify_tcb_version_against_store(tx, quote_info) ==
        QuoteVerificationResult::Verified);
    }

    SUBCASE("Minimum TCB below the reported TCB: Verified")
    {
      auto lower_tcb = facts.reported_tcb;
      REQUIRE(lower_tcb.microcode.has_value());
      lower_tcb.microcode = lower_tcb.microcode.value() - 1;
      auto store = make_store();
      populate_store_for_fixture(
        *store, fixture, facts, false, false, lower_tcb);
      auto tx = store->create_read_only_tx();
      CHECK(
        verify_tcb_version_against_store(tx, quote_info) ==
        QuoteVerificationResult::Verified);
    }

    SUBCASE("Minimum TCB above the reported TCB: FailedInvalidTcbVersion")
    {
      auto higher_tcb = facts.reported_tcb;
      REQUIRE(higher_tcb.microcode.has_value());
      higher_tcb.microcode = higher_tcb.microcode.value() + 1;
      auto store = make_store();
      populate_store_for_fixture(
        *store, fixture, facts, false, false, higher_tcb);
      auto tx = store->create_read_only_tx();
      CHECK(
        verify_tcb_version_against_store(tx, quote_info) ==
        QuoteVerificationResult::FailedInvalidTcbVersion);
    }

    if (facts.reported_tcb.fmc.has_value())
    {
      // Turin-only comparison path.
      SUBCASE("Minimum fmc above the reported fmc: FailedInvalidTcbVersion")
      {
        auto higher_fmc_tcb = facts.reported_tcb;
        higher_fmc_tcb.fmc = higher_fmc_tcb.fmc.value() + 1;
        auto store = make_store();
        populate_store_for_fixture(
          *store, fixture, facts, false, false, higher_fmc_tcb);
        auto tx = store->create_read_only_tx();
        CHECK(
          verify_tcb_version_against_store(tx, quote_info) ==
          QuoteVerificationResult::FailedInvalidTcbVersion);
      }
    }
    else
    {
      // Milan/Genoa-only comparison path (family/model, no fmc).
      SUBCASE(
        "Minimum boot_loader above the reported boot_loader: "
        "FailedInvalidTcbVersion")
      {
        auto higher_bl_tcb = facts.reported_tcb;
        REQUIRE(higher_bl_tcb.boot_loader.has_value());
        higher_bl_tcb.boot_loader = higher_bl_tcb.boot_loader.value() + 1;
        auto store = make_store();
        populate_store_for_fixture(
          *store, fixture, facts, false, false, higher_bl_tcb);
        auto tx = store->create_read_only_tx();
        CHECK(
          verify_tcb_version_against_store(tx, quote_info) ==
          QuoteVerificationResult::FailedInvalidTcbVersion);
      }
    }
  }

  SUBCASE("Non-SNP quote formats trivially verify")
  {
    auto store = make_store();
    auto tx = store->create_read_only_tx();
    for (const auto format :
         {QuoteFormat::oe_sgx_v1, QuoteFormat::insecure_virtual})
    {
      QuoteInfo quote_info = {
        .format = format,
        .quote = {},
        .endorsements = {},
        .uvm_endorsements = std::nullopt};
      CHECK(
        verify_tcb_version_against_store(tx, quote_info) ==
        QuoteVerificationResult::Verified);
    }
  }
}

TEST_CASE("AttestationProvider::get_measurement")
{
  auto fixture = all_product_fixtures().front();
  auto quote_info = make_snp_quote_info(fixture);
  auto measurement = AttestationProvider::get_measurement(quote_info);
  REQUIRE(measurement.has_value());

  QuoteInfo bad_quote_info = {
    .format = QuoteFormat::amd_sev_snp_v1,
    .quote = std::vector<uint8_t>(100),
    .endorsements = {},
    .uvm_endorsements = std::nullopt,
  };
  CHECK_FALSE(AttestationProvider::get_measurement(bad_quote_info).has_value());
}

TEST_CASE("AttestationProvider::get_snp_attestation_report")
{
  auto fixture = all_product_fixtures().front();
  auto quote_info = make_snp_quote_info(fixture);
  CHECK(
    AttestationProvider::get_snp_attestation_report(quote_info).has_value());

  // Non-SNP format: rejected before any parsing is attempted.
  QuoteInfo virtual_quote_info = {
    .format = QuoteFormat::insecure_virtual,
    .quote = {},
    .endorsements = {},
    .uvm_endorsements = std::nullopt,
  };
  CHECK_FALSE(
    AttestationProvider::get_snp_attestation_report(virtual_quote_info)
      .has_value());

  // Malformed/truncated report: caught and turned into nullopt.
  QuoteInfo bad_quote_info = {
    .format = QuoteFormat::amd_sev_snp_v1,
    .quote = std::vector<uint8_t>(100),
    .endorsements = {},
    .uvm_endorsements = std::nullopt,
  };
  CHECK_FALSE(AttestationProvider::get_snp_attestation_report(bad_quote_info)
                .has_value());
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
TEST_CASE("AttestationProvider::get_snp_attestation (deprecated legacy API)")
{
  auto fixture = all_product_fixtures().front();
  auto quote_info = make_snp_quote_info(fixture);
  auto legacy = AttestationProvider::get_snp_attestation(quote_info);
  REQUIRE(legacy.has_value());

  pal::PlatformAttestationMeasurement measurement;
  pal::PlatformAttestationReportData report_data;
  auto report = pal::verify_snp_attestation_report_and_get(
    quote_info, measurement, report_data);
  CHECK(
    legacy->cpuid_fam_id ==
    tav_snp_attestation_report_cpuid_fam_id(report.get()));

  // Non-SNP format.
  QuoteInfo virtual_quote_info = {
    .format = QuoteFormat::insecure_virtual,
    .quote = {},
    .endorsements = {},
    .uvm_endorsements = std::nullopt,
  };
  CHECK_FALSE(
    AttestationProvider::get_snp_attestation(virtual_quote_info).has_value());
}
#pragma GCC diagnostic pop

TEST_CASE("AttestationProvider::get_host_data: SNP")
{
  for (const auto& fixture : all_product_fixtures())
  {
    auto facts = derive_facts(fixture);
    auto quote_info = make_snp_quote_info(fixture);
    auto host_data = AttestationProvider::get_host_data(quote_info);
    REQUIRE(host_data.has_value());
    CHECK(host_data.value() == facts.host_data);
  }

  // Malformed report.
  QuoteInfo bad_quote_info = {
    .format = QuoteFormat::amd_sev_snp_v1,
    .quote = std::vector<uint8_t>(100),
    .endorsements = {},
    .uvm_endorsements = std::nullopt,
  };
  CHECK_FALSE(AttestationProvider::get_host_data(bad_quote_info).has_value());
}

TEST_CASE("AttestationProvider::get_host_data: SGX returns nullopt")
{
  QuoteInfo quote_info = {
    .format = QuoteFormat::oe_sgx_v1,
    .quote = {},
    .endorsements = {},
    .uvm_endorsements = std::nullopt,
  };
  CHECK_FALSE(AttestationProvider::get_host_data(quote_info).has_value());
}

TEST_CASE("pal::verify_virtual_attestation_report: malformed quotes")
{
  pal::PlatformAttestationMeasurement measurement;
  pal::PlatformAttestationReportData report_data;

  SUBCASE("Not JSON at all")
  {
    QuoteInfo quote_info = {
      .format = QuoteFormat::insecure_virtual,
      .quote = {0xff, 0xfe, 0x00},
      .endorsements = {},
      .uvm_endorsements = std::nullopt,
    };
    CHECK_THROWS(pal::verify_virtual_attestation_report(
      quote_info, measurement, report_data));
  }

  SUBCASE("Missing measurement field")
  {
    auto j = nlohmann::json::object();
    j["report_data"] = std::vector<uint8_t>(32, 0);
    auto dumped = j.dump();
    QuoteInfo quote_info = {
      .format = QuoteFormat::insecure_virtual,
      .quote = std::vector<uint8_t>(dumped.begin(), dumped.end()),
      .endorsements = {},
      .uvm_endorsements = std::nullopt,
    };
    CHECK_THROWS(pal::verify_virtual_attestation_report(
      quote_info, measurement, report_data));
  }

  SUBCASE("Missing report_data field")
  {
    auto j = nlohmann::json::object();
    j["measurement"] = "some-measurement";
    auto dumped = j.dump();
    QuoteInfo quote_info = {
      .format = QuoteFormat::insecure_virtual,
      .quote = std::vector<uint8_t>(dumped.begin(), dumped.end()),
      .endorsements = {},
      .uvm_endorsements = std::nullopt,
    };
    CHECK_THROWS(pal::verify_virtual_attestation_report(
      quote_info, measurement, report_data));
  }

  SUBCASE("Well-formed quote succeeds and round-trips the raw fields")
  {
    auto j = nlohmann::json::object();
    j["measurement"] = "some-measurement";
    j["report_data"] = std::vector<uint8_t>(32, 0x42);
    auto dumped = j.dump();
    QuoteInfo quote_info = {
      .format = QuoteFormat::insecure_virtual,
      .quote = std::vector<uint8_t>(dumped.begin(), dumped.end()),
      .endorsements = {},
      .uvm_endorsements = std::nullopt,
    };
    pal::verify_virtual_attestation_report(
      quote_info, measurement, report_data);
    CHECK(
      std::string(measurement.data.begin(), measurement.data.end()) ==
      "some-measurement");
    CHECK(report_data.data == std::vector<uint8_t>(32, 0x42));
  }
}

TEST_CASE("VCEK certificate extensions missing: chip ID and TCB SPLs")
{
  // A plain self-signed certificate has none of the AMD VCEK extensions
  // (chip ID, TCB SPLs), exercising the "extension not present" branches of
  // get_endorsed_chip_id_from_cert and get_endorsed_tcb_from_cert (Milan/
  // Genoa and Turin variants) without needing a real VCEK certificate.
  //
  // The full
  // verify_snp_attestation_report/verify_snp_attestation_report_and_get
  // pipeline now fails closed (throws std::logic_error) when
  // get_endorsed_tcb_from_cert returns nullopt for a real report's VCEK
  // leaf certificate, rather than silently skipping the endorsed-vs-reported
  // TCB comparison. That end-to-end rejection cannot be exercised here: it
  // requires a VCEK leaf certificate that is missing the TCB SPL extension
  // but nonetheless chains to a real AMD root of trust, which cannot be
  // fabricated in a unit test (a self-signed certificate, as used below,
  // fails chain validation long before the TCB SPL extension is even
  // consulted). So only this lower-level function is tested directly.
  auto key_pair = ccf::crypto::make_ec_key_pair();
  auto cert = ccf::crypto::create_self_signed_cert(
    key_pair, "CN=test", {}, "20240101000000Z", 365);

  CHECK_FALSE(pal::get_endorsed_chip_id_from_cert(cert).has_value());
  CHECK_FALSE(
    pal::get_endorsed_tcb_from_cert(pal::snp::ProductName::Milan, cert)
      .has_value());
  CHECK_FALSE(
    pal::get_endorsed_tcb_from_cert(pal::snp::ProductName::Turin, cert)
      .has_value());
}

TEST_CASE("AttestationProvider::verify_quote_against_store: SNP")
{
  for (const auto& fixture : all_product_fixtures())
  {
    auto facts = derive_facts(fixture);
    auto quote_info = make_snp_quote_info(fixture);
    // The fixture's own report_data is unrelated to any public key that
    // this test can supply the private key for, so the final quoted-node
    // public-key stage is always expected to fail once every earlier store
    // stage has succeeded (see the "public key mismatch" subcase below).
    const std::vector<uint8_t> arbitrary_node_public_key_der = {1, 2, 3, 4};
    pal::PlatformAttestationMeasurement measurement;

    SUBCASE("malformed quote: Failed")
    {
      // pal::verify_quote (cryptographic/structural verification) is tried
      // before any store lookups; a truncated report fails there and
      // verify_quote_against_store reports the generic Failed result.
      auto store = make_store();
      auto tx = store->create_read_only_tx();
      auto truncated_quote_info = quote_info;
      truncated_quote_info.quote.resize(quote_info.quote.size() / 2);
      CHECK(
        AttestationProvider::verify_quote_against_store(
          tx,
          truncated_quote_info,
          arbitrary_node_public_key_der,
          measurement,
          std::nullopt) == QuoteVerificationResult::Failed);
    }

    SUBCASE("host data not in store: FailedInvalidHostData")
    {
      auto store = make_store();
      auto tx = store->create_read_only_tx();
      CHECK(
        AttestationProvider::verify_quote_against_store(
          tx,
          quote_info,
          arbitrary_node_public_key_der,
          measurement,
          std::nullopt) == QuoteVerificationResult::FailedInvalidHostData);
    }

    // When host data is present in the report but not listed in the store,
    // an optional code_transparent_statement is used as an alternative path
    // (verify_code_transparent_statement). A malformed statement cannot be
    // parsed as a signed CBOR COSE_Sign1 envelope, so the outer try/catch in
    // verify_code_transparent_statement converts the parse failure into
    // FailedInvalidHostData, the same result as when no statement is given
    // at all.
    SUBCASE(
      "host data not in store, malformed code transparent statement: "
      "FailedInvalidHostData")
    {
      auto store = make_store();
      auto tx = store->create_read_only_tx();
      const std::vector<uint8_t> malformed_transparent_statement = {
        0xff, 0xff, 0xff};
      CHECK(
        AttestationProvider::verify_quote_against_store(
          tx,
          quote_info,
          arbitrary_node_public_key_der,
          measurement,
          malformed_transparent_statement) ==
        QuoteVerificationResult::FailedInvalidHostData);
    }

    SUBCASE("measurement not in store: FailedMeasurementNotFound")
    {
      auto store = make_store();
      populate_store_for_fixture(
        *store, fixture, facts, false, true, std::nullopt, false);
      auto tx = store->create_read_only_tx();
      CHECK(
        AttestationProvider::verify_quote_against_store(
          tx,
          quote_info,
          arbitrary_node_public_key_der,
          measurement,
          std::nullopt) == QuoteVerificationResult::FailedMeasurementNotFound);
    }

    SUBCASE("TCB CPUID missing from store: FailedInvalidCPUID")
    {
      auto store = make_store();
      populate_store_for_fixture(
        *store, fixture, facts, true, true, std::nullopt, false);
      auto tx = store->create_read_only_tx();
      CHECK(
        AttestationProvider::verify_quote_against_store(
          tx,
          quote_info,
          arbitrary_node_public_key_der,
          measurement,
          std::nullopt) == QuoteVerificationResult::FailedInvalidCPUID);
    }

    SUBCASE("TCB minimum too high in store: FailedInvalidTcbVersion")
    {
      auto higher_tcb = facts.reported_tcb;
      REQUIRE(higher_tcb.microcode.has_value());
      higher_tcb.microcode = higher_tcb.microcode.value() + 1;
      auto store = make_store();
      populate_store_for_fixture(
        *store, fixture, facts, true, true, higher_tcb);
      auto tx = store->create_read_only_tx();
      CHECK(
        AttestationProvider::verify_quote_against_store(
          tx,
          quote_info,
          arbitrary_node_public_key_der,
          measurement,
          std::nullopt) == QuoteVerificationResult::FailedInvalidTcbVersion);
    }

    SUBCASE(
      "All store stages pass, quoted public key mismatch: "
      "FailedInvalidQuotedPublicKey")
    {
      auto store = make_store();
      populate_store_for_fixture(*store, fixture, facts, true, true);
      auto tx = store->create_read_only_tx();
      CHECK(
        AttestationProvider::verify_quote_against_store(
          tx,
          quote_info,
          arbitrary_node_public_key_der,
          measurement,
          std::nullopt) ==
        QuoteVerificationResult::FailedInvalidQuotedPublicKey);
      CHECK(measurement.data == facts.measurement.data);
    }
  }
}

TEST_CASE(
  "AttestationProvider::verify_quote_against_store: virtual, full "
  "success path")
{
  // Unlike the SNP fixtures (whose report_data comes from an attestation
  // this test does not hold the signing key for), a virtual quote's
  // report_data is entirely test-controlled, so this is the one format for
  // which the full Verified path (including the quoted node public key
  // check) can be exercised end to end.
  auto node_public_key_der = std::vector<uint8_t>{10, 20, 30, 40, 50};
  auto expected_hash = ccf::crypto::Sha256Hash(node_public_key_der);

  const std::string measurement_str = "virtual-measurement";
  auto j = nlohmann::json::object();
  j["measurement"] = measurement_str;
  j["report_data"] =
    std::vector<uint8_t>(expected_hash.h.begin(), expected_hash.h.end());
  j["host_data"] = expected_hash.hex_str();
  auto dumped = j.dump();
  QuoteInfo quote_info = {
    .format = QuoteFormat::insecure_virtual,
    .quote = std::vector<uint8_t>(dumped.begin(), dumped.end()),
    .endorsements = {},
    .uvm_endorsements = std::nullopt,
  };

  auto store = make_store();
  {
    auto tx = store->create_tx();
    tx.rw<VirtualMeasurements>(Tables::NODE_VIRTUAL_MEASUREMENTS)
      ->put(measurement_str, CodeStatus::ALLOWED_TO_JOIN);
    tx.rw<VirtualHostDataMap>(Tables::VIRTUAL_HOST_DATA)->insert(expected_hash);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  auto tx = store->create_read_only_tx();
  pal::PlatformAttestationMeasurement measurement;
  CHECK(
    AttestationProvider::verify_quote_against_store(
      tx, quote_info, node_public_key_der, measurement, std::nullopt) ==
    QuoteVerificationResult::Verified);
  CHECK(
    std::string(measurement.data.begin(), measurement.data.end()) ==
    measurement_str);
}
