// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Consumer tests for the staged Confidential ACI attestation C ABI (tav/caci.h).

#include "support.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

using namespace tav_test;

namespace {

// did:x509 root and UVM parameters mirror demos/caci-c-ffi/run_tests.py, which
// in turn matches the CACI C FFI demo CI job and README.
constexpr const char kTrustedDidx509[] =
    "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s"
    "::eku:1.3.6.1.4.1.311.76.59.1.2";
constexpr const char kUvmFeed[] = "ContainerPlat-AMD-UVM";
constexpr uint64_t kMinimumSvn = 104;

// The demo hard-codes a single minimum-TCB entry for the fixture platform.
constexpr uint32_t kMinimumTcbCpuid = 0x00A00F11;
constexpr std::array<uint8_t, 8> kMinimumTcbValue = {
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0xdb};

// Split a two-certificate PEM chain (ASK then ARK) into its two PEM blocks.
std::pair<std::string, std::string> split_pem_chain(const std::string &chain) {
    static const std::string begin = "-----BEGIN CERTIFICATE-----";
    static const std::string end = "-----END CERTIFICATE-----";

    size_t ask_begin = chain.find(begin);
    if (ask_begin == std::string::npos) fixture_error("chain missing ASK certificate");
    size_t ask_end = chain.find(end, ask_begin);
    if (ask_end == std::string::npos) fixture_error("chain ASK certificate unterminated");
    ask_end += end.size();

    size_t ark_begin = chain.find(begin, ask_end);
    if (ark_begin == std::string::npos) fixture_error("chain missing ARK certificate");
    size_t ark_end = chain.find(end, ark_begin);
    if (ark_end == std::string::npos) fixture_error("chain ARK certificate unterminated");
    ark_end += end.size();

    return {chain.substr(ask_begin, ask_end - ask_begin),
            chain.substr(ark_begin, ark_end - ark_begin)};
}

struct CaciInputs {
    std::vector<uint8_t> report;
    std::string ark;
    std::string ask;
    std::string vcek;
    std::vector<uint8_t> uvm;
    std::vector<uint8_t> policy; // one 32-byte SNP HOST_DATA digest
};

CaciInputs load_caci_inputs() {
    CaciInputs in;
    in.report = hex_decode(read_file("caci/tests/fixtures/report.hex"));
    in.uvm = base64_decode(read_file("caci/tests/fixtures/reference-info.base64"));
    in.policy = hex_decode(read_file("demos/caci-c-ffi/test-data/policy.hex"));
    REQUIRE(in.policy.size() == 32);

    std::string bundle = to_string(base64_decode(read_file("caci/tests/fixtures/host-amd-cert.base64")));
    in.vcek = json_string_field(bundle, "vcekCert");
    std::string chain = json_string_field(bundle, "certificateChain");
    auto [ask, ark] = split_pem_chain(chain);
    in.ask = std::move(ask);
    in.ark = std::move(ark);
    return in;
}

// Owns the two verified handles that tav_verify_caci_attestation consumes.
struct VerifiedArtifacts {
    TavSnpAttestationReport *attestation = nullptr;
    TavCborValue *uvm_endorsement = nullptr;

    ~VerifiedArtifacts() {
        tav_cbor_value_free(uvm_endorsement);
        tav_snp_attestation_report_free(attestation);
    }
};

void verify_staged_artifacts(const CaciInputs &in, VerifiedArtifacts &out) {
    TavError *error = tav_verify_snp_attestation(
        in.report.data(), in.report.size(),
        reinterpret_cast<const uint8_t *>(in.ark.data()), in.ark.size(),
        reinterpret_cast<const uint8_t *>(in.ask.data()), in.ask.size(),
        reinterpret_cast<const uint8_t *>(in.vcek.data()), in.vcek.size(),
        &out.attestation);
    REQUIRE(error == nullptr);
    REQUIRE(out.attestation != nullptr);

    error = tav_verify_caci_uvm_endorsement(
        in.uvm.data(), in.uvm.size(),
        kTrustedDidx509, std::strlen(kTrustedDidx509),
        &out.uvm_endorsement);
    REQUIRE(error == nullptr);
    REQUIRE(out.uvm_endorsement != nullptr);
}

TavError *verify_caci(const CaciInputs &in, const VerifiedArtifacts &artifacts,
                      TavByteBuffer **report_data) {
    return tav_verify_caci_attestation(
        artifacts.attestation,
        &kMinimumTcbCpuid,
        kMinimumTcbValue.data(),
        1,
        in.policy.data(),
        1,
        artifacts.uvm_endorsement,
        kUvmFeed, std::strlen(kUvmFeed),
        kMinimumSvn,
        report_data);
}

} // namespace

TEST_CASE("caci: staged verification of the fixture attestation succeeds") {
    CaciInputs in = load_caci_inputs();
    VerifiedArtifacts artifacts;
    verify_staged_artifacts(in, artifacts);

    TavByteBuffer *report_data = nullptr;
    TavError *error = verify_caci(in, artifacts, &report_data);

    REQUIRE(error == nullptr);
    REQUIRE(report_data != nullptr);
    CHECK(tav_byte_buffer_len(report_data) == 64);

    // The verified REPORT_DATA must match the SNP report's own REPORT_DATA field.
    const uint8_t *report_data_field = nullptr;
    size_t report_data_field_len = 0;
    tav_snp_attestation_report_report_data(
        artifacts.attestation, &report_data_field, &report_data_field_len);
    REQUIRE(report_data_field_len == tav_byte_buffer_len(report_data));
    CHECK(std::memcmp(tav_byte_buffer_data(report_data), report_data_field,
                      tav_byte_buffer_len(report_data)) == 0);

    tav_byte_buffer_free(report_data);
}

TEST_CASE("caci: an untrusted policy digest is rejected") {
    CaciInputs in = load_caci_inputs();
    VerifiedArtifacts artifacts;
    verify_staged_artifacts(in, artifacts);

    // Flip a byte so the report's HOST_DATA no longer matches any trusted digest.
    in.policy.at(0) ^= 0xff;

    // Seed a non-null sentinel: verification fails deep in the policy check, but
    // the out-parameter must still be reset to NULL and never populated.
    TavByteBuffer *report_data = reinterpret_cast<TavByteBuffer *>(0x1);
    TavError *error = verify_caci(in, artifacts, &report_data);

    REQUIRE(error != nullptr);
    CHECK(tav_error_code(error) == TAV_ERROR_CACI_POLICY);
    CHECK(std::string(tav_error_message(error)).size() > 0);
    CHECK(report_data == nullptr);
    tav_error_free(error);
}

TEST_CASE("caci: uvm-endorsement handle out-parameter is write-only on failure") {
    // A non-null sentinel must be overwritten with NULL before any fallible work.
    TavCborValue *uvm = reinterpret_cast<TavCborValue *>(0x1);
    TavError *error = tav_verify_caci_uvm_endorsement(nullptr, 0, nullptr, 0, &uvm);

    REQUIRE(error != nullptr);
    CHECK(uvm == nullptr);
    CHECK(tav_error_code(error) == TAV_ERROR_INVALID_ARGUMENT);
    tav_error_free(error);
}

TEST_CASE("caci: report-data byte-buffer out-parameter is write-only on failure") {
    TavByteBuffer *bytes = reinterpret_cast<TavByteBuffer *>(0x1);
    TavError *error = tav_verify_caci_attestation(
        nullptr, nullptr, nullptr, 0, nullptr, 0, nullptr, nullptr, 0, 0, &bytes);

    REQUIRE(error != nullptr);
    CHECK(bytes == nullptr);
    tav_error_free(error);
}
