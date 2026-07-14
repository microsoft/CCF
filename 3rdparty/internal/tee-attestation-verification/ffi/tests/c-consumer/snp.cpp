// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Consumer tests for the SNP attestation C ABI (tav/snp.h).

#include "support.h"

using namespace tav_test;

namespace {

struct MilanInputs {
    std::vector<uint8_t> report;
    std::vector<uint8_t> ark;
    std::vector<uint8_t> ask;
    std::vector<uint8_t> vcek;
};

MilanInputs load_milan_inputs() {
    return MilanInputs{
        read_file("attestation/tests/test_data/milan_attestation_report.bin"),
        read_file("attestation/src/pinned_arks/milan_ark.pem"),
        read_file("attestation/tests/test_data/milan_ask.pem"),
        read_file("attestation/tests/test_data/milan_vcek.pem"),
    };
}

TavError *verify_milan(const MilanInputs &in, TavSnpAttestationReport **report) {
    return tav_verify_snp_attestation(
        in.report.data(), in.report.size(),
        in.ark.data(), in.ark.size(),
        in.ask.data(), in.ask.size(),
        in.vcek.data(), in.vcek.size(),
        report);
}

using BytesAccessor =
    void (*)(const TavSnpAttestationReport *, const uint8_t **, size_t *);

// Calls a borrowed-view byte accessor and returns its contents as lowercase
// hex, so fixed-size fields can be compared against the checked-in golden.
std::string hex_field(const TavSnpAttestationReport *report, BytesAccessor accessor) {
    const uint8_t *data = nullptr;
    size_t len = 0;
    accessor(report, &data, &len);
    REQUIRE(data != nullptr);

    return hex_encode(data, len);
}

} // namespace

TEST_CASE("snp: every report accessor exposes the golden Milan value") {
    MilanInputs in = load_milan_inputs();

    TavSnpAttestationReport *report = nullptr;
    TavError *error = verify_milan(in, &report);

    REQUIRE(error == nullptr);
    REQUIRE(report != nullptr);

    // Golden values from demos/c-ffi/test-data/milan-output.golden.txt, which is
    // produced from the same four Milan fixtures loaded above. This exercises
    // every accessor declared in tav/snp.h exactly once.

    // Scalar accessors.
    CHECK(tav_snp_attestation_report_version(report) == 3);
    CHECK(tav_snp_attestation_report_guest_svn(report) == 2);
    CHECK(tav_snp_attestation_report_policy(report) == 0x3001full);
    CHECK(tav_snp_attestation_report_policy_abi_minor(report) == 31);
    CHECK(tav_snp_attestation_report_policy_abi_major(report) == 0);
    CHECK(tav_snp_attestation_report_policy_smt(report));
    CHECK_FALSE(tav_snp_attestation_report_policy_migrate_ma(report));
    CHECK_FALSE(tav_snp_attestation_report_policy_debug(report));
    CHECK_FALSE(tav_snp_attestation_report_policy_single_socket(report));
    CHECK_FALSE(tav_snp_attestation_report_policy_cxl_allow(report));
    CHECK_FALSE(tav_snp_attestation_report_policy_mem_aes_256_xts(report));
    CHECK_FALSE(tav_snp_attestation_report_policy_rapl_dis(report));
    CHECK_FALSE(tav_snp_attestation_report_policy_ciphertext_hiding_dram(report));
    CHECK_FALSE(tav_snp_attestation_report_policy_page_swap_disable(report));
    CHECK(tav_snp_attestation_report_vmpl(report) == 0);
    CHECK(tav_snp_attestation_report_signature_algo(report) == 1);
    CHECK(tav_snp_attestation_report_platform_info(report) == 0x25ull);
    CHECK(tav_snp_attestation_report_flags(report) == 0x0u);
    CHECK_FALSE(tav_snp_attestation_report_flags_author_key_en(report));
    CHECK_FALSE(tav_snp_attestation_report_flags_mask_chip_key(report));
    CHECK(tav_snp_attestation_report_flags_signing_key(report) == 0);
    CHECK(tav_snp_attestation_report_cpuid_fam_id(report) == 25);
    CHECK(tav_snp_attestation_report_cpuid_mod_id(report) == 1);
    CHECK(tav_snp_attestation_report_cpuid_step(report) == 1);
    CHECK(tav_snp_attestation_report_current_build(report) == 29);
    CHECK(tav_snp_attestation_report_current_minor(report) == 55);
    CHECK(tav_snp_attestation_report_current_major(report) == 1);
    CHECK(tav_snp_attestation_report_committed_build(report) == 29);
    CHECK(tav_snp_attestation_report_committed_minor(report) == 55);
    CHECK(tav_snp_attestation_report_committed_major(report) == 1);

    // Borrowed byte-slice accessors. The full contents (and therefore lengths)
    // are compared against the golden hex.
    CHECK(hex_field(report, tav_snp_attestation_report_family_id) ==
          "01000000000000000000000000000000");
    CHECK(hex_field(report, tav_snp_attestation_report_image_id) ==
          "02000000000000000000000000000000");
    CHECK(hex_field(report, tav_snp_attestation_report_platform_version) ==
          "04000000000018db");
    CHECK(hex_field(report, tav_snp_attestation_report_report_data) ==
          "0000000000000000000000000000000000000000000000000000000000000000"
          "0000000000000000000000000000000000000000000000000000000000000000");
    CHECK(hex_field(report, tav_snp_attestation_report_measurement) ==
          "5feee30d6d7e1a29f403d70a4198237ddfb13051a2d6976439487c609388ed7f9818"
          "9887920ab2fa0096903a0c23fca1");
    CHECK(hex_field(report, tav_snp_attestation_report_host_data) ==
          "4f4448c67f3c8dfc8de8a5e37125d807dadcc41f06cf23f615dbd52eec777d10");
    CHECK(hex_field(report, tav_snp_attestation_report_id_key_digest) ==
          "0ad79ceb0b648b0e6a90d8aa9f6ea24c33a968b6632085353145e8b19a4741a2dab9"
          "ba342e13be4fc0d225e889cc1a58");
    CHECK(hex_field(report, tav_snp_attestation_report_author_key_digest) ==
          "00000000000000000000000000000000000000000000000000000000000000000000"
          "0000000000000000000000000000");
    CHECK(hex_field(report, tav_snp_attestation_report_report_id) ==
          "5e01036273418d910bdca3f5cb9c7d849e88e2141483eb6cc9afd794ffbbbcbc");
    CHECK(hex_field(report, tav_snp_attestation_report_report_id_ma) ==
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    CHECK(hex_field(report, tav_snp_attestation_report_reported_tcb) ==
          "04000000000018db");
    CHECK(hex_field(report, tav_snp_attestation_report_chip_id) ==
          "4ffb5cb4fd594f3fee6528fc3fb10370bb38abe89dcd5ba2cf0ab6a11df2ca282add"
          "516bef45a890a8c9f9732bdca68f9f3f16c42e846030a800295dbeb19ba5");
    CHECK(hex_field(report, tav_snp_attestation_report_committed_tcb) ==
          "04000000000018db");
    CHECK(hex_field(report, tav_snp_attestation_report_launch_tcb) ==
          "04000000000018db");
    CHECK(hex_field(report, tav_snp_attestation_report_signature_r) ==
          "c4c97ce68cfa7fe769a569fc55cee5ad38b238a4e1db928436a006b76e9a5885851d"
          "13c88892e5ffd93f3e1cf853f3b7000000000000000000000000000000000000000"
          "000000000");
    CHECK(hex_field(report, tav_snp_attestation_report_signature_s) ==
          "1e739e881fffadfeab34e3fb205ff0a5d8992496d0fb390a18baa725de048253e664"
          "e519b8f38309061b4af2a3e69f53000000000000000000000000000000000000000"
          "000000000");

    tav_snp_attestation_report_free(report);
}

TEST_CASE("snp: a tampered report fails verification and leaves the handle null") {
    MilanInputs in = load_milan_inputs();
    // Corrupt the measurement region so the AMD signature no longer matches.
    in.report.at(0x90) ^= 0xff;

    TavSnpAttestationReport *report = nullptr;
    TavError *error = verify_milan(in, &report);

    REQUIRE(error != nullptr);
    CHECK(report == nullptr);
    CHECK(tav_error_code(error) == TAV_ERROR_SNP_SIGNATURE_VERIFICATION_ERROR);
    CHECK(std::string(tav_error_message(error)).size() > 0);
    tav_error_free(error);
}

TEST_CASE("snp: oversized input is rejected before any dereference") {
    uint8_t dummy = 0;
    TavSnpAttestationReport *report = nullptr;

    TavError *error = tav_verify_snp_attestation(
        &dummy, kMaxInputLen + 1,
        &dummy, 1,
        &dummy, 1,
        &dummy, 1,
        &report);

    REQUIRE(error != nullptr);
    CHECK(tav_error_code(error) == TAV_ERROR_INVALID_ARGUMENT);
    CHECK(std::string(tav_error_message(error)) ==
          "attestation report exceeds maximum input size");
    CHECK(report == nullptr);
    tav_error_free(error);
}
