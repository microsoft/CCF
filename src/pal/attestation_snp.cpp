// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#  include "ccf/ds/logger.h"
#  include "ccf/pal/new_attestation.h"
#  include "ccf/crypto/pem.h"
#  include "ccf/crypto/verifier.h"
#  include "clients/rpc_tls_client.h"
#  include "crypto/ecdsa.h"

#  include <fcntl.h>
#  include <sys/ioctl.h>
#  include <unistd.h>

namespace ccf::pal::attestation::snp {

    using ReportData = std::array<uint8_t, 64>;

    namespace constants {

        static constexpr size_t report_data_size = 64;
        static constexpr size_t measurement_size = 48;
        static constexpr size_t host_data_size = 32;

        // Changes on 5.19+ kernel
        constexpr auto DEVICE = "/dev/sev";

        // From https://developer.amd.com/sev/
        constexpr auto amd_milan_root_signing_public_key =
        R"(-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsV
mD7FktuotWwX1fNgW41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU
0V5tkKiU1EesNFta1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S
1ju8X93+6dxDUrG2SzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI5
2Naz5m2B+O+vjsC060d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3K
FYXP59XmJgtcog05gmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd
/y8KxX7jksTEzAOgbKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBk
gnlENEWx1UcbQQrs+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V
9TJQqnN3Q53kt5viQi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnq
z55I0u33wh4r0ZNQeTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+Og
pCCoMNit2uLo9M18fHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXo
QPHfbkH0CyPfhl1jWhJFZasCAwEAAQ==
-----END PUBLIC KEY-----
)";

        // Table 3
#  pragma pack(push, 1)
        struct TcbVersion
        {
        uint8_t boot_loader;
        uint8_t tee;
        uint8_t reserved[4];
        uint8_t snp;
        uint8_t microcode;
        };
#  pragma pack(pop)
        static_assert(
        sizeof(TcbVersion) == sizeof(uint64_t),
        "Can't cast TcbVersion to uint64_t");

#  pragma pack(push, 1)
        struct Signature
        {
        uint8_t r[72];
        uint8_t s[72];
        uint8_t reserved[512 - 144];
        };
#  pragma pack(pop)

        // Table. 105
        enum class SignatureAlgorithm : uint32_t
        {
        invalid = 0,
        ecdsa_p384_sha384 = 1
        };

#  pragma pack(push, 1)
        // Table 21
        struct AttestationReport
        {
        uint32_t version; /* 0x000 */
        uint32_t guest_svn; /* 0x004 */
        uint64_t policy; /* 0x008 */
        uint8_t family_id[16]; /* 0x010 */
        uint8_t image_id[16]; /* 0x020 */
        uint32_t vmpl; /* 0x030 */
        SignatureAlgorithm signature_algo; /* 0x034 */
        struct TcbVersion platform_version; /* 0x038 */
        uint64_t platform_info; /* 0x040 */
        uint32_t flags; /* 0x048 */
        uint32_t reserved0; /* 0x04C */
        uint8_t report_data[report_data_size]; /* 0x050 */
        uint8_t measurement[measurement_size]; /* 0x090 */
        uint8_t host_data[host_data_size]; /* 0x0C0 */
        uint8_t id_key_digest[48]; /* 0x0E0 */
        uint8_t author_key_digest[48]; /* 0x110 */
        uint8_t report_id[32]; /* 0x140 */
        uint8_t report_id_ma[32]; /* 0x160 */
        struct TcbVersion reported_tcb; /* 0x180 */
        uint8_t reserved1[24]; /* 0x188 */
        uint8_t chip_id[64]; /* 0x1A0 */
        struct TcbVersion committed_tcb; /* 0x1E0 */
        uint8_t current_minor; /* 0x1E8 */
        uint8_t current_build; /* 0x1E9 */
        uint8_t current_major; /* 0x1EA */
        uint8_t reserved2; /* 0x1EB */
        uint8_t committed_build; /* 0x1EC */
        uint8_t committed_minor; /* 0x1ED */
        uint8_t committed_major; /* 0x1EE */
        uint8_t reserved3; /* 0x1EF */
        struct TcbVersion launch_tcb; /* 0x1F0 */
        uint8_t reserved4[168]; /* 0x1F8 */
        struct Signature signature; /* 0x2A0 */
        };
#  pragma pack(pop)

        // Table 20
        struct AttestationReq
        {
        uint8_t report_data[report_data_size];
        uint32_t vmpl;
        uint8_t reserved[28];
        };

        // Table 23
#  pragma pack(push, 1)
        struct AttestationResp
        {
        uint32_t status;
        uint32_t report_size;
        uint8_t reserved[0x20 - 0x8];
        struct AttestationReport report;
        uint8_t padding[64];
        // padding to the size of SEV_SNP_REPORT_RSP_BUF_SZ (i.e., 1280 bytes)
        };
#  pragma pack(pop)

        struct GuestRequest
        {
        uint8_t req_msg_type;
        uint8_t rsp_msg_type;
        uint8_t msg_version;
        uint16_t request_len;
        uint64_t request_uaddr;
        uint16_t response_len;
        uint64_t response_uaddr;
        uint32_t error; /* firmware error code on failure (see psp-sev.h) */
        };

        // Table 99
        enum MsgType
        {
        MSG_TYPE_INVALID = 0,
        MSG_CPUID_REQ,
        MSG_CPUID_RSP,
        MSG_KEY_REQ,
        MSG_KEY_RSP,
        MSG_REPORT_REQ,
        MSG_REPORT_RSP,
        MSG_EXPORT_REQ,
        MSG_EXPORT_RSP,
        MSG_IMPORT_REQ,
        MSG_IMPORT_RSP,
        MSG_ABSORB_REQ,
        MSG_ABSORB_RSP,
        MSG_VMRK_REQ,
        MSG_VMRK_RSP,
        MSG_TYPE_MAX
        };

    }

#  define SEV_GUEST_IOC_TYPE2 'S'
#  define SEV_SNP_GUEST_MSG_REPORT2 \
_IOWR(SEV_GUEST_IOC_TYPE2, 0x1, struct constants::GuestRequest)

    ReportData make_report_data(crypto::Sha256Hash& node_public_key_hash) {
        ReportData report_data{};
        std::copy(
            node_public_key_hash.h.begin(), node_public_key_hash.h.end(), report_data.begin());
        return report_data;
    }

    Attestation generate(ReportData& report_data) {

        Attestation attestation{
            .quote = Quote{
                .format = QuoteFormat::amd_sev_snp_v1
            },
        };

        int fd = open(constants::DEVICE, O_RDWR | O_CLOEXEC);
        if (fd < 0)
        {
            throw std::logic_error(
            fmt::format("Failed to open \"{}\"", constants::DEVICE));
        }

        constants::AttestationReq req = {};
        constants::AttestationResp resp = {};

        // Arbitrary report data
        memcpy(req.report_data, report_data.data(), constants::report_data_size);

        // Documented at
        // https://www.kernel.org/doc/html/latest/virt/coco/sev-guest.html
        constants::GuestRequest payload = {
            .req_msg_type = constants::MSG_REPORT_REQ,
            .rsp_msg_type = constants::MSG_REPORT_RSP,
            .msg_version = 1,
            .request_len = sizeof(req),
            .request_uaddr = reinterpret_cast<uint64_t>(&req),
            .response_len = sizeof(resp),
            .response_uaddr = reinterpret_cast<uint64_t>(&resp),
            .error = 0};

        int rc = ioctl(fd, SEV_SNP_GUEST_MSG_REPORT2, &payload);
        if (rc < 0)
        {
            CCF_APP_FAIL("IOCTL call failed: {}", strerror(errno));
            CCF_APP_FAIL("Payload error: {}", payload.error);
            throw std::logic_error(
            "Failed to issue ioctl SEV_SNP_GUEST_MSG_REPORT2");
        }

        auto quote = &resp.report;
        auto quote_bytes = reinterpret_cast<uint8_t*>(&resp.report);
        attestation.quote.raw.assign(quote_bytes, quote_bytes + resp.report_size);

        client::RpcTlsClient client{
            "americas.test.acccache.azure.net",
            "443",
            nullptr,
            std::make_shared<tls::Cert>(
            nullptr, std::nullopt, std::nullopt, std::nullopt, false)};

        auto params = nlohmann::json::object();
        params["api-version"] = "2020-10-15-preview";

        auto response = client.get(
            fmt::format(
            "/SevSnpVM/certificates/{}/{}",
            fmt::format("{:02x}", fmt::join(quote->chip_id, "")),
            fmt::format("{:0x}", *(uint64_t*)(&quote->reported_tcb))),
            params);

        if (response.status != HTTP_STATUS_OK)
        {
            throw std::logic_error("Failed to get attestation endorsements");
        }

        attestation.endorsements.assign(
            response.body.begin(), response.body.end());

        return attestation;
    }

    bool verify(Attestation& attestation) {

        assert(attestation.quote.format == QuoteFormat::amd_sev_snp_v1);
        auto attestation_report = *reinterpret_cast<const constants::AttestationReport*>(attestation.quote.raw.data());

        auto certificates = crypto::split_x509_cert_bundle(std::string(
            attestation.endorsements.begin(), attestation.endorsements.end()));
        auto chip_certificate = certificates[0];
        auto sev_version_certificate = certificates[1];
        auto root_certificate = certificates[2];

        auto root_cert_verifier = crypto::make_verifier(root_certificate);

        if (
            root_cert_verifier->public_key_pem().str() !=
            constants::amd_milan_root_signing_public_key)
        {
            throw std::logic_error(fmt::format(
            "The root of trust public key for this attestation was not the "
            "expected one {}",
            root_cert_verifier->public_key_pem().str()));
        }

        if (!root_cert_verifier->verify_certificate({&root_certificate}))
        {
            throw std::logic_error(
            "The root of trust public key for this attestation was not self "
            "signed as expected");
        }

        auto chip_cert_verifier = crypto::make_verifier(chip_certificate);
        if (!chip_cert_verifier->verify_certificate(
                {&root_certificate, &sev_version_certificate}))
        {
            throw std::logic_error(
            "The chain of signatures from the root of trust to this "
            "attestation is broken");
        }

        if (attestation_report.signature_algo != constants::SignatureAlgorithm::ecdsa_p384_sha384)
        {
            throw std::logic_error(fmt::format(
            "Unsupported signature algorithm: {} (supported: {})",
            attestation_report.signature_algo,
            constants::SignatureAlgorithm::ecdsa_p384_sha384));
        }

        // Make ASN1 DER signature
        auto quote_signature = crypto::ecdsa_sig_from_r_s(
            attestation_report.signature.r,
            sizeof(attestation_report.signature.r),
            attestation_report.signature.s,
            sizeof(attestation_report.signature.s),
            false /* little endian */
        );

        std::span quote_without_signature{
            attestation.quote.raw.data(),
            attestation.quote.raw.size() - sizeof(attestation_report.signature)};
        if (!chip_cert_verifier->verify(quote_without_signature, quote_signature))
        {
            throw std::logic_error(
            "Chip certificate (VCEK) did not sign this attestation");
        }

        attestation.state = VerificationState::Verified;
        return true;
    }

    constants::AttestationReport get_snp_report(Attestation& attestation) {

        if (attestation.state == VerificationState::Unverified) {
            snp::verify(attestation);
        }
        assert(attestation.state == VerificationState::Verified);

        return *reinterpret_cast<const constants::AttestationReport*>(attestation.quote.raw.data());
    }

    ReportData get_report_data(Attestation& attestation) {
        ReportData report_data{};
        auto attestation_report = get_snp_report(attestation);
        std::copy(
            std::begin(attestation_report.report_data),
            std::end(attestation_report.report_data),
            report_data.begin());

        return report_data;
    }

    std::optional<MREnclave> get_mrenclave(Attestation& attestation) {
        return std::nullopt;
    }

    std::optional<Measurement> get_measurement(Attestation& attestation) {
        Measurement measurement{};
        auto attestation_report = get_snp_report(attestation);
        std::copy(
            std::begin(attestation_report.measurement),
            std::end(attestation_report.measurement),
            measurement.begin());
        return measurement;
    }

    std::optional<HostData> get_host_data(Attestation& attestation) {
        HostData host_data{};
        auto attestation_report = get_snp_report(attestation);
        std::copy(
            std::begin(attestation_report.host_data),
            std::end(attestation_report.host_data),
            host_data.begin());
        return host_data;
    }

    std::optional<SecurityPolicy> get_policy(Attestation& attestation) {
        return std::nullopt;
    }

}