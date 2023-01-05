// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/attestation_sev_snp_endorsements.h"

#include <array>
#include <map>
#include <string>

namespace ccf::pal
{
  // Based on the SEV-SNP ABI Spec document at
  // https://www.amd.com/system/files/TechDocs/56860.pdf
  static constexpr size_t snp_attestation_report_data_size = 64;
  static constexpr size_t snp_attestation_measurement_size = 48;

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
  using AttestationReportData =
    std::array<uint8_t, snp_attestation_report_data_size>;
  using AttestationMeasurement =
    std::array<uint8_t, snp_attestation_measurement_size>;
#endif

  namespace snp
  {
    static constexpr auto NO_SECURITY_POLICY = "";

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
#pragma pack(push, 1)
    struct TcbVersion
    {
      uint8_t boot_loader;
      uint8_t tee;
      uint8_t reserved[4];
      uint8_t snp;
      uint8_t microcode;
    };
#pragma pack(pop)
    static_assert(
      sizeof(TcbVersion) == sizeof(uint64_t),
      "Can't cast TcbVersion to uint64_t");

#pragma pack(push, 1)
    struct Signature
    {
      uint8_t r[72];
      uint8_t s[72];
      uint8_t reserved[512 - 144];
    };
#pragma pack(pop)

    // Table. 105
    enum class SignatureAlgorithm : uint32_t
    {
      invalid = 0,
      ecdsa_p384_sha384 = 1
    };

#pragma pack(push, 1)
    // Table 8
    struct GuestPolicy
    {
      uint8_t abi_minor;
      uint8_t abi_major;
      uint8_t smt : 1;
      uint8_t reserved : 1;
      uint8_t migrate_ma : 1;
      uint8_t debug : 1;
      uint8_t single_socket : 1;
      uint64_t reserved2 : 43;
    };
#pragma pack(pop)

#pragma pack(push, 1)
    // Table 21
    struct Attestation
    {
      uint32_t version; /* 0x000 */
      uint32_t guest_svn; /* 0x004 */
      struct GuestPolicy policy; /* 0x008 */
      uint8_t family_id[16]; /* 0x010 */
      uint8_t image_id[16]; /* 0x020 */
      uint32_t vmpl; /* 0x030 */
      SignatureAlgorithm signature_algo; /* 0x034 */
      struct TcbVersion platform_version; /* 0x038 */
      uint64_t platform_info; /* 0x040 */
      uint32_t flags; /* 0x048 */
      uint32_t reserved0; /* 0x04C */
      uint8_t report_data[snp_attestation_report_data_size]; /* 0x050 */
      uint8_t measurement[snp_attestation_measurement_size]; /* 0x090 */
      uint8_t host_data[32]; /* 0x0C0 */
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
#pragma pack(pop)

    // Table 20
    struct AttestationReq
    {
      uint8_t report_data[snp_attestation_report_data_size];
      uint32_t vmpl;
      uint8_t reserved[28];
    };

    // Table 23
#pragma pack(push, 1)
    struct AttestationResp
    {
      uint32_t status;
      uint32_t report_size;
      uint8_t reserved[0x20 - 0x8];
      struct Attestation report;
      uint8_t padding[64];
      // padding to the size of SEV_SNP_REPORT_RSP_BUF_SZ (i.e., 1280 bytes)
    };
#pragma pack(pop)

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

    // Changes on 5.19+ kernel
    constexpr auto DEVICE = "/dev/sev";

    static EndorsementEndpointsConfiguration
    make_endorsement_endpoint_configuration(
      const Attestation& quote,
      const snp::EndorsementsServers& endorsements_servers = {})
    {
      EndorsementEndpointsConfiguration config;

      auto chip_id_hex = fmt::format("{:02x}", fmt::join(quote.chip_id, ""));
      auto reported_tcb =
        fmt::format("{:0x}", *(uint64_t*)(&quote.reported_tcb));

      if (endorsements_servers.empty())
      {
        // Default to Azure server if no servers are specified
        config.servers.emplace_back(make_azure_endorsements_server(
          default_azure_endorsements_endpoint_host, chip_id_hex, reported_tcb));
        return config;
      }

      for (auto const& server : endorsements_servers)
      {
        switch (server.type)
        {
          case EndorsementsEndpointType::Azure:
          {
            auto url =
              server.url.value_or(default_azure_endorsements_endpoint_host);
            config.servers.emplace_back(
              make_azure_endorsements_server(url, chip_id_hex, reported_tcb));
            break;
          }
          case EndorsementsEndpointType::AMD:
          {
            auto boot_loader =
              fmt::format("{}", quote.reported_tcb.boot_loader);
            auto tee = fmt::format("{}", quote.reported_tcb.tee);
            auto snp = fmt::format("{}", quote.reported_tcb.snp);
            auto microcode = fmt::format("{}", quote.reported_tcb.microcode);

            auto url =
              server.url.value_or(default_azure_endorsements_endpoint_host);
            config.servers.emplace_back(make_amd_endorsements_server(
              url, chip_id_hex, boot_loader, tee, snp, microcode));
            break;
          }
          default:
          {
            throw std::logic_error(fmt::format(
              "Unsupported endorsements server type: {}", server.type));
          }
        }
      }

      return config;
    }
  }

#define SEV_GUEST_IOC_TYPE 'S'
#define SEV_SNP_GUEST_MSG_REPORT \
  _IOWR(SEV_GUEST_IOC_TYPE, 0x1, struct snp::GuestRequest)

}
