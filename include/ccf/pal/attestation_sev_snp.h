// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/enum_formatter.h"
#include "ccf/pal/attestation_sev_snp_endorsements.h"
#include "ccf/pal/measurement.h"
#include "ccf/pal/report_data.h"

#include <array>
#include <cstdint>
#include <map>
#include <string>

namespace ccf::pal::snp
{
  // Based on the SEV-SNP ABI Spec document at
  // https://www.amd.com/system/files/TechDocs/56860.pdf

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
  constexpr auto amd_genoa_root_signing_public_key =
    R"(-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3Cd95S/uFOuRIskW9vz9
VDBF69NDQF79oRhL/L2PVQGhK3YdfEBgpF/JiwWFBsT/fXDhzA01p3LkcT/7Ldjc
RfKXjHl+0Qq/M4dZkh6QDoUeKzNBLDcBKDDGWo3v35NyrxbA1DnkYwUKU5AAk4P9
4tKXLp80oxt84ahyHoLmc/LqsGsp+oq1Bz4PPsYLwTG4iMKVaaT90/oZ4I8oibSr
u92vJhlqWO27d/Rxc3iUMyhNeGToOvgx/iUo4gGpG61NDpkEUvIzuKcaMx8IdTpW
g2DF6SwF0IgVMffnvtJmA68BwJNWo1E4PLJdaPfBifcJpuBFwNVQIPQEVX3aP89H
JSp8YbY9lySS6PlVEqTBBtaQmi4ATGmMR+n2K/e+JAhU2Gj7jIpJhOkdH9firQDn
mlA2SFfJ/Cc0mGNzW9RmIhyOUnNFoclmkRhl3/AQU5Ys9Qsan1jT/EiyT+pCpmnA
+y9edvhDCbOG8F2oxHGRdTBkylungrkXJGYiwGrR8kaiqv7NN8QhOBMqYjcbrkEr
0f8QMKklIS5ruOfqlLMCBw8JLB3LkjpWgtD7OpxkzSsohN47Uom86RY6lp72g8eX
HP1qYrnvhzaG1S70vw6OkbaaC9EjiH/uHgAJQGxon7u0Q7xgoREWA/e7JcBQwLg8
0Hq/sbRuqesxz7wBWSY254cCAwEAAQ==
-----END PUBLIC KEY-----
)";
  constexpr auto amd_turin_root_signing_public_key =
    R"(-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwaAriB7EIuVc4ZB1wD3Y
fDxL+9eyS7+izm0Jj3W772NINCWl8Bj3w/JD2ZjmbRxWdIq/4d9iarCKorXloJUB
1jRdgxqccTx1aOoig4+2w1XhVVJT7K457wT5ZLNJgQaxqa9Etkwjd6+9sOhlCDE9
l43kQ0R2BikVJa/uyyVOSwEk5w5tXKOuG9jvq6QtAMJasW38wlqRDaKEGtZ9VUgG
on27ZuL4sTJuC/azz9/iQBw8kEilzOl95AiTkeY5jSEBDWbAqnZk5qlM7kISKG20
kgQm14mhNKDI2p2oua+zuAG7i52epoRF2GfU0TYk/yf+vCNB2tnechFQuP2e8bLk
95ZdqPi9/UWw4JXjtdEA4u2JYplSSUPQVAXKt6LVqujtJcM59JKr2u0XQ75KwxcM
p15gSXhBfInvPAwuAY4dEwwGqT8oIg4esPHwEsmChhYeDIxPG9R4fx9O0q6p8Gb+
HXlTiS47P9YNeOpidOUKzDl/S1OvyhDtSL8LJc24QATFydo/iD/KUdvFTRlD0crk
AMkZLoWQ8hLDGc6BZJXsdd7Zf2e4UW3tI/1oh/2t23Ot3zyhTcv5gDbABu0LjVe9
8uRnS15SMwK//lJt9e5BqKvgABkSoABf+B4VFtPVEX0ygrYaFaI9i5ABrxnVBmzX
pRb21iI1NlNCfOGUPIhVpWECAwEAAQ==
-----END PUBLIC KEY-----
)";

  using AMDFamily = uint8_t;
  using AMDModel = uint8_t;
  inline const std::map<std::pair<AMDFamily, AMDModel>, const char*>
    amd_root_signing_keys{
      {{0x19, 0x01}, amd_milan_root_signing_public_key},
      {{0x19, 0x11}, amd_genoa_root_signing_public_key},
      // Disabled until we can test this
      //{{0x1A, 0x02}, amd_turin_root_signing_public_key},
    };

#pragma pack(push, 1)
  // Table 3
  struct TcbVersion
  {
    uint8_t boot_loader = 0;
    uint8_t tee = 0;
    uint8_t reserved[4];
    uint8_t snp = 0;
    uint8_t microcode = 0;

    bool operator==(const TcbVersion&) const = default;
  };
#pragma pack(pop)
  static_assert(
    sizeof(TcbVersion) == sizeof(uint64_t),
    "Can't cast TcbVersion to uint64_t");
  DECLARE_JSON_TYPE(TcbVersion);
  DECLARE_JSON_REQUIRED_FIELDS(TcbVersion, boot_loader, tee, snp, microcode);

#pragma pack(push, 1)
  struct Signature
  {
    uint8_t r[72];
    uint8_t s[72];
    uint8_t reserved[512 - 144];
  };
#pragma pack(pop)

  // Table 105
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
  static_assert(
    sizeof(GuestPolicy) == sizeof(uint64_t),
    "Can't cast GuestPolicy to uint64_t");

  static constexpr uint8_t attestation_flags_signing_key_vcek = 0;

#pragma pack(push, 1)
  struct Flags
  {
    uint8_t author_key_en : 1;
    uint8_t mask_chip_key : 1;
    uint8_t signing_key : 3;
    uint64_t reserved : 27;
  };
#pragma pack(pop)
  static_assert(
    sizeof(Flags) == sizeof(uint32_t), "Can't cast Flags to uint32_t");

#pragma pack(push, 1)
  // Table 22
  struct PlatformInfo
  {
    uint8_t smt_en : 1;
    uint8_t tsme_en : 1;
    uint64_t reserved : 62;
  };
#pragma pack(pop)
  static_assert(
    sizeof(PlatformInfo) == sizeof(uint64_t),
    "Can't cast PlatformInfo to uint64_t");

#pragma pack(push, 1)
  // Table 21

  static constexpr uint32_t minimum_attestation_version = 2;
  static constexpr uint32_t attestation_policy_abi_major = 1;

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
    PlatformInfo platform_info; /* 0x040 */
    Flags flags; /* 0x048 */
    uint32_t reserved0; /* 0x04C */
    uint8_t report_data[snp_attestation_report_data_size]; /* 0x050 */
    uint8_t measurement[snp_attestation_measurement_size]; /* 0x090 */
    uint8_t host_data[32]; /* 0x0C0 */
    uint8_t id_key_digest[48]; /* 0x0E0 */
    uint8_t author_key_digest[48]; /* 0x110 */
    uint8_t report_id[32]; /* 0x140 */
    uint8_t report_id_ma[32]; /* 0x160 */
    struct TcbVersion reported_tcb; /* 0x180 */
    uint8_t cpuid_fam_id; /* 0x188*/
    uint8_t cpuid_mod_id; /* 0x189 */
    uint8_t cpuid_step; /* 0x18A */
    uint8_t reserved1[21]; /* 0x18B */
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

  static HostPort get_endpoint_loc(
    const EndorsementsServer& server, const HostPort& default_values)
  {
    if (server.url.has_value())
    {
      auto url = server.url.value();
      auto pos = url.find(':');
      if (pos == std::string::npos)
      {
        return {url, default_values.port};
      }
      else
      {
        return {url.substr(0, pos), url.substr(pos + 1)};
      }
    }

    return default_values;
  }

  static EndorsementEndpointsConfiguration
  make_endorsement_endpoint_configuration(
    const Attestation& quote,
    const snp::EndorsementsServers& endorsements_servers = {})
  {
    EndorsementEndpointsConfiguration config;

    auto chip_id_hex = fmt::format("{:02x}", fmt::join(quote.chip_id, ""));
    auto reported_tcb = fmt::format("{:0x}", *(uint64_t*)(&quote.reported_tcb));

    constexpr size_t default_max_retries_count = 10;

    if (endorsements_servers.empty())
    {
      // Default to Azure server if no servers are specified
      config.servers.emplace_back(make_azure_endorsements_server(
        default_azure_endorsements_endpoint,
        chip_id_hex,
        reported_tcb,
        default_max_retries_count));
      return config;
    }

    for (auto const& server : endorsements_servers)
    {
      size_t max_retries_count =
        server.max_retries_count.value_or(default_max_retries_count);
      switch (server.type)
      {
        case EndorsementsEndpointType::Azure:
        {
          auto loc =
            get_endpoint_loc(server, default_azure_endorsements_endpoint);
          config.servers.emplace_back(make_azure_endorsements_server(
            loc, chip_id_hex, reported_tcb, max_retries_count));
          break;
        }
        case EndorsementsEndpointType::AMD:
        {
          auto boot_loader = fmt::format("{}", quote.reported_tcb.boot_loader);
          auto tee = fmt::format("{}", quote.reported_tcb.tee);
          auto snp = fmt::format("{}", quote.reported_tcb.snp);
          auto microcode = fmt::format("{}", quote.reported_tcb.microcode);

          auto loc =
            get_endpoint_loc(server, default_amd_endorsements_endpoint);
          config.servers.emplace_back(make_amd_endorsements_server(
            loc,
            chip_id_hex,
            boot_loader,
            tee,
            snp,
            microcode,
            max_retries_count));
          break;
        }
        case EndorsementsEndpointType::THIM:
        {
          auto loc =
            get_endpoint_loc(server, default_thim_endorsements_endpoint);
          config.servers.emplace_back(make_thim_endorsements_server(
            loc, chip_id_hex, reported_tcb, max_retries_count));
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

  class AttestationInterface
  {
  public:
    virtual const snp::Attestation& get() const = 0;
    virtual std::vector<uint8_t> get_raw() = 0;

    virtual ~AttestationInterface() = default;
  };

  static uint8_t MIN_TCB_VERIF_VERSION = 3;
#pragma pack(push, 1)
  // AMD CPUID specification. Chapter 2 Fn0000_0001_EAX
  // Milan: 0x00A00F11
  // Genoa: 0X00A10F11
  // Note: The CPUID is little-endian so the hex_string is reversed
  struct CPUID
  {
    uint8_t stepping : 4;
    uint8_t base_model : 4;
    uint8_t base_family : 4;
    uint8_t reserved : 4;
    uint8_t extended_model : 4;
    uint8_t extended_family : 8;
    uint8_t reserved2 : 4;

    bool operator==(const CPUID&) const = default;
    std::string hex_str() const
    {
      CPUID buf = *this;
      auto buf_ptr = reinterpret_cast<uint8_t*>(&buf);
      const std::span<const uint8_t> tcb_bytes{
        buf_ptr, buf_ptr + sizeof(CPUID)};
      return fmt::format(
        "{:02x}", fmt::join(tcb_bytes.rbegin(), tcb_bytes.rend(), ""));
    }
    inline uint8_t get_family_id() const
    {
      return this->base_family + this->extended_family;
    }
    inline uint8_t get_model_id() const
    {
      return (this->extended_model << 4) | this->base_model;
    }
  };
#pragma pack(pop)
  DECLARE_JSON_TYPE(CPUID);
  DECLARE_JSON_REQUIRED_FIELDS(
    CPUID, stepping, base_model, base_family, extended_model, extended_family);
  static_assert(
    sizeof(CPUID) == sizeof(uint32_t), "Can't cast CPUID to uint32_t");
  static CPUID cpuid_from_hex(const std::string& hex_str)
  {
    CPUID ret;
    auto buf_ptr = reinterpret_cast<uint8_t*>(&ret);
    ccf::ds::from_hex(hex_str, buf_ptr, buf_ptr + sizeof(CPUID));
    std::reverse(
      buf_ptr, buf_ptr + sizeof(CPUID)); // fix little endianness of AMD
    return ret;
  }

  // On SEVSNP cpuid cannot be trusted and must be validated against an
  // attestation.
  static CPUID get_cpuid_untrusted()
  {
    uint32_t ieax = 1;
    uint64_t iebx = 0;
    uint64_t iecx = 0;
    uint64_t iedx = 0;
    uint32_t oeax = 0;
    uint64_t oebx = 0;
    uint64_t oecx = 0;
    uint64_t oedx = 0;
    // pass in e{b,c,d}x to prevent cpuid from blatting other registers
    asm volatile("cpuid"
                 : "=a"(oeax), "=b"(oebx), "=c"(oecx), "=d"(oedx)
                 : "a"(ieax), "b"(iebx), "c"(iecx), "d"(iedx));
    auto cpuid = *reinterpret_cast<CPUID*>(&oeax);
    return cpuid;
  }
}

namespace ccf::kv::serialisers
{
  // Use hex string to ensure uniformity between the endpoint perspective and
  // the kv's key
  template <>
  struct BlitSerialiser<ccf::pal::snp::CPUID>
  {
    static SerialisedEntry to_serialised(const ccf::pal::snp::CPUID& chip)
    {
      auto hex_str = chip.hex_str();
      return SerialisedEntry(hex_str.begin(), hex_str.end());
    }

    static ccf::pal::snp::CPUID from_serialised(const SerialisedEntry& data)
    {
      return ccf::pal::snp::cpuid_from_hex(
        std::string(data.data(), data.end()));
    }
  };
}