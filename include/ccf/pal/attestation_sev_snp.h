// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/enum_formatter.h"
#include "ccf/ds/json.h"
#include "ccf/ds/unit_strings.h"
#include "ccf/pal/attestation_sev_snp_endorsements.h"
#include "ccf/pal/measurement.h"
#include "ccf/pal/report_data.h"
#include "ccf/pal/sev_snp_cpuid.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

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

  inline const std::map<ProductName, const char*> amd_root_signing_keys{
    {ProductName::Milan, amd_milan_root_signing_public_key},
    {ProductName::Genoa, amd_genoa_root_signing_public_key},
    // Disabled until we can test this
    //{ProductName::turin, amd_turin_root_signing_public_key},
  };

  static uint8_t MIN_TCB_VERIF_VERSION = 3;
#pragma pack(push, 1)
  // Table 3
  constexpr size_t snp_tcb_version_size = 8;

  struct TcbVersionMilanGenoa
  {
    uint8_t boot_loader = 0;
    uint8_t tee = 0;
    uint8_t reserved[4];
    uint8_t snp = 0;
    uint8_t microcode = 0;
  };
  static_assert(
    sizeof(TcbVersionMilanGenoa) == snp_tcb_version_size,
    "Milan/Genoa TCB version size mismatch");

  struct TcbVersionTurin
  {
    uint8_t fmc = 0;
    uint8_t boot_loader = 0;
    uint8_t tee = 0;
    uint8_t snp = 0;
    uint8_t reserved[3];
    uint8_t microcode = 0;
  };
  static_assert(
    sizeof(TcbVersionTurin) == snp_tcb_version_size,
    "Turin TCB version size mismatch");
#pragma pack(pop)

  struct TcbVersionPolicy
  {
    std::optional<std::string> hexstring = std::nullopt;
    std::optional<uint32_t> microcode = std::nullopt;
    std::optional<uint32_t> snp = std::nullopt;
    std::optional<uint32_t> tee = std::nullopt;
    std::optional<uint32_t> boot_loader = std::nullopt;
    std::optional<uint32_t> fmc = std::nullopt;

    [[nodiscard]] TcbVersionMilanGenoa to_milan_genoa() const
    {
      auto valid = true;
      valid &= microcode.has_value();
      valid &= snp.has_value();
      valid &= tee.has_value();
      valid &= boot_loader.has_value();
      if (!valid)
      {
        throw std::logic_error(
          fmt::format("Invalid TCB version policy for Milan or Genoa"));
      }
      return TcbVersionMilanGenoa{
        static_cast<uint8_t>(boot_loader.value()),
        static_cast<uint8_t>(tee.value()),
        {0, 0, 0, 0}, // reserved
        static_cast<uint8_t>(snp.value()),
        static_cast<uint8_t>(microcode.value())};
    }

    [[nodiscard]] TcbVersionTurin to_turin() const
    {
      auto valid = true;
      valid &= microcode.has_value();
      valid &= snp.has_value();
      valid &= tee.has_value();
      valid &= boot_loader.has_value();
      valid &= fmc.has_value();
      if (!valid)
      {
        throw std::logic_error(
          fmt::format("Invalid TCB version policy for Turin"));
      }
      return TcbVersionTurin{
        static_cast<uint8_t>(fmc.value()),
        static_cast<uint8_t>(boot_loader.value()),
        static_cast<uint8_t>(tee.value()),
        static_cast<uint8_t>(snp.value()),
        {0, 0, 0}, // reserved
        static_cast<uint8_t>(microcode.value())};
    }

    static bool is_valid(TcbVersionPolicy& minimum, TcbVersionPolicy& test)
    {
      auto more_than_min =
        [](std::optional<uint32_t>& min, std::optional<uint32_t>& test) {
          if ((min.has_value() != test.has_value()))
          {
            return false;
          }
          if (!min.has_value() && !test.has_value())
          {
            return true;
          }
          // both set
          return min.value() <= test.value();
        };
      auto valid = true;
      valid &= more_than_min(minimum.microcode, test.microcode);
      valid &= more_than_min(minimum.snp, test.snp);
      valid &= more_than_min(minimum.tee, test.tee);
      valid &= more_than_min(minimum.boot_loader, test.boot_loader);
      valid &= more_than_min(minimum.fmc, test.fmc);
      return valid;
    }
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(TcbVersionPolicy);
  DECLARE_JSON_REQUIRED_FIELDS(TcbVersionPolicy);
  DECLARE_JSON_OPTIONAL_FIELDS(
    TcbVersionPolicy, fmc, boot_loader, tee, snp, microcode, hexstring);

  struct TcbVersionRaw
  {
  private:
    uint8_t underlying_data[snp_tcb_version_size];

  public:
    bool operator==(const TcbVersionRaw& other) const = default;

    [[nodiscard]] std::vector<uint8_t> data() const
    {
      return {
        static_cast<const uint8_t*>(underlying_data),
        static_cast<const uint8_t*>(underlying_data) + snp_tcb_version_size};
    }
    [[nodiscard]] std::string to_hex() const
    {
      auto data = this->data();
      // reverse to match endianness
      std::reverse(data.begin(), data.end());
      return ccf::ds::to_hex(data);
    }
    static TcbVersionRaw from_hex(const std::string& hex)
    {
      auto data = ccf::ds::from_hex(hex);
      if (data.size() != snp_tcb_version_size)
      {
        throw std::logic_error(
          fmt::format("Invalid TCB version data size: {}", data.size()));
      }
      // reverse to match endianness
      std::reverse(data.begin(), data.end());
      TcbVersionRaw tcb_version{};
      std::memcpy(
        static_cast<void*>(tcb_version.underlying_data),
        data.data(),
        snp_tcb_version_size);
      return tcb_version;
    }

    [[nodiscard]] TcbVersionPolicy to_policy(ProductName product) const
    {
      switch (product)
      {
        case ProductName::Milan:
        case ProductName::Genoa:
        {
          auto tcb = *reinterpret_cast<const TcbVersionMilanGenoa*>(this);
          return TcbVersionPolicy{
            .hexstring = this->to_hex(),
            .microcode = tcb.microcode,
            .snp = tcb.snp,
            .tee = tcb.tee,
            .boot_loader = tcb.boot_loader,
            .fmc = std::nullopt // fmc is not applicable for Milan/Genoa
          };
        }
        case ProductName::Turin:
        {
          auto tcb = *reinterpret_cast<const TcbVersionTurin*>(this);
          return TcbVersionPolicy{
            .hexstring = this->to_hex(),
            .microcode = tcb.microcode,
            .snp = tcb.snp,
            .tee = tcb.tee,
            .boot_loader = tcb.boot_loader,
            .fmc = tcb.fmc};
        }
        default:
          throw std::logic_error(
            "Unsupported SEV-SNP product for TCB version policy");
      }
    }
  };
  static_assert(
    sizeof(TcbVersionRaw) == snp_tcb_version_size,
    "TCB version raw size mismatch");
#pragma pack(push, 1)
  inline void to_json(nlohmann::json& j, const TcbVersionRaw& tcb_version)
  {
    j = tcb_version.to_hex();
  }
  inline void from_json(const nlohmann::json& j, TcbVersionRaw& tcb_version_raw)
  {
    if (!j.is_string())
    {
      throw std::logic_error(
        fmt::format("Invalid TCB version raw data: {}", j.dump()));
    }
    tcb_version_raw = TcbVersionRaw::from_hex(j.get<std::string>());
  }
  inline std::string schema_name(const TcbVersionRaw& tcb_version)
  {
    (void)tcb_version;
    return "TcbVersionRaw";
  }

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
    "Cannot cast GuestPolicy to uint64_t");

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
    sizeof(Flags) == sizeof(uint32_t), "Cannot cast Flags to uint32_t");

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
    "Cannot cast PlatformInfo to uint64_t");

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
    TcbVersionRaw platform_version; /* 0x038 */
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
    TcbVersionRaw reported_tcb; /* 0x180 */
    uint8_t cpuid_fam_id; /* 0x188*/
    uint8_t cpuid_mod_id; /* 0x189 */
    uint8_t cpuid_step; /* 0x18A */
    uint8_t reserved1[21]; /* 0x18B */
    uint8_t chip_id[64]; /* 0x1A0 */
    TcbVersionRaw committed_tcb; /* 0x1E0 */
    uint8_t current_minor; /* 0x1E8 */
    uint8_t current_build; /* 0x1E9 */
    uint8_t current_major; /* 0x1EA */
    uint8_t reserved2; /* 0x1EB */
    uint8_t committed_build; /* 0x1EC */
    uint8_t committed_minor; /* 0x1ED */
    uint8_t committed_major; /* 0x1EE */
    uint8_t reserved3; /* 0x1EF */
    TcbVersionRaw launch_tcb; /* 0x1F0 */
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
    static const ds::SizeString default_max_client_response_size =
      ds::SizeString("100mb");

    if (endorsements_servers.empty())
    {
      // Default to Azure server if no servers are specified
      config.servers.emplace_back(make_azure_endorsements_server(
        default_azure_endorsements_endpoint,
        chip_id_hex,
        reported_tcb,
        default_max_retries_count,
        default_max_client_response_size));
      return config;
    }

    for (auto const& server : endorsements_servers)
    {
      size_t max_retries_count =
        server.max_retries_count.value_or(default_max_retries_count);
      size_t max_client_response_size =
        server.max_client_response_size.value_or(
          default_max_client_response_size);
      switch (server.type)
      {
        case EndorsementsEndpointType::Azure:
        {
          auto loc =
            get_endpoint_loc(server, default_azure_endorsements_endpoint);
          config.servers.emplace_back(make_azure_endorsements_server(
            loc,
            chip_id_hex,
            reported_tcb,
            max_retries_count,
            max_client_response_size));
          break;
        }
        case EndorsementsEndpointType::AMD:
        {
          auto product =
            get_sev_snp_product(quote.cpuid_fam_id, quote.cpuid_mod_id);

          std::string boot_loader;
          std::string tee;
          std::string snp;
          std::string microcode;
          std::optional<std::string> fmc = std::nullopt;
          switch (product)
          {
            case ProductName::Milan:
            case ProductName::Genoa:
            {
              auto tcb = quote.reported_tcb.to_policy(product).to_milan_genoa();
              boot_loader = fmt::format("{}", tcb.boot_loader);
              tee = fmt::format("{}", tcb.tee);
              snp = fmt::format("{}", tcb.snp);
              microcode = fmt::format("{}", tcb.microcode);
              break;
            }
            case ProductName::Turin:
            {
              auto tcb = quote.reported_tcb.to_policy(product).to_turin();
              boot_loader = fmt::format("{}", tcb.boot_loader);
              tee = fmt::format("{}", tcb.tee);
              snp = fmt::format("{}", tcb.snp);
              microcode = fmt::format("{}", tcb.microcode);
              fmc = fmt::format("{}", tcb.fmc);
              break;
            }
            default:
            {
              throw std::logic_error(
                fmt::format("Unsupported SEV-SNP product: {}", product));
            }
          }

          auto loc =
            get_endpoint_loc(server, default_amd_endorsements_endpoint);
          config.servers.emplace_back(make_amd_endorsements_server(
            loc,
            chip_id_hex,
            boot_loader,
            tee,
            snp,
            microcode,
            product,
            max_retries_count,
            max_client_response_size,
            fmc));
          break;
        }
        case EndorsementsEndpointType::THIM:
        {
          auto loc =
            get_endpoint_loc(server, default_thim_endorsements_endpoint);
          config.servers.emplace_back(make_thim_endorsements_server(
            loc,
            chip_id_hex,
            reported_tcb,
            max_retries_count,
            max_client_response_size));
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