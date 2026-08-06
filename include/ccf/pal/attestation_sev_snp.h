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
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace ccf::pal::snp
{
  // Based on the SEV-SNP ABI Spec document at
  // https://www.amd.com/system/files/TechDocs/56860.pdf

  static constexpr auto NO_SECURITY_POLICY = "";

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
      // NOLINTBEGIN(bugprone-unchecked-optional-access)
      return TcbVersionMilanGenoa{
        static_cast<uint8_t>(boot_loader.value()),
        static_cast<uint8_t>(tee.value()),
        {0, 0, 0, 0}, // reserved
        static_cast<uint8_t>(snp.value()),
        static_cast<uint8_t>(microcode.value())};
      // NOLINTEND(bugprone-unchecked-optional-access)
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
      // NOLINTBEGIN(bugprone-unchecked-optional-access)
      return TcbVersionTurin{
        static_cast<uint8_t>(fmc.value()),
        static_cast<uint8_t>(boot_loader.value()),
        static_cast<uint8_t>(tee.value()),
        static_cast<uint8_t>(snp.value()),
        {0, 0, 0}, // reserved
        static_cast<uint8_t>(microcode.value())};
      // NOLINTEND(bugprone-unchecked-optional-access)
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
    uint8_t underlying_data[snp_tcb_version_size]{};

  public:
    bool operator==(const TcbVersionRaw& other) const = default;

    TcbVersionRaw() = default;

    TcbVersionRaw(const std::vector<uint8_t>& data)
    {
      if (data.size() != snp_tcb_version_size)
      {
        throw std::logic_error(
          fmt::format("Invalid TCB version raw data size: {}", data.size()));
      }
      std::memcpy(
        static_cast<void*>(underlying_data), data.data(), snp_tcb_version_size);
    }

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
          throw std::logic_error(fmt::format(
            "Unsupported SEV-SNP product for TCB version policy: {}", product));
      }
    }

    [[nodiscard]] TcbVersionMilanGenoa* as_milan_genoa()
    {
      return reinterpret_cast<TcbVersionMilanGenoa*>(this);
    }

    [[nodiscard]] TcbVersionTurin* as_turin()
    {
      return reinterpret_cast<TcbVersionTurin*>(this);
    }
  };
  static_assert(
    sizeof(TcbVersionRaw) == snp_tcb_version_size,
    "TCB version raw size mismatch");

  class AttestationReportFactory;

  class AttestationReport
  {
  private:
    class Impl;
    std::unique_ptr<Impl> impl;

    explicit AttestationReport(std::unique_ptr<Impl> impl_);
    friend class AttestationReportFactory;

  public:
    AttestationReport(AttestationReport&&) noexcept;
    AttestationReport& operator=(AttestationReport&&) noexcept;
    ~AttestationReport();

    AttestationReport(const AttestationReport&) = delete;
    AttestationReport& operator=(const AttestationReport&) = delete;

    [[nodiscard]] uint32_t version() const;
    [[nodiscard]] uint32_t guest_svn() const;
    [[nodiscard]] uint64_t policy() const;
    [[nodiscard]] uint8_t policy_abi_minor() const;
    [[nodiscard]] uint8_t policy_abi_major() const;
    [[nodiscard]] bool policy_smt() const;
    [[nodiscard]] bool policy_migrate_ma() const;
    [[nodiscard]] bool policy_debug() const;
    [[nodiscard]] bool policy_single_socket() const;
    [[nodiscard]] uint32_t vmpl() const;
    [[nodiscard]] uint32_t signature_algo() const;
    [[nodiscard]] uint64_t platform_info() const;
    [[nodiscard]] uint32_t flags() const;
    [[nodiscard]] bool flags_author_key_en() const;
    [[nodiscard]] bool flags_mask_chip_key() const;
    [[nodiscard]] uint8_t flags_signing_key() const;
    [[nodiscard]] uint8_t cpuid_fam_id() const;
    [[nodiscard]] uint8_t cpuid_mod_id() const;
    [[nodiscard]] uint8_t cpuid_step() const;
    [[nodiscard]] uint8_t current_build() const;
    [[nodiscard]] uint8_t current_minor() const;
    [[nodiscard]] uint8_t current_major() const;
    [[nodiscard]] uint8_t committed_build() const;
    [[nodiscard]] uint8_t committed_minor() const;
    [[nodiscard]] uint8_t committed_major() const;

    [[nodiscard]] std::vector<uint8_t> family_id() const;
    [[nodiscard]] std::vector<uint8_t> image_id() const;
    [[nodiscard]] TcbVersionRaw platform_version() const;
    [[nodiscard]] std::vector<uint8_t> report_data() const;
    [[nodiscard]] std::vector<uint8_t> measurement() const;
    [[nodiscard]] std::vector<uint8_t> host_data() const;
    [[nodiscard]] std::vector<uint8_t> id_key_digest() const;
    [[nodiscard]] std::vector<uint8_t> author_key_digest() const;
    [[nodiscard]] std::vector<uint8_t> report_id() const;
    [[nodiscard]] std::vector<uint8_t> report_id_ma() const;
    [[nodiscard]] TcbVersionRaw reported_tcb() const;
    [[nodiscard]] std::vector<uint8_t> chip_id() const;
    [[nodiscard]] std::vector<uint8_t> chip_id_for_vcek() const;
    [[nodiscard]] TcbVersionRaw committed_tcb() const;
    [[nodiscard]] TcbVersionRaw launch_tcb() const;
    [[nodiscard]] std::vector<uint8_t> signature_r() const;
    [[nodiscard]] std::vector<uint8_t> signature_s() const;
  };

  AttestationReport parse_attestation_report_unverified(
    std::span<const uint8_t> report);

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

  static constexpr uint8_t attestation_flags_signing_key_vcek = 0;
  static constexpr size_t attestation_report_size = 1184;
  static constexpr uint32_t minimum_attestation_version = 3;
  static constexpr uint32_t attestation_policy_abi_major = 1;

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
      return {url.substr(0, pos), url.substr(pos + 1)};
    }

    return default_values;
  }

  static EndorsementEndpointsConfiguration
  make_endorsement_endpoint_configuration(
    const AttestationReport& quote,
    const snp::EndorsementsServers& endorsements_servers = {})
  {
    if (quote.version() < minimum_attestation_version)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: attestation version {} is not supported. Minimum "
        "supported version is {}",
        quote.version(),
        minimum_attestation_version));
    }

    EndorsementEndpointsConfiguration config;

    auto chip_id_hex =
      fmt::format("{:02x}", fmt::join(quote.chip_id_for_vcek(), ""));
    const auto reported_tcb_raw = quote.reported_tcb().data();
    uint64_t reported_tcb_value = 0;
    std::memcpy(
      &reported_tcb_value, reported_tcb_raw.data(), sizeof(reported_tcb_value));
    auto reported_tcb = fmt::format("{:0x}", reported_tcb_value);

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
            get_sev_snp_product(quote.cpuid_fam_id(), quote.cpuid_mod_id());

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
              auto tcb =
                quote.reported_tcb().to_policy(product).to_milan_genoa();
              boot_loader = fmt::format("{}", tcb.boot_loader);
              tee = fmt::format("{}", tcb.tee);
              snp = fmt::format("{}", tcb.snp);
              microcode = fmt::format("{}", tcb.microcode);
              break;
            }
            case ProductName::Turin:
            {
              auto tcb = quote.reported_tcb().to_policy(product).to_turin();
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
      return {hex_str.begin(), hex_str.end()};
    }

    static ccf::pal::snp::CPUID from_serialised(const SerialisedEntry& data)
    {
      return ccf::pal::snp::cpuid_from_hex(
        std::string(data.data(), data.end()));
    }
  };
}