// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/hex.h"
#include "ccf/ds/json.h"

#include <cstdint>
#include <stdexcept>
#include <string>

namespace ccf::pal::snp
{

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
    [[nodiscard]] std::string hex_str() const
    {
      CPUID buf = *this;
      auto* buf_ptr = reinterpret_cast<uint8_t*>(&buf);
      const std::span<const uint8_t> tcb_bytes{
        buf_ptr, buf_ptr + sizeof(CPUID)};
      return fmt::format(
        "{:02x}", fmt::join(tcb_bytes.rbegin(), tcb_bytes.rend(), ""));
    }
    [[nodiscard]] uint8_t get_family_id() const
    {
      return this->base_family + this->extended_family;
    }
    [[nodiscard]] uint8_t get_model_id() const
    {
      return (this->extended_model << 4) | this->base_model;
    }
  };
#pragma pack(pop)
  DECLARE_JSON_TYPE(CPUID);
  DECLARE_JSON_REQUIRED_FIELDS(
    CPUID, stepping, base_model, base_family, extended_model, extended_family);
  static_assert(
    sizeof(CPUID) == sizeof(uint32_t), "Cannot cast CPUID to uint32_t");
  static CPUID cpuid_from_hex(const std::string& hex_str)
  {
    CPUID ret{};
    auto* buf_ptr = reinterpret_cast<uint8_t*>(&ret);
    ccf::ds::from_hex(hex_str, buf_ptr, buf_ptr + sizeof(CPUID));
    std::reverse(
      buf_ptr, buf_ptr + sizeof(CPUID)); // fix little endianness of AMD
    return ret;
  }

  // On SEVSNP cpuid cannot be trusted and must later be validated against an
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

  enum class ProductName
  {
    Milan,
    Genoa,
    Turin
  };

  inline std::string to_string(ProductName product)
  {
    switch (product)
    {
      case ProductName::Milan:
        return "Milan";
      case ProductName::Genoa:
        return "Genoa";
      case ProductName::Turin:
        return "Turin";
      default:
        throw std::logic_error("Unknown SEV-SNP product");
    }
  }

  DECLARE_JSON_ENUM(
    ProductName,
    {
      {ProductName::Milan, "Milan"},
      {ProductName::Genoa, "Genoa"},
      {ProductName::Turin, "Turin"},
    });

  using AMDFamily = uint8_t;
  using AMDModel = uint8_t;

  inline ProductName get_sev_snp_product(AMDFamily family, AMDModel model)
  {
    constexpr uint8_t milan_family = 0x19;
    constexpr uint8_t milan_model = 0x01;
    if (family == milan_family && model == milan_model)
    {
      return ProductName::Milan;
    }
    constexpr uint8_t genoa_family = 0x19;
    constexpr uint8_t genoa_model = 0x11;
    if (family == genoa_family && model == genoa_model)
    {
      return ProductName::Genoa;
    }
    constexpr uint8_t turin_family = 0x1A;
    constexpr uint8_t turin_model = 0x01;
    if (family == turin_family && model == turin_model)
    {
      return ProductName::Turin;
    }
    throw std::logic_error(fmt::format(
      "SEV-SNP: Unsupported CPUID family {} model {}", family, model));
  }

  inline ProductName get_sev_snp_product(const CPUID& cpuid)
  {
    return get_sev_snp_product(cpuid.get_family_id(), cpuid.get_model_id());
  }

  inline std::string get_cpuid_of_snp_sev_product(ProductName product)
  {
    switch (product)
    {
      case ProductName::Milan:
        return "00a00f11";
      case ProductName::Genoa:
        return "00a10f11";
      case ProductName::Turin:
        return "00b00f11";
      default:
        throw std::logic_error(fmt::format(
          "SEV-SNP: Unsupported product for CPUID: {}", to_string(product)));
    }
  }
}