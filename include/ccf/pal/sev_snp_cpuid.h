// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

#include <cstdint>
#include <stdexcept>
#include <string>

namespace ccf::pal::snp
{

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
}