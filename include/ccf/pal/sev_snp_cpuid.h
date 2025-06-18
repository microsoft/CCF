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
  };

  inline std::string to_string(ProductName product)
  {
    switch (product)
    {
      case ProductName::Milan:
        return "Milan";
      case ProductName::Genoa:
        return "Genoa";
      default:
        throw std::logic_error("Unknown SEV-SNP product");
    }
  }

  DECLARE_JSON_ENUM(
    ProductName,
    {
      {ProductName::Milan, "Milan"},
      {ProductName::Genoa, "Genoa"},
    });

  using AMDFamily = uint8_t;
  using AMDModel = uint8_t;

  inline ProductName get_sev_snp_product(AMDFamily family, AMDModel model)
  {
    if (family == 0x19 && model == 0x01)
    {
      return ProductName::Milan;
    }
    if (family == 0x19 && model == 0x11)
    {
      return ProductName::Genoa;
    }
    throw std::logic_error(fmt::format(
      "SEV-SNP: Unsupported CPUID family {} model {}", family, model));
  }
}