// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

#include <cstdint>

namespace ccf::crypto
{
  enum class MLDSAParameterSet : uint8_t
  {
    ML_DSA_44,
    ML_DSA_65,
    ML_DSA_87
  };

  DECLARE_JSON_ENUM(
    MLDSAParameterSet,
    {{MLDSAParameterSet::ML_DSA_44, "ML-DSA-44"},
     {MLDSAParameterSet::ML_DSA_65, "ML-DSA-65"},
     {MLDSAParameterSet::ML_DSA_87, "ML-DSA-87"}});
}
