// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/service/map.h"
#include "kv/kv_types.h"

namespace ccf
{
  enum RecoveryType : std::uint8_t
  {
    NONE = 0,
    RECOVERY_SHARES = 1,
    LOCAL_UNSEALING = 2
  };

  DECLARE_JSON_ENUM(
    RecoveryType,
    {{RecoveryType::NONE, "None"},
     {RecoveryType::RECOVERY_SHARES, "RECOVERY_SHARES"},
     {RecoveryType::LOCAL_UNSEALING, "LOCAL_UNSEALING"}});

  using LastRecoveryType = ServiceValue<RecoveryType>;
  namespace Tables
  {
    static constexpr auto LAST_RECOVERY_TYPE =
      "public:ccf.internal.last_recovery_type";
  }
}