// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/service/reconfiguration_type.h"

DECLARE_JSON_ENUM(
  ReconfigurationType,
  {{ReconfigurationType::ONE_TRANSACTION, "OneTransaction"},
   {ReconfigurationType::TWO_TRANSACTION, "TwoTransaction"}})
