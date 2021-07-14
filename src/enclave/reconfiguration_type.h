// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"

enum ReconfigurationType
{
  ONE_TRANSACTION = 0,
  TWO_TRANSACTION = 1
};

DECLARE_JSON_ENUM(
  ReconfigurationType,
  {{ReconfigurationType::ONE_TRANSACTION, "OneTransaction"},
   {ReconfigurationType::TWO_TRANSACTION, "TwoTransaction"}})
