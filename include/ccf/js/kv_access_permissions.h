// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/core/context.h"

namespace ccf::js
{
  enum class KVAccessPermissions
  {
    READ_WRITE,
    READ_ONLY,
    ILLEGAL
  };
}
