// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/json/schema.h"
#include "ccf/json/serialization.h"

namespace ccf::json
{
  /** Generate JSON Schema 2020-12, retaining custom CCF ADL constraints. */
  template <typename T>
  nlohmann::json schema()
  {
    return detail::prepare_schema(detail::native_schema<T>());
  }
}
