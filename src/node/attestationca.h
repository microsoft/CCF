// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "entities.h"

#include <vector>

namespace ccf
{
  using AttestationCAs = Store::Map<std::vector<uint8_t>, bool>;
}