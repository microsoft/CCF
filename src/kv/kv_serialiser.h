// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "kv/raw_serialise.h"

namespace ccf::kv
{
  using RawKvStoreSerialiser = GenericSerialiseWrapper<RawWriter>;
  using RawKvStoreDeserialiser = GenericDeserialiseWrapper<RawReader>;
}
