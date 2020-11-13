// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "entities.h"

namespace ccf
{
  using CertDERs = kv::Map<Cert, ObjectId>;
  using CACertDERs = kv::Map<std::string, Cert>;
  // Mapping from hex-encoded digest of PEM cert to entity id
  using CertDigests = kv::Map<std::string, ObjectId>;
}
