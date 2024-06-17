// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoint.h"
#include "ccf/service/map.h"

namespace ccf
{
  using DynamicEndpoints =
    ccf::ServiceMap<endpoints::EndpointKey, endpoints::EndpointProperties>;
}