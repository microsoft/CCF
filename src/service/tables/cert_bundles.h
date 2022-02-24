// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/map.h"

namespace ccf
{
  using CACertBundlePEMs = ServiceMap<std::string, std::string>;
  namespace Tables
  {
    static constexpr auto CA_CERT_BUNDLE_PEMS =
      "public:ccf.gov.tls.ca_cert_bundles";
  }
}
