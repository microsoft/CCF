// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/ds/json.h"
#include "ccf/service/map.h"

namespace ccf
{
  // Maps each interface name to a certificate
  using ACMECertificates = ServiceMap<std::string, ccf::crypto::Pem>;

  namespace Tables
  {
    static constexpr auto ACME_CERTIFICATES =
      "public:ccf.gov.service.acme_certificates";
  }
}
