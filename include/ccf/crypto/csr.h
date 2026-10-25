// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>

namespace ccf::crypto
{
  /**
   * Key whose signature a certificate signing request carries.
   *
   * A request is normally signed by the subject's own private key. When
   * issuing a new certificate for an old subject whose private key is no
   * longer available, the issuer builds and signs the request itself, which
   * is slightly unusual. CCF uses this to re-endorse previous service
   * identities, which are self-signed, with new endorsements by the current
   * service identity.
   */
  enum class CSRSigner : std::uint8_t
  {
    SUBJECT = 0,
    ISSUER = 1
  };
}
