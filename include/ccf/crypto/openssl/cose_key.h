// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose_key.h"

#include <openssl/types.h>

namespace ccf::crypto::OpenSSL
{
  /**
   * The public key of a parsed X.509 certificate, which may be untrusted, with
   * the same requirements as COSEKey::from_der_cert(). This avoids parsing a
   * certificate that the caller has already parsed, for example to validate
   * its chain.
   *
   * The key is shared with cert rather than copied. cert need not outlive the
   * result.
   *
   * @throws std::invalid_argument if cert is null, or its key cannot be
   * decoded or is not supported
   */
  [[nodiscard]] COSEKey cose_key_from_x509(const X509* cert);
}
