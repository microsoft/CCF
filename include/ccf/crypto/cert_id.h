// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/did_key.h"
#include "ccf/crypto/sha256_hash.h"
#include "ccf/crypto/verifier.h"
#include "ccf/identity_id_format.h"

namespace ccf::crypto
{
  inline std::string compute_cert_id(
    const Pem& cert, IdentityIdFormat format = IdentityIdFormat::SHA256)
  {
    const auto verifier = make_verifier(cert);
    if (format == IdentityIdFormat::DIDKey)
    {
      return did_key_from_public_key_der(verifier->public_key_der());
    }
    return Sha256Hash(verifier->cert_der()).hex_str();
  }
}
