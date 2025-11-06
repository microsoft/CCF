// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/extensions/extension_interface.h"

namespace ccf::js::extensions
{
  /**
   * Adds the following functions:
   *
   * - ccf.crypto.sign
   * - ccf.crypto.verifySignature
   *
   * - ccf.crypto.pubPemToJwk
   * - ccf.crypto.pemToJwk
   *
   * - ccf.crypto.pubRsaPemToJwk
   * - ccf.crypto.rsaPemToJwk
   *
   * - ccf.crypto.pubEddsaPemToJwk
   * - ccf.crypto.eddsaPemToJwk
   *
   * - ccf.crypto.pubJwkToPem
   * - ccf.crypto.jwkToPem
   *
   * - ccf.crypto.pubRsaJwkToPem
   * - ccf.crypto.rsaJwkToPem
   *
   * - ccf.crypto.pubEddsaJwkToPem
   * - ccf.crypto.eddsaJwkToPem
   *
   * - ccf.crypto.generateAesKey
   * - ccf.crypto.generateRsaKeyPair
   * - ccf.crypto.generateEddsaKeyPair
   *
   * - ccf.crypto.unwrapKey
   * - ccf.crypto.digest
   *
   * - ccf.crypto.isValidX509CertBundle
   * - ccf.crypto.isValidX509CertChain
   *
   **/
  class CryptoExtension : public ExtensionInterface
  {
  public:
    CryptoExtension() = default;

    void install(js::core::Context& ctx) override;
  };
}
