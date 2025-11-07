// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/extensions/extension_interface.h"

namespace ccf::js::extensions
{
  /**
   * Adds the following functions:
   *
   * - snp_attestation.verifySnpAttestation
   *
   **/
  class SnpAttestationExtension : public ExtensionInterface
  {
  public:
    SnpAttestationExtension() = default;

    void install(js::core::Context& ctx) override;
  };
}