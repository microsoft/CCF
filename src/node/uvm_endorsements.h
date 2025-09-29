// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/base64.h"
#include "ccf/ds/json.h"
#include "ccf/pal/measurement.h"
#include "ccf/pal/uvm_endorsements.h"
#include "ccf/service/tables/uvm_endorsements.h"
#include "crypto/openssl/cose_verifier.h"
#include "node/cose_common.h"

#include <didx509cpp/didx509cpp.h>
#include <nlohmann/json.hpp>
#include <qcbor/qcbor.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <span>
#include <t_cose/t_cose_sign1_verify.h>

namespace ccf
{
  struct UvmEndorsementsProtectedHeader
  {
    int64_t alg;
    std::string content_type;
    std::vector<std::vector<uint8_t>> x5_chain;
    std::string iss;
    std::string feed;
  };

  // Roots of trust for UVM endorsements/measurement in AMD SEV-SNP attestations
  static std::vector<pal::UVMEndorsements> default_uvm_roots_of_trust = {
    // Confidential Azure Kubertnetes Service (AKS)
    {"did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6."
     "1.4.1.311.76.59.1.2",
     "ContainerPlat-AMD-UVM",
     "100"},
    // Confidential Azure Container Instances (ACI)
    {"did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6."
     "1.4.1.311.76.59.1.5",
     "ConfAKS-AMD-UVM",
     "1"}};

  pal::UVMEndorsements verify_uvm_endorsements_against_roots_of_trust(
    const std::vector<uint8_t>& uvm_endorsements_raw,
    const pal::PlatformAttestationMeasurement& uvm_measurement,
    const std::vector<pal::UVMEndorsements>& uvm_roots_of_trust);
}