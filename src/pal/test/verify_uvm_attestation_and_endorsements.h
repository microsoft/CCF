// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/ds/logger_level.h"
#include "ccf/ds/quote_info.h"
#include "ccf/node/quote.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/attestation_sev_snp_endorsements.h"
#include "ccf/pal/measurement.h"
#include "ccf/pal/uvm_endorsements.h"
#include "crypto/openssl/ec_key_pair.h"
#include "ds/ccf_assert.h"
#include "ds/files.h"
#include "ds/internal_logger.h"
#include "host/env.h"
#include "node/uvm_endorsements.h"
#include "pal/quote_generation.h"

#include <iostream>
#include <stdexcept>
#include <string>

static std::vector<ccf::pal::UVMEndorsements> uvm_endorsements_roots_of_trust;

namespace ccf
{
  QuoteVerificationResult verify_quoted_node_public_key(
    const std::vector<uint8_t>&, const ccf::crypto::Sha256Hash&);
}