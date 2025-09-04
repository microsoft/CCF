// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/pal/attestation_sev_snp.h"

namespace ccf::pal
{
  std::optional<snp::TcbVersionRaw> get_endorsed_tcb_from_cert(
    snp::ProductName product, const crypto::Pem& vcek_leaf_cert);
  std::optional<std::vector<uint8_t>> get_endorsed_chip_id_from_cert(
    crypto::Pem& vcek_leaf_cert);
}
