// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/quote_info.h"
#include "ccf/node/quote.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/snp_ioctl.h"
#include "ccf/service/tables/tcb_verification.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "pal/quote_generation.h"

#include <random>
#include <span>
#include <string>

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

using namespace ccf;

TEST_CASE("E2E")
{
  kv::Store kv_store;
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  auto tx = kv_store.create_tx();
  auto h = tx.wo<SnpTcbVersionMap>(Tables::SNP_TCB_VERSIONS);

  REQUIRE(pal::snp::is_sev_snp());

  auto attest_intf = pal::snp::get_attestation({});
  QuoteInfo quote_info = {};
  quote_info.format = QuoteFormat::amd_sev_snp_v1;
  quote_info.quote = attest_intf->get_raw();

  auto rc = verify_tcb_version_against_store(tx, quote_info);
  CHECK_EQ(rc, QuoteVerificationResult::FailedInvalidCPUID);

  auto attestation = attest_intf->get();

  // populate store with info from current attestation
  auto current_tcb = attestation.reported_tcb;
  pal::snp::AttestChipModel chip_id{
    .family = attestation.cpuid_fam_id,
    .model = attestation.cpuid_mod_id,
    .stepping = attestation.cpuid_step,
  };
  h->put(chip_id, current_tcb);

  rc = verify_tcb_version_against_store(tx, quote_info);
  CHECK_EQ(rc, QuoteVerificationResult::Verified);

  auto new_tcb_snp = current_tcb;
  new_tcb_snp.snp += 1;
  h->put(chip_id, new_tcb_snp);
  rc = verify_tcb_version_against_store(tx, quote_info);
  CHECK_EQ(rc, QuoteVerificationResult::FailedInvalidTcbVersion);

  auto new_tcb_microcode = current_tcb;
  new_tcb_microcode.microcode += 1;
  h->put(chip_id, new_tcb_microcode);
  rc = verify_tcb_version_against_store(tx, quote_info);
  CHECK_EQ(rc, QuoteVerificationResult::FailedInvalidTcbVersion);
}