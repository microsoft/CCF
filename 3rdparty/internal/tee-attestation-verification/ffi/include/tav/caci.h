// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "tav/cose.h"
#include "tav/snp.h"
#include "tav/utils.h"

#define TAV_CACI_API

#ifdef __cplusplus
extern "C" {
#endif

/*
 * C ABI for staged Confidential ACI attestation verification.
 *
 * Ownership and lifetime:
 * - Use tav_verify_snp_attestation from tav/snp.h to verify the SNP report and
 *   obtain an owned TavSnpAttestationReport.
 * - tav_verify_caci_uvm_endorsement returns an owned TavCborValue containing
 *   the verified UVM COSE/CBOR document. Inspect it with the CBOR accessors in
 *   tav/cose.h and release it with tav_cbor_value_free.
 * - tav_verify_caci_attestation writes an owned TavByteBuffer* through
 *   out_report_data. Read it with tav_byte_buffer_data/tav_byte_buffer_len and
 *   release it with tav_byte_buffer_free.
 * - Freeing NULL owned handles and NULL byte buffers is a no-op.
 * - Owned handle out-parameters (TavCborValue **) and byte-buffer
 *   out-parameters (TavByteBuffer **) are write-only: they are reset to NULL
 *   before any fallible work and set to an owned value only on
 *   success.
 *
 * All public functions return NULL on success or an owned TavError on
 * failure unless documented otherwise. Inspect errors with
 * tav_error_code/tav_error_message, then free them with
 * tav_error_free.
 */

/*
 * Verify an ACI/UVM endorsement COSE blob against a caller-pinned did:x509 root.
 *
 * trusted_didx509 is a UTF-8 byte slice and does not need to be NUL-terminated.
 * out_uvm_endorsement must point to a writable handle slot. It is reset to NULL
 * before any fallible work and set to an owned handle only on success.
 */
TAV_CACI_API TavError *tav_verify_caci_uvm_endorsement(
    const uint8_t *uvm_endorsement,
    size_t uvm_endorsement_len,
    const char *trusted_didx509,
    size_t trusted_didx509_len,
    TavCborValue **out_uvm_endorsement);

/*
 * Verify the relying-party CACI policy over staged verified artifacts.
 *
 * The minimum TCB policy is passed as two parallel arrays of minimum_tcb_count
 * entries: minimum_tcb_cpuids holds one uint32_t CPUID per entry, and
 * minimum_tcb_values holds minimum_tcb_count contiguous 8-byte TCB values (the
 * size of an SNP TCB_VERSION). Both pointers may be NULL only when
 * minimum_tcb_count is zero.
 *
 * trusted_policy_digests points to trusted_policy_digest_count contiguous
 * 32-byte SHA-256 policy digests (the size of the SNP HOST_DATA field). At least
 * one digest is required. uvm_feed is a UTF-8 byte slice and does not need to be
 * NUL-terminated.
 *
 * On success, out_report_data receives an owned TavByteBuffer holding the
 * 64-byte verified SNP REPORT_DATA.
 */
TAV_CACI_API TavError *tav_verify_caci_attestation(
    const TavSnpAttestationReport *attestation,
    const uint32_t *minimum_tcb_cpuids,
    const uint8_t *minimum_tcb_values,
    size_t minimum_tcb_count,
    const uint8_t *trusted_policy_digests,
    size_t trusted_policy_digest_count,
    const TavCborValue *uvm_endorsement,
    const char *uvm_feed,
    size_t uvm_feed_len,
    uint64_t minimum_svn,
    TavByteBuffer **out_report_data);

#ifdef __cplusplus
}
#endif
