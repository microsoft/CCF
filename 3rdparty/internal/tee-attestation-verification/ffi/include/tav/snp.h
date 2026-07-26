// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "tav/utils.h"

#define TAV_API

#ifdef __cplusplus
extern "C" {
#endif

/*
 * C ABI for caller-provided-certificate SNP attestation verification.
 *
 * Usage summary:
 * - Call tav_verify_snp_attestation with the raw attestation report and the
 *   ARK, ASK, and VCEK certificates in PEM format.
 * - On success, verification writes a TavSnpAttestationReport* to out_report.
 *   Pass that report handle to the tav_snp_attestation_report_* accessors.
 * - Free the report handle with tav_snp_attestation_report_free when finished.
 *
 * Error behavior:
 * - tav_verify_snp_attestation returns NULL on success, or an owned TavError*
 *   on failure. Inspect failures with tav_error_code and tav_error_message,
 *   then free them with tav_error_free.
 * - tav_verify_snp_attestation reports invalid verification inputs and invalid
 *   out_report state as TavError failures. Each input buffer is capped at
 *   1 GiB.
 * - Error accessors are defensive for NULL TavError pointers: tav_error_code
 *   returns TAV_ERROR_IS_NULL and tav_error_message returns a static
 *   diagnostic string.
 * - Report accessors require valid handles and valid out-parameters where
 *   applicable. Passing NULL, dangling, freed, or otherwise invalid pointers is
 *   undefined behavior, except that free functions accept NULL and do nothing.
 * - Byte accessors write borrowed library-owned views to caller-provided
 *   pointer/length out-parameters. The borrowed data remains valid only until
 *   the owning report handle is freed, and must not be freed by the caller.
 */

typedef struct TavSnpAttestationReport TavSnpAttestationReport;

/*
 * Verify an SNP attestation report using caller-provided ARK, ASK, and VCEK
 * certificates in PEM format.
 *
 * out_report must point to a writable report-handle slot. The slot is set to
 * NULL before any fallible work and set to an owned handle only on success.
 */
TAV_API TavError *tav_verify_snp_attestation(
    const uint8_t *report_bytes,
    size_t report_len,
    const uint8_t *ark_pem,
    size_t ark_pem_len,
    const uint8_t *ask_pem,
    size_t ask_pem_len,
    const uint8_t *vcek_pem,
    size_t vcek_pem_len,
    TavSnpAttestationReport **out_report);

/* Scalar report accessors. Invalid report pointers are undefined behavior. */
TAV_API uint32_t tav_snp_attestation_report_version(
    const TavSnpAttestationReport *report);
TAV_API uint32_t tav_snp_attestation_report_guest_svn(
    const TavSnpAttestationReport *report);
TAV_API uint64_t tav_snp_attestation_report_policy(
    const TavSnpAttestationReport *report);
TAV_API uint8_t tav_snp_attestation_report_policy_abi_minor(
    const TavSnpAttestationReport *report);
TAV_API uint8_t tav_snp_attestation_report_policy_abi_major(
    const TavSnpAttestationReport *report);
TAV_API bool tav_snp_attestation_report_policy_smt(
    const TavSnpAttestationReport *report);
TAV_API bool tav_snp_attestation_report_policy_migrate_ma(
    const TavSnpAttestationReport *report);
TAV_API bool tav_snp_attestation_report_policy_debug(
    const TavSnpAttestationReport *report);
TAV_API bool tav_snp_attestation_report_policy_single_socket(
    const TavSnpAttestationReport *report);
TAV_API bool tav_snp_attestation_report_policy_cxl_allow(
    const TavSnpAttestationReport *report);
TAV_API bool tav_snp_attestation_report_policy_mem_aes_256_xts(
    const TavSnpAttestationReport *report);
TAV_API bool tav_snp_attestation_report_policy_rapl_dis(
    const TavSnpAttestationReport *report);
TAV_API bool tav_snp_attestation_report_policy_ciphertext_hiding_dram(
    const TavSnpAttestationReport *report);
TAV_API bool tav_snp_attestation_report_policy_page_swap_disable(
    const TavSnpAttestationReport *report);
TAV_API uint32_t tav_snp_attestation_report_vmpl(
    const TavSnpAttestationReport *report);
TAV_API uint32_t tav_snp_attestation_report_signature_algo(
    const TavSnpAttestationReport *report);
TAV_API uint64_t tav_snp_attestation_report_platform_info(
    const TavSnpAttestationReport *report);
TAV_API uint32_t tav_snp_attestation_report_flags(
    const TavSnpAttestationReport *report);
TAV_API bool tav_snp_attestation_report_flags_author_key_en(
    const TavSnpAttestationReport *report);
TAV_API bool tav_snp_attestation_report_flags_mask_chip_key(
    const TavSnpAttestationReport *report);
TAV_API uint8_t tav_snp_attestation_report_flags_signing_key(
    const TavSnpAttestationReport *report);
TAV_API uint8_t tav_snp_attestation_report_cpuid_fam_id(
    const TavSnpAttestationReport *report);
TAV_API uint8_t tav_snp_attestation_report_cpuid_mod_id(
    const TavSnpAttestationReport *report);
TAV_API uint8_t tav_snp_attestation_report_cpuid_step(
    const TavSnpAttestationReport *report);
TAV_API uint8_t tav_snp_attestation_report_current_build(
    const TavSnpAttestationReport *report);
TAV_API uint8_t tav_snp_attestation_report_current_minor(
    const TavSnpAttestationReport *report);
TAV_API uint8_t tav_snp_attestation_report_current_major(
    const TavSnpAttestationReport *report);
TAV_API uint8_t tav_snp_attestation_report_committed_build(
    const TavSnpAttestationReport *report);
TAV_API uint8_t tav_snp_attestation_report_committed_minor(
    const TavSnpAttestationReport *report);
TAV_API uint8_t tav_snp_attestation_report_committed_major(
    const TavSnpAttestationReport *report);

/*
 * Borrowed byte-slice report accessors. report, data, and len must be valid
 * pointers. *data and *len are overwritten. The returned data pointer is
 * borrowed from report and remains valid only until
 * tav_snp_attestation_report_free(report).
 */
TAV_API void tav_snp_attestation_report_report_data(
    const TavSnpAttestationReport *report,
    const uint8_t **data,
    size_t *len);
TAV_API void tav_snp_attestation_report_family_id(
    const TavSnpAttestationReport *report,
    const uint8_t **data,
    size_t *len);
TAV_API void tav_snp_attestation_report_image_id(
    const TavSnpAttestationReport *report,
    const uint8_t **data,
    size_t *len);
TAV_API void tav_snp_attestation_report_platform_version(
    const TavSnpAttestationReport *report,
    const uint8_t **data,
    size_t *len);
TAV_API void tav_snp_attestation_report_measurement(
    const TavSnpAttestationReport *report,
    const uint8_t **data,
    size_t *len);
TAV_API void tav_snp_attestation_report_host_data(
    const TavSnpAttestationReport *report,
    const uint8_t **data,
    size_t *len);
TAV_API void tav_snp_attestation_report_id_key_digest(
    const TavSnpAttestationReport *report,
    const uint8_t **data,
    size_t *len);
TAV_API void tav_snp_attestation_report_author_key_digest(
    const TavSnpAttestationReport *report,
    const uint8_t **data,
    size_t *len);
TAV_API void tav_snp_attestation_report_report_id(
    const TavSnpAttestationReport *report,
    const uint8_t **data,
    size_t *len);
TAV_API void tav_snp_attestation_report_report_id_ma(
    const TavSnpAttestationReport *report,
    const uint8_t **data,
    size_t *len);
TAV_API void tav_snp_attestation_report_reported_tcb(
    const TavSnpAttestationReport *report,
    const uint8_t **data,
    size_t *len);
TAV_API void tav_snp_attestation_report_chip_id(
    const TavSnpAttestationReport *report,
    const uint8_t **data,
    size_t *len);
TAV_API void tav_snp_attestation_report_committed_tcb(
    const TavSnpAttestationReport *report,
    const uint8_t **data,
    size_t *len);
TAV_API void tav_snp_attestation_report_launch_tcb(
    const TavSnpAttestationReport *report,
    const uint8_t **data,
    size_t *len);
TAV_API void tav_snp_attestation_report_signature_r(
    const TavSnpAttestationReport *report,
    const uint8_t **data,
    size_t *len);
TAV_API void tav_snp_attestation_report_signature_s(
    const TavSnpAttestationReport *report,
    const uint8_t **data,
    size_t *len);

/* Frees a report handle returned by tav_verify_snp_attestation. NULL is a no-op. */
TAV_API void tav_snp_attestation_report_free(TavSnpAttestationReport *report);

#ifdef __cplusplus
}
#endif
