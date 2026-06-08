/*
 *  t_cose_short_circuit.h
 *
 * Copyright 2019-2022, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_SHORT_CIRCUIT_H__
#define __T_COSE_SHORT_CIRCUIT_H__

#include <stdint.h>
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file t_cose_short_circuit.h
 *
 * \brief Functions used to compute and verify short-circuit signatures.
 *
 * These signatures don't use any cryptographic algorithm and don't
 * provide any security guarantees at all. They are provided for
 * demonstration purposes, and will not be used unless explicitly
 * enabled by users of the library.
 *
 */

#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN

/**
 * \brief Compute the size of a short-circuit signature.
 *
 * \param[in] cose_algorithm_id Algorithm ID. This is used only to make
 *                              the short-circuit signature the same size
 *                              as the real signature would be for the
 *                              particular algorithm.
 * \param[out] sig_size         The returned size in bytes.
 *
 * \return An error code or \ref T_COSE_SUCCESS.
 */
enum t_cose_err_t
short_circuit_sig_size(int32_t cose_algorithm_id, size_t *sig_size);

/**
 * \brief Create a short-circuit signature
 *
 * \param[in] cose_algorithm_id Algorithm ID. This is used only to make
 *                              the short-circuit signature the same size
 *                              as the real signature would be for the
 *                              particular algorithm.
 * \param[in] hash_to_sign      The bytes to sign. Typically, a hash of
 *                              a payload.
 * \param[in] signature_buffer  Pointer and length of buffer into which
 *                              the resulting signature is put.
 * \param[in] signature         Pointer and length of the signature
 *                              returned.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * This creates the short-circuit signature that is a concatenation of
 * hashes up to the expected size of the signature. This is a test
 * mode only has it has no security value. This is retained in
 * commercial production code as a useful test or demo that can run
 * even if key material is not set up or accessible.
 */
enum t_cose_err_t
short_circuit_sign(int32_t               cose_algorithm_id,
                   struct q_useful_buf_c hash_to_sign,
                   struct q_useful_buf   signature_buffer,
                   struct q_useful_buf_c *signature);

/**
 * \brief Verify a short-circuit signature
 *
 * \param[in] hash_to_verify  Pointer and length of hash to verify.
 * \param[in] signature       Pointer and length of signature.
 *
 * \return This returns one of the error codes defined by \ref
 *         t_cose_err_t.
 *
 * See t_cose_sign1_sign_init() for description of the short-circuit
 * signature.
 */
enum t_cose_err_t
t_cose_crypto_short_circuit_verify(struct q_useful_buf_c hash_to_verify,
                                   struct q_useful_buf_c signature);

#endif

#ifdef __cplusplus
}
#endif

#endif
