/*
 *  t_cose_short_circuit.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose_short_circuit.h"
#include "t_cose_standard_constants.h"
#include "t_cose_crypto.h"

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
 * See documentation in t_cose_short_circuit.h
 */
enum t_cose_err_t
short_circuit_sig_size(int32_t cose_algorithm_id, size_t *sig_size)
{
    *sig_size = cose_algorithm_id == COSE_ALGORITHM_ES256 ? T_COSE_EC_P256_SIG_SIZE :
                cose_algorithm_id == COSE_ALGORITHM_ES384 ? T_COSE_EC_P384_SIG_SIZE :
                cose_algorithm_id == COSE_ALGORITHM_ES512 ? T_COSE_EC_P512_SIG_SIZE :
                0;

    return sig_size == 0 ? T_COSE_ERR_UNSUPPORTED_SIGNING_ALG : T_COSE_SUCCESS;
}


/**
 * See documentation in t_cose_short_circuit.h
 */
enum t_cose_err_t
short_circuit_sign(int32_t               cose_algorithm_id,
                   struct q_useful_buf_c hash_to_sign,
                   struct q_useful_buf   signature_buffer,
                   struct q_useful_buf_c *signature)
{
    /* approximate stack use on 32-bit machine: local use: 16 bytes
     */
    enum t_cose_err_t return_value;
    size_t            array_indx;
    size_t            amount_to_copy;
    size_t            sig_size;

    return_value = short_circuit_sig_size(cose_algorithm_id, &sig_size);

    /* Check the signature length against buffer size */
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    if(sig_size > signature_buffer.len) {
        /* Buffer too small for this signature type */
        return_value = T_COSE_ERR_SIG_BUFFER_SIZE;
        goto Done;
    }

    /* Loop concatening copies of the hash to fill out to signature size */
    for(array_indx = 0; array_indx < sig_size; array_indx += hash_to_sign.len) {
        amount_to_copy = sig_size - array_indx;
        if(amount_to_copy > hash_to_sign.len) {
            amount_to_copy = hash_to_sign.len;
        }
        memcpy((uint8_t *)signature_buffer.ptr + array_indx,
               hash_to_sign.ptr,
               amount_to_copy);
    }
    signature->ptr = signature_buffer.ptr;
    signature->len = sig_size;
    return_value   = T_COSE_SUCCESS;

Done:
    return return_value;
}

/**
 * See documentation in t_cose_short_circuit.h
 */
enum t_cose_err_t
t_cose_crypto_short_circuit_verify(struct q_useful_buf_c hash_to_verify,
                                   struct q_useful_buf_c signature)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   local vars                                    24          12
     *   TOTAL                                         24          12
     */
    struct q_useful_buf_c hash_from_sig;
    enum t_cose_err_t     return_value;

    hash_from_sig = q_useful_buf_head(signature, hash_to_verify.len);
    if(q_useful_buf_c_is_null(hash_from_sig)) {
        return_value = T_COSE_ERR_SIG_VERIFY;
        goto Done;
    }

    if(q_useful_buf_compare(hash_from_sig, hash_to_verify)) {
        return_value = T_COSE_ERR_SIG_VERIFY;
    } else {
        return_value = T_COSE_SUCCESS;
    }

Done:
    return return_value;
}

#else /* T_COSE_DISABLE_SHORT_CIRCUIT_SIGN */

/* So some of the build checks don't get confused by an empty object file */
void t_cose_short_circuit_placeholder()
{}


#endif /* T_COSE_DISABLE_SHORT_CIRCUIT_SIGN */

