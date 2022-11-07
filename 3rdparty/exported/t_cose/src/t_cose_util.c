/*
 *  t_cose_util.c
 *
 * Copyright 2019-2021, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "qcbor/qcbor.h"
#include "t_cose/t_cose_common.h"
#include "t_cose_util.h"
#include "t_cose_standard_constants.h"
#include "t_cose_crypto.h"


/**
 * \file t_cose_util.c
 *
 * \brief Implementation of t_cose utility functions.
 *
 * These are some functions common to signing and verification,
 * primarily the to-be-signed bytes hashing.
 */


/*
 * Public function. See t_cose_util.h
 */
int32_t hash_alg_id_from_sig_alg_id(int32_t cose_algorithm_id)
{
    /* If other hashes, particularly those that output bigger hashes
     * are added here, various other parts of this code have to be
     * changed to have larger buffers, in particular
     * \ref T_COSE_CRYPTO_MAX_HASH_SIZE.
     */
    /* ? : operator precedence is correct here. This makes smaller
     * code than a switch statement and is easier to read.
     */
    return cose_algorithm_id == COSE_ALGORITHM_ES256 ? COSE_ALGORITHM_SHA_256 :
#ifndef T_COSE_DISABLE_ES384
           cose_algorithm_id == COSE_ALGORITHM_ES384 ? COSE_ALGORITHM_SHA_384 :
#endif
#ifndef T_COSE_DISABLE_ES512
           cose_algorithm_id == COSE_ALGORITHM_ES512 ? COSE_ALGORITHM_SHA_512 :
#endif
                                                       T_COSE_INVALID_ALGORITHM_ID;
}




/**
 * \brief Hash an encoded bstr without actually encoding it in memory
 *
 * @param hash_ctx  Hash context to hash it into
 * @param bstr      Bytes of the bstr
 *
 * If \c bstr is \c NULL_Q_USEFUL_BUF_C, a zero-length bstr will be
 * hashed into the output.
 */
static void hash_bstr(struct t_cose_crypto_hash *hash_ctx,
                      struct q_useful_buf_c      bstr)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   buffer_for_encoded                             9           9
     *   useful_buf                                    16           8
     *   hash function (a guess! variable!)        16-512      16-512
     *   TOTAL                                     41-537      23-529
     */

    /* make a struct q_useful_buf on the stack of size QCBOR_HEAD_BUFFER_SIZE */
    Q_USEFUL_BUF_MAKE_STACK_UB (buffer_for_encoded_head, QCBOR_HEAD_BUFFER_SIZE);
    struct q_useful_buf_c       encoded_head;

    encoded_head = QCBOREncode_EncodeHead(buffer_for_encoded_head,
                                          CBOR_MAJOR_TYPE_BYTE_STRING,
                                          0,
                                          bstr.len);

    /* An encoded bstr is the CBOR head with its length followed by the bytes */
    t_cose_crypto_hash_update(hash_ctx, encoded_head);
    t_cose_crypto_hash_update(hash_ctx, bstr);
}


/*
 * Public function. See t_cose_util.h
 */
/*
 * Format of to-be-signed bytes used by create_tbs_hash().  This is
 * defined in COSE (RFC 8152) section 4.4. It is the input to the
 * hash.
 *
 * Sig_structure = [
 *    context : "Signature" / "Signature1" / "CounterSignature",
 *    body_protected : empty_or_serialized_map,
 *    ? sign_protected : empty_or_serialized_map,
 *    external_aad : bstr,
 *    payload : bstr
 * ]
 *
 * body_protected refers to the protected parameters from the main
 * COSE_Sign1 structure. This is a little hard to to understand in the
 * spec.
 */
enum t_cose_err_t create_tbs_hash(int32_t                cose_algorithm_id,
                                  struct q_useful_buf_c  protected_parameters,
                                  struct q_useful_buf_c  aad,
                                  struct q_useful_buf_c  payload,
                                  struct q_useful_buf    buffer_for_hash,
                                  struct q_useful_buf_c *hash)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   local vars                                     8           6
     *   hash_ctx                                   8-224       8-224
     *   hash function (a guess! variable!)        16-512      16-512
     *   TOTAL                                     32-748      30-746
     */
    enum t_cose_err_t           return_value;
    struct t_cose_crypto_hash   hash_ctx;
    int32_t                     hash_alg_id;

    /* Start the hashing */
    hash_alg_id = hash_alg_id_from_sig_alg_id(cose_algorithm_id);
    /* Don't check hash_alg_id for failure. t_cose_crypto_hash_start()
     * will handle error properly. It was also checked earlier.
     */
    return_value = t_cose_crypto_hash_start(&hash_ctx, hash_alg_id);
    if(return_value) {
        goto Done;
    }

    /*
     * Format of to-be-signed bytes.  This is defined in COSE (RFC
     * 8152) section 4.4. It is the input to the hash.
     *
     * Sig_structure = [
     *    context : "Signature" / "Signature1" / "CounterSignature",
     *    body_protected : empty_or_serialized_map,
     *    ? sign_protected : empty_or_serialized_map,
     *    external_aad : bstr,
     *    payload : bstr
     * ]
     *
     * sign_protected is not used with COSE_Sign1 since there is no
     * signer chunk.
     *
     * external_aad allows external data to be covered by the
     * signature, but may be a NULL_Q_USEFUL_BUF_C in which case a
     * zero-length bstr will be correctly hashed into the result.
     *
     * Instead of formatting the TBS bytes in one buffer, they are
     * formatted in chunks and fed into the hash. If actually
     * formatted, the TBS bytes are slightly larger than the payload,
     * so this saves a lot of memory.
     */

    /* Hand-constructed CBOR for the array of 4 and the context string.
     * \x84 is an array of 4. \x6A is a text string of 10 bytes. */
    t_cose_crypto_hash_update(&hash_ctx, Q_USEFUL_BUF_FROM_SZ_LITERAL("\x84\x6A" COSE_SIG_CONTEXT_STRING_SIGNATURE1));

    /* body_protected */
    hash_bstr(&hash_ctx, protected_parameters);

    /* external_aad */
    hash_bstr(&hash_ctx, aad);

    /* payload */
    hash_bstr(&hash_ctx, payload);

    /* Finish the hash and set up to return it */
    return_value = t_cose_crypto_hash_finish(&hash_ctx,
                                             buffer_for_hash,
                                             hash);
Done:
    return return_value;
}


#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
/* This is a random hard coded kid (key ID) that is used to indicate
 * short-circuit signing. It is OK to hard code this as the
 * probability of collision with this ID is very low and the same as
 * for collision between any two key IDs of any sort.
 */

static const uint8_t defined_short_circuit_kid[] = {
    0xef, 0x95, 0x4b, 0x4b, 0xd9, 0xbd, 0xf6, 0x70,
    0xd0, 0x33, 0x60, 0x82, 0xf5, 0xef, 0x15, 0x2a,
    0xf8, 0xf3, 0x5b, 0x6a, 0x6c, 0x00, 0xef, 0xa6,
    0xa9, 0xa7, 0x1f, 0x49, 0x51, 0x7e, 0x18, 0xc6};

static struct q_useful_buf_c short_circuit_kid;

/*
 * Public function. See t_cose_util.h
 */
struct q_useful_buf_c get_short_circuit_kid(void)
{
    short_circuit_kid.len = sizeof(defined_short_circuit_kid);
    short_circuit_kid.ptr = defined_short_circuit_kid;

    return short_circuit_kid;
}
#endif
