/*
 *  t_cose_sign1_verify.c
 *
 * Copyright 2019-2021, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "qcbor/qcbor_decode.h"
#ifndef QCBOR_SPIFFY_DECODE
#error This t_cose requires a version of QCBOR that supports spiffy decode
#endif
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose_crypto.h"
#include "t_cose_util.h"
#include "t_cose_parameters.h"



/**
 * \file t_cose_sign1_verify.c
 *
 * \brief \c COSE_Sign1 verification implementation.
 */



#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
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
static inline enum t_cose_err_t
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
#endif /* T_COSE_DISABLE_SHORT_CIRCUIT_SIGN */


/**
 * \brief Check the tagging of the COSE about to be verified.
 *
 * \param[in] me                 The verification context.
 * \param[in] decode_context     The decoder context to pull from.
 *
 * \return This returns one of the error codes defined by \ref
 *         t_cose_err_t.
 *
 * This must be called after decoding the opening array of four that
 * starts all COSE message that is the item that is the content of the
 * tags.
 *
 * This checks that the tag usage is as requested by the caller.
 *
 * This returns any tags that enclose the COSE message for processing
 * at the level above COSE.
 */
static inline enum t_cose_err_t
process_tags(struct t_cose_sign1_verify_ctx *me, QCBORDecodeContext *decode_context)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   local vars                                    20          16
     *   TOTAL                                         20          16
     */
    uint64_t uTag;
    uint32_t item_tag_index = 0;
    int returned_tag_index;

    /* The 0th tag is the only one that might identify the type of the
     * CBOR we are trying to decode so it is handled special.
     */
    uTag = QCBORDecode_GetNthTagOfLast(decode_context, item_tag_index);
    item_tag_index++;
    if(me->option_flags & T_COSE_OPT_TAG_REQUIRED) {
        /* The protocol that is using COSE says the input CBOR must
         * be a COSE tag.
         */
        if(uTag != CBOR_TAG_COSE_SIGN1) {
            return T_COSE_ERR_INCORRECTLY_TAGGED;
        }
    }
    if(me->option_flags & T_COSE_OPT_TAG_PROHIBITED) {
        /* The protocol that is using COSE says the input CBOR must
         * not be a COSE tag.
         */
        if(uTag == CBOR_TAG_COSE_SIGN1) {
            return T_COSE_ERR_INCORRECTLY_TAGGED;
        }
    }
    /* If the protocol using COSE doesn't say one way or another about the
     * tag, then either is OK.
     */


    /* Initialize auTags, the returned tags, to CBOR_TAG_INVALID64 */
#if CBOR_TAG_INVALID64 != 0xffffffffffffffff
#error Initializing return tags array
#endif
    memset(me->auTags, 0xff, sizeof(me->auTags));

    returned_tag_index = 0;

    if(uTag != CBOR_TAG_COSE_SIGN1) {
        /* Never return the tag that this code is about to process. Note
         * that you can sign a COSE_SIGN1 recursively. This only takes out
         * the one tag layer that is processed here.
         */
        me->auTags[returned_tag_index] = uTag;
        returned_tag_index++;
    }

    while(1) {
        uTag = QCBORDecode_GetNthTagOfLast(decode_context, item_tag_index);
        item_tag_index++;
        if(uTag == CBOR_TAG_INVALID64) {
            break;
        }
        if(returned_tag_index > T_COSE_MAX_TAGS_TO_RETURN) {
            return T_COSE_ERR_TOO_MANY_TAGS;
        }
        me->auTags[returned_tag_index] = uTag;
        returned_tag_index++;
    }

    return T_COSE_SUCCESS;
}


/**
 * \brief Map QCBOR decode error to COSE errors.
 *
 * \param[in] qcbor_error   The QCBOR error to map.
 *
 * \return This returns one of the error codes defined by
 *         \ref t_cose_err_t.
 */
static inline enum t_cose_err_t
qcbor_decode_error_to_t_cose_error(QCBORError qcbor_error)
{
    if(qcbor_error == QCBOR_ERR_TOO_MANY_TAGS) {
        return T_COSE_ERR_TOO_MANY_TAGS;
    }
    if(QCBORDecode_IsNotWellFormedError(qcbor_error)) {
        return T_COSE_ERR_CBOR_NOT_WELL_FORMED;
    }
    if(qcbor_error != QCBOR_SUCCESS) {
        return T_COSE_ERR_SIGN1_FORMAT;
    }
    return T_COSE_SUCCESS;
}


enum t_cose_err_t
t_cose_sign1_verify_internal(struct t_cose_sign1_verify_ctx *me,
                             struct q_useful_buf_c           cose_sign1,
                             struct q_useful_buf_c           aad,
                             struct q_useful_buf_c          *payload,
                             struct t_cose_parameters       *returned_parameters,
                             bool                            is_dc)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   local vars                                    80          40
     *   Decode context                               312         256
     *   Hash output                                32-64       32-64
     *   header parameter lists                       244         176
     *   MAX(parse_headers         768     628
     *       process tags           20      16
     *       check crit             24      12
     *       create_tbs_hash     32-748  30-746
     *       crypto lib verify  64-1024 64-1024) 768-1024    768-1024
     *   TOTAL                                  1724-1436   1560-1272
     */
    QCBORDecodeContext            decode_context;
    struct q_useful_buf_c         protected_parameters;
    enum t_cose_err_t             return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(   buffer_for_tbs_hash, T_COSE_CRYPTO_MAX_HASH_SIZE);
    struct q_useful_buf_c         tbs_hash;
    struct q_useful_buf_c         signature;
    struct t_cose_label_list      critical_parameter_labels;
    struct t_cose_label_list      unknown_parameter_labels;
    struct t_cose_parameters      parameters;
    QCBORError                    qcbor_error;
#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
    struct q_useful_buf_c         short_circuit_kid;
#endif

    clear_label_list(&unknown_parameter_labels);
    clear_label_list(&critical_parameter_labels);
    clear_cose_parameters(&parameters);


    /* === Decoding of the array of four starts here === */
    QCBORDecode_Init(&decode_context, cose_sign1, QCBOR_DECODE_MODE_NORMAL);

    /* --- The array of 4 and tags --- */
    QCBORDecode_EnterArray(&decode_context, NULL);
    return_value = qcbor_decode_error_to_t_cose_error(QCBORDecode_GetError(&decode_context));
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }
    return_value = process_tags(me, &decode_context);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* --- The protected parameters --- */
    QCBORDecode_EnterBstrWrapped(&decode_context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &protected_parameters);
    if(protected_parameters.len) {
        return_value = parse_cose_header_parameters(&decode_context,
                                                    &parameters,
                                                    &critical_parameter_labels,
                                                    &unknown_parameter_labels);
        if(return_value != T_COSE_SUCCESS) {
            goto Done;
        }
    }
    QCBORDecode_ExitBstrWrapped(&decode_context);

    /* ---  The unprotected parameters --- */
    return_value = parse_cose_header_parameters(&decode_context,
                                                &parameters,
                                                 NULL,
                                                &unknown_parameter_labels);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* --- The payload --- */
    if(is_dc) {
        QCBORItem tmp;
        QCBORDecode_GetNext(&decode_context, &tmp);
        if (tmp.uDataType != QCBOR_TYPE_NULL) {
            return_value = T_COSE_ERR_CBOR_FORMATTING;
            goto Done;
        }
        /* In detached content mode, the payload should be set by
         * function caller, so there is no need to set tye payload.
         */
    } else {
        QCBORDecode_GetByteString(&decode_context, payload);
    }

    /* --- The signature --- */
    QCBORDecode_GetByteString(&decode_context, &signature);

    /* --- Finish up the CBOR decode --- */
    QCBORDecode_ExitArray(&decode_context);

    /* This check make sure the array only had the expected four
     * items. It works for definite and indefinte length arrays. Also
     * makes sure there were no extra bytes. Also that the payload
     * and signature were decoded correctly. */
    qcbor_error = QCBORDecode_Finish(&decode_context);
    return_value = qcbor_decode_error_to_t_cose_error(qcbor_error);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* === End of the decoding of the array of four === */


    if((me->option_flags & T_COSE_OPT_REQUIRE_KID) && q_useful_buf_c_is_null(parameters.kid)) {
        return_value = T_COSE_ERR_NO_KID;
        goto Done;
    }

    return_value = check_critical_labels(&critical_parameter_labels,
                                         &unknown_parameter_labels);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }


    /* -- Skip signature verification if requested --*/
    if(me->option_flags & T_COSE_OPT_DECODE_ONLY) {
        return_value = T_COSE_SUCCESS;
        goto Done;
    }


    /* -- Compute the TBS bytes -- */
    return_value = create_tbs_hash(parameters.cose_algorithm_id,
                                   protected_parameters,
                                   aad,
                                   *payload,
                                   buffer_for_tbs_hash,
                                   &tbs_hash);
    if(return_value) {
        goto Done;
    }


    /* -- Check for short-circuit signature and verify if it exists -- */
#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
    short_circuit_kid = get_short_circuit_kid();
    if(!q_useful_buf_compare(parameters.kid, short_circuit_kid)) {
        if(!(me->option_flags & T_COSE_OPT_ALLOW_SHORT_CIRCUIT)) {
            return_value = T_COSE_ERR_SHORT_CIRCUIT_SIG;
            goto Done;
        }

        return_value = t_cose_crypto_short_circuit_verify(tbs_hash, signature);
        goto Done;
    }
#endif /* T_COSE_DISABLE_SHORT_CIRCUIT_SIGN */


    /* -- Verify the signature (if it wasn't short-circuit) -- */
    return_value = t_cose_crypto_verify(parameters.cose_algorithm_id,
                                        me->verification_key,
                                        parameters.kid,
                                        tbs_hash,
                                        signature);

Done:
    if(returned_parameters != NULL) {
        *returned_parameters = parameters;
    }

    return return_value;

}

