/*
 * t_cose_make_test_messages.c
 *
 * Copyright (c) 2019-2022, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose_make_test_messages.h"
#include "qcbor/qcbor.h"
#include "t_cose_crypto.h"
#include "t_cose_util.h"


/**
 * \file t_cose_make_test_messages.c
 *
 * This makes \c COSE_Sign1 messages of various sorts for testing
 * verification. Some of them are badly formed to test various
 * verification failures.
 *
 * This is essentially a hacked-up version of t_cose_sign1_sign.c.
 */


#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
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
static inline enum t_cose_err_t
short_circuit_sign(int32_t               cose_algorithm_id,
                   struct q_useful_buf_c hash_to_sign,
                   struct q_useful_buf   signature_buffer,
                   struct q_useful_buf_c *signature)
{
    /* approximate stack use on 32-bit machine: local use: 16 bytes
     */
    enum t_cose_err_t return_value;
    size_t            array_index;
    size_t            amount_to_copy;
    size_t            sig_size;

    sig_size = cose_algorithm_id == COSE_ALGORITHM_ES256 ? T_COSE_EC_P256_SIG_SIZE :
               cose_algorithm_id == COSE_ALGORITHM_ES384 ? T_COSE_EC_P384_SIG_SIZE :
               cose_algorithm_id == COSE_ALGORITHM_ES512 ? T_COSE_EC_P512_SIG_SIZE :
                                                           0;

    /* Check the signature length against buffer size*/
    if(sig_size == 0) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    if(sig_size > signature_buffer.len) {
        /* Buffer too small for this signature type */
        return_value = T_COSE_ERR_SIG_BUFFER_SIZE;
        goto Done;
    }

    /* Loop concatening copies of the hash to fill out to signature size */
    for(array_index = 0; array_index < sig_size; array_index += hash_to_sign.len) {
        amount_to_copy = sig_size - array_index;
        if(amount_to_copy > hash_to_sign.len) {
            amount_to_copy = hash_to_sign.len;
        }
        memcpy((uint8_t *)signature_buffer.ptr + array_index,
               hash_to_sign.ptr,
               amount_to_copy);
    }
    signature->ptr = signature_buffer.ptr;
    signature->len = sig_size;
    return_value   = T_COSE_SUCCESS;

Done:
    return return_value;
}
#endif /* T_COSE_DISABLE_SHORT_CIRCUIT_SIGN */


/**
 * \brief  Makes various protected parameters for various tests
 *
 * \param[in] test_message_options  Flags to select test modes.
 * \param[in] cose_algorithm_id     The algorithm ID to put in the parameters.
 * \param[in] buffer_for_protected_parameters  Pointer and length into which
 *                                             the resulting encoded protected
 *                                             parameters is put.
 *
 * \return The pointer and length of the protected parameters is
 * returned, or \c NULL_Q_USEFUL_BUF_C if this fails.
 *
 * The protected parameters are returned in fully encoded CBOR format as
 * they are added to the \c COSE_Sign1 as a binary string. This is
 * different from the unprotected parameters which are not handled this
 * way.
 *
 * This returns \c NULL_Q_USEFUL_BUF_C if buffer_for_protected_parameters was
 * too small. See also definition of
 * \c T_COSE_SIGN1_MAX_SIZE_PROTECTED_PARAMETERS.
 */
static inline struct q_useful_buf_c
encode_protected_parameters(uint32_t            test_message_options,
                            int32_t             cose_algorithm_id,
                            struct q_useful_buf buffer_for_protected_parameters)
{
    /* approximate stack use on 32-bit machine:
     * local use: 170
     * with calls: 210
     */
    struct q_useful_buf_c protected_parameters;
    QCBORError            qcbor_result;
    QCBOREncodeContext    cbor_encode_ctx;
    struct q_useful_buf_c return_value;

    if(test_message_options & T_COSE_TEST_EMPTY_PROTECTED_PARAMETERS) {
        /* An empty q_useful_buf_c */
        return (struct q_useful_buf_c){buffer_for_protected_parameters.ptr, 0};
    }


    if(test_message_options & T_COSE_TEST_UNCLOSED_PROTECTED) {
        *(uint8_t *)(buffer_for_protected_parameters.ptr) = 0xa1;
        return (struct q_useful_buf_c){buffer_for_protected_parameters.ptr, 1};
    }

    QCBOREncode_Init(&cbor_encode_ctx, buffer_for_protected_parameters);

    if(test_message_options & T_COSE_TEST_BAD_PROTECTED) {
        QCBOREncode_OpenArray(&cbor_encode_ctx);
        QCBOREncode_AddInt64(&cbor_encode_ctx, 42);
        QCBOREncode_CloseArray(&cbor_encode_ctx);
        goto Finish;
    }

    if(test_message_options & T_COSE_TEST_INDEFINITE_MAPS_ARRAYS) {
        QCBOREncode_OpenMapIndefiniteLength(&cbor_encode_ctx);
    } else {
        QCBOREncode_OpenMap(&cbor_encode_ctx);
    }
    QCBOREncode_AddInt64ToMapN(&cbor_encode_ctx,
                               COSE_HEADER_PARAM_ALG,
                               cose_algorithm_id);

    if(test_message_options & T_COSE_TEST_UNKNOWN_CRIT_UINT_PARAMETER) {
        /* This is the parameter that will be unknown */
        QCBOREncode_AddInt64ToMapN(&cbor_encode_ctx, 42, 43);
        /* This is the critical labels parameter */
        if(test_message_options & T_COSE_TEST_INDEFINITE_MAPS_ARRAYS) {
            QCBOREncode_OpenArrayIndefiniteLengthInMapN(&cbor_encode_ctx, COSE_HEADER_PARAM_CRIT);
        } else {
            QCBOREncode_OpenArrayInMapN(&cbor_encode_ctx, COSE_HEADER_PARAM_CRIT);
        }
        QCBOREncode_AddInt64(&cbor_encode_ctx, 42);
        QCBOREncode_AddInt64(&cbor_encode_ctx, 43);
        QCBOREncode_AddInt64(&cbor_encode_ctx, 44);
        if(test_message_options & T_COSE_TEST_INDEFINITE_MAPS_ARRAYS) {
            QCBOREncode_CloseArrayIndefiniteLength(&cbor_encode_ctx);
        } else {
            QCBOREncode_CloseArray(&cbor_encode_ctx);
        }
    }

    if(test_message_options & T_COSE_TEST_UNKNOWN_CRIT_TSTR_PARAMETER) {
        /* This is the parameter that will be unknown */
        QCBOREncode_AddInt64ToMap(&cbor_encode_ctx, "hh", 43);
        /* This is the critical labels parameter */
        QCBOREncode_OpenArrayInMapN(&cbor_encode_ctx, COSE_HEADER_PARAM_CRIT);
        QCBOREncode_AddSZString(&cbor_encode_ctx, "hh");
        QCBOREncode_AddSZString(&cbor_encode_ctx, "h");
        QCBOREncode_AddSZString(&cbor_encode_ctx, "hhh");
        QCBOREncode_CloseArray(&cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_BAD_CRIT_LABEL) {
        /* This is the critical labels parameter */
        QCBOREncode_OpenArrayInMapN(&cbor_encode_ctx, COSE_HEADER_PARAM_CRIT);
        QCBOREncode_AddBool(&cbor_encode_ctx, true);
        QCBOREncode_CloseArray(&cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_CRIT_PARAMETER_EXIST) {
        /* This is the critical labels parameter */
        QCBOREncode_OpenArrayInMapN(&cbor_encode_ctx, COSE_HEADER_PARAM_CRIT);
        int i;
        /* Add the maxium */
        for(i = 0; i < T_COSE_PARAMETER_LIST_MAX; i++) {
            QCBOREncode_AddInt64(&cbor_encode_ctx, i + 10);
        }
        QCBOREncode_CloseArray(&cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_TOO_MANY_CRIT_PARAMETER_EXIST) {
        /* This is the critical labels parameter */
        QCBOREncode_OpenArrayInMapN(&cbor_encode_ctx, COSE_HEADER_PARAM_CRIT);
        int i;
        /* One more than the maximum */
        for(i = 0; i < T_COSE_PARAMETER_LIST_MAX+1; i++) {
            QCBOREncode_AddInt64(&cbor_encode_ctx, i + 10);
        }
        QCBOREncode_CloseArray(&cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_TOO_MANY_TSTR_CRIT_LABLELS) {
        /* This is the critical labels parameter */
        QCBOREncode_OpenArrayInMapN(&cbor_encode_ctx, COSE_HEADER_PARAM_CRIT);
        int i;
        /* One more than the maximum */
        for(i = 0; i < T_COSE_PARAMETER_LIST_MAX+1; i++) {
            QCBOREncode_AddSZString(&cbor_encode_ctx, "");
        }
        QCBOREncode_CloseArray(&cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_EMPTY_CRIT_PARAMETER) {
        QCBOREncode_OpenArrayInMapN(&cbor_encode_ctx, COSE_HEADER_PARAM_CRIT);
        QCBOREncode_CloseArray(&cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_KID_IN_PROTECTED) {
        QCBOREncode_AddBytesToMapN(&cbor_encode_ctx,
                                   COSE_HEADER_PARAM_KID,
                                   Q_USEFUL_BUF_FROM_SZ_LITERAL("kid"));
    }

    if(test_message_options & T_COSE_TEST_DUP_CONTENT_ID) {
        QCBOREncode_AddUInt64ToMapN(&cbor_encode_ctx,
                                    COSE_HEADER_PARAM_CONTENT_TYPE,
                                    3);
    }

    if(test_message_options & T_COSE_TEST_INDEFINITE_MAPS_ARRAYS) {
        QCBOREncode_CloseMapIndefiniteLength(&cbor_encode_ctx);
    } else {
        QCBOREncode_CloseMap(&cbor_encode_ctx);
    }

Finish:
    qcbor_result = QCBOREncode_Finish(&cbor_encode_ctx, &protected_parameters);

    if(qcbor_result == QCBOR_SUCCESS) {
        return_value = protected_parameters;
    } else {
        return_value = NULL_Q_USEFUL_BUF_C;
    }

    return return_value;
}


/**
 * \brief Add the unprotected parameters to a CBOR encoding context
 *
 * \param[in] test_message_options  Flags to select test modes.
 * \param[in] cbor_encode_ctx       CBOR encoding context to output to.
 * \param[in] kid                   The key ID to go into the kid parameter.
 *
 * No error is returned. If an error occurred it will be returned when
 * \c QCBOR_Finish() is called on \c cbor_encode_ctx.
 *
 * The unprotected parameters added by this are the key ID plus
 * lots of different test parameters.
 */
static inline void
add_unprotected_parameters(uint32_t              test_message_options,
                           QCBOREncodeContext   *cbor_encode_ctx,
                           struct q_useful_buf_c kid)
{
    if(test_message_options & T_COSE_TEST_UNPROTECTED_NOT_MAP) {
        QCBOREncode_OpenArray(cbor_encode_ctx);
        QCBOREncode_AddBytes(cbor_encode_ctx, kid);
        QCBOREncode_CloseArray(cbor_encode_ctx);
        return; /* skip the rest for this degenerate test */
    }

    if(test_message_options & T_COSE_TEST_INDEFINITE_MAPS_ARRAYS) {
        QCBOREncode_OpenMapIndefiniteLength(cbor_encode_ctx);
    } else {
        QCBOREncode_OpenMap(cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_NOT_WELL_FORMED_1) {
        QCBOREncode_AddEncoded(cbor_encode_ctx,
                               Q_USEFUL_BUF_FROM_SZ_LITERAL("xxxxxx"));
    }

    /* Put in a byte string (not a text string) for the parameter label */
    if(test_message_options & T_COSE_TEST_PARAMETER_LABEL) {
        QCBOREncode_AddBytes(cbor_encode_ctx, kid);
        QCBOREncode_AddBytes(cbor_encode_ctx, kid);
    }

    if(test_message_options & T_COSE_TEST_BAD_CRIT_PARAMETER) {
        QCBOREncode_AddSZStringToMapN(cbor_encode_ctx,
                                      COSE_HEADER_PARAM_CRIT, "hi");
    }

    if(test_message_options & T_COSE_TEST_EXTRA_PARAMETER) {
        QCBOREncode_OpenArrayInMapN(cbor_encode_ctx, 55);
        QCBOREncode_OpenMap(cbor_encode_ctx);
        QCBOREncode_AddSZStringToMapN(cbor_encode_ctx, 66, "hi");
        QCBOREncode_CloseMap(cbor_encode_ctx);
        QCBOREncode_CloseArray(cbor_encode_ctx);
    }


    if(test_message_options & T_COSE_TEST_NOT_WELL_FORMED_2) {
        QCBOREncode_OpenArrayInMapN(cbor_encode_ctx, 55);
        QCBOREncode_OpenMap(cbor_encode_ctx);
        QCBOREncode_AddSZStringToMapN(cbor_encode_ctx, 66, "hi");
        /* 0xff is a break outside of anything indefinite and thus
         * not-well-formed, This test used to use a 0x3d before
         * spiffy decode, but spiffy decode can traverse that
         * without error because it is not an
         * QCBORDecode_IsUnrecoverableError().
         * Improvement: add a test case for the 3d error back in
         */
        QCBOREncode_AddEncoded(cbor_encode_ctx,
                               Q_USEFUL_BUF_FROM_SZ_LITERAL("\xff"));
        QCBOREncode_AddSZStringToMapN(cbor_encode_ctx, 67, "bye");

        QCBOREncode_CloseMap(cbor_encode_ctx);
        QCBOREncode_CloseArray(cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_CRIT_NOT_PROTECTED) {
        /* This is the critical labels parameter */
        QCBOREncode_OpenArrayInMapN(cbor_encode_ctx, COSE_HEADER_PARAM_CRIT);
        int i;
        /* Add the maxium */
        for(i = 0; i < T_COSE_PARAMETER_LIST_MAX; i++) {
            QCBOREncode_AddInt64(cbor_encode_ctx, i + 100);
            QCBOREncode_AddSZString(cbor_encode_ctx, "xxxx");
        }
        QCBOREncode_CloseArray(cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_TOO_MANY_UNKNOWN) {
        int i;
        for(i = 0; i < T_COSE_PARAMETER_LIST_MAX + 1; i++ ) {
            QCBOREncode_AddBoolToMapN(cbor_encode_ctx, i+10, true);
        }
    }

    if(!q_useful_buf_c_is_null_or_empty(kid)) {
        QCBOREncode_AddBytesToMapN(cbor_encode_ctx, COSE_HEADER_PARAM_KID, kid);
    }

    if(test_message_options & T_COSE_TEST_ALL_PARAMETERS) {
        QCBOREncode_AddBytesToMapN(cbor_encode_ctx,
                                   COSE_HEADER_PARAM_IV,
                                   Q_USEFUL_BUF_FROM_SZ_LITERAL("iv"));
        QCBOREncode_AddBytesToMapN(cbor_encode_ctx,
                                   COSE_HEADER_PARAM_PARTIAL_IV,
                                   Q_USEFUL_BUF_FROM_SZ_LITERAL("partial_iv"));
        QCBOREncode_AddInt64ToMapN(cbor_encode_ctx,
                                   COSE_HEADER_PARAM_CONTENT_TYPE,
                                   1);
        /* A slighly complex unknown header parameter */
        QCBOREncode_OpenArrayInMapN(cbor_encode_ctx, 55);
        QCBOREncode_OpenMap(cbor_encode_ctx);
        QCBOREncode_AddSZStringToMapN(cbor_encode_ctx, 66, "hi");
        QCBOREncode_AddSZStringToMapN(cbor_encode_ctx, 67, "bye");
        QCBOREncode_CloseMap(cbor_encode_ctx);
        QCBOREncode_OpenArray(cbor_encode_ctx);
        QCBOREncode_OpenMap(cbor_encode_ctx);
        QCBOREncode_CloseMap(cbor_encode_ctx);
        QCBOREncode_CloseArray(cbor_encode_ctx);
        QCBOREncode_CloseArray(cbor_encode_ctx);
    }

    if(test_message_options & T_COSE_TEST_TOO_LARGE_CONTENT_TYPE) {
        QCBOREncode_AddInt64ToMapN(cbor_encode_ctx,
                                   COSE_HEADER_PARAM_CONTENT_TYPE,
                                   UINT16_MAX+1);
    }

    if(test_message_options & T_COSE_TEST_DUP_CONTENT_ID) {
        QCBOREncode_AddUInt64ToMapN(cbor_encode_ctx,
                                    COSE_HEADER_PARAM_CONTENT_TYPE,
                                    3);
    }

    if(test_message_options & T_COSE_TEST_INDEFINITE_MAPS_ARRAYS) {
        QCBOREncode_CloseMapIndefiniteLength(cbor_encode_ctx);
    } else {
        QCBOREncode_CloseMap(cbor_encode_ctx);
    }
}


/*
 * Buffer for the protected parameters. There used to be a buffer in
 * t_cose_sign1_sign_ctx but it was removed when code was improved.
 * This needs to be carried between encoding the header and doing
 * the signatured, so a buffer is needed. The size is that of the
 * largest test protected header and some padding.
 */
static uint8_t s_protected_params[40];

/**
 * Replica of t_cose_sign1_encode_parameters() with modifications to
 * output various good and bad messages for testing verification.
 */
static enum t_cose_err_t
t_cose_sign1_test_message_encode_parameters(struct t_cose_sign1_sign_ctx *me,
                                            uint32_t                       test_mess_options,
                                            QCBOREncodeContext           *cbor_encode_ctx)
{
    enum t_cose_err_t      return_value;
    struct q_useful_buf_c  kid;
    int32_t                hash_alg_id;
    struct q_useful_buf    buffer_for_protected_parameters;


    /* Check the cose_algorithm_id now by getting the hash alg as an early
     * error check even though it is not used until later.
     */
    hash_alg_id = hash_alg_id_from_sig_alg_id(me->cose_algorithm_id);
    if(hash_alg_id == T_COSE_INVALID_ALGORITHM_ID) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    /* Add the CBOR tag indicating COSE_Sign1 */
    if(!(me->option_flags & T_COSE_OPT_OMIT_CBOR_TAG)) {
        QCBOREncode_AddTag(cbor_encode_ctx, CBOR_TAG_COSE_SIGN1);
    }

    /* Get started with the tagged array that holds the four parts of
     * a cose single signed message */
    if(test_mess_options & T_COSE_TEST_INDEFINITE_MAPS_ARRAYS) {
        QCBOREncode_OpenArrayIndefiniteLength(cbor_encode_ctx);
    } else {
        QCBOREncode_OpenArray(cbor_encode_ctx);
    }

    /* The protected parameters, which are added as a wrapped bstr  */
    if( ! (test_mess_options & T_COSE_TEST_NO_PROTECTED_PARAMETERS)) {
        buffer_for_protected_parameters = Q_USEFUL_BUF_FROM_BYTE_ARRAY(s_protected_params);

        me->protected_parameters = encode_protected_parameters(test_mess_options,
                                                               me->cose_algorithm_id,
                                                               buffer_for_protected_parameters);
        QCBOREncode_AddBytes(cbor_encode_ctx, me->protected_parameters);
    }

    /* The Unprotected parameters */
    /* Get the key id because it goes into the parameters that are about
     to be made. */
    if(me->option_flags & T_COSE_OPT_SHORT_CIRCUIT_SIG) {
#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
        kid = get_short_circuit_kid();
#else
        return T_COSE_ERR_SHORT_CIRCUIT_SIG_DISABLED;
#endif
    } else {
        kid = me->kid;
    }

    if( ! (test_mess_options & T_COSE_TEST_NO_UNPROTECTED_PARAMETERS)) {
        add_unprotected_parameters(test_mess_options, cbor_encode_ctx, kid);
    }

    QCBOREncode_BstrWrap(cbor_encode_ctx);

    /* Any failures in CBOR encoding will be caught in finish when the
     * CBOR encoding is closed off. No need to track here as the CBOR
     * encoder tracks it internally. */

    return_value = T_COSE_SUCCESS;

    return return_value;
}


/**
 * Replica of t_cose_sign1_output_signature() with modifications to
 * output various good and bad messages for testing verification.
 */
static enum t_cose_err_t
t_cose_sign1_test_message_output_signature(struct t_cose_sign1_sign_ctx *me,
                                           uint32_t                      test_mess_options,
                                           QCBOREncodeContext           *cbor_encode_ctx)
{
    /* approximate stack use on 32-bit machine:
     *   32 bytes local use
     *   220 to 434 for calls dependin on hash implementation
     *   32 to 64 bytes depending on hash alg (SHA256, 384 or 512)
     *   64 to 260 depending on EC alg
     *   348 to 778 depending on hash and EC alg
     *   Also add stack use by EC and hash functions
     */
    enum t_cose_err_t            return_value;
    QCBORError                   cbor_err;
    /* pointer and length of the completed tbs hash */
    struct q_useful_buf_c        tbs_hash;
    /* Pointer and length of the completed signature */
    struct q_useful_buf_c        signature;
    /* Pointer and length of the buffer for the signature */
    struct q_useful_buf          buffer_for_signature;
    /* Buffer for the tbs hash. */
    Q_USEFUL_BUF_MAKE_STACK_UB(  buffer_for_tbs_hash, T_COSE_CRYPTO_MAX_HASH_SIZE);
    struct q_useful_buf_c        signed_payload;

    QCBOREncode_CloseBstrWrap2(cbor_encode_ctx, false, &signed_payload);

    /* Check there are no CBOR encoding errors before proceeding with
     * hashing and signing. This is not actually necessary as the
     * errors will be caught correctly later, but it does make it a
     * bit easier for the caller to debug problems.
     */
    cbor_err = QCBOREncode_GetErrorState(cbor_encode_ctx);
    if(cbor_err == QCBOR_ERR_BUFFER_TOO_SMALL) {
        return_value = T_COSE_ERR_TOO_SMALL;
        goto Done;
    } else if(cbor_err != QCBOR_SUCCESS) {
        return_value = T_COSE_ERR_CBOR_FORMATTING;
        goto Done;
    }

    /* Create the hash of the to-be-signed bytes. Inputs to the hash
     * are the protected parameters, the payload that is getting signed, the
     * cose signature alg from which the hash alg is determined. The
     * cose_algorithm_id was checked in t_cose_sign1_init() so it
     * doesn't need to be checked here.
     */
    return_value = create_tbs_hash(me->cose_algorithm_id,
                                   me->protected_parameters,
                                   NULL_Q_USEFUL_BUF_C,
                                   signed_payload,
                                   buffer_for_tbs_hash,
                                   &tbs_hash);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* The signature gets written directly into the output buffer.
     * The matching QCBOREncode_CloseBytes call further down still needs do a
     * memmove to make space for the CBOR header, but at least we avoid the need
     * to allocate an extra buffer.
     */
    QCBOREncode_OpenBytes(cbor_encode_ctx, &buffer_for_signature);

    /* Compute the signature using public key crypto. The key selector
     * and algorithm ID are passed in to know how and what to sign
     * with. The hash of the TBS bytes are what is signed. A buffer in
     * which to place the signature is passed in and the signature is
     * returned.
     *
     * Short-circuit signing is invoked if requested. It does no
     * public key operation and requires no key. It is just a test
     * mode that always works.
     */
    if(!(me->option_flags & T_COSE_OPT_SHORT_CIRCUIT_SIG)) {
        /* Normal, non-short-circuit signing */
        return_value = t_cose_crypto_sign(me->cose_algorithm_id,
                                          me->signing_key,
                                          tbs_hash,
                                          buffer_for_signature,
                                         &signature);
    } else {
#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
        return_value = short_circuit_sign(me->cose_algorithm_id,
                                          tbs_hash,
                                          buffer_for_signature,
                                          &signature);
#endif
    }

    if(return_value) {
        goto Done;
    }

    /* Add signature to CBOR and close out the array */
    QCBOREncode_CloseBytes(cbor_encode_ctx, signature.len);

    if(test_mess_options & T_COSE_TEST_INDEFINITE_MAPS_ARRAYS) {
        QCBOREncode_CloseArrayIndefiniteLength(cbor_encode_ctx);
    } else {
        QCBOREncode_CloseArray(cbor_encode_ctx);
    }

    /* The layer above this must check for and handle CBOR encoding
     * errors CBOR encoding errors.  Some are detected at the start of
     * this function, but they cannot all be deteced there.
     */
Done:
    return return_value;
}


/*
 * Public function. See t_cose_make_test_messages.h
 */
enum t_cose_err_t
t_cose_test_message_sign1_sign(struct t_cose_sign1_sign_ctx *me,
                               uint32_t                    test_message_options,
                               struct q_useful_buf_c         payload,
                               struct q_useful_buf           out_buf,
                               struct q_useful_buf_c        *result)
{
    QCBOREncodeContext  encode_context;
    enum t_cose_err_t   return_value;

    /* -- Initialize CBOR encoder context with output buffer */
    QCBOREncode_Init(&encode_context, out_buf);

    /* -- Output the header parameters into the encoder context -- */
    return_value = t_cose_sign1_test_message_encode_parameters(me, test_message_options, &encode_context);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* -- Output the payload into the encoder context -- */
    /* Payload may or may not actually be CBOR format here. This
     * function does the job just fine because it just adds bytes to
     * the encoded output without anything extra.
     */
    QCBOREncode_AddEncoded(&encode_context, payload);

    /* -- Sign and put signature in the encoder context -- */
    return_value = t_cose_sign1_test_message_output_signature(me,
                                                              test_message_options,
                                                              &encode_context);
    if(return_value) {
        goto Done;
    }

    /* -- Close off and get the resulting encoded CBOR -- */
    if(QCBOREncode_Finish(&encode_context, result)) {
        return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
        goto Done;
    }

Done:
    return return_value;
}

