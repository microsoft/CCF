/*
 * t_cose_sign1_sign.c
 *
 * Copyright (c) 2018-2021, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose/t_cose_sign1_sign.h"
#include "qcbor/qcbor.h"
#include "t_cose_standard_constants.h"
#include "t_cose_crypto.h"
#include "t_cose_util.h"
#include "t_cose_short_circuit.h"

#ifndef QCBOR_1_1
// The OpenBytes API we use was only added in 1.1.
#error t_cose requires QCBOR 1.1 or greater
#endif

/**
 * \file t_cose_sign1_sign.c
 *
 * \brief This implements t_cose signing
 *
 * Stack usage to sign is dependent on the signing alg and key size
 * and type of hash implementation. t_cose_sign1_finish() is the main
 * user of stack It is 384 for \ref COSE_ALGORITHM_ES256 and 778 for
 * \ref COSE_ALGORITHM_ES512.
 */


/*
 * Cross-check to make sure public definition of algorithm
 * IDs matches the internal ones.
 */
#if T_COSE_ALGORITHM_ES256 != COSE_ALGORITHM_ES256
#error COSE algorithm identifier definitions are in error
#endif

#if T_COSE_ALGORITHM_ES384 != COSE_ALGORITHM_ES384
#error COSE algorithm identifier definitions are in error
#endif

#if T_COSE_ALGORITHM_ES512 != COSE_ALGORITHM_ES512
#error COSE algorithm identifier definitions are in error
#endif

#if T_COSE_ALGORITHM_PS256 != COSE_ALGORITHM_PS256
#error COSE algorithm identifier definitions are in error
#endif

#if T_COSE_ALGORITHM_PS384 != COSE_ALGORITHM_PS384
#error COSE algorithm identifier definitions are in error
#endif

#if T_COSE_ALGORITHM_PS512 != COSE_ALGORITHM_PS512
#error COSE algorithm identifier definitions are in error
#endif

/**
 * \brief  Makes the protected header parameters for COSE.
 *
 * \param[in] cose_algorithm_id      The COSE algorithm ID to put in the
 *                                   header parameters.
 * \param[in,out] cbor_encode_ctx    Encoding context to output to.
 *
 * \return   The pointer and length of the encoded protected
 *           parameters is returned, or \c NULL_Q_USEFUL_BUF_C if this fails.
 *           This will have the same pointer as \c buffer_for_parameters,
 *           but the pointer is conts and the length is that of the valid
 *           data, not of the size of the buffer.
 *
 * The protected parameters are returned in fully encoded CBOR format as
 * they are added to the \c COSE_Sign1 message as a binary string. This is
 * different from the unprotected parameters which are not handled this
 * way.
 */
static inline struct q_useful_buf_c
encode_protected_parameters(int32_t             cose_algorithm_id,
                            QCBOREncodeContext *cbor_encode_ctx)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   local vars                                    16           8
     *   QCBOR   (guess)                               32          24
     *   TOTAL                                         48          32
     */
    struct q_useful_buf_c protected_parameters;

    QCBOREncode_BstrWrap(cbor_encode_ctx);
    QCBOREncode_OpenMap(cbor_encode_ctx);
    QCBOREncode_AddInt64ToMapN(cbor_encode_ctx,
                               COSE_HEADER_PARAM_ALG,
                               cose_algorithm_id);
    QCBOREncode_CloseMap(cbor_encode_ctx);
    QCBOREncode_CloseBstrWrap2(cbor_encode_ctx, false, &protected_parameters);

    return protected_parameters;
}


/**
 * \brief Add the unprotected parameters to a CBOR encoding context
 *
 * \param[in] me               The t_cose signing context.
 * \param[in] kid              The key ID.
 * \param[in] cbor_encode_ctx  CBOR encoding context to output to
 *
 * \returns An error of type \ref t_cose_err_t.
 *
 * The unprotected parameters added by this are the kid and content type.
 *
 * In the case of a QCBOR encoding error, T_COSE_SUCCESS will be returned
 * and the error will be caught when \c QCBOR_Finish() is called on \c
 * cbor_encode_ctx.
 */
static inline enum t_cose_err_t
add_unprotected_parameters(const struct t_cose_sign1_sign_ctx *me,
                           const struct q_useful_buf_c         kid,
                           QCBOREncodeContext                 *cbor_encode_ctx)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   QCBOR   (guess)                               32          24
     *   TOTAL                                         32          24
     */

    QCBOREncode_OpenMap(cbor_encode_ctx);

    if(!q_useful_buf_c_is_null_or_empty(kid)) {
        QCBOREncode_AddBytesToMapN(cbor_encode_ctx,
                                   COSE_HEADER_PARAM_KID,
                                   kid);
    }

#ifndef T_COSE_DISABLE_CONTENT_TYPE
    if(me->content_type_uint != T_COSE_EMPTY_UINT_CONTENT_TYPE &&
       me->content_type_tstr != NULL) {
        /* Both the string and int content types are not allowed */
        return T_COSE_ERR_DUPLICATE_PARAMETER;
    }


    if(me->content_type_uint != T_COSE_EMPTY_UINT_CONTENT_TYPE) {
        QCBOREncode_AddUInt64ToMapN(cbor_encode_ctx,
                                    COSE_HEADER_PARAM_CONTENT_TYPE,
                                    me->content_type_uint);
    }

    if(me->content_type_tstr != NULL) {
        QCBOREncode_AddSZStringToMapN(cbor_encode_ctx,
                                      COSE_HEADER_PARAM_CONTENT_TYPE,
                                      me->content_type_tstr);
    }
#else
    (void)me; /* avoid unused parameter warning */
#endif

    QCBOREncode_CloseMap(cbor_encode_ctx);

    return T_COSE_SUCCESS;
}


/*
 * Semi-private function. See t_cose_sign1_sign.h
 */
enum t_cose_err_t
t_cose_sign1_encode_parameters_internal(struct t_cose_sign1_sign_ctx *me,
                                        bool                          payload_is_detached,
                                        QCBOREncodeContext           *cbor_encode_ctx)
{
    enum t_cose_err_t      return_value;
    struct q_useful_buf_c  kid;

    if (!signature_algorithm_id_is_supported(me->cose_algorithm_id)) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    /* Add the CBOR tag indicating COSE_Sign1 */
    if(!(me->option_flags & T_COSE_OPT_OMIT_CBOR_TAG)) {
        QCBOREncode_AddTag(cbor_encode_ctx, CBOR_TAG_COSE_SIGN1);
    }

    /* Get started with the tagged array that holds the four parts of
     * a cose single signed message */
    QCBOREncode_OpenArray(cbor_encode_ctx);

    /* The protected parameters, which are added as a wrapped bstr  */
    me->protected_parameters = encode_protected_parameters(me->cose_algorithm_id, cbor_encode_ctx);

    /* The Unprotected parameters */
    /* Get the kid because it goes into the parameters that are about
     * to be made. */
    kid = me->kid;

    if(me->option_flags & T_COSE_OPT_SHORT_CIRCUIT_SIG) {
#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
        if(q_useful_buf_c_is_null_or_empty(kid)) {
            /* No kid passed in, Use the short-circuit kid */
            kid = get_short_circuit_kid();
        }
#else
        return_value = T_COSE_ERR_SHORT_CIRCUIT_SIG_DISABLED;
        goto Done;
#endif
    }

    return_value = add_unprotected_parameters(me, kid, cbor_encode_ctx);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    if(!payload_is_detached) {
        QCBOREncode_BstrWrap(cbor_encode_ctx);
    }

    /* Any failures in CBOR encoding will be caught in finish when the
     * CBOR encoding is closed off. No need to track here as the CBOR
     * encoder tracks it internally.
     */

Done:
    return return_value;
}

#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
/**
 * \brief Compute the short-circuit signature for a COSE_Sign1 message.
 *
 * \param[in] me                    The t_cose signing context.
 * \param[in] aad                   The Additional Authenticated Data or \c NULL_Q_USEFUL_BUF_C.
 * \param[in] payload               Pointer and length of payload to sign.
 * \param[in] buffer_for_signature  Pointer and length of buffer to output to.
 * \param[out] signature            Pointer and length of the resulting signature.
 *
 * \returns An error of type \ref t_cose_err_t.
 *
 * This function does not actually perform any kind of cryptographic
 * signature, and should only be used as a test mode.
 *
 * If \c buffer_for_signature contains a \c NULL pointer, this function
 * will compute the necessary size, and set \c signature accordingly.
 */
static inline enum t_cose_err_t
sign1_sign_short_circuit(struct t_cose_sign1_sign_ctx *me,
                         struct q_useful_buf_c         aad,
                         struct q_useful_buf_c         payload,
                         struct q_useful_buf           buffer_for_signature,
                         struct q_useful_buf_c         *signature)
{
    enum t_cose_err_t            return_value;

    Q_USEFUL_BUF_MAKE_STACK_UB(  buffer_for_tbs_hash, T_COSE_CRYPTO_MAX_HASH_SIZE);
    struct q_useful_buf_c        tbs_hash;

    /* Create the hash of the to-be-signed bytes. Inputs to the
     * hash are the protected parameters, the payload that is
     * getting signed, the cose signature alg from which the hash
     * alg is determined. The cose_algorithm_id was checked in
     * t_cose_sign1_init() so it doesn't need to be checked here.
     */
    return_value = create_tbs_hash(me->cose_algorithm_id,
                                   me->protected_parameters,
                                   aad,
                                   payload,
                                   buffer_for_tbs_hash,
                                   &tbs_hash);
    if (return_value) {
        goto Done;
    }

    if (buffer_for_signature.ptr == NULL) {
        /* Output size calculation. Only need signature size. */
        signature->ptr = NULL;
        return_value = short_circuit_sig_size(me->cose_algorithm_id, &signature->len);
    } else {
        /* Perform the a short circuit signing */
        return_value = short_circuit_sign(me->cose_algorithm_id,
                                          tbs_hash,
                                          buffer_for_signature,
                                          signature);
    }

Done:
    return return_value;
}
#endif /* T_COSE_DISABLE_SHORT_CIRCUIT_SIGN */

#ifndef T_COSE_DISABLE_EDDSA
/**
 * \brief Compute an EDDSA signature for a COSE_Sign1 message.
 *
 * \param[in] me                    The t_cose signing context.
 * \param[in] aad                   The Additional Authenticated Data or \c NULL_Q_USEFUL_BUF_C.
 * \param[in] payload               Pointer and length of payload to sign.
 * \param[in] buffer_for_signature  Pointer and length of buffer to output to.
 * \param[out] signature            Pointer and length of the resulting signature.
 *
 * \returns An error of type \ref t_cose_err_t.
 *
 * Unlike other algorithms, EDDSA signing requires two passes over the
 * to-be-signed data, and therefore cannot be performed incrementally.
 * This function serializes the to-be-signed bytes and uses the crypto
 * adapter to compute the signature over them. An auxiliary buffer,
 * used to store the to-be-signed bytes, must have previously been
 * configured by calling the \ref t_cose_sign1_sign_set_auxiliary_buffer
 * function.
 *
 * If \c buffer_for_signature contains a \c NULL pointer, this function
 * will compute the necessary size, and update \c signature accordingly.
 */
static inline enum t_cose_err_t
sign1_sign_eddsa(struct t_cose_sign1_sign_ctx *me,
                 struct q_useful_buf_c         aad,
                 struct q_useful_buf_c         payload,
                 struct q_useful_buf           buffer_for_signature,
                 struct q_useful_buf_c        *signature)
{
    enum t_cose_err_t            return_value;
    struct q_useful_buf_c        tbs;

    /* Serialize the TBS data into the auxiliary buffer.
     * If auxiliary_buffer.ptr is NULL this will succeed, computing
     * the necessary size.
     */
    return_value = create_tbs(me->protected_parameters,
                              aad,
                              payload,
                              me->auxiliary_buffer,
                             &tbs);
    if (return_value == T_COSE_ERR_TOO_SMALL) {
        /* Be a bit more specific about which buffer is too small */
        return_value = T_COSE_ERR_AUXILIARY_BUFFER_SIZE;
    }
    if (return_value) {
        goto Done;
    }

    /* Record how much buffer we actually used / would have used,
     * allowing the caller to allocate an appropriately sized buffer.
     * This is particularly useful when buffer_for_signature.ptr is
     * NULL and no signing is actually taking place yet.
     */
    me->auxiliary_buffer_size = tbs.len;

    if (buffer_for_signature.ptr == NULL) {
        /* Output size calculation. Only need signature size. */
        signature->ptr = NULL;
        return_value  = t_cose_crypto_sig_size(me->cose_algorithm_id,
                                               me->signing_key,
                                              &signature->len);
    } else if (me->auxiliary_buffer.ptr == NULL) {
        /* Without a real auxiliary buffer, we have nothing to sign. */
        return_value = T_COSE_ERR_NEED_AUXILIARY_BUFFER;
    } else {
        /* Perform the public key signing over the TBS bytes we just
         * serialized.
         */
        return_value = t_cose_crypto_sign_eddsa(me->signing_key,
                                                tbs,
                                                buffer_for_signature,
                                                signature);
    }

Done:
    return return_value;
}
#endif /* T_COSE_DISABLE_EDDSA */

/**
 * \brief Compute a signature for a COSE_Sign1 message, following the
 * general procedure which works for most algorithms.
 *
 * \param[in] me                    The t_cose signing context.
 * \param[in] aad                   The Additional Authenticated Data or \c NULL_Q_USEFUL_BUF_C.
 * \param[in] payload               Pointer and length of payload to sign.
 * \param[in] buffer_for_signature  Pointer and length of buffer to output to.
 * \param[out] signature            Pointer and length of the resulting signature.
 *
 * \returns An error of type \ref t_cose_err_t.
 *
 * The message's to-be-signed bytes are hashed incrementally using the
 * chosen algorithm's digest function, and the result is signed by the
 * crypto adapter.
 *
 * This function does not support short-circuit signing or EDDSA
 * signatures, which require a special procedure. See
 * \ref sign1_sign_short_circuit and \ref sign1_sign_eddsa.
 *
 * If \c buffer_for_signature contains a \c NULL pointer, this function
 * will compute the necessary size, and update \c signature accordingly.
 */
static inline enum t_cose_err_t
sign1_sign_default(struct t_cose_sign1_sign_ctx *me,
                   struct q_useful_buf_c         aad,
                   struct q_useful_buf_c         payload,
                   struct q_useful_buf           buffer_for_signature,
                   struct q_useful_buf_c        *signature)
{
    enum t_cose_err_t            return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(  buffer_for_tbs_hash, T_COSE_CRYPTO_MAX_HASH_SIZE);
    struct q_useful_buf_c        tbs_hash;

    /* Create the hash of the to-be-signed bytes. Inputs to the
     * hash are the protected parameters, the payload that is
     * getting signed, the cose signature alg from which the hash
     * alg is determined. The cose_algorithm_id was checked in
     * t_cose_sign1_init() so it doesn't need to be checked here.
     */
    return_value = create_tbs_hash(me->cose_algorithm_id,
                                   me->protected_parameters,
                                   aad,
                                   payload,
                                   buffer_for_tbs_hash,
                                   &tbs_hash);
    if (return_value) {
        goto Done;
    }

    if (buffer_for_signature.ptr == NULL) {
        /* Output size calculation. Only need signature size. */
        signature->ptr = NULL;
        return_value  = t_cose_crypto_sig_size(me->cose_algorithm_id,
                                               me->signing_key,
                                              &signature->len);
    } else {
        /* Perform the public key signing */
        return_value = t_cose_crypto_sign(me->cose_algorithm_id,
                                          me->signing_key,
                                          tbs_hash,
                                          buffer_for_signature,
                                          signature);
    }

Done:
    return return_value;
}

/*
 * Semi-private function. See t_cose_sign1_sign.h
 */
enum t_cose_err_t
t_cose_sign1_encode_signature_aad_internal(struct t_cose_sign1_sign_ctx *me,
                                           struct q_useful_buf_c         aad,
                                           struct q_useful_buf_c         detached_payload,
                                           QCBOREncodeContext           *cbor_encode_ctx)
{
    enum t_cose_err_t            return_value;
    QCBORError                   cbor_err;
    /* Pointer and length of the completed signature */
    struct q_useful_buf_c        signature;
    /* Pointer and length of the buffer for the signature */
    struct q_useful_buf          buffer_for_signature;
    struct q_useful_buf_c        signed_payload;

    if(q_useful_buf_c_is_null(detached_payload)) {
        QCBOREncode_CloseBstrWrap2(cbor_encode_ctx, false, &signed_payload);
    } else {
        signed_payload = detached_payload;
    }

    /* Check that there are no CBOR encoding errors before proceeding
     * with hashing and signing. This is not actually necessary as the
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

    /* The signature gets written directly into the output buffer.
     * The matching QCBOREncode_CloseBytes call further down still needs do a
     * memmove to make space for the CBOR header, but at least we avoid the need
     * to allocate an extra buffer.
     */
    QCBOREncode_OpenBytes(cbor_encode_ctx, &buffer_for_signature);

    /* Sign the message using the appropriate procedure, depending on
     * the flags and algorithm.
     */
#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
    if (me->option_flags & T_COSE_OPT_SHORT_CIRCUIT_SIG) {
        return_value = sign1_sign_short_circuit(me,
                                                aad,
                                                signed_payload,
                                                buffer_for_signature,
                                               &signature);
    } else
#endif
#ifndef T_COSE_DISABLE_EDDSA
    if (me->cose_algorithm_id == COSE_ALGORITHM_EDDSA) {
        return_value = sign1_sign_eddsa(me,
                                        aad,
                                        signed_payload,
                                        buffer_for_signature,
                                       &signature);
    } else
#endif
    {
        return_value = sign1_sign_default(me,
                aad,
                signed_payload,
                buffer_for_signature,
                &signature);
    }

    if (return_value)
        goto Done;

    /* Add signature to CBOR and close out the array */
    QCBOREncode_CloseBytes(cbor_encode_ctx, signature.len);
    QCBOREncode_CloseArray(cbor_encode_ctx);

    /* The layer above this must check for and handle CBOR encoding
     * errors CBOR encoding errors.  Some are detected at the start of
     * this function, but they cannot all be deteced there.
     */
Done:
    return return_value;

}


/*
 * Semi-private function. See t_cose_sign1_sign.h
 */
enum t_cose_err_t
t_cose_sign1_sign_aad_internal(struct t_cose_sign1_sign_ctx *me,
                               bool                         payload_is_detached,
                               struct q_useful_buf_c         payload,
                               struct q_useful_buf_c         aad,
                               struct q_useful_buf           out_buf,
                               struct q_useful_buf_c        *result)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   local vars                                     8           4
     *   encode context                               168         148
     *   QCBOR   (guess)                               32          24
     *   max(encode_param, encode_signature)     224-1316    216-1024
     *   TOTAL                                   432-1524    392-1300
     */
    QCBOREncodeContext  encode_context;
    enum t_cose_err_t   return_value;

    /* -- Initialize CBOR encoder context with output buffer -- */
    QCBOREncode_Init(&encode_context, out_buf);

    /* -- Output the header parameters into the encoder context -- */
    return_value = t_cose_sign1_encode_parameters_internal(me,
                                                           payload_is_detached,
                                                           &encode_context);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    if(payload_is_detached) {
        /* -- Output NULL but the payload -- */
        /* In detached content mode, the output COSE binary does not
         * contain the target payload, and it should be derivered
         * in another channel.
         */
        QCBOREncode_AddNULL(&encode_context);
    } else {
        /* -- Output the payload into the encoder context -- */
        /* Payload may or may not actually be CBOR format here. This
         * function does the job just fine because it just adds bytes to
         * the encoded output without anything extra.
         */
        QCBOREncode_AddEncoded(&encode_context, payload);
    }

    /* -- Sign and put signature in the encoder context -- */
    if(!payload_is_detached) {
        payload = NULL_Q_USEFUL_BUF_C;
    }
    return_value = t_cose_sign1_encode_signature_aad_internal(me,
                                                              aad,
                                                              payload,
                                                              &encode_context);
    if(return_value) {
        goto Done;
    }

    QCBORError cbor_err = QCBOREncode_GetErrorState(&encode_context);
    if(cbor_err == QCBOR_ERR_BUFFER_TOO_SMALL) {
        return_value = T_COSE_ERR_TOO_SMALL;
        goto Done;
    } else if(cbor_err != QCBOR_SUCCESS) {
        return_value = T_COSE_ERR_CBOR_FORMATTING;
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

