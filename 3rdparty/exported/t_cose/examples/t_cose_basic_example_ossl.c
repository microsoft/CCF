/*
 *  t_cose_basic_example_ossl.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


/**
 * \file t_cose_basic_example_ossl.c
 *
 * \brief Example code for signing and verifying a COSE_Sign1 message
 *        using OpenSSL
 *
 * This file has simple code to sign a payload and verify it.
 *
 * This works with OpenSSL. It assumes t_cose has been wired up to the
 * OpenSSL crypto library and hase code specific to OpenSSL to make an
 * EC key pair. See t_cose README for more details on how integration
 * with crypto libraries works.
 */

#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"

#include <stdio.h>

#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/evp.h"



/**
 * \brief Make a key pair in OpenSSL library form.
 *
 * \param[in] cose_algorithm_id  The algorithm to sign with, for example
 *                               \ref T_COSE_ALGORITHM_ES256.
 * \param[out] key_pair          The key pair. This must be freed.
 *
 * The key made here is fixed and just useful for testing.
 */
enum t_cose_err_t make_ossl_key_pair(int32_t            cose_algorithm_id,
                                     struct t_cose_key *key_pair)
{
    enum t_cose_err_t  return_value;
    int                ossl_result;
    int                ossl_key_type;
    int                ossl_curve_nid;
    EVP_PKEY          *pkey = NULL;
    EVP_PKEY_CTX      *ctx;

    switch (cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
        ossl_key_type  = EVP_PKEY_EC;
        ossl_curve_nid = NID_X9_62_prime256v1;
        break;

    case T_COSE_ALGORITHM_ES384:
        ossl_key_type  = EVP_PKEY_EC;
        ossl_curve_nid = NID_secp384r1;
        break;

    case T_COSE_ALGORITHM_ES512:
        ossl_key_type  = EVP_PKEY_EC;
        ossl_curve_nid = NID_secp521r1;
        break;

    case T_COSE_ALGORITHM_EDDSA:
        ossl_key_type = EVP_PKEY_ED25519;
        break;

    default:
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    ctx = EVP_PKEY_CTX_new_id(ossl_key_type, NULL);
    if(ctx == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        return_value = T_COSE_ERR_FAIL;
        goto Done;
    }

    if (ossl_key_type == EVP_PKEY_EC) {
        ossl_result = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, ossl_curve_nid);
        if(ossl_result != 1) {
            return_value = T_COSE_ERR_FAIL;
            goto Done;
        }
    }

    pkey = EVP_PKEY_new();

    ossl_result = EVP_PKEY_keygen(ctx, &pkey);

    if(ossl_result != 1) {
        return_value = T_COSE_ERR_FAIL;
        goto Done;
    }

    key_pair->k.key_ptr  = pkey;
    key_pair->crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    return_value         = T_COSE_SUCCESS;

Done:
    return return_value;
}


/**
 * \brief  Free an OpenSSL key.
 *
 * \param[in] key_pair   The key pair to close / deallocate / free.
 */
void free_ossl_key_pair(struct t_cose_key key_pair)
{
    EVP_PKEY_free(key_pair.k.key_ptr);
}


/**
 * \brief  Print a q_useful_buf_c on stdout in hex ASCII text.
 *
 * \param[in] string_label   A string label to output first
 * \param[in] buf            The q_useful_buf_c to output.
 *
 * This is just for pretty printing.
 */
static void print_useful_buf(const char *string_label, struct q_useful_buf_c buf)
{
    if(string_label) {
        printf("%s", string_label);
    }

    printf("    %ld bytes\n", buf.len);

    printf("    ");

    size_t i;
    for(i = 0; i < buf.len; i++) {
        const uint8_t Z = ((const uint8_t *)buf.ptr)[i];
        printf("%02x ", Z);
        if((i % 8) == 7) {
            printf("\n    ");
        }
    }
    printf("\n");

    fflush(stdout);
}


/**
 * \brief  Sign and verify example with one-step signing
 *
 * The one-step (plus init and key set up) signing uses more memory, but
 * is simpler to use. In the code below constructed_payload_buffer is
 * the extra buffer that two-step signing avoids.
 */
int32_t one_step_sign_example(void)
{

    struct t_cose_sign1_sign_ctx   sign_ctx;
    enum t_cose_err_t              return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          signed_cose;
    Q_USEFUL_BUF_MAKE_STACK_UB(    constructed_payload_buffer, 300);
    struct q_useful_buf_c          constructed_payload;
    struct q_useful_buf_c          returned_payload;
    struct t_cose_key              key_pair;
    struct t_cose_sign1_verify_ctx verify_ctx;
    QCBOREncodeContext             cbor_encode;
    QCBORError                     qcbor_result;


    /* ------   Construct the payload    ------
     *
     * The payload is constructed into its own continguous buffer.
     * In this case the payload is CBOR format so it uses QCBOR to
     * encode it, but CBOR is not required for COSE payloads so it could
     * be anything at all.
     *
     * The payload constructed here is a map of some label-value
     * pairs similar to a CWT or EAT, but using string labels
     * rather than integers. It is just a little example.
     */
    QCBOREncode_Init(&cbor_encode, constructed_payload_buffer);
    QCBOREncode_OpenMap(&cbor_encode);
    QCBOREncode_AddSZStringToMap(&cbor_encode, "BeingType", "Humanoid");
    QCBOREncode_AddSZStringToMap(&cbor_encode, "Greeting", "We come in peace");
    QCBOREncode_AddInt64ToMap(&cbor_encode, "ArmCount", 2);
    QCBOREncode_AddInt64ToMap(&cbor_encode, "HeadCount", 1);
    QCBOREncode_AddSZStringToMap(&cbor_encode, "BrainSize", "medium");
    QCBOREncode_AddBoolToMap(&cbor_encode, "DrinksWater", true);
    QCBOREncode_CloseMap(&cbor_encode);
    qcbor_result = QCBOREncode_Finish(&cbor_encode, &constructed_payload);

    printf("Encoded payload (size = %ld): %d (%s)\n",
           constructed_payload.len,
           qcbor_result,
           qcbor_result ? "fail" : "success");
    if(qcbor_result) {
        return_value = (enum t_cose_err_t)qcbor_result;
        goto Done;
    }


    /* ------   Make an ECDSA key pair    ------
     *
     * The key pair will be used for both signing and encryption. The
     * data type is struct t_cose_key on the outside, but internally
     * the format is that of the crypto library used, PSA in this
     * case. They key is just passed through t_cose to the underlying
     * crypto library.
     *
     * The making and destroying of the key pair is the only code
     * dependent on the crypto library in this file.
     */
    return_value = make_ossl_key_pair(T_COSE_ALGORITHM_ES256, &key_pair);

    printf("Made EC key with curve prime256v1: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }


    /* ------   Initialize for signing    ------
     *
     * Initialize the signing context by telling it the signing
     * algorithm and signing options. No options are set here hence
     * the 0 value.
     *
     * Set up the signing key and kid (key ID). No kid is passed here
     * hence the NULL_Q_USEFUL_BUF_C.
     */

    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_ES256);

    t_cose_sign1_set_signing_key(&sign_ctx, key_pair,  NULL_Q_USEFUL_BUF_C);

    printf("Initialized t_cose and configured signing key\n");


    /* ------   Sign    ------
     *
     * This performs encoding of the headers, the signing and formatting
     * in one shot.
     *
     * With this API the payload ends up in memory twice, once as the
     * input and once in the output. If the payload is large, this
     * needs about double the size of the payload to work.
     */
    return_value = t_cose_sign1_sign(/* The context set up with signing key */
                                     &sign_ctx,
                                     /* Pointer and length of payload to be
                                      * signed.
                                      */
                                     constructed_payload,
                                     /* Non-const pointer and length of the
                                      * buffer where the completed output is
                                      * written to. The length here is that
                                      * of the whole buffer.
                                      */
                                     signed_cose_buffer,
                                     /* Const pointer and actual length of
                                      * the completed, signed and encoded
                                      * COSE_Sign1 message. This points
                                      * into the output buffer and has the
                                      * lifetime of the output buffer.
                                      */
                                     &signed_cose);

    printf("Finished signing: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }

    print_useful_buf("Completed COSE_Sign1 message:\n", signed_cose);


    printf("\n");


    /* ------   Set up for verification   ------
     *
     * Initialize the verification context.
     *
     * The verification key works the same way as the signing
     * key. Internally it must be in the format for the crypto library
     * used. It is passed straight through t_cose.
     */
    t_cose_sign1_verify_init(&verify_ctx, 0);

    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    printf("Initialized t_cose for verification and set verification key\n");


    /* ------   Perform the verification   ------
     *
     * Verification is relatively simple. The COSE_Sign1 message to
     * verify is passed in and the payload is returned if verification
     * is successful.  The key must be of the correct type for the
     * algorithm used to sign the COSE_Sign1.
     *
     * The COSE header parameters will be returned if requested, but
     * in this example they are not as NULL is passed for the location
     * to put them.
     */
    return_value = t_cose_sign1_verify(&verify_ctx,
                                       signed_cose,         /* COSE to verify */
                                       &returned_payload,  /* Payload from signed_cose */
                                       NULL);      /* Don't return parameters */

    printf("Verification complete: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }

    print_useful_buf("Signed payload:\n", returned_payload);


    /* ------   Free key pair   ------
     *
     * Some implementations of PSA allocate slots for the keys in
     * use. This call indicates that the key slot can be de allocated.
     */
    printf("Freeing key pair\n\n\n");
    free_ossl_key_pair(key_pair);

Done:
    return (int32_t)return_value;
}




/**
 * \brief  Sign and verify example with two-step signing
 *
 * The two-step (plus init and key set up) signing has the payload
 * constructed directly into the output buffer, uses less memory,
 * but is more complicated to use.
 */
int two_step_sign_example(void)
{
    struct t_cose_sign1_sign_ctx   sign_ctx;
    enum t_cose_err_t              return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          signed_cose;
    struct q_useful_buf_c          payload;
    struct t_cose_key              key_pair;
    QCBOREncodeContext             cbor_encode;
    QCBORError                     cbor_error;
    struct t_cose_sign1_verify_ctx verify_ctx;



    /* ------   Make an ECDSA key pair    ------
     *
     * The key pair will be used for both signing and encryption. The
     * data type is struct t_cose_key on the outside, but internally
     * the format is that of the crypto library used, PSA in this
     * case. They key is just passed through t_cose to the underlying
     * crypto library.
     *
     * The making and destroying of the key pair is the only code
     * dependent on the crypto library in this file.
     */
    return_value = make_ossl_key_pair(T_COSE_ALGORITHM_ES256, &key_pair);

    printf("Made EC key with curve prime256v1: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }


    /* ------   Initialize for signing    ------
     *
     * Set up the QCBOR encoding context with the output buffer. This
     * is where all the outputs including the payload goes. In this
     * case the maximum size is small and known so a fixed length
     * buffer is given. If it is not known then QCBOR and t_cose can
     * run without a buffer to calculate the needed size. In all
     * cases, if the buffer is too small QCBOR and t_cose will error
     * out gracefully and not overrun any buffers.
     *
     * Initialize the signing context by telling it the signing
     * algorithm and signing options. No options are set here hence
     * the 0 value.
     *
     * Set up the signing key and kid (key ID). No kid is passed here
     * hence the NULL_Q_USEFUL_BUF_C.
     */

    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_ES256);

    t_cose_sign1_set_signing_key(&sign_ctx, key_pair,  NULL_Q_USEFUL_BUF_C);

    printf("Initialized QCBOR, t_cose and configured signing key\n");


    /* ------   Encode the headers    ------
     *
     * This just outputs the COSE_Sign1 header parameters and gets set
     * up for the payload to be output.
     */
    return_value = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);

    printf("Encoded COSE headers: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }


    /* ------   Output the payload    ------
     *
     * QCBOREncode functions are used to add the payload. It all goes
     * directly into the output buffer without any temporary copies.
     * QCBOR keeps track of the what is the payload so t_cose knows
     * what to hash and sign.
     *
     * The encoded CBOR here can be very large and complex. The only
     * limit is that the output buffer is large enough. If it is too
     * small, one of the following two calls will report the error as
     * QCBOR tracks encoding errors internally so the code calling it
     * doesn't have to.
     *
     * The payload constructed here is a map of some label-value
     * pairs similar to a CWT or EAT, but using string labels
     * rather than integers. It is just a little example.
     *
     * A simpler alternative is to call t_cose_sign1_sign() instead of
     * t_cose_sign1_encode_parameters() and
     * t_cose_sign1_encode_signature(), however this requires memory
     * to hold a copy of the payload and the output COSE_Sign1
     * message. For that call the payload is just passed in as a
     * buffer.
     */
    QCBOREncode_OpenMap(&cbor_encode);
    QCBOREncode_AddSZStringToMap(&cbor_encode, "BeingType", "Humanoid");
    QCBOREncode_AddSZStringToMap(&cbor_encode, "Greeting", "We come in peace");
    QCBOREncode_AddInt64ToMap(&cbor_encode, "ArmCount", 2);
    QCBOREncode_AddInt64ToMap(&cbor_encode, "HeadCount", 1);
    QCBOREncode_AddSZStringToMap(&cbor_encode, "BrainSize", "medium");
    QCBOREncode_AddBoolToMap(&cbor_encode, "DrinksWater", true);
    QCBOREncode_CloseMap(&cbor_encode);

    printf("Payload added\n");


    /* ------   Sign    ------
     *
     * This call signals the end payload construction, causes the actual
     * signing to run.
     */
    return_value = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);

    printf("Fnished signing: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }


    /* ------   Complete CBOR Encoding   ------
     *
     * This closes out the CBOR encoding returning any errors that
     * might have been recorded.
     *
     * The resulting signed message is returned in signed_cose. It is
     * a pointer and length into the buffer give to
     * QCBOREncode_Init().
     */
    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    printf("Finished CBOR encoding: %d (%s)\n", cbor_error, return_value ? "fail" : "success");
    if(cbor_error) {
        goto Done;
    }

    print_useful_buf("Completed COSE_Sign1 message:\n", signed_cose);


    printf("\n");


    /* ------   Set up for verification   ------
     *
     * Initialize the verification context.
     *
     * The verification key works the same way as the signing
     * key. Internally it must be in the format for the crypto library
     * used. It is passed straight through t_cose.
     */
    t_cose_sign1_verify_init(&verify_ctx, 0);

    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    printf("Initialized t_cose for verification and set verification key\n");


    /* ------   Perform the verification   ------
     *
     * Verification is relatively simple. The COSE_Sign1 message to
     * verify is passed in and the payload is returned if verification
     * is successful.  The key must be of the correct type for the
     * algorithm used to sign the COSE_Sign1.
     *
     * The COSE header parameters will be returned if requested, but
     * in this example they are not as NULL is passed for the location
     * to put them.
     */
    return_value = t_cose_sign1_verify(&verify_ctx,
                                       signed_cose,         /* COSE to verify */
                                       &payload,  /* Payload from signed_cose */
                                       NULL);      /* Don't return parameters */

    printf("Verification complete: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }

    print_useful_buf("Signed payload:\n", payload);


    /* ------   Free key pair   ------
     *
     * OpenSSL uses memory allocation for keys, so they must be freed.
     */
    printf("Freeing key pair\n\n\n");
    free_ossl_key_pair(key_pair);

Done:
    return (int)return_value;
}

/**
 * \brief  Sign and verify example with dynamically allocated buffers
 *
 * The signing operation of t_cose requires the caller to provide a
 * buffer large enough to hold the result. If the provided buffer is
 * too small, the operation will fail.
 *
 * When EDDSA is used, an additional auxiliary buffer is needed for
 * both signing and verification.
 *
 * While memory-constrained applications may want to use stack or
 * statically allocated buffers of a fixed size, others prefer the
 * flexibility of dynamically allocating buffers of the right size on
 * demand.
 *
 * This example shows how to call t_cose to determine the size of the
 * output and auxiliary buffers, before dynamically allocating them
 * using malloc and free. Any alternative allocator could also have
 * been used.
 *
 */
int32_t dynamic_buffer_example(void)
{
    struct t_cose_sign1_sign_ctx   sign_ctx;
    enum t_cose_err_t              return_value;
    struct q_useful_buf            signed_cose_buffer;
    struct q_useful_buf_c          signed_cose;
    struct q_useful_buf            auxiliary_buffer;
    struct q_useful_buf_c          constructed_payload;
    struct q_useful_buf_c          returned_payload;
    struct t_cose_key              key_pair;
    struct t_cose_sign1_verify_ctx verify_ctx;

    /* ------   Prepare the payload   ------ */
    constructed_payload = Q_USEFUL_BUF_FROM_SZ_LITERAL("payload");
    printf("Encoded payload size = %ld\n", constructed_payload.len);


    /* ------   Make an EDDSA key pair    ------ */
    return_value = make_ossl_key_pair(T_COSE_ALGORITHM_EDDSA, &key_pair);
    printf("Made EC key with curve ed25519: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }

    /* ------   Initialize for signing    ------ */
    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_EDDSA);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair,  NULL_Q_USEFUL_BUF_C);

    /* ------   Compute the size of the output and auxiliary buffers   ------
     *
     * A large but NULL output buffer is given to the signing operation.
     * The size of result, signed_cose, will reflect how big of a buffer
     * needs to be provided for the real operation.
     *
     * Similarly, the necessary auxiliary buffer size is saved in the
     * signing context and available by calling t_cose_sign1_sign_auxiliary_buffer_size.
     *
     * Both sizes are used later on to allocate the proper buffers.
     */
    return_value = t_cose_sign1_sign(&sign_ctx,
                                      constructed_payload,
                                      (struct q_useful_buf){ NULL, SIZE_MAX },
                                     &signed_cose);
    printf("Computed signing size %d (%s)\n", return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }
    printf("Output buffer size = %zu bytes\n", signed_cose.len);
    printf("Auxiliary buffer size = %zu bytes\n", t_cose_sign1_sign_auxiliary_buffer_size(&sign_ctx));

    /* ------   Allocate buffers of the right size   ------ */
    signed_cose_buffer.ptr = malloc(signed_cose.len);
    signed_cose_buffer.len = signed_cose.len;

    auxiliary_buffer.len = t_cose_sign1_sign_auxiliary_buffer_size(&sign_ctx);
    auxiliary_buffer.ptr = malloc(auxiliary_buffer.len);

    if (signed_cose_buffer.ptr == NULL || auxiliary_buffer.ptr == NULL) {
        printf("Buffer allocation failed\n");
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    /* ------   Sign    ------
     *
     * Call the sign function again, this time providing it with the
     * real buffers.
     */
    t_cose_sign1_sign_set_auxiliary_buffer(&sign_ctx, auxiliary_buffer);
    return_value = t_cose_sign1_sign(&sign_ctx,
                                      constructed_payload,
                                      signed_cose_buffer,
                                     &signed_cose);

    printf("Finished signing: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }

    print_useful_buf("Completed COSE_Sign1 message:\n", signed_cose);


    printf("\n");

    /* ------ Free the auxiliary buffer ------
     *
     * We could have re-used the allocation for the verification step
     * (since it would be the same size), but for demonstration purpose
     * we deallocate it here and re-compute its size from the signed
     * message.
     */
    free(auxiliary_buffer.ptr);

    /* ------   Compute the size of the auxiliary buffer   ------
     *
     * We call the verify procedure with the DECODE_ONLY flag.
     *
     * This is only necessary because EDDSA is used as a signing
     * algorithm. Other algorithms have no need for an auxiliary
     * buffer.
     */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_DECODE_ONLY);
    printf("Initialized t_cose for decoding\n");

    return_value = t_cose_sign1_verify(&verify_ctx, signed_cose, NULL, NULL);
    printf("Decode-only complete: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }
    printf("Auxiliary buffer size = %zu bytes\n", t_cose_sign1_verify_auxiliary_buffer_size(&verify_ctx));

    /* ------   Allocate an auxiliary buffer of the right size   ------ */
    auxiliary_buffer.len = t_cose_sign1_verify_auxiliary_buffer_size(&verify_ctx);
    auxiliary_buffer.ptr = malloc(auxiliary_buffer.len);
    if (auxiliary_buffer.ptr == NULL) {
        printf("Auxiliary buffer allocation failed\n");
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    /* ------   Set up for verification   ------
     *
     * We re-initialize the context, without any flags this time so it
     * performs the actual verification.
     */
    t_cose_sign1_verify_init(&verify_ctx, 0);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);
    t_cose_sign1_verify_set_auxiliary_buffer(&verify_ctx, auxiliary_buffer);

    printf("Initialized t_cose for verification and set verification key\n");

    /* ------   Perform the verification   ------ */
    return_value = t_cose_sign1_verify(&verify_ctx,
                                       signed_cose,       /* COSE to verify */
                                       &returned_payload, /* Payload from signed_cose */
                                       NULL);             /* Don't return parameters */

    printf("Verification complete: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }

    print_useful_buf("Signed payload:\n", returned_payload);

    /* ------   Free the output and auxiliary buffers   ------ */
    free(signed_cose_buffer.ptr);
    free(auxiliary_buffer.ptr);

    /* ------   Free key pair   ------ */
    printf("Freeing key pair\n\n\n");
    free_ossl_key_pair(key_pair);

Done:
    return (int32_t)return_value;

}

int main(int argc, const char * argv[])
{
    (void)argc; /* Avoid unused parameter error */
    (void)argv;

    one_step_sign_example();
    two_step_sign_example();
    dynamic_buffer_example();
}
