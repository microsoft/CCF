/*
 *  t_cose_basic_example_psa.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"

#include "psa/crypto.h"

#include <stdio.h>


/**
 * \file t_cose_basic_example_psa.c
 *
 * \brief Example code for signing and verifying a COSE_Sign1 message using PSA
 *
 * This file has simple code to sign a payload and verify it.
 *
 * This works with PSA / MBed Crypto. It assumes t_cose has been wired
 * up to PSA / MBed Crypto and has code specific to this library to
 * make a key pair that will be passed through t_cose. See t_cose
 * README for more details on how integration with crypto libraries
 * works.
 */


/*
 * Some hard coded keys for the test cases here.
 */
#define PRIVATE_KEY_prime256v1 \
0xf1, 0xb7, 0x14, 0x23, 0x43, 0x40, 0x2f, 0x3b, 0x5d, 0xe7, 0x31, 0x5e, 0xa8, \
0x94, 0xf9, 0xda, 0x5c, 0xf5, 0x03, 0xff, 0x79, 0x38, 0xa3, 0x7c, 0xa1, 0x4e, \
0xb0, 0x32, 0x86, 0x98, 0x84, 0x50

#define PRIVATE_KEY_secp384r1 \
0x03, 0xdf, 0x14, 0xf4, 0xb8, 0xa4, 0x3f, 0xd8, 0xab, 0x75, 0xa6, 0x04, 0x6b, \
0xd2, 0xb5, 0xea, 0xa6, 0xfd, 0x10, 0xb2, 0xb2, 0x03, 0xfd, 0x8a, 0x78, 0xd7, \
0x91, 0x6d, 0xe2, 0x0a, 0xa2, 0x41, 0xeb, 0x37, 0xec, 0x3d, 0x4c, 0x69, 0x3d, \
0x23, 0xba, 0x2b, 0x4f, 0x6e, 0x5b, 0x66, 0xf5, 0x7f

#define PRIVATE_KEY_secp521r1 \
0x00, 0x45, 0xd2, 0xd1, 0x43, 0x94, 0x35, 0xfa, 0xb3, 0x33, 0xb1, 0xc6, 0xc8, \
0xb5, 0x34, 0xf0, 0x96, 0x93, 0x96, 0xad, 0x64, 0xd5, 0xf5, 0x35, 0xd6, 0x5f, \
0x68, 0xf2, 0xa1, 0x60, 0x65, 0x90, 0xbb, 0x15, 0xfd, 0x53, 0x22, 0xfc, 0x97, \
0xa4, 0x16, 0xc3, 0x95, 0x74, 0x5e, 0x72, 0xc7, 0xc8, 0x51, 0x98, 0xc0, 0x92, \
0x1a, 0xb3, 0xb8, 0xe9, 0x2d, 0xd9, 0x01, 0xb5, 0xa4, 0x21, 0x59, 0xad, 0xac, \
0x6d


/**
 * \brief Make an EC key pair in PSA / Mbed library form.
 *
 * \param[in] cose_algorithm_id  The algorithm to sign with, for example
 *                               \ref T_COSE_ALGORITHM_ES256.
 * \param[out] key_pair          The key pair. This must be freed.
 *
 * The key made here is fixed and just useful for testing.
 */
enum t_cose_err_t make_psa_ecdsa_key_pair(int32_t            cose_algorithm_id,
                                          struct t_cose_key *key_pair)
{
    psa_key_type_t        key_type;
    psa_status_t          crypto_result;
    mbedtls_svc_key_id_t  key_handle;
    psa_algorithm_t       key_alg;
    const uint8_t        *private_key;
    size_t                private_key_len;
    psa_key_attributes_t  key_attributes;


    static const uint8_t private_key_256[] = {PRIVATE_KEY_prime256v1};
    static const uint8_t private_key_384[] = {PRIVATE_KEY_secp384r1};
    static const uint8_t private_key_521[] = {PRIVATE_KEY_secp521r1};

    /* There is not a 1:1 mapping from alg to key type, but
     * there is usually an obvious curve for an algorithm. That
     * is what this does.
     */

    switch(cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
        private_key     = private_key_256;
        private_key_len = sizeof(private_key_256);
        key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
        break;

    case T_COSE_ALGORITHM_ES384:
        private_key     = private_key_384;
        private_key_len = sizeof(private_key_384);
        key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_384);
        break;

    case T_COSE_ALGORITHM_ES512:
        private_key     = private_key_521;
        private_key_len = sizeof(private_key_521);
        key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_512);
        break;

    default:
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }


    /* OK to call this multiple times */
    crypto_result = psa_crypto_init();
    if(crypto_result != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }


    /* When importing a key with the PSA API there are two main things
     * to do.
     *
     * First you must tell it what type of key it is as this cannot be
     * discovered from the raw data. The variable key_type contains
     * that information including the EC curve. This is sufficient for
     * psa_import_key() to succeed, but you probably want actually use
     * the key.
     *
     * Second, you must say what algorithm(s) and operations the key
     * can be used as the PSA Crypto Library has policy enforcement.
     *
     * How this is done varies quite a lot in the newer
     * PSA Crypto API compared to the older.
     */

    key_attributes = psa_key_attributes_init();

    /* Say what algorithm and operations the key can be used with / for */
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&key_attributes, key_alg);

    /* The type of key including the EC curve */
    psa_set_key_type(&key_attributes, key_type);

    /* Import the private key. psa_import_key() automatically
     * generates the public key from the private so no need to import
     * more than the private key. (With ECDSA the public key is always
     * deterministically derivable from the private key).
     */
    crypto_result = psa_import_key(&key_attributes,
                                   private_key,
                                   private_key_len,
                                   &key_handle);

    if (crypto_result != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    key_pair->k.key_handle = key_handle;
    key_pair->crypto_lib   = T_COSE_CRYPTO_LIB_PSA;

    return T_COSE_SUCCESS;
}


/**
 * \brief  Free a PSA / MBed key.
 *
 * \param[in] key_pair   The key pair to close / deallocate / free.
 */
void free_psa_ecdsa_key_pair(struct t_cose_key key_pair)
{
    psa_close_key((mbedtls_svc_key_id_t)key_pair.k.key_handle);
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
int32_t one_step_sign_example()
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
     * In this case the payload is CBOR formatm so it uses QCBOR to
     * encode it, but CBOR is not
     * required by COSE so it could be anything at all.
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
    return_value = make_psa_ecdsa_key_pair(T_COSE_ALGORITHM_ES256, &key_pair);

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
    free_psa_ecdsa_key_pair(key_pair);

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
int two_step_sign_example()
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
    return_value = make_psa_ecdsa_key_pair(T_COSE_ALGORITHM_ES256, &key_pair);

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

    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);

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
     * Some implementations of PSA allocate slots for the keys in
     * use. This call indicates that the key slot can be de allocated.
     */
    printf("Freeing key pair\n\n\n");
    free_psa_ecdsa_key_pair(key_pair);

Done:
    return (int)return_value;
}

int main(int argc, const char * argv[])
{
    (void)argc; /* Avoid unused parameter error */
    (void)argv;

    one_step_sign_example();
    two_step_sign_example();
}
