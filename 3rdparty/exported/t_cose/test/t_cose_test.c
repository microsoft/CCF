/*
 *  t_cose_test.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose_test.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose_make_test_messages.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose_crypto.h" /* For signature size constant */
#include "t_cose_util.h" /* for get_short_circuit_kid */


/* String used by RFC 8152 and C-COSE tests and examples for payload */
#define SZ_CONTENT "This is the content."
static const struct q_useful_buf_c s_input_payload = {SZ_CONTENT, sizeof(SZ_CONTENT)-1};

/*
 * Public function, see t_cose_test.h
 */
int_fast32_t short_circuit_self_test()
{
    struct t_cose_sign1_sign_ctx    sign_ctx;
    struct t_cose_sign1_verify_ctx  verify_ctx;
    enum t_cose_err_t               result;
    Q_USEFUL_BUF_MAKE_STACK_UB(     signed_cose_buffer, 200);
    struct q_useful_buf_c           signed_cose;
    struct q_useful_buf_c           payload;


    /* --- Make COSE Sign1 object --- */
    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);

    /* No key necessary because short-circuit test mode is used */

    result = t_cose_sign1_sign(&sign_ctx,
                                s_input_payload,
                                signed_cose_buffer,
                                &signed_cose);
    if(result) {
        return 1000 + (int32_t)result;
    }
    /* --- Done making COSE Sign1 object  --- */


    /* --- Start verifying the COSE Sign1 object  --- */
    /* Select short circuit signing */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);

    /* No key necessary with short circuit */

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                /* COSE to verify */
                                signed_cose,
                                /* The returned payload */
                                &payload,
                                /* Don't return parameters */
                                NULL);
    if(result) {
        return 2000 + (int32_t)result;
    }

    /* compare payload output to the one expected */
    if(q_useful_buf_compare(payload, s_input_payload)) {
        return 3000;
    }
    /* This value comes from C-COSE test case sign-pass-03.json. The test
     * case JSON gives the expected TBS bytes. These were then run through
     * openssl dgst -sha256 -binary | hexdump -e '"\n" 8/1 "0x%01x,  "'.
     *
     * Short-circuit signature are just the hash of the TBS bytes. They are
     * twice to fake the length of a real signature. In the COSE format the
     * signature is last, so this hash occurs as the last 32 bytes of a
     * the encoded COSE.
     *
     * This is a useful test because it confirms the TBS byte calculation is
     * right in comparison to C-COSE.
     */
    static const uint8_t hash_of_tbs[] = {
        0x4c,  0x33,  0x63,  0xb4,  0x99,  0xe1,  0xda,  0xc4,
        0xaa,  0xfc,  0x8d,  0x69,  0x23,  0xf1,  0xca,  0x65,
        0x77,  0xdf,  0xda,  0x80,  0xda,  0x24,  0xe5,  0x4f,
        0xb9,  0x24,  0x24,  0x90,  0x64,  0x82,  0x7c,  0x88};

    if(q_useful_buf_compare(Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(hash_of_tbs),
                            q_useful_buf_tail(signed_cose, signed_cose.len - 32))) {
        return 4000;
    }
    /* --- Done verifying the COSE Sign1 object  --- */


   /* --- Make COSE Sign1 object --- */
    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);

    /* No key necessary because short-circuit test mode is used */

    result = t_cose_sign1_sign_aad(&sign_ctx,
                                    s_input_payload,
                                    Q_USEFUL_BUF_FROM_SZ_LITERAL("some aad"),
                                    signed_cose_buffer,
                                   &signed_cose);
    if(result) {
        return 1000 + (int32_t)result;
    }
    /* --- Done making COSE Sign1 object  --- */


    /* --- Start verifying the COSE Sign1 object  --- */
    /* Select short circuit signing */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);

    /* No key necessary with short circuit */

    /* Run the signature verification */
    result = t_cose_sign1_verify_aad(&verify_ctx,
                                     /* COSE to verify */
                                     signed_cose,
                                     Q_USEFUL_BUF_FROM_SZ_LITERAL("some aad"),
                                     /* The returned payload */
                                     &payload,
                                     /* Don't return parameters */
                                     NULL);
    if(result) {
        return 2000 + (int32_t)result;
    }

    /* compare payload output to the one expected */
    if(q_useful_buf_compare(payload, s_input_payload)) {
        return 3000;
    }

    return 0;
}

/*
 * Public function, see t_cose_test.h
 */
int_fast32_t short_circuit_self_detached_content_test()
{
    struct t_cose_sign1_sign_ctx    sign_ctx;
    struct t_cose_sign1_verify_ctx  verify_ctx;
    enum t_cose_err_t               result;
    Q_USEFUL_BUF_MAKE_STACK_UB(     signed_cose_buffer, 200);
    struct q_useful_buf_c           signed_cose;
    struct q_useful_buf_c           payload;


    /* --- Make COSE Sign1 object --- */
    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);

    /* No key necessary because short-circuit test mode is used */

    result = t_cose_sign1_sign_detached(&sign_ctx,
                                          NULL_Q_USEFUL_BUF_C,
                                          s_input_payload,
                                          signed_cose_buffer,
                                         &signed_cose);
    if(result) {
        return 1000 + (int32_t)result;
    }
    /* --- Done making COSE Sign1 object  --- */


    /* --- Start verifying the COSE Sign1 object  --- */
    /* Select short circuit signing */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);

    /* No key necessary with short circuit */

    /* The detached content */
    payload = s_input_payload;

    /* Run the signature verification */
    result = t_cose_sign1_verify_detached(&verify_ctx,
                                          /* COSE to verify */
                                          signed_cose,
                                          /* No AAD */
                                          NULL_Q_USEFUL_BUF_C,
                                          /* The detached payload */
                                          payload,
                                          /* Don't return parameters */
                                          NULL);
    if(result) {
        return 2000 + (int32_t)result;
    }

    /* compare payload output to the one expected */
    if(q_useful_buf_compare(payload, s_input_payload)) {
        return 3000;
    }

    /* This value comes from C-COSE test case sign-pass-03.json. The test
     * case JSON gives the expected TBS bytes. These were then run through
     * openssl dgst -sha256 -binary | hexdump -e '"\n" 8/1 "0x%01x,  "'.
     *
     * Short-circuit signature are just the hash of the TBS bytes. They are
     * twice to fake the length of a real signature. In the COSE format the
     * signature is last, so this hash occurs as the last 32 bytes of a
     * the encoded COSE.
     *
     * This is a useful test because it confirms the TBS byte calculation is
     * right in comparison to C-COSE.
     */
    static const uint8_t hash_of_tbs[] = {
        0x4c,  0x33,  0x63,  0xb4,  0x99,  0xe1,  0xda,  0xc4,
        0xaa,  0xfc,  0x8d,  0x69,  0x23,  0xf1,  0xca,  0x65,
        0x77,  0xdf,  0xda,  0x80,  0xda,  0x24,  0xe5,  0x4f,
        0xb9,  0x24,  0x24,  0x90,  0x64,  0x82,  0x7c,  0x88};

    if(q_useful_buf_compare(Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(hash_of_tbs),
                            q_useful_buf_tail(signed_cose, signed_cose.len - 32))) {
        return 4000;
    }

    /* --- Done verifying the COSE Sign1 object  --- */

    return 0;
}


/*
 * Public function, see t_cose_test.h
 */
int_fast32_t short_circuit_verify_fail_test()
{
    struct t_cose_sign1_sign_ctx    sign_ctx;
    struct t_cose_sign1_verify_ctx  verify_ctx;
    enum t_cose_err_t               result;
    Q_USEFUL_BUF_MAKE_STACK_UB(     signed_cose_buffer, 200);
    struct q_useful_buf_c           signed_cose;
    struct q_useful_buf_c           payload;
    size_t                          payload_offset;

    /* --- Start making COSE Sign1 object  --- */
    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);

    /* No key necessary because short-circuit test mode is used */

    result = t_cose_sign1_sign(&sign_ctx,
                                     s_input_payload,
                                     signed_cose_buffer,
                                     &signed_cose);
    if(result) {
        return 1000 + (int32_t)result;
    }
    /* --- Done making COSE Sign1 object  --- */


    /* --- Start Tamper with payload  --- */
    /* Find the offset of the payload in COSE_Sign1 */
    payload_offset = q_useful_buf_find_bytes(signed_cose, s_input_payload);
    if(payload_offset == SIZE_MAX) {
        return 6000;
    }
    /* Change "payload" to "hayload" */
    struct q_useful_buf temp_unconst = q_useful_buf_unconst(signed_cose);
    ((char *)temp_unconst.ptr)[payload_offset] = 'h';
    /* --- Tamper with payload Done --- */


    /* --- Start verifying the COSE Sign1 object  --- */

    /* Select short circuit signing */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);

    /* No key necessary with short circuit */

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                       /* COSE to verify */
                                       signed_cose,
                                       /* The returned payload */
                                       &payload,
                                       /* Don't return parameters */
                                       NULL);
    if(result != T_COSE_ERR_SIG_VERIFY) {
        return 4000 + (int32_t)result;
    }
    /* --- Done verifying the COSE Sign1 object  --- */


    /* === AAD Verification Failure Test === */
    /* --- Start making COSE Sign1 object  --- */
    t_cose_sign1_sign_init(&sign_ctx,
                            T_COSE_OPT_SHORT_CIRCUIT_SIG,
                            T_COSE_ALGORITHM_ES256);

    /* No key necessary because short-circuit test mode is used */

    result = t_cose_sign1_sign_aad(&sign_ctx,
                                    s_input_payload,
                                    Q_USEFUL_BUF_FROM_SZ_LITERAL("some aad"),
                                    signed_cose_buffer,
                                    &signed_cose);
    if(result) {
        return 1000 + (int32_t)result;
    }
    /* --- Done making COSE Sign1 object  --- */

    /* --- Start verifying the COSE Sign1 object  --- */

    /* Select short circuit signing */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);

    /* No key necessary with short circuit */

    /* Run the signature verification */
    result = t_cose_sign1_verify_aad(&verify_ctx,
                                     /* COSE to verify */
                                     signed_cose,
                                     /* Slightly different AAD */
                                     Q_USEFUL_BUF_FROM_SZ_LITERAL("home aad"),
                                     /* The returned payload */
                                     &payload,
                                     /* Don't return parameters */
                                     NULL);
    if(result != T_COSE_ERR_SIG_VERIFY) {
        return 4000 + (int32_t)result;
    }
    /* --- Done verifying the COSE Sign1 object  --- */

    return 0;
}


/*
 * Public function, see t_cose_test.h
 */
int_fast32_t short_circuit_signing_error_conditions_test()
{
    struct t_cose_sign1_sign_ctx sign_ctx;
    QCBOREncodeContext           cbor_encode;
    enum t_cose_err_t            result;
    Q_USEFUL_BUF_MAKE_STACK_UB(  signed_cose_buffer, 300);
    Q_USEFUL_BUF_MAKE_STACK_UB(  small_signed_cose_buffer, 15);
    struct q_useful_buf_c        signed_cose;


    /* -- Test bad algorithm ID 0 -- */
    /* Use reserved alg ID 0 to cause error. */
    t_cose_sign1_sign_init(&sign_ctx, T_COSE_OPT_SHORT_CIRCUIT_SIG, 0);

    result = t_cose_sign1_sign(&sign_ctx,
                                     s_input_payload,
                                     signed_cose_buffer,
                                     &signed_cose);
    if(result != T_COSE_ERR_UNSUPPORTED_SIGNING_ALG) {
        return -1;
    }


    /* -- Test bad algorithm ID -4444444 -- */
    /* Use unassigned alg ID -4444444 to cause error. */
    t_cose_sign1_sign_init(&sign_ctx, T_COSE_OPT_SHORT_CIRCUIT_SIG, -4444444);

    result = t_cose_sign1_sign(&sign_ctx,
                                     s_input_payload,
                                     signed_cose_buffer,
                                     &signed_cose);
    if(result != T_COSE_ERR_UNSUPPORTED_SIGNING_ALG) {
        return -2;
    }



    /* -- Tests detection of CBOR encoding error in the payload -- */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);
    result = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);


    QCBOREncode_AddSZString(&cbor_encode, "payload");
    /* Force a CBOR encoding error by closing a map that is not open */
    QCBOREncode_CloseMap(&cbor_encode);

    result = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);

    if(result != T_COSE_ERR_CBOR_FORMATTING) {
        return -3;
    }


    /* -- Tests the output buffer being too small -- */
    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);

    result = t_cose_sign1_sign(&sign_ctx,
                                     s_input_payload,
                                     small_signed_cose_buffer,
                                     &signed_cose);

    if(result != T_COSE_ERR_TOO_SMALL) {
        return -4;
    }

    return 0;
}


/*
 * Public function, see t_cose_test.h
 */
int_fast32_t short_circuit_make_cwt_test()
{
    struct t_cose_sign1_sign_ctx    sign_ctx;
    struct t_cose_sign1_verify_ctx  verify_ctx;
    QCBOREncodeContext              cbor_encode;
    enum t_cose_err_t               result;
    Q_USEFUL_BUF_MAKE_STACK_UB(     signed_cose_buffer, 200);
    struct q_useful_buf_c           signed_cose;
    struct q_useful_buf_c           payload;
    QCBORError                      cbor_error;

    /* --- Start making COSE Sign1 object  --- */

    /* The CBOR encoder instance that the COSE_Sign1 is output into */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);

    /* Do the first part of the the COSE_Sign1, the parameters */
    result = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);
    if(result) {
        return 1000 + (int32_t)result;
    }

    QCBOREncode_OpenMap(&cbor_encode);
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 1, "coap://as.example.com");
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 2, "erikw");
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 3, "coap://light.example.com");
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 4, 1444064944);
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 5, 1443944944);
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 6, 1443944944);
    const uint8_t xx[] = {0x0b, 0x71};
    QCBOREncode_AddBytesToMapN(&cbor_encode, 7, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(xx));
    QCBOREncode_CloseMap(&cbor_encode);

    /* Finish up the COSE_Sign1. This is where the signing happens */
    result = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(result) {
        return 2000 + (int32_t)result;
    }

    /* Finally close off the CBOR formatting and get the pointer and length
     * of the resulting COSE_Sign1
     */
    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return 3000 + (int32_t)cbor_error;
    }
    /* --- Done making COSE Sign1 object  --- */


    /* --- Compare to expected from CWT RFC --- */
    /* The first part, the intro and protected pararameters must be the same */
    const uint8_t cwt_first_part_bytes[] = {0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26};
    struct q_useful_buf_c fp = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(cwt_first_part_bytes);
    struct q_useful_buf_c head = q_useful_buf_head(signed_cose, sizeof(cwt_first_part_bytes));
    if(q_useful_buf_compare(head, fp)) {
        return -1;
    }

    /* Skip the key id, because this has the short-circuit key id */
    const size_t kid_encoded_len =
       1 +
       1 +
       2 +
       32; // length of short-circuit key id

    /* Compare the payload */
    const uint8_t rfc8392_payload_bytes[] = {
        0x58, 0x50, 0xa7, 0x01, 0x75, 0x63, 0x6f, 0x61, 0x70, 0x3a, 0x2f,
        0x2f, 0x61, 0x73, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x2e, 0x63, 0x6f, 0x6d, 0x02, 0x65, 0x65, 0x72, 0x69, 0x6b, 0x77,
        0x03, 0x78, 0x18, 0x63, 0x6f, 0x61, 0x70, 0x3a, 0x2f, 0x2f, 0x6c,
        0x69, 0x67, 0x68, 0x74, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x04, 0x1a, 0x56, 0x12, 0xae, 0xb0,
        0x05, 0x1a, 0x56, 0x10, 0xd9, 0xf0, 0x06, 0x1a, 0x56, 0x10, 0xd9,
        0xf0, 0x07, 0x42, 0x0b, 0x71};

    struct q_useful_buf_c fp2 = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(rfc8392_payload_bytes);

    struct q_useful_buf_c payload2 = q_useful_buf_tail(signed_cose,
                                                       sizeof(cwt_first_part_bytes)+kid_encoded_len);
    struct q_useful_buf_c pl3 = q_useful_buf_head(payload2,
                                                sizeof(rfc8392_payload_bytes));
    if(q_useful_buf_compare(pl3, fp2)) {
        return -2;
    }

    /* Skip the signature because ECDSA signatures usually have a random
     component */


    /* --- Start verifying the COSE Sign1 object  --- */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);

    /* No key necessary with short circuit */

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                       /* COSE to verify */
                                       signed_cose,
                                       /* The returned payload */
                                       &payload,
                                       /* Don't return parameters */
                                       NULL);
    if(result) {
        return 4000 + (int32_t)result;
    }

    /* Format the expected payload CBOR fragment */

    /* compare payload output to the one expected */
    if(q_useful_buf_compare(payload, q_useful_buf_tail(fp2, 2))) {
        return 5000;
    }
    /* --- Done verifying the COSE Sign1 object  --- */

    return 0;
}


/*
 * Public function, see t_cose_test.h
 */
int_fast32_t short_circuit_decode_only_test()
{
    struct t_cose_sign1_sign_ctx    sign_ctx;
    struct t_cose_sign1_verify_ctx  verify_ctx;
    QCBOREncodeContext              cbor_encode;
    enum t_cose_err_t               result;
    Q_USEFUL_BUF_MAKE_STACK_UB(     signed_cose_buffer, 200);
    struct q_useful_buf_c           signed_cose;
    struct q_useful_buf_c           payload;
    Q_USEFUL_BUF_MAKE_STACK_UB(     expected_payload_buffer, 10);
    struct q_useful_buf_c           expected_payload;
    QCBORError                      cbor_error;

    /* --- Start making COSE Sign1 object  --- */

    /* The CBOR encoder instance that the COSE_Sign1 is output into */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);

    /* Do the first part of the the COSE_Sign1, the parameters */
    result = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);
    if(result) {
        return 1000 + (int32_t)result;
    }


    QCBOREncode_AddSZString(&cbor_encode, "payload");

    /* Finish up the COSE_Sign1. This is where the signing happens */
    result = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(result) {
        return 2000 + (int32_t)result;
    }

    /* Finally close of the CBOR formatting and get the pointer and
     * length of the resulting COSE_Sign1
     */
    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return 3000 + (int32_t)cbor_error;
    }
    /* --- Done making COSE Sign1 object  --- */

    /* --- Tweak signature bytes --- */
    /* The signature is the last thing so reach back that many bytes
     * and tweak so if signature verification were attempted, it would
     * fail (but this is a decode-only test so it won't fail).
     */
    const size_t last_byte_offset = signed_cose.len - T_COSE_EC_P256_SIG_SIZE;
    struct q_useful_buf temp_unconst = q_useful_buf_unconst(signed_cose);
    ((uint8_t *)temp_unconst.ptr)[last_byte_offset]++;


    /* --- Start verifying the COSE Sign1 object  --- */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_DECODE_ONLY);

    /* Decode-only mode so no key and no signature check. */

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                       /* COSE to verify */
                                       signed_cose,
                                       /* The returned payload */
                                       &payload,
                                       /* Don't return parameters */
                                       NULL);


    if(result) {
        return 4000 + (int32_t)result;
    }

    /* Format the expected payload CBOR fragment */
    QCBOREncode_Init(&cbor_encode, expected_payload_buffer);
    QCBOREncode_AddSZString(&cbor_encode, "payload");
    QCBOREncode_Finish(&cbor_encode, &expected_payload);

    /* compare payload output to the one expected */
    if(q_useful_buf_compare(payload, expected_payload)) {
        return 5000;
    }
    /* --- Done verifying the COSE Sign1 object  --- */

    return 0;
}


/*
 18( [
    / protected / h’a10126’ / {
        \ alg \ 1:-7 \ ECDSA 256 \
    }/ ,
    / unprotected / {
      / kid / 4:’11’
    },
    / payload / ’This is the content.’,

       / signature / h’8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4
   d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5
   a4c345cacb36’
] )

 */

/* This comes from Appendix_C_2_1.json from COSE_C by Jim Schaad */
static const uint8_t rfc8152_example_2_1[] = {
    0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA1, 0x04,
    0x42, 0x31, 0x31, 0x54, 0x54, 0x68, 0x69, 0x73,
    0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
    0x63, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x2E, /* end of hdrs and payload*/
    0x58, 0x40, 0x8E, 0xB3, 0x3E, 0x4C, 0xA3, 0x1D, /* Sig starts with 0x58 */
    0x1C, 0x46, 0x5A, 0xB0, 0x5A, 0xAC, 0x34, 0xCC,
    0x6B, 0x23, 0xD5, 0x8F, 0xEF, 0x5C, 0x08, 0x31,
    0x06, 0xC4, 0xD2, 0x5A, 0x91, 0xAE, 0xF0, 0xB0,
    0x11, 0x7E, 0x2A, 0xF9, 0xA2, 0x91, 0xAA, 0x32,
    0xE1, 0x4A, 0xB8, 0x34, 0xDC, 0x56, 0xED, 0x2A,
    0x22, 0x34, 0x44, 0x54, 0x7E, 0x01, 0xF1, 0x1D,
    0x3B, 0x09, 0x16, 0xE5, 0xA4, 0xC3, 0x45, 0xCA,
    0xCB, 0x36};


/*
 * Public function, see t_cose_test.h
 */
int_fast32_t cose_example_test()
{
    enum t_cose_err_t             result;
    Q_USEFUL_BUF_MAKE_STACK_UB(   signed_cose_buffer, 200);
    struct q_useful_buf_c         output;
    struct t_cose_sign1_sign_ctx  sign_ctx;
    struct q_useful_buf_c         head_actual;
    struct q_useful_buf_c         head_exp;

    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);

    t_cose_sign1_set_signing_key(&sign_ctx,
                                 T_COSE_NULL_KEY,
                                 Q_USEFUL_BUF_FROM_SZ_LITERAL("11"));

    /* Make example C.2.1 from RFC 8152 */

    result = t_cose_sign1_sign(&sign_ctx,
                                      s_input_payload,
                                      signed_cose_buffer,
                                     &output);

    if(result != T_COSE_SUCCESS) {
        return (int32_t)result;
    }

    /* Compare only the headers and payload as this was not signed
     * with the same key as the example. The first 32 bytes contain
     * the header parameters and payload. */
    head_actual = q_useful_buf_head(output, 32);
    head_exp = q_useful_buf_head(Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(rfc8152_example_2_1), 32);

    if(q_useful_buf_compare(head_actual, head_exp)) {
        return -1000;
    }

    return (int32_t)result;
}


static enum t_cose_err_t run_test_sign_and_verify(uint32_t test_mess_options)
{
    struct t_cose_sign1_sign_ctx    sign_ctx;
    struct t_cose_sign1_verify_ctx  verify_ctx;
    QCBOREncodeContext              cbor_encode;
    enum t_cose_err_t               result;
    Q_USEFUL_BUF_MAKE_STACK_UB(     signed_cose_buffer, 200);
    struct q_useful_buf_c           signed_cose;
    struct q_useful_buf_c           payload;

    /* --- Start making COSE Sign1 object  --- */

    /* The CBOR encoder instance that the COSE_Sign1 is output into */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);

    result =
        t_cose_test_message_sign1_sign(&sign_ctx,
                                       test_mess_options,
                                       Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"),
                                       signed_cose_buffer,
                                       &signed_cose);
    if(result) {
        return result;
    }
    /* --- Done making COSE Sign1 object  --- */


    /* --- Start verifying the COSE Sign1 object  --- */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);

    /* No key necessary with short circuit */


    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                       /* COSE to verify */
                                       signed_cose,
                                       /* The returned payload */
                                       &payload,
                                       /* Don't return parameters */
                                       NULL);

    return result;
}


#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
int_fast32_t all_header_parameters_test()
{
    enum t_cose_err_t               result;
    Q_USEFUL_BUF_MAKE_STACK_UB(     signed_cose_buffer, 300);
    struct q_useful_buf_c           output;
    struct q_useful_buf_c           payload;
    struct t_cose_parameters        parameters;
    struct t_cose_sign1_sign_ctx    sign_ctx;
    struct t_cose_sign1_verify_ctx  verify_ctx;


    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);

    t_cose_sign1_set_signing_key(&sign_ctx,
                                 T_COSE_NULL_KEY,
                                 Q_USEFUL_BUF_FROM_SZ_LITERAL("11"));

    result =
        t_cose_test_message_sign1_sign(&sign_ctx,
                                       T_COSE_TEST_ALL_PARAMETERS,
                                       s_input_payload,
                                       signed_cose_buffer,
                                      &output);
    if(result) {
        return 1;
    }

    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);

    /* No key necessary with short circuit */


    result = t_cose_sign1_verify(&verify_ctx,
                                       /* COSE to verify */
                                       output,
                                       /* The returned payload */
                                       &payload,
                                       /* Get parameters for checking */
                                       &parameters);

    // Need to compare to short circuit kid
    if(q_useful_buf_compare(parameters.kid, get_short_circuit_kid())) {
        return 2;
    }

    if(parameters.cose_algorithm_id != T_COSE_ALGORITHM_ES256) {
        return 3;
    }

#ifndef T_COSE_DISABLE_CONTENT_TYPE
    if(parameters.content_type_uint != 1) {
        return 4;
    }
#endif /* T_COSE_DISABLE_CONTENT_TYPE */

    if(q_useful_buf_compare(parameters.iv,
                            Q_USEFUL_BUF_FROM_SZ_LITERAL("iv"))) {
        return 5;
    }

    if(q_useful_buf_compare(parameters.partial_iv,
                            Q_USEFUL_BUF_FROM_SZ_LITERAL("partial_iv"))) {
        return 6;
    }

    return 0;
}
#endif

struct test_case {
    uint32_t           test_option;
    enum t_cose_err_t  result;
};

static struct test_case bad_parameters_tests_table[] = {

    {T_COSE_TEST_EMPTY_PROTECTED_PARAMETERS, T_COSE_ERR_UNSUPPORTED_SIGNING_ALG},

    {T_COSE_TEST_UNCLOSED_PROTECTED, T_COSE_ERR_PARAMETER_CBOR},

#ifndef T_COSE_DISABLE_CONTENT_TYPE
    {T_COSE_TEST_DUP_CONTENT_ID, T_COSE_ERR_DUPLICATE_PARAMETER},

    {T_COSE_TEST_TOO_LARGE_CONTENT_TYPE, T_COSE_ERR_BAD_CONTENT_TYPE},
#endif /* T_COSE_DISABLE_CONTENT_TYPE */

    {T_COSE_TEST_NOT_WELL_FORMED_2, T_COSE_ERR_CBOR_NOT_WELL_FORMED},

    {T_COSE_TEST_KID_IN_PROTECTED, T_COSE_ERR_DUPLICATE_PARAMETER},

    {T_COSE_TEST_TOO_MANY_UNKNOWN, T_COSE_ERR_TOO_MANY_PARAMETERS},

    {T_COSE_TEST_UNPROTECTED_NOT_MAP, T_COSE_ERR_PARAMETER_CBOR},

    {T_COSE_TEST_BAD_CRIT_PARAMETER, T_COSE_ERR_CRIT_PARAMETER},

    {T_COSE_TEST_NOT_WELL_FORMED_1, T_COSE_ERR_CBOR_NOT_WELL_FORMED},

    {T_COSE_TEST_NO_UNPROTECTED_PARAMETERS, T_COSE_ERR_PARAMETER_CBOR},

    {T_COSE_TEST_NO_PROTECTED_PARAMETERS, T_COSE_ERR_PARAMETER_CBOR},

    {T_COSE_TEST_EXTRA_PARAMETER, T_COSE_SUCCESS},

    {T_COSE_TEST_PARAMETER_LABEL, T_COSE_ERR_PARAMETER_CBOR},

    {T_COSE_TEST_BAD_PROTECTED, T_COSE_ERR_PARAMETER_CBOR},

    {0, 0}
};


/*
 * Public function, see t_cose_test.h
 */
int_fast32_t bad_parameters_test()
{
    struct test_case *test;

    for(test = bad_parameters_tests_table; test->test_option; test++) {
        if(run_test_sign_and_verify(test->test_option) != test->result) {
            return (int_fast32_t)(test - bad_parameters_tests_table + 1);
        }
    }

    return 0;
}




static struct test_case crit_tests_table[] = {
    /* Test existance of the critical header. Also makes sure that
     * it works with the max number of labels allowed in it.
     */
    {T_COSE_TEST_CRIT_PARAMETER_EXIST, T_COSE_SUCCESS},

    /* Exceed the max number of labels by one and get an error */
    {T_COSE_TEST_TOO_MANY_CRIT_PARAMETER_EXIST, T_COSE_ERR_CRIT_PARAMETER},

    /* A critical parameter exists in the protected section, but the
     * format of the internals of this parameter is not the expected CBOR
     */
    {T_COSE_TEST_BAD_CRIT_LABEL, T_COSE_ERR_CRIT_PARAMETER},

    /* A critical label is listed in the protected section, but
     * the label doesn't exist. This works for integer-labeled header params.
     */
    {T_COSE_TEST_UNKNOWN_CRIT_UINT_PARAMETER, T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER},

    /* A critical label is listed in the protected section, but
     * the label doesn't exist. This works for string-labeled header params.
     */
    {T_COSE_TEST_UNKNOWN_CRIT_TSTR_PARAMETER, T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER},

    /* The critical labels list is not protected */
    {T_COSE_TEST_CRIT_NOT_PROTECTED, T_COSE_ERR_PARAMETER_NOT_PROTECTED},

    {T_COSE_TEST_EMPTY_CRIT_PARAMETER, T_COSE_ERR_CRIT_PARAMETER},

    {T_COSE_TEST_TOO_MANY_TSTR_CRIT_LABLELS, T_COSE_ERR_CRIT_PARAMETER},

    {0, 0}
};


/*
 * Public function, see t_cose_test.h
 */
int_fast32_t crit_parameters_test()
{
    struct test_case *test;

    for(test = crit_tests_table; test->test_option; test++) {
        if(run_test_sign_and_verify(test->test_option) != test->result) {
            return (int_fast32_t)(test - crit_tests_table + 1);
        }
    }

    return 0;
}


#ifndef T_COSE_DISABLE_CONTENT_TYPE
/*
 * Public function, see t_cose_test.h
 */
int_fast32_t content_type_test()
{
    struct t_cose_parameters        parameters;
    struct t_cose_sign1_sign_ctx    sign_ctx;
    Q_USEFUL_BUF_MAKE_STACK_UB(     signed_cose_buffer, 200);
    struct q_useful_buf_c           output;
    struct q_useful_buf_c           payload;
    enum t_cose_err_t               result;
    struct t_cose_sign1_verify_ctx  verify_ctx;


    /* -- integer content type -- */
    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);

    t_cose_sign1_set_content_type_uint(&sign_ctx, 42);

    result = t_cose_sign1_sign(&sign_ctx,
                                      s_input_payload,
                                      signed_cose_buffer,
                                     &output);
    if(result) {
        return 1;
    }

    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);

    result = t_cose_sign1_verify(&verify_ctx,
                                        output,
                                       &payload,
                                       &parameters);
    if(result) {
        return 2;
    }

    if(parameters.content_type_uint != 42) {
        return 5;
    }


    /* -- string content type -- */
    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);

    t_cose_sign1_set_content_type_tstr(&sign_ctx, "text/plain");

    result = t_cose_sign1_sign(&sign_ctx,
                                     s_input_payload,
                                     signed_cose_buffer,
                                     &output);
    if(result) {
        return 1;
    }

    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);

    result = t_cose_sign1_verify(&verify_ctx,
                                       output,
                                       &payload,
                                       &parameters);
    if(result) {
        return 2;
    }

    if(q_useful_buf_compare(parameters.content_type_tstr, Q_USEFUL_BUF_FROM_SZ_LITERAL("text/plain"))) {
        return 6;
    }


    /* -- content type in error -- */
    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);

    t_cose_sign1_set_content_type_tstr(&sign_ctx, "text/plain");
    t_cose_sign1_set_content_type_uint(&sign_ctx, 42);


    result = t_cose_sign1_sign(&sign_ctx,
                                     Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"),
                                     signed_cose_buffer,
                                     &output);
    if(result != T_COSE_ERR_DUPLICATE_PARAMETER) {
        return 1;
    }
    return 0;
}
#endif /* T_COSE_DISABLE_CONTENT_TYPE */


struct sign1_sample {
    struct q_useful_buf_c CBOR;
    enum t_cose_err_t     expected_error;
};

static struct sign1_sample sign1_sample_inputs[] = {
    /* 0. With an indefinite length string payload */
    { {(uint8_t[]){0x84, 0x40, 0xa0, 0x5f, 0x00, 0xff, 0x40}, 7}, T_COSE_ERR_SIGN1_FORMAT},
    /* 1. Too few items in unprotected header parameters bucket */
    { {(uint8_t[]){0x84, 0x40, 0xa3, 0x40, 0x40}, 5}, T_COSE_ERR_PARAMETER_CBOR},
    /* 2. Too few items in definite array */
    { {(uint8_t[]){0x83, 0x40, 0xa0, 0x40}, 4}, T_COSE_ERR_SIGN1_FORMAT},
    /* 3. Too-long signature */
    { {(uint8_t[]){0x84, 0x40, 0xa0, 0x40, 0x4f}, 5}, T_COSE_ERR_CBOR_NOT_WELL_FORMED},
    /* 4. Too-long payload */
    { {(uint8_t[]){0x84, 0x40, 0xa0, 0x4f, 0x40}, 5}, T_COSE_ERR_CBOR_NOT_WELL_FORMED},
    /* 5. Too-long protected parameters bucket */
    { {(uint8_t[]){0x84, 0x4f, 0xa0, 0x40, 0x40}, 5}, T_COSE_ERR_CBOR_NOT_WELL_FORMED},
    /* 6. Unterminated indefinite length */
    { {(uint8_t[]){0x9f, 0x40, 0xbf, 0xff, 0x40, 0x40}, 6}, T_COSE_ERR_SIGN1_FORMAT},
    /* 7. The smallest legal COSE_Sign1 using indefinite lengths */
    { {(uint8_t[]){0x9f, 0x40, 0xbf, 0xff, 0x40, 0x40, 0xff}, 7}, T_COSE_SUCCESS},
    /* 8. The smallest legal COSE_Sign1 using definite lengths */
    { {(uint8_t[]){0x84, 0x40, 0xa0, 0x40, 0x40}, 5}, T_COSE_SUCCESS},
    /* 9. Just one not-well-formed byte -- a reserved value */
    { {(uint8_t[]){0x3c}, 1}, T_COSE_ERR_CBOR_NOT_WELL_FORMED },
    /* terminate the list */
    { {NULL, 0}, 0 },
};


/*
 * Public function, see t_cose_test.h
 */
int_fast32_t sign1_structure_decode_test(void)
{
    const struct sign1_sample      *sample;
    struct q_useful_buf_c           payload;
    enum t_cose_err_t               result;
    struct t_cose_sign1_verify_ctx  verify_ctx;


    for(sample = sign1_sample_inputs; !q_useful_buf_c_is_null(sample->CBOR); sample++) {
        t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_DECODE_ONLY);

        result = t_cose_sign1_verify(&verify_ctx,
                                      sample->CBOR,
                                     &payload,
                                      NULL);

        if(result != sample->expected_error) {
            /* Returns 100 * index of the input + the unexpected error code */
            const size_t sample_index = (size_t)(sample - sign1_sample_inputs);
            return (int32_t)((sample_index+1)*100 + result);
        }
    }

    return 0;
}


#ifdef T_COSE_ENABLE_HASH_FAIL_TEST

/* Linkage to global variable in t_cose_test_crypto.c. This is only
 * used for an occasional test in a non-threaded environment so a global
 * variable is safe. This test and the hacks in the crypto code are
 * never enabled for commercial deployments.
 */
extern int hash_test_mode;


/*
 * Public function, see t_cose_test.h
 */
int_fast32_t short_circuit_hash_fail_test()
{
    struct t_cose_sign1_sign_ctx sign_ctx;
    enum t_cose_err_t            result;
    struct q_useful_buf_c        wrapped_payload;
    Q_USEFUL_BUF_MAKE_STACK_UB(  signed_cose_buffer, 200);

    /* See test description in t_cose_test.h for a full description of
     * what this does and what it needs to run.
     */


    /* Set the global variable to cause the hash implementation to
     * error out so this test can see what happens
     */
    hash_test_mode = 1;

    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);

    result = t_cose_sign1_sign(&sign_ctx,
                                     s_input_payload,
                                     signed_cose_buffer,
                                     &wrapped_payload);

    hash_test_mode = 0;

    if(result != T_COSE_ERR_HASH_GENERAL_FAIL) {
        return 2000 + (int32_t)result;
    }


    /* Set the global variable to cause the hash implementation to
     * error out so this test can see what happens
     */
    hash_test_mode = 2;

    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);

    result = t_cose_sign1_sign(&sign_ctx,
                                     s_input_payload,
                                     signed_cose_buffer,
                                     &wrapped_payload);

    hash_test_mode = 0;

    if(result != T_COSE_ERR_HASH_GENERAL_FAIL) {
        return 2000 + (int32_t)result;
    }

    return 0;
}

#endif /* T_COSE_ENABLE_HASH_FAIL_TEST */


/*
 * Public function, see t_cose_test.h
 */
int_fast32_t tags_test()
{
    struct t_cose_sign1_sign_ctx    sign_ctx;
    struct t_cose_sign1_verify_ctx  verify_ctx;
    QCBOREncodeContext              cbor_encode;
    enum t_cose_err_t               result;
    Q_USEFUL_BUF_MAKE_STACK_UB(     signed_cose_buffer, 200);
    struct q_useful_buf_c           signed_cose;
    struct q_useful_buf_c           payload;
    QCBORError                      cbor_error;
    uint64_t                        tag;

    /* --- Start making COSE Sign1 object tagged 900(901(18())) --- */

    /* The CBOR encoder instance that the COSE_Sign1 is output into */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    QCBOREncode_AddTag(&cbor_encode, 900);

    QCBOREncode_AddTag(&cbor_encode, 901);

    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);

    /* Do the first part of the the COSE_Sign1, the parameters */
    result = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);
    if(result) {
        return 1000 + (int32_t)result;
    }

    QCBOREncode_OpenMap(&cbor_encode);
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 1, "coap://as.example.com");
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 2, "erikw");
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 3, "coap://light.example.com");
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 4, 1444064944);
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 5, 1443944944);
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 6, 1443944944);
    const uint8_t xx[] = {0x0b, 0x71};
    QCBOREncode_AddBytesToMapN(&cbor_encode, 7, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(xx));
    QCBOREncode_CloseMap(&cbor_encode);

    /* Finish up the COSE_Sign1. This is where the signing happens */
    result = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(result) {
        return 2000 + (int32_t)result;
    }

    /* Finally close off the CBOR formatting and get the pointer and length
     * of the resulting COSE_Sign1
     */
    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return 3000 + (int32_t)cbor_error;
    }
    /* --- Done making COSE Sign1 object tagged 900(901(18(0))) --- */


    /* --- Compare to expected from CWT RFC --- */
    /* The first part, the intro and protected pararameters must be the same */
    const uint8_t cwt_first_part_bytes[] = {0xd9, 0x03, 0x84, 0xd9, 0x03, 0x85, 0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26};
    struct q_useful_buf_c fp = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(cwt_first_part_bytes);
    struct q_useful_buf_c head = q_useful_buf_head(signed_cose, sizeof(cwt_first_part_bytes));
    if(q_useful_buf_compare(head, fp)) {
        return -1;
    }

    /* Skip the key id, because this has the short-circuit key id */
    const size_t kid_encoded_len =
    1 +
    1 +
    2 +
    32; // length of short-circuit key id

    /* Compare the payload */
    const uint8_t rfc8392_payload_bytes[] = {
        0x58, 0x50, 0xa7, 0x01, 0x75, 0x63, 0x6f, 0x61, 0x70, 0x3a, 0x2f,
        0x2f, 0x61, 0x73, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x2e, 0x63, 0x6f, 0x6d, 0x02, 0x65, 0x65, 0x72, 0x69, 0x6b, 0x77,
        0x03, 0x78, 0x18, 0x63, 0x6f, 0x61, 0x70, 0x3a, 0x2f, 0x2f, 0x6c,
        0x69, 0x67, 0x68, 0x74, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x04, 0x1a, 0x56, 0x12, 0xae, 0xb0,
        0x05, 0x1a, 0x56, 0x10, 0xd9, 0xf0, 0x06, 0x1a, 0x56, 0x10, 0xd9,
        0xf0, 0x07, 0x42, 0x0b, 0x71};

    struct q_useful_buf_c fp2 = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(rfc8392_payload_bytes);

    struct q_useful_buf_c payload2 = q_useful_buf_tail(signed_cose,
                                                       sizeof(cwt_first_part_bytes)+kid_encoded_len);
    struct q_useful_buf_c pl3 = q_useful_buf_head(payload2,
                                                  sizeof(rfc8392_payload_bytes));
    if(q_useful_buf_compare(pl3, fp2)) {
        return -2;
    }

    /* Skip the signature because ECDSA signatures usually have a random
     component */


    /* --- Start verifying the COSE Sign1 object  --- */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);

    /* No key necessary with short circuit */

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                 /* COSE to verify */
                                 signed_cose,
                                 /* The returned payload */
                                 &payload,
                                 /* Don't return parameters */
                                 NULL);
    if(result) {
        return 4000 + (int32_t)result;
    }

    tag = t_cose_sign1_get_nth_tag(&verify_ctx, 0);
    if(tag != 901) {
        return -3;
    }

    tag = t_cose_sign1_get_nth_tag(&verify_ctx, 1);
    if(tag != 900) {
        return -3;
    }

    tag = t_cose_sign1_get_nth_tag(&verify_ctx, 2);
    if(tag != CBOR_TAG_INVALID64) {
        return -4;
    }

    /* compare payload output to the one expected */
    if(q_useful_buf_compare(payload, q_useful_buf_tail(fp2, 2))) {
        return 5000;
    }
    /* --- Done verifying the COSE Sign1 object  --- */


    /* --- Start verifying the COSE Sign1 object, requiring tag--- */
    t_cose_sign1_verify_init(&verify_ctx,
                             T_COSE_OPT_ALLOW_SHORT_CIRCUIT | T_COSE_OPT_TAG_REQUIRED);

    /* No key necessary with short circuit */

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                 /* COSE to verify */
                                 signed_cose,
                                 /* The returned payload */
                                 &payload,
                                 /* Don't return parameters */
                                 NULL);
    if(result != T_COSE_SUCCESS) {
        return 4000 + (int32_t)result;
    }

    /* --- Done verifying the COSE Sign1 object  --- */



    /* --- Start verifying the COSE Sign1 object, prohibiting tag--- */
    t_cose_sign1_verify_init(&verify_ctx,
                             T_COSE_OPT_ALLOW_SHORT_CIRCUIT | T_COSE_OPT_TAG_PROHIBITED);

    /* No key necessary with short circuit */

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                 /* COSE to verify */
                                 signed_cose,
                                 /* The returned payload */
                                 &payload,
                                 /* Don't return parameters */
                                 NULL);
    if(result != T_COSE_ERR_INCORRECTLY_TAGGED) {
        return 4000 + (int32_t)result;
    }

    /* --- Done verifying the COSE Sign1 object  --- */



    /* --- Start making COSE Sign1 object  --- */

    /* The CBOR encoder instance that the COSE_Sign1 is output into */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    QCBOREncode_AddTag(&cbor_encode, 900);
    QCBOREncode_AddTag(&cbor_encode, 901);
    QCBOREncode_AddTag(&cbor_encode, 902);
    QCBOREncode_AddTag(&cbor_encode, 903);
    QCBOREncode_AddTag(&cbor_encode, 904);

    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);

    /* Do the first part of the the COSE_Sign1, the parameters */
    result = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);
    if(result) {
        return 1000 + (int32_t)result;
    }

    QCBOREncode_OpenMap(&cbor_encode);
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 1, "coap://as.example.com");
    QCBOREncode_CloseMap(&cbor_encode);

    /* Finish up the COSE_Sign1. This is where the signing happens */
    result = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(result) {
        return 2000 + (int32_t)result;
    }

    /* Finally close off the CBOR formatting and get the pointer and length
     * of the resulting COSE_Sign1
     */
    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return 3000 + (int32_t)cbor_error;
    }
    /* --- Done making COSE Sign1 object  --- */

    /* --- Start verifying the COSE Sign1 object  --- */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);

    /* No key necessary with short circuit */

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                 /* COSE to verify */
                                 signed_cose,
                                 /* The returned payload */
                                 &payload,
                                 /* Don't return parameters */
                                 NULL);
    if(result != T_COSE_ERR_TOO_MANY_TAGS) {
        return 4000 + (int32_t)result;
    }



    /* --- Start making COSE Sign1 object tagged 900(901()) --- */

    /* The CBOR encoder instance that the COSE_Sign1 is output into */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    QCBOREncode_AddTag(&cbor_encode, 900);

    QCBOREncode_AddTag(&cbor_encode, 901);

    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG | T_COSE_OPT_OMIT_CBOR_TAG,
                           T_COSE_ALGORITHM_ES256);

    /* Do the first part of the the COSE_Sign1, the parameters */
    result = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);
    if(result) {
        return 1000 + (int32_t)result;
    }

    QCBOREncode_OpenMap(&cbor_encode);
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 1, "coap://as.example.com");
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 2, "erikw");
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 3, "coap://light.example.com");
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 4, 1444064944);
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 5, 1443944944);
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 6, 1443944944);
    const uint8_t xxy[] = {0x0b, 0x71};
    QCBOREncode_AddBytesToMapN(&cbor_encode, 7, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(xxy));
    QCBOREncode_CloseMap(&cbor_encode);

    /* Finish up the COSE_Sign1. This is where the signing happens */
    result = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(result) {
        return 2000 + (int32_t)result;
    }

    /* Finally close off the CBOR formatting and get the pointer and length
     * of the resulting COSE_Sign1
     */
    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return 3000 + (int32_t)cbor_error;
    }
    /* --- Done making COSE Sign1 object tagged 900(901(18(0))) --- */



    /* --- Compare to expected from CWT RFC --- */
    /* The first part, the intro and protected pararameters must be the same */
    const uint8_t cwt_first_part_bytes1[] = {0xd9, 0x03, 0x84, 0xd9, 0x03, 0x85, 0x84, 0x43, 0xa1, 0x01, 0x26};
    struct q_useful_buf_c fp1 = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(cwt_first_part_bytes1);
    struct q_useful_buf_c head1 = q_useful_buf_head(signed_cose, sizeof(cwt_first_part_bytes1));
    if(q_useful_buf_compare(head1, fp1)) {
        return -1;
    }

    /* --- Start verifying the COSE Sign1 object, requiring tag--- */
    t_cose_sign1_verify_init(&verify_ctx,
                             T_COSE_OPT_ALLOW_SHORT_CIRCUIT | T_COSE_OPT_TAG_REQUIRED);

    /* No key necessary with short circuit */

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                 /* COSE to verify */
                                 signed_cose,
                                 /* The returned payload */
                                 &payload,
                                 /* Don't return parameters */
                                 NULL);
    if(result != T_COSE_ERR_INCORRECTLY_TAGGED) {
        return 4000 + (int32_t)result;
    }


    /* --- Start verifying the COSE Sign1 object, prohibiting tag--- */
    t_cose_sign1_verify_init(&verify_ctx,
                             T_COSE_OPT_ALLOW_SHORT_CIRCUIT | T_COSE_OPT_TAG_PROHIBITED);

    /* No key necessary with short circuit */

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                 /* COSE to verify */
                                 signed_cose,
                                 /* The returned payload */
                                 &payload,
                                 /* Don't return parameters */
                                 NULL);
    if(result != T_COSE_SUCCESS) {
        return 4000 + (int32_t)result;
    }

    /* --- Done verifying the COSE Sign1 object  --- */

    return 0;
}


int_fast32_t get_size_test()
{
    struct t_cose_sign1_sign_ctx   sign_ctx;
    QCBOREncodeContext             cbor_encode;
    enum t_cose_err_t              return_value;
    struct q_useful_buf            nil_buf;
    size_t                         calculated_size;
    QCBORError                     cbor_error;
    struct q_useful_buf_c          actual_signed_cose;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          payload;

    /* ---- Common Set up ---- */
    payload = Q_USEFUL_BUF_FROM_SZ_LITERAL("payload");

    /* ---- First calculate the size ----- */
    nil_buf = (struct q_useful_buf) {NULL, SIZE_MAX};
    QCBOREncode_Init(&cbor_encode, nil_buf);

    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);

    return_value = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);
    if(return_value) {
        return 2000 + (int32_t)return_value;
    }

    QCBOREncode_AddEncoded(&cbor_encode, payload);

    return_value = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(return_value) {
        return 3000 + (int32_t)return_value;
    }

    cbor_error = QCBOREncode_FinishGetSize(&cbor_encode, &calculated_size);
    if(cbor_error) {
        return 4000 + (int32_t)cbor_error;
    }

    /* ---- General sanity check ---- */
    size_t expected_min = 32 + payload.len + 64;

    if(calculated_size < expected_min || calculated_size > expected_min + 30) {
        return -1;
    }



    /* ---- Now make a real COSE_Sign1 and compare the size ---- */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);

    return_value = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);
    if(return_value) {
        return 2000 + (int32_t)return_value;
    }

    QCBOREncode_AddEncoded(&cbor_encode, payload);

    return_value = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(return_value) {
        return 3000 + (int32_t)return_value;
    }

    cbor_error = QCBOREncode_Finish(&cbor_encode, &actual_signed_cose);
    if(actual_signed_cose.len != calculated_size) {
        return -2;
    }

    /* ---- Again with one-call API to make COSE_Sign1 ---- */\
    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           T_COSE_ALGORITHM_ES256);
    return_value = t_cose_sign1_sign(&sign_ctx,
                                     payload,
                                     signed_cose_buffer,
                                     &actual_signed_cose);
    if(return_value) {
        return 7000 + (int32_t)return_value;
    }

    if(actual_signed_cose.len != calculated_size) {
        return -3;
    }


    return 0;
}


/*
 * Public function, see t_cose_test.h
 */
int_fast32_t indef_array_and_map_test()
{
    enum t_cose_err_t  return_value;
    uint32_t           t_opts;

    /* This makes some COSEs with
     *  - The main array of four indefinite length
     *  - The protected header parameters map indef
     *  - The unprotected header parameters map indef
     *  - The critical pamaraters array inde
     */

    /* General test with indefinite lengths */
    return_value = run_test_sign_and_verify(T_COSE_TEST_INDEFINITE_MAPS_ARRAYS);
    if(return_value != T_COSE_SUCCESS) {
        return 1000 + (int32_t) return_value;
    }

    /* Test critical parameters encoded as indefinite length */
    t_opts = T_COSE_TEST_INDEFINITE_MAPS_ARRAYS |
             T_COSE_TEST_UNKNOWN_CRIT_UINT_PARAMETER;
    return_value = run_test_sign_and_verify(t_opts);
    if(return_value != T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER) {
        return 2000 + (int32_t) return_value;
    }

    /* Another general test with indefinite lengths */
    t_opts = T_COSE_TEST_INDEFINITE_MAPS_ARRAYS |
             T_COSE_TEST_ALL_PARAMETERS;
    return_value = run_test_sign_and_verify(t_opts);
    if(return_value != T_COSE_SUCCESS) {
        return 3000 + (int32_t) return_value;
    }

    return 0;
}
