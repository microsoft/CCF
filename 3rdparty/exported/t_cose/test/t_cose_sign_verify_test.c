/*
 *  t_cose_sign_verify_test.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose_make_test_pub_key.h"

#include "t_cose_crypto.h" /* Just for t_cose_crypto_sig_size() */


/*
 * Public function, see t_cose_sign_verify_test.h
 */
int_fast32_t sign_verify_basic_test_alg(int32_t cose_alg)
{
    struct t_cose_sign1_sign_ctx   sign_ctx;
    int32_t                        return_value;
    enum t_cose_err_t              result;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          signed_cose;
    struct t_cose_key              key_pair;
    struct q_useful_buf_c          payload;
    struct t_cose_sign1_verify_ctx verify_ctx;

    /* -- Get started with context initialization, selecting the alg -- */
    t_cose_sign1_sign_init(&sign_ctx, 0, cose_alg);

    /* Make an ECDSA key pair that will be used for both signing and
     * verification.
     */
    result = make_ecdsa_key_pair(cose_alg, &key_pair);
    if(result) {
        return 1000 + (int32_t)result;
    }
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);

    result = t_cose_sign1_sign(&sign_ctx,
                      Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"),
                      signed_cose_buffer,
                      &signed_cose);
    if(result) {
        return_value = 2000 + (int32_t)result;
        goto Done;
    }

    /* Verification */
    t_cose_sign1_verify_init(&verify_ctx, 0);

    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    result = t_cose_sign1_verify(&verify_ctx,
                                       signed_cose,         /* COSE to verify */
                                       &payload,  /* Payload from signed_cose */
                                       NULL);      /* Don't return parameters */
    if(result) {
        return_value = 5000 + (int32_t)result;
        goto Done;
    }


    /* compare payload output to the one expected */
    if(q_useful_buf_compare(payload, Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"))) {
        return_value = 6000;
        goto Done;
    }

    return_value = 0;

Done:
    /* Many crypto libraries allocate memory, slots, etc for keys */
    free_ecdsa_key_pair(key_pair);

    return return_value;
}


/*
 * Public function, see t_cose_sign_verify_test.h
 */
int_fast32_t sign_verify_basic_test()
{
    int_fast32_t return_value;

   return_value  = sign_verify_basic_test_alg(T_COSE_ALGORITHM_ES256);
   if(return_value) {
        return 20000 + return_value;
   }

#ifndef T_COSE_DISABLE_ES384
    return_value  = sign_verify_basic_test_alg(T_COSE_ALGORITHM_ES384);
    if(return_value) {
        return 30000 + return_value;
    }
#endif

#ifndef T_COSE_DISABLE_ES512
    return_value  = sign_verify_basic_test_alg(T_COSE_ALGORITHM_ES512);
    if(return_value) {
        return 50000 + return_value;
    }
#endif

    return 0;

}


/*
 * Public function, see t_cose_sign_verify_test.h
 */
int_fast32_t sign_verify_sig_fail_test()
{
    struct t_cose_sign1_sign_ctx   sign_ctx;
    QCBOREncodeContext             cbor_encode;
    int32_t                        return_value;
    enum t_cose_err_t              result;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          signed_cose;
    struct t_cose_key              key_pair;
    struct q_useful_buf_c          payload;
    QCBORError                     cbor_error;
    struct t_cose_sign1_verify_ctx verify_ctx;
    size_t                         tamper_offset;


    /* Make an ECDSA key pair that will be used for both signing and
     * verification.
     */
    result = make_ecdsa_key_pair(T_COSE_ALGORITHM_ES256, &key_pair);
    if(result) {
        return 1000 + (int32_t)result;
    }

    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_ES256);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);

    result = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);
    if(result) {
        return_value = 2000 + (int32_t)result;
        goto Done;
    }

    QCBOREncode_AddSZString(&cbor_encode, "payload");


    result = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(result) {
        return_value = 3000 + (int32_t)result;
        goto Done;
    }

    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return_value = 4000 + (int32_t)cbor_error;
        goto Done;
    }

    /* tamper with the pay load to see that the signature verification fails */
    tamper_offset = q_useful_buf_find_bytes(signed_cose, Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"));
    if(tamper_offset == SIZE_MAX) {
        return_value = 99;
        goto Done;
    }
    /* Change "payload" to "hayload" */
    struct q_useful_buf temp_unconst = q_useful_buf_unconst(signed_cose);
    ((char *)temp_unconst.ptr)[tamper_offset] = 'h';

    t_cose_sign1_verify_init(&verify_ctx, 0);

    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    result = t_cose_sign1_verify(&verify_ctx,
                                 signed_cose,   /* COSE to verify */
                                &payload,       /* Payload from signed_cose */
                                 NULL);         /* Don't return parameters */

    if(result != T_COSE_ERR_SIG_VERIFY) {
        return_value = 5000 + (int32_t)result;
    }

    return_value = 0;

Done:
    free_ecdsa_key_pair(key_pair);

    return return_value;
}


/*
 * Public function, see t_cose_sign_verify_test.h
 */
int_fast32_t sign_verify_make_cwt_test()
{
    struct t_cose_sign1_sign_ctx   sign_ctx;
    QCBOREncodeContext             cbor_encode;
    int32_t                        return_value;
    enum t_cose_err_t              result;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          signed_cose;
    struct t_cose_key              key_pair;
    struct q_useful_buf_c          payload;
    QCBORError                     cbor_error;
    struct t_cose_sign1_verify_ctx verify_ctx;
    struct q_useful_buf_c          expected_rfc8392_first_part;
    struct q_useful_buf_c          expected_payload;
    struct q_useful_buf_c          actual_rfc8392_first_part;

    /* -- initialize for signing --
     *  No special options selected
     */
    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_ES256);


    /* -- Key and kid --
     * The ECDSA key pair made is both for signing and verification.
     * The kid comes from RFC 8932
     */
    result = make_ecdsa_key_pair(T_COSE_ALGORITHM_ES256, &key_pair);
    if(result) {
        return 1000 + (int32_t)result;
    }
    t_cose_sign1_set_signing_key(&sign_ctx,
                                  key_pair,
                                  Q_USEFUL_BUF_FROM_SZ_LITERAL("AsymmetricECDSA256"));


    /* -- Encoding context and output of parameters -- */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);
    result = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);
    if(result) {
        return_value = 2000 + (int32_t)result;
        goto Done;
    }


    /* -- The payload as from RFC 8932 -- */
    QCBOREncode_OpenMap(&cbor_encode);
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 1, "coap://as.example.com");
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 2, "erikw");
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 3, "coap://light.example.com");
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 4, 1444064944);
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 5, 1443944944);
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 6, 1443944944);
    const uint8_t xx[] = {0x0b, 0x71};
    QCBOREncode_AddBytesToMapN(&cbor_encode, 7,
                               Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(xx));
    QCBOREncode_CloseMap(&cbor_encode);


    /* -- Finish up the COSE_Sign1. This is where the signing happens -- */
    result = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(result) {
        return_value = 3000 + (int32_t)result;
        goto Done;
    }

    /* Finally close off the CBOR formatting and get the pointer and length
     * of the resulting COSE_Sign1
     */
    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return_value = (int32_t)cbor_error + 4000;
        goto Done;
    }
    /* --- Done making COSE Sign1 object  --- */


    /* Compare to expected from CWT RFC */
    /* The first part, the intro and protected parameters must be the same */
    const uint8_t rfc8392_first_part_bytes[] = {
        0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa1, 0x04, 0x52, 0x41, 0x73, 0x79,
        0x6d, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x45, 0x43, 0x44, 0x53, 0x41,
        0x32, 0x35, 0x36, 0x58, 0x50, 0xa7, 0x01, 0x75, 0x63, 0x6f, 0x61, 0x70,
        0x3a, 0x2f, 0x2f, 0x61, 0x73, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x02, 0x65, 0x65, 0x72, 0x69, 0x6b, 0x77,
        0x03, 0x78, 0x18, 0x63, 0x6f, 0x61, 0x70, 0x3a, 0x2f, 0x2f, 0x6c, 0x69,
        0x67, 0x68, 0x74, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
        0x63, 0x6f, 0x6d, 0x04, 0x1a, 0x56, 0x12, 0xae, 0xb0, 0x05, 0x1a, 0x56,
        0x10, 0xd9, 0xf0, 0x06, 0x1a, 0x56, 0x10, 0xd9, 0xf0, 0x07, 0x42, 0x0b,
        0x71};
    expected_rfc8392_first_part = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(rfc8392_first_part_bytes);
    actual_rfc8392_first_part = q_useful_buf_head(signed_cose, sizeof(rfc8392_first_part_bytes));
    if(q_useful_buf_compare(actual_rfc8392_first_part, expected_rfc8392_first_part)) {
        return_value = -1;
        goto Done;
    }

    /* --- Start verifying the COSE Sign1 object  --- */
    /* Run the signature verification */
    t_cose_sign1_verify_init(&verify_ctx, 0);

    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    result =  t_cose_sign1_verify(&verify_ctx,
                                        signed_cose, /* COSE to verify */
                                       &payload, /* Payload from signed_cose */
                                        NULL);  /* Don't return parameters */

    if(result) {
        return_value = 5000 + (int32_t)result;
        goto Done;
    }

    /* Format the expected payload CBOR fragment */

    /* Skip the key id, because this has the short-circuit key id */
    const size_t kid_encoded_len =
      1 +
      1 +
      1 +
      strlen("AsymmetricECDSA256"); // length of short-circuit key id


    /* compare payload output to the one expected */
    expected_payload = q_useful_buf_tail(expected_rfc8392_first_part, kid_encoded_len + 8);
    if(q_useful_buf_compare(payload, expected_payload)) {
        return_value = 6000;
    }
    /* --- Done verifying the COSE Sign1 object  --- */

    return_value = 0;

Done:
    /* Many crypto libraries allocate memory, slots, etc for keys */
    free_ecdsa_key_pair(key_pair);

    return return_value;
}


/*
 * Public function, see t_cose_sign_verify_test.h
 */
static int size_test(int32_t               cose_algorithm_id,
                     struct q_useful_buf_c kid,
                     struct t_cose_key     key_pair)
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
    size_t                         sig_size;

    /* ---- Common Set up ---- */
    payload = Q_USEFUL_BUF_FROM_SZ_LITERAL("payload");
    return_value = t_cose_crypto_sig_size(cose_algorithm_id, key_pair, &sig_size);

    /* ---- First calculate the size ----- */
    nil_buf = (struct q_useful_buf) {NULL, INT32_MAX};
    QCBOREncode_Init(&cbor_encode, nil_buf);

    t_cose_sign1_sign_init(&sign_ctx,  0,  cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, kid);

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
    size_t expected_min = sig_size + payload.len + kid.len;

    if(calculated_size < expected_min || calculated_size > expected_min + 30) {
        return -1;
    }



    /* ---- Now make a real COSE_Sign1 and compare the size ---- */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_sign1_sign_init(&sign_ctx,  0,  cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, kid);

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
    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, kid);
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
 * Public function, see t_cose_sign_verify_test.h
 */
int_fast32_t sign_verify_get_size_test()
{
    enum t_cose_err_t   return_value;
    struct t_cose_key   key_pair;
    int32_t             result;

    return_value = make_ecdsa_key_pair(T_COSE_ALGORITHM_ES256, &key_pair);
    if(return_value) {
        return 1000 + (int32_t)return_value;
    }

    result = size_test(T_COSE_ALGORITHM_ES256, NULL_Q_USEFUL_BUF_C, key_pair);
    free_ecdsa_key_pair(key_pair);
    if(result) {
        return 2000 + result;
    }


#ifndef T_COSE_DISABLE_ES384

    return_value = make_ecdsa_key_pair(T_COSE_ALGORITHM_ES384, &key_pair);
    if(return_value) {
        return 3000 + (int32_t)return_value;
    }

    result = size_test(T_COSE_ALGORITHM_ES384, NULL_Q_USEFUL_BUF_C, key_pair);
    free_ecdsa_key_pair(key_pair);
    if(result) {
        return 4000 + result;
    }

#endif /* T_COSE_DISABLE_ES384 */


#ifndef T_COSE_DISABLE_ES512

    return_value = make_ecdsa_key_pair(T_COSE_ALGORITHM_ES512, &key_pair);
    if(return_value) {
        return 5000 + (int32_t)return_value;
    }

    result = size_test(T_COSE_ALGORITHM_ES512, NULL_Q_USEFUL_BUF_C, key_pair);
    if(result) {
        free_ecdsa_key_pair(key_pair);
        return 6000 + result;
    }

    result = size_test(T_COSE_ALGORITHM_ES512,
                       Q_USEFUL_BUF_FROM_SZ_LITERAL("greasy kid stuff"),
                       key_pair);
    free_ecdsa_key_pair(key_pair);
    if(result) {
        return 7000 + result;
    }

#endif /* T_COSE_DISABLE_ES512 */


    return 0;
}


/* These are complete known-good COSE messages for a verification
 * test. The key used to verify them is made by make_ecdsa_key_pair().
 * It always makes the same key for both MbedTLS and OpenSSL.
 *
 * These were made by setting a break point in sign_verify_basic_test()
 * and copying the output of the signing.
 */
static const uint8_t signed_cose_made_by_ossl_crypto_256[] = {
    0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA0, 0x47,
    0x70, 0x61, 0x79, 0x6C, 0x6F, 0x61, 0x64, 0x58,
    0x40, 0xF2, 0x2B, 0xAE, 0x15, 0xA8, 0xA6, 0x7A,
    0x60, 0x6B, 0x0B, 0xEA, 0xCB, 0xB6, 0x21, 0xD0,
    0xA0, 0xAC, 0x99, 0xCE, 0x2A, 0xD3, 0xD8, 0x1F,
    0xA5, 0x25, 0x77, 0x04, 0x8C, 0x27, 0xF8, 0x7F,
    0xF2, 0x25, 0x78, 0xFA, 0xDE, 0xED, 0xB0, 0xFB,
    0xC7, 0xB3, 0x31, 0xCF, 0x4F, 0x5C, 0xC8, 0x25,
    0xDE, 0xFD, 0x2D, 0xB9, 0xF3, 0x6C, 0xD7, 0xCB,
    0x69, 0x53, 0xCB, 0x05, 0xE3, 0x60, 0xAC, 0x98,
    0xE6};

#ifndef T_COSE_DISABLE_ES384
static const uint8_t signed_cose_made_by_psa_crypto_384[] = {
    0xD2, 0x84, 0x44, 0xA1, 0x01, 0x38, 0x22, 0xA0,
    0x47, 0x70, 0x61, 0x79, 0x6C, 0x6F, 0x61, 0x64,
    0x58, 0x60, 0x2C, 0x6C, 0x08, 0xF3, 0x36, 0x9E,
    0x35, 0x7A, 0x6B, 0xE5, 0xD6, 0x6E, 0xF9, 0x30,
    0x06, 0x2B, 0xD8, 0x73, 0xAB, 0x7E, 0x9B, 0x9D,
    0x4A, 0x30, 0xDD, 0x62, 0x75, 0xE5, 0xD6, 0x61,
    0x39, 0xF7, 0x4D, 0xC3, 0x7C, 0xF0, 0xEB, 0x58,
    0x9D, 0x78, 0xCA, 0x70, 0xD3, 0xA2, 0xF9, 0x23,
    0x85, 0xE6, 0x45, 0x18, 0x04, 0xBE, 0x9F, 0xA0,
    0xE3, 0x97, 0x4A, 0x12, 0x82, 0xF2, 0x87, 0x4F,
    0x3B, 0xF6, 0x9D, 0xC3, 0xE2, 0x99, 0xCC, 0x67,
    0x69, 0x34, 0xDB, 0x1C, 0xF4, 0xAF, 0x95, 0x83,
    0x74, 0x1B, 0x5C, 0xCD, 0xD5, 0x11, 0xC1, 0x07,
    0xE2, 0xD9, 0x3B, 0x16, 0x31, 0x5A, 0x55, 0x58,
    0x6C, 0xC9};
#endif /* T_COSE_DISABLE_ES384 */


#ifndef T_COSE_DISABLE_ES512
static const uint8_t signed_cose_made_by_openssl_crypto_521[] = {
    0xD2, 0x84, 0x44, 0xA1, 0x01, 0x38, 0x23, 0xA0,
    0x47, 0x70, 0x61, 0x79, 0x6C, 0x6F, 0x61, 0x64,
    0x58, 0x84, 0x01, 0x54, 0x10, 0x66, 0x49, 0x6B,
    0x8B, 0xDC, 0xB0, 0xCE, 0x03, 0x73, 0x30, 0x01,
    0x92, 0xF1, 0xE3, 0x18, 0x37, 0xF1, 0x91, 0xC1,
    0x57, 0xB5, 0x13, 0xB8, 0x30, 0x10, 0xA6, 0xA6,
    0x29, 0xDC, 0x74, 0xA0, 0x5E, 0x39, 0xC8, 0x2F,
    0x2B, 0x5D, 0x1C, 0xDB, 0x90, 0x47, 0x50, 0xA0,
    0x97, 0x47, 0x0E, 0x99, 0x66, 0x6F, 0xC4, 0xA5,
    0xBB, 0xD7, 0xF7, 0x99, 0xD3, 0x87, 0x7A, 0x1B,
    0x03, 0xCA, 0x6A, 0xDB, 0x01, 0x04, 0xB5, 0x9D,
    0xB6, 0x18, 0xE9, 0x2A, 0xD2, 0x0A, 0x32, 0x05,
    0x88, 0xDA, 0x7D, 0xB8, 0xAD, 0x7A, 0xCE, 0x5F,
    0x49, 0x1F, 0xBD, 0xF3, 0x98, 0xDE, 0x44, 0x05,
    0x38, 0xD0, 0x2C, 0x12, 0x83, 0x09, 0x7A, 0xF8,
    0xE8, 0x5F, 0xA7, 0x33, 0xA3, 0xE3, 0xE9, 0x35,
    0x11, 0x22, 0x48, 0x09, 0xA2, 0x95, 0x6C, 0x9B,
    0x97, 0xA9, 0xE9, 0xBF, 0xA8, 0x63, 0x73, 0x88,
    0x24, 0xB0, 0x84, 0x46, 0xA8, 0x90};
#endif /* T_COSE_DISABLE_ES512 */


int_fast32_t known_good_test(void)
{
    int32_t                        return_value;
    enum t_cose_err_t              result;
    struct t_cose_key              key_pair;
    struct q_useful_buf_c          payload;
    struct t_cose_sign1_verify_ctx verify_ctx;
    struct q_useful_buf_c          valid_message;

    /* Improvement: rewrite this to fetch the algorithm header and
     * look up the key from it, so the generalizes to all sorts of
     * good known inputs for all sorts of algorithms. (Could do key id
     * too...) But for now this accomplishes what is needed.
     */

    result = make_ecdsa_key_pair(T_COSE_ALGORITHM_ES256, &key_pair);
    if(result) {
        return_value = 1000 + (int32_t)result;
        goto Done;
    }

    t_cose_sign1_verify_init(&verify_ctx, 0);

    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    valid_message = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(signed_cose_made_by_ossl_crypto_256);
    result = t_cose_sign1_verify(&verify_ctx,
                                  valid_message, /* COSE to verify */
                                 &payload,       /* Payload from signed_cose */
                                  NULL);         /* Don't return parameters */
     if(result) {
         return_value = 5000 + (int32_t)result;
         goto Done;
     }

    free_ecdsa_key_pair(key_pair);

#ifndef T_COSE_DISABLE_ES384
    result = make_ecdsa_key_pair(T_COSE_ALGORITHM_ES384, &key_pair);
    if(result) {
        return_value = 1100 + (int32_t)result;
        goto Done;
    }

    t_cose_sign1_verify_init(&verify_ctx, 0);

    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    valid_message = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(signed_cose_made_by_psa_crypto_384);

    result = t_cose_sign1_verify(&verify_ctx,
                                 valid_message, /* COSE to verify */
                                &payload,       /* Payload from signed_cose */
                                 NULL);         /* Don't return parameters */
    if(result) {
        return_value = 5100 + (int32_t)result;
        goto Done;
    }

    free_ecdsa_key_pair(key_pair);
#endif /* T_COSE_DISABLE_ES384 */


#ifndef T_COSE_DISABLE_ES512
    result = make_ecdsa_key_pair(T_COSE_ALGORITHM_ES512, &key_pair);
    if(result) {
        return_value = 1200 + (int32_t)result;
        goto Done;
    }

    t_cose_sign1_verify_init(&verify_ctx, 0);

    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    valid_message = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(signed_cose_made_by_openssl_crypto_521);

    result = t_cose_sign1_verify(&verify_ctx,
                                 valid_message, /* COSE to verify */
                                &payload,       /* Payload from signed_cose */
                                 NULL);         /* Don't return parameters */
    if(result) {
        return_value = 5200 + (int32_t)result;
        goto Done;
    }

    free_ecdsa_key_pair(key_pair);
#endif /* T_COSE_DISABLE_ES512 */

    /* Can't make signed messages and compare them to a known good
     * value because ECDSA signature have a random component. They are
     * never the same. There are other tests here that evaluate the
     * structure of the signed messages and there tests that verify
     * messages made by the signing function. */

    return_value = 0;

Done:
    return return_value;
}
