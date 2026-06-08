/*
 *  t_cose_sign_verify_test.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include <stdlib.h>
#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose_make_test_pub_key.h"
#include "t_cose_sign_verify_test.h"

#include "t_cose_crypto.h" /* Just for t_cose_crypto_sig_size() */

/* These are complete known-good COSE messages for a verification
 * test. The key used to verify them is made by make_key_pair().
 * It always makes the same key for both MbedTLS and OpenSSL.
 *
 * These were made by setting a break point in sign_verify_basic_test()
 * and copying the output of the signing.
 */
static const uint8_t signed_cose_made_by_ossl_crypto_es256[] = {
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

static const uint8_t signed_cose_made_by_psa_crypto_es384[] = {
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

static const uint8_t signed_cose_made_by_ossl_crypto_es512[] = {
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

static const uint8_t signed_cose_made_by_psa_crypto_ps256[] = {
    0xd2, 0x84, 0x44, 0xa1, 0x01, 0x38, 0x24, 0xa0,
    0x47, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
    0x59, 0x01, 0x00, 0x41, 0x9a, 0x28, 0xe2, 0xe4,
    0x9a, 0x56, 0x90, 0xc1, 0x8c, 0xcd, 0x31, 0xd7,
    0x9c, 0x17, 0x42, 0x30, 0xfe, 0xcc, 0x33, 0x41,
    0xd7, 0xcc, 0x6a, 0x16, 0x53, 0x38, 0xd0, 0x15,
    0x31, 0x7c, 0x5c, 0x84, 0x40, 0xc7, 0xcd, 0x8e,
    0xdf, 0xc9, 0x28, 0x1c, 0xd4, 0xb0, 0xa9, 0x0f,
    0x44, 0x17, 0x50, 0x7e, 0x0e, 0xc8, 0xc5, 0xdf,
    0x6a, 0xc4, 0xbf, 0x5a, 0xdf, 0x0e, 0x0f, 0x91,
    0xfe, 0x12, 0x8d, 0x0e, 0x5b, 0x29, 0xf1, 0xc5,
    0xde, 0xbc, 0x6e, 0x61, 0xc7, 0x43, 0x64, 0x1b,
    0x0c, 0x5e, 0x9d, 0x72, 0xf6, 0x93, 0x71, 0x4c,
    0x4d, 0x67, 0xa1, 0x1c, 0xd7, 0x98, 0x5a, 0x59,
    0x1d, 0x98, 0x12, 0x63, 0x88, 0x40, 0x00, 0x9e,
    0x04, 0x9d, 0x77, 0x83, 0x39, 0xa5, 0x69, 0x83,
    0x88, 0x53, 0x38, 0xc9, 0x87, 0x04, 0xcf, 0x5a,
    0x8f, 0x77, 0x6d, 0xda, 0x14, 0x6a, 0x65, 0x2f,
    0xc3, 0xd9, 0xd7, 0x52, 0x18, 0x3f, 0x04, 0x4c,
    0x0d, 0x09, 0xf5, 0x15, 0x31, 0x7c, 0xc7, 0x95,
    0x91, 0xb2, 0x74, 0x3d, 0x31, 0xbc, 0x6a, 0x9b,
    0x49, 0x56, 0xe7, 0xe1, 0xca, 0xb1, 0xb2, 0x36,
    0x08, 0x02, 0x5d, 0xc0, 0xb7, 0xb1, 0x1e, 0x2c,
    0x5c, 0x6f, 0x74, 0x4c, 0x2f, 0x4f, 0x8a, 0xb9,
    0x9e, 0xb4, 0x36, 0xfe, 0xf4, 0xb9, 0xd2, 0x36,
    0x6a, 0xa9, 0x76, 0xdd, 0xcd, 0x37, 0x80, 0x40,
    0x02, 0x76, 0xe6, 0x61, 0xfb, 0x32, 0xa8, 0xf1,
    0x7c, 0x47, 0x7d, 0x69, 0xc1, 0x7b, 0xa3, 0x68,
    0x3c, 0xa1, 0x2c, 0x7c, 0x5c, 0x3d, 0x87, 0x15,
    0x0a, 0xee, 0xc1, 0x2a, 0x8c, 0x67, 0xb9, 0xd2,
    0x03, 0xec, 0x46, 0xc9, 0xef, 0xe1, 0xe4, 0x82,
    0x75, 0x4a, 0xf2, 0x57, 0xde, 0xac, 0x34, 0xfe,
    0x2c, 0x9d, 0xb6, 0x58, 0x5f, 0xfe, 0x67, 0x3e,
    0xb5, 0x37, 0xe2, 0xbe, 0x5d, 0x38, 0xa8, 0x64,
    0x03, 0xc0, 0xb3
};

static const uint8_t signed_cose_made_by_psa_crypto_ps384[] = {
    0xd2, 0x84, 0x44, 0xa1, 0x01, 0x38, 0x25, 0xa0,
    0x47, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
    0x59, 0x01, 0x00, 0x5e, 0xa1, 0x14, 0xd9, 0xb9,
    0xb1, 0x6a, 0x0c, 0x17, 0x93, 0xe8, 0x94, 0x88,
    0x5e, 0x5a, 0x12, 0x30, 0x5d, 0x0b, 0x70, 0xbb,
    0xb0, 0x89, 0xad, 0x49, 0x86, 0x1e, 0xeb, 0x3e,
    0xed, 0xff, 0x07, 0x5b, 0xa9, 0x7e, 0x7e, 0xa3,
    0x2e, 0x6e, 0x1b, 0x7c, 0x9c, 0xe1, 0x22, 0xd3,
    0x5e, 0x7d, 0x0e, 0x1e, 0xfe, 0xc2, 0x03, 0x3f,
    0x03, 0xfc, 0x3a, 0xef, 0x59, 0x3f, 0xda, 0x86,
    0x46, 0xe0, 0xb0, 0xe6, 0x06, 0xa3, 0xf2, 0x48,
    0x90, 0x76, 0xff, 0x32, 0x2d, 0x44, 0xf4, 0x1c,
    0x18, 0x0e, 0x24, 0x6f, 0x8e, 0x55, 0x82, 0xf0,
    0xf5, 0x06, 0x6b, 0xab, 0xfe, 0x52, 0x81, 0x32,
    0x8a, 0xb1, 0xa2, 0xec, 0x1b, 0x07, 0x9e, 0xd6,
    0x19, 0x6b, 0x0a, 0x7e, 0x1d, 0x10, 0xad, 0xf2,
    0xb3, 0x3e, 0x3c, 0x0d, 0x23, 0x15, 0x4e, 0x2d,
    0x34, 0x59, 0x4d, 0x2d, 0x59, 0x76, 0x66, 0x40,
    0x17, 0x15, 0x84, 0x04, 0x3b, 0x37, 0x57, 0xac,
    0xab, 0x7f, 0xcc, 0x51, 0x99, 0x80, 0x31, 0x1a,
    0xd8, 0x1e, 0x63, 0x0b, 0x67, 0xd1, 0x21, 0xc3,
    0xbe, 0x33, 0x4d, 0xfd, 0x40, 0x7e, 0x04, 0x16,
    0xe8, 0x2c, 0x0b, 0xe8, 0x3c, 0x39, 0xcc, 0xcd,
    0x9a, 0x6a, 0xc6, 0x15, 0x1e, 0x49, 0xad, 0x54,
    0xee, 0x7d, 0x38, 0x47, 0x59, 0x17, 0xa5, 0xcc,
    0x03, 0x81, 0x63, 0x26, 0xd1, 0x7f, 0x4d, 0x38,
    0xf5, 0x00, 0xd5, 0x66, 0xd8, 0x53, 0x8a, 0x33,
    0x19, 0xb3, 0xcb, 0x8d, 0x65, 0x79, 0xb0, 0xe7,
    0xf4, 0xdd, 0x9a, 0x97, 0x7c, 0xb4, 0x13, 0x18,
    0x6d, 0xc6, 0x4c, 0xbc, 0xd3, 0xed, 0x8a, 0x6e,
    0x1b, 0xf0, 0x53, 0xc7, 0x71, 0x44, 0xc9, 0xf3,
    0xba, 0xaf, 0x20, 0xc5, 0x21, 0x98, 0xde, 0x71,
    0xc9, 0xa2, 0x49, 0xe4, 0xf5, 0x1d, 0x76, 0xea,
    0x6b, 0xc6, 0x74, 0xbe, 0xc6, 0xee, 0x65, 0x5d,
    0xfa, 0x81, 0x29
};

static const uint8_t signed_cose_made_by_psa_crypto_ps512[] = {
    0xd2, 0x84, 0x44, 0xa1, 0x01, 0x38, 0x26, 0xa0,
    0x47, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
    0x59, 0x01, 0x00, 0x12, 0x53, 0xfe, 0x15, 0xda,
    0xb3, 0x01, 0x84, 0x40, 0x7b, 0x8b, 0x11, 0x0d,
    0x34, 0x40, 0x13, 0x97, 0x51, 0xa3, 0xf6, 0x53,
    0x93, 0xee, 0x98, 0xe8, 0xb7, 0x7c, 0x4a, 0x33,
    0xba, 0x90, 0xc4, 0xd9, 0x03, 0x16, 0x32, 0x55,
    0xfb, 0x64, 0x56, 0x9a, 0x65, 0x3c, 0x98, 0x8d,
    0xc4, 0xe4, 0x99, 0x79, 0xf3, 0x09, 0x88, 0x22,
    0x3e, 0x12, 0x38, 0xd0, 0xe0, 0xf2, 0xac, 0xf4,
    0x07, 0x66, 0xd4, 0x99, 0x38, 0x2c, 0x7a, 0x62,
    0x0c, 0x55, 0xbd, 0x57, 0x65, 0x5f, 0x3b, 0xe4,
    0x6a, 0xfd, 0x7c, 0x62, 0xe1, 0x7a, 0xbf, 0xe9,
    0x28, 0x9e, 0xd4, 0x03, 0x13, 0x54, 0xf4, 0x34,
    0x30, 0xe9, 0x1e, 0xec, 0xcb, 0x55, 0x23, 0xb3,
    0x2e, 0x0c, 0x1e, 0x41, 0x08, 0x04, 0x1a, 0x51,
    0x91, 0x72, 0x15, 0x78, 0x0d, 0x3c, 0x64, 0xaa,
    0x0b, 0xdc, 0x8d, 0x29, 0xc1, 0x6e, 0x89, 0x58,
    0x74, 0x2a, 0x3e, 0xf6, 0xb3, 0xab, 0x61, 0xa1,
    0x0b, 0xe9, 0x03, 0x44, 0xce, 0xb3, 0x27, 0x1c,
    0x25, 0x21, 0x59, 0x9a, 0x7b, 0x6a, 0x61, 0x1f,
    0xee, 0x3b, 0x21, 0x3b, 0x2c, 0xd9, 0x40, 0x17,
    0x5d, 0x1f, 0xee, 0x62, 0x21, 0xf4, 0x67, 0x7f,
    0xd6, 0x58, 0x2a, 0xaa, 0x75, 0xf1, 0x00, 0x26,
    0xb6, 0x04, 0x6c, 0x4d, 0xd0, 0x5a, 0x53, 0x97,
    0xc9, 0xa0, 0xb6, 0x8b, 0xf3, 0xe3, 0x2f, 0xe3,
    0x01, 0x30, 0x87, 0x89, 0xda, 0x9e, 0x4c, 0xb9,
    0x98, 0xd0, 0x0c, 0xc2, 0x92, 0x90, 0xbb, 0xb1,
    0x40, 0xe2, 0xd8, 0xd2, 0x23, 0x8b, 0x92, 0xd7,
    0x55, 0x81, 0x4a, 0xeb, 0xed, 0x08, 0xe9, 0x43,
    0xe8, 0x33, 0xa1, 0x47, 0x3c, 0x2b, 0xc1, 0xd0,
    0x69, 0x9a, 0xf9, 0x97, 0x9f, 0x2f, 0xf1, 0xab,
    0x6f, 0x6e, 0xd2, 0xb2, 0xea, 0x0b, 0xc9, 0x02,
    0xb7, 0x4d, 0x60, 0x1b, 0x3a, 0x10, 0x51, 0x20,
    0x12, 0x5c, 0x32
};

static const uint8_t signed_cose_made_by_pycose_eddsa[] = {
    0xd2, 0x84, 0x43, 0xa1, 0x01, 0x27, 0xa0, 0x47,
    0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x58,
    0x40, 0x17, 0x02, 0xb0, 0xf2, 0x3f, 0x47, 0xe8,
    0x9f, 0xab, 0x39, 0xcd, 0xd3, 0xd6, 0x5a, 0x57,
    0x76, 0x37, 0xb2, 0xbc, 0x8e, 0xd1, 0xe3, 0xa9,
    0xc1, 0x4d, 0xf3, 0xbf, 0x4a, 0x93, 0x4c, 0xe7,
    0xe2, 0xa8, 0xae, 0x46, 0xb5, 0x82, 0x48, 0x79,
    0xde, 0x7b, 0x81, 0xd0, 0x25, 0xbc, 0xf8, 0x32,
    0xab, 0x41, 0x00, 0xc5, 0xd9, 0x39, 0xc7, 0xf2,
    0x07, 0x27, 0x70, 0xf3, 0x76, 0xd2, 0x8d, 0xbe,
    0x00
};

struct test_case {
    int32_t cose_algorithm_id;
    struct q_useful_buf_c known_good_message;
};

/**
 * List of algorithms the tests cases run over.
 *
 * For each algorithm, a known valid message is associated.
 */
static struct test_case test_cases[] = {
    /* Annoyingly, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL doesn't work in a const-context */
    { T_COSE_ALGORITHM_ES256, { signed_cose_made_by_ossl_crypto_es256, sizeof(signed_cose_made_by_ossl_crypto_es256) } },
    { T_COSE_ALGORITHM_ES384, { signed_cose_made_by_psa_crypto_es384, sizeof(signed_cose_made_by_psa_crypto_es384) } },
    { T_COSE_ALGORITHM_ES512, { signed_cose_made_by_ossl_crypto_es512, sizeof(signed_cose_made_by_ossl_crypto_es512) } },
    { T_COSE_ALGORITHM_PS256, { signed_cose_made_by_psa_crypto_ps256, sizeof(signed_cose_made_by_psa_crypto_ps256) } },
    { T_COSE_ALGORITHM_PS384, { signed_cose_made_by_psa_crypto_ps384, sizeof(signed_cose_made_by_psa_crypto_ps384) } },
    { T_COSE_ALGORITHM_PS512, { signed_cose_made_by_psa_crypto_ps512, sizeof(signed_cose_made_by_psa_crypto_ps512) } },
    { T_COSE_ALGORITHM_EDDSA, { signed_cose_made_by_pycose_eddsa, sizeof(signed_cose_made_by_pycose_eddsa) } },
    { 0 }, /* Sentinel value with an invalid algorithm id */
};

static int_fast32_t sign_verify_basic_test_alg(int32_t cose_alg)
{
    struct t_cose_sign1_sign_ctx   sign_ctx;
    int32_t                        return_value;
    enum t_cose_err_t              result;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          signed_cose;
    struct t_cose_key              key_pair;
    struct q_useful_buf_c          payload;
    struct t_cose_sign1_verify_ctx verify_ctx;
    Q_USEFUL_BUF_MAKE_STACK_UB(    auxiliary_buffer, 100);

    /* Make a key pair that will be used for both signing and verification.
     */
    result = make_key_pair(cose_alg, &key_pair);
    if(result) {
        return 1000 + (int32_t)result;
    }

    /* -- Get started with context initialization, selecting the alg -- */
    t_cose_sign1_sign_init(&sign_ctx, 0, cose_alg);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);
    t_cose_sign1_sign_set_auxiliary_buffer(&sign_ctx, auxiliary_buffer);

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
    t_cose_sign1_verify_set_auxiliary_buffer(&verify_ctx, auxiliary_buffer);

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
    free_key_pair(key_pair);

    return return_value;
}


/*
 * Public function, see t_cose_sign_verify_test.h
 */
int_fast32_t sign_verify_basic_test()
{
    int_fast32_t return_value;
    const struct test_case* tc;
    for (tc = test_cases; tc->cose_algorithm_id != 0; tc++) {
        if (t_cose_is_algorithm_supported(tc->cose_algorithm_id)) {
            return_value = sign_verify_basic_test_alg(tc->cose_algorithm_id);
            if (return_value) {
                return (int32_t)(1 + tc - test_cases) * 10000 + return_value;
            }
        }
    }

    return 0;
}

/*
 * Public function, see t_cose_sign_verify_test.h
 */
int_fast32_t sig_fail_test(int32_t cose_alg)
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
    Q_USEFUL_BUF_MAKE_STACK_UB(    auxiliary_buffer, 100);
    size_t                         tamper_offset;


    /* Make a key pair that will be used for both signing and
     * verification.
     */
    result = make_key_pair(cose_alg, &key_pair);
    if(result) {
        return 1000 + (int32_t)result;
    }

    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_sign1_sign_init(&sign_ctx, 0, cose_alg);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);
    t_cose_sign1_sign_set_auxiliary_buffer(&sign_ctx, auxiliary_buffer);

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
    t_cose_sign1_verify_set_auxiliary_buffer(&verify_ctx, auxiliary_buffer);

    result = t_cose_sign1_verify(&verify_ctx,
                                 signed_cose,   /* COSE to verify */
                                &payload,       /* Payload from signed_cose */
                                 NULL);         /* Don't return parameters */

    if(result != T_COSE_ERR_SIG_VERIFY) {
        return_value = 5000 + (int32_t)result;
    }

    return_value = 0;

Done:
    free_key_pair(key_pair);

    return return_value;
}


/*
 * Public function, see t_cose_sign_verify_test.h
 */
int_fast32_t sign_verify_sig_fail_test()
{
    int_fast32_t return_value;
    const struct test_case* tc;
    for (tc = test_cases; tc->cose_algorithm_id != 0; tc++) {
        if (t_cose_is_algorithm_supported(tc->cose_algorithm_id)) {
            return_value = sig_fail_test(tc->cose_algorithm_id);
            if (return_value) {
                return (int32_t)(1 + tc - test_cases) * 10000 + return_value;
            }
        }
    }
    return 0;
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
    result = make_key_pair(T_COSE_ALGORITHM_ES256, &key_pair);
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
    free_key_pair(key_pair);

    return return_value;
}


static int_fast32_t size_test(int32_t               cose_algorithm_id,
                              struct q_useful_buf_c kid)
{
    struct t_cose_key              key_pair;
    struct t_cose_sign1_sign_ctx   sign_ctx;
    QCBOREncodeContext             cbor_encode;
    int32_t                        return_value;
    enum t_cose_err_t              result;
    struct q_useful_buf            nil_buf;
    size_t                         calculated_size;
    QCBORError                     cbor_error;
    struct q_useful_buf_c          actual_signed_cose;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    Q_USEFUL_BUF_MAKE_STACK_UB(    auxiliary_buffer, 100);
    struct q_useful_buf_c          payload;
    size_t                         sig_size;

    result = make_key_pair(cose_algorithm_id, &key_pair);
    if(result) {
        return 1000 + (int32_t)result;
    }

    /* ---- Common Set up ---- */
    payload = Q_USEFUL_BUF_FROM_SZ_LITERAL("payload");
    result = t_cose_crypto_sig_size(cose_algorithm_id, key_pair, &sig_size);
    if(result) {
        return_value = 2000 + (int32_t)result;
        goto Done;
    }

    /* ---- First calculate the size ----- */
    nil_buf = (struct q_useful_buf) {NULL, INT32_MAX};
    QCBOREncode_Init(&cbor_encode, nil_buf);

    t_cose_sign1_sign_init(&sign_ctx,  0,  cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, kid);

    result = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);
    if(result) {
        return_value = 3000 + (int32_t)result;
        goto Done;
    }

    QCBOREncode_AddEncoded(&cbor_encode, payload);

    result = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(result) {
        return_value = 4000 + (int32_t)result;
        goto Done;
    }

    cbor_error = QCBOREncode_FinishGetSize(&cbor_encode, &calculated_size);
    if(cbor_error) {
        return_value = 5000 + (int32_t)cbor_error;
        goto Done;
    }

    /* ---- General sanity check ---- */
    size_t expected_min = sig_size + payload.len + kid.len;

    if(calculated_size < expected_min || calculated_size > expected_min + 30) {
        return_value = -1;
        goto Done;
    }

    /**
     * Get the expected auxiliary buffer size. For anything but EDDSA, this should be zero.
     */
    size_t auxiliary_buffer_size = t_cose_sign1_sign_auxiliary_buffer_size(&sign_ctx);
    if (cose_algorithm_id == T_COSE_ALGORITHM_EDDSA) {
        /* TBS is a bit smaller, given it doesn't include the signature */
        expected_min = payload.len + kid.len;
        if(auxiliary_buffer_size < expected_min || auxiliary_buffer_size > expected_min + 30) {
            return_value = -2;
            goto Done;
        }
    } else if (auxiliary_buffer_size != 0) {
        return_value = -3;
        goto Done;
    }

    /* ---- Now make a real COSE_Sign1 and compare the size ---- */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_sign1_sign_init(&sign_ctx,  0,  cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, kid);
    if (auxiliary_buffer_size > 0) {
        t_cose_sign1_sign_set_auxiliary_buffer(&sign_ctx, auxiliary_buffer);
    }

    result = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);
    if(result) {
        return_value = 6000 + (int32_t)result;
        goto Done;
    }

    QCBOREncode_AddEncoded(&cbor_encode, payload);

    result = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(result) {
        return_value = 7000 + (int32_t)result;
        goto Done;
    }

    cbor_error = QCBOREncode_Finish(&cbor_encode, &actual_signed_cose);
    if(actual_signed_cose.len != calculated_size) {
        return_value = -4;
        goto Done;
    }

    /* ---- Again with one-call API to make COSE_Sign1 ---- */\
    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, kid);
    if (auxiliary_buffer_size > 0) {
        t_cose_sign1_sign_set_auxiliary_buffer(&sign_ctx, auxiliary_buffer);
    }
    result = t_cose_sign1_sign(&sign_ctx,
                                payload,
                                signed_cose_buffer,
                               &actual_signed_cose);
    if(result) {
        return_value = 8000 + (int32_t)result;
        goto Done;
    }

    if(actual_signed_cose.len != calculated_size) {
        return_value = -5;
        goto Done;
    }

    return_value = 0;

Done:
    free_key_pair(key_pair);

    return return_value;
}


/*
 * Public function, see t_cose_sign_verify_test.h
 */
int_fast32_t sign_verify_get_size_test()
{
    int_fast32_t return_value;
    const struct test_case* tc;
    for (tc = test_cases; tc->cose_algorithm_id != 0; tc++) {
        if (t_cose_is_algorithm_supported(tc->cose_algorithm_id)) {
            return_value = size_test(tc->cose_algorithm_id,
                                     NULL_Q_USEFUL_BUF_C);
            if (return_value) {
                return (int32_t)(1 + tc - test_cases) * 10000 + return_value;
            }

            return_value = size_test(tc->cose_algorithm_id,
                                     Q_USEFUL_BUF_FROM_SZ_LITERAL("greasy kid stuff"));
            if (return_value) {
                return (int32_t)(1 + tc - test_cases) * 10000 + return_value;
            }
        }
    }
    return 0;

}


static int_fast32_t known_good_test(int cose_algorithm_id, struct q_useful_buf_c signed_message)
{
    int32_t                        return_value;
    enum t_cose_err_t              result;
    struct t_cose_sign1_verify_ctx verify_ctx;
    struct t_cose_key              key_pair;
    struct q_useful_buf_c          payload;
    struct t_cose_parameters       parameters;
    Q_USEFUL_BUF_MAKE_STACK_UB(    auxiliary_buffer, 100);

    /**
     * Decode the signed message once without a key, to extract
     * the algorithm ID.
     *
     * We don't strictly need this step, since the algorithm
     * is passed as an argument, but it is a nice sanity check.
     */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_DECODE_ONLY);
    result = t_cose_sign1_verify(&verify_ctx,
                                 signed_message,
                                 &payload,
                                 &parameters);
    if(result) {
        return_value = 1000 + (int32_t)result;
        goto Done2;
    }

    if (parameters.cose_algorithm_id != cose_algorithm_id) {
        return_value = 2000 + (int32_t)result;
        goto Done2;
    }

    result = make_key_pair(cose_algorithm_id, &key_pair);
    if(result) {
        return_value = 3000 + (int32_t)result;
        goto Done2;
    }

    /**
     * Some sanity check for the size of the auxiliary buffer.
     * With EDDSA, it is roughly the size of the payload plus a dozen bytes.
     * Otherwise it should be zero.
     */
    size_t auxiliary_buffer_size = t_cose_sign1_verify_auxiliary_buffer_size(&verify_ctx);
    if (cose_algorithm_id == T_COSE_ALGORITHM_EDDSA) {
        size_t expected_min = payload.len;
        if(auxiliary_buffer_size < expected_min || auxiliary_buffer_size > expected_min + 30) {
            return_value = -1;
            goto Done;
        }
    } else if (auxiliary_buffer_size != 0) {
        return_value = -2;
        goto Done;
    }

    t_cose_sign1_verify_init(&verify_ctx, 0);
    t_cose_sign1_verify_set_auxiliary_buffer(&verify_ctx, auxiliary_buffer);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);
    result = t_cose_sign1_verify(&verify_ctx,
                                 signed_message,
                                 &payload,
                                 &parameters);
    if(result) {
        return_value = 4000 + (int32_t)result;
        goto Done;
    }

    if(q_useful_buf_compare(payload, Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"))) {
        return_value = 5000;
        goto Done;
    }

    return_value = 0;

Done:
    free_key_pair(key_pair);

Done2:
    return return_value;
}

int_fast32_t sign_verify_known_good_test(void)
{
    int_fast32_t return_value = 0;
    const struct test_case* tc;
    for (tc = test_cases; tc->cose_algorithm_id != 0; tc++) {
        if (t_cose_is_algorithm_supported(tc->cose_algorithm_id)) {
            return_value = known_good_test(tc->cose_algorithm_id,
                                           tc->known_good_message);
            if (return_value) {
                return (int32_t)(1 + tc - test_cases) * 10000 + return_value;
            }
        }
    }

    /* Can't make signed messages and compare them to a known good
     * value because signatures have a random component. They are
     * never the same. There are other tests here that evaluate the
     * structure of the signed messages and there tests that verify
     * messages made by the signing function. */

    return return_value;
}

/**
 * Try to sign and verify against an algorithm that is
 * not supported by the current t_cose configuration
 * and crypto adapter.
 */
static int_fast32_t
sign_verify_unsupported_test_alg(int32_t cose_alg,
                                 struct q_useful_buf_c signed_message)
{
    struct t_cose_key              key_pair;
    int32_t                        return_value;
    enum t_cose_err_t              result;
    struct t_cose_sign1_sign_ctx   sign_ctx;
    struct t_cose_sign1_verify_ctx verify_ctx;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          signed_cose;
    Q_USEFUL_BUF_MAKE_STACK_UB(    auxiliary_buffer, 100);

    result = make_key_pair(T_COSE_ALGORITHM_ES256, &key_pair);
    if(result) {
        return 1000 + (int32_t)result;
    }

    t_cose_sign1_sign_init(&sign_ctx, 0, cose_alg);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);
    t_cose_sign1_sign_set_auxiliary_buffer(&sign_ctx, auxiliary_buffer);

    result = t_cose_sign1_sign(&sign_ctx,
                               Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"),
                               signed_cose_buffer,
                               &signed_cose);

    t_cose_sign1_verify_init(&verify_ctx, 0);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);
    t_cose_sign1_verify_set_auxiliary_buffer(&verify_ctx, auxiliary_buffer);
    result = t_cose_sign1_verify(&verify_ctx, signed_message, NULL, NULL);
    if (result != T_COSE_ERR_UNSUPPORTED_SIGNING_ALG) {
        return_value = 2000 + (int32_t)result;
        goto Done;
    }

    return_value = 0;

Done:
    free_key_pair(key_pair);
    return return_value;
}

int_fast32_t sign_verify_unsupported_test(void)
{
    int_fast32_t return_value;
    const struct test_case* tc;
    for (tc = test_cases; tc->cose_algorithm_id != 0; tc++) {
        /* Unlike other tests, this one runs only on unsupported algorithms.
         * Depending on the configuration and crypto adapter, this could mean never.
         */
        if (!t_cose_is_algorithm_supported(tc->cose_algorithm_id)) {
            return_value = sign_verify_unsupported_test_alg(tc->cose_algorithm_id,
                                                            tc->known_good_message);
            if (return_value) {
                return (int32_t)(1 + tc - test_cases) * 10000 + return_value;
            }
        }
    }
    return 0;
}

/*
 * Public function, see t_cose_sign_verify_test.h
 */
int_fast32_t sign_verify_bad_auxiliary_buffer(void)
{
    enum t_cose_err_t              result;
    int32_t                        return_value;
    struct t_cose_key              key_pair;
    const struct q_useful_buf_c    known_good_message = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(signed_cose_made_by_pycose_eddsa);
    struct t_cose_sign1_sign_ctx   sign_ctx;
    struct t_cose_sign1_verify_ctx verify_ctx;
    Q_USEFUL_BUF_MAKE_STACK_UB(    small_auxiliary_buffer, 5);
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          signed_cose;

    /* Only EDDSA uses the auxiliary buffer, so this test is
     * meaning less if we don't support it.
     */
    if (!t_cose_is_algorithm_supported(T_COSE_ALGORITHM_EDDSA)) {
        return 0;
    }

    result = make_key_pair(T_COSE_ALGORITHM_EDDSA, &key_pair);
    if(result) {
        return 1000 + (int32_t)result;
    }

    /* Try to verify the message without setting up an auxiliary buffer.
     * This should fail with T_COSE_ERR_NEED_AUXILIARY_BUFFER.
     */
    t_cose_sign1_verify_init(&verify_ctx, 0);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);
    result = t_cose_sign1_verify(&verify_ctx, known_good_message, NULL, NULL);
    if (result != T_COSE_ERR_NEED_AUXILIARY_BUFFER) {
        return_value = 2000 + (int32_t)result;
        goto Done;
    }

    /* Do the same again, but this time use an auxiliary buffer that is
     * obviously too small.
     * This time it should fail with T_COSE_ERR_AUXILIARY_BUFFER_SIZE.
     */
    t_cose_sign1_verify_init(&verify_ctx, 0);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);
    t_cose_sign1_verify_set_auxiliary_buffer(&verify_ctx, small_auxiliary_buffer);
    result = t_cose_sign1_verify(&verify_ctx, known_good_message, NULL, NULL);
    if (result != T_COSE_ERR_AUXILIARY_BUFFER_SIZE) {
        return_value = 3000 + (int32_t)result;
        goto Done;
    }

    /* Now we try something similar, but with signing instead. */
    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_EDDSA);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);
    result = t_cose_sign1_sign(&sign_ctx,
                      Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"),
                      signed_cose_buffer,
                      &signed_cose);
    if (result != T_COSE_ERR_NEED_AUXILIARY_BUFFER) {
        return_value = 4000 + (int32_t)result;
        goto Done;
    }

    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_EDDSA);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);
    t_cose_sign1_sign_set_auxiliary_buffer(&sign_ctx, small_auxiliary_buffer);
    result = t_cose_sign1_sign(&sign_ctx,
                      Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"),
                      signed_cose_buffer,
                      &signed_cose);
    if (result != T_COSE_ERR_AUXILIARY_BUFFER_SIZE) {
        return_value = 5000 + (int32_t)result;
        goto Done;
    }

    return_value = 0;

Done:
    free_key_pair(key_pair);

    return return_value;
}
