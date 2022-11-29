/*
 *  t_cose_rsa_test_key.h
 *
 * Copyright 2019-2022, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


/**
 * An RSA private key in PKCS #1 (RFC 8017) format.
 *
 * This was generated by:
 * 
 *   openssl genrsa 2048 | sed -e '1d' -e '$d' | base64 --decode  | xxd -i
 *
 * This file is used whether mbedtls or OpenSSL is used.
 *
 * On its own, the file is not itself valid C, and must be wrapped in a variable
 * definition before being included.
 */
0x30, 0x82, 0x04, 0xa3, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
0x9e, 0x4e, 0x3b, 0x05, 0xb4, 0x33, 0xe5, 0x49, 0x68, 0xdc, 0x64, 0xa0,
0x4e, 0x2c, 0x63, 0xd8, 0x11, 0x25, 0x7c, 0xe0, 0x63, 0xb6, 0x64, 0x89,
0x0b, 0xbd, 0xcd, 0x62, 0x30, 0xd4, 0x52, 0xa2, 0x52, 0xe0, 0x61, 0x84,
0xee, 0xf9, 0x6e, 0x14, 0x9f, 0x9e, 0x0e, 0xee, 0x67, 0x51, 0x09, 0xa9,
0x15, 0x05, 0x07, 0x17, 0x09, 0x93, 0x76, 0x87, 0x45, 0x2b, 0x89, 0xfd,
0x7c, 0xa7, 0xfa, 0xfc, 0x1b, 0x7b, 0x6e, 0xbb, 0x5f, 0xfc, 0x8a, 0xca,
0xc9, 0x14, 0xb4, 0xd0, 0xe8, 0x91, 0xb1, 0x60, 0xe8, 0x89, 0x54, 0xe0,
0x06, 0x0b, 0x59, 0xff, 0x90, 0x12, 0x34, 0x47, 0xd7, 0xbf, 0x82, 0xa8,
0x48, 0x77, 0x46, 0x56, 0x2c, 0xfb, 0x84, 0x00, 0x01, 0xdb, 0x6b, 0x14,
0xe2, 0x5a, 0xc7, 0x77, 0x3c, 0x8e, 0x48, 0x59, 0x21, 0xc6, 0x7a, 0x28,
0x17, 0x3f, 0xfa, 0xe1, 0xea, 0xc4, 0x6f, 0xa0, 0x0d, 0xf0, 0x04, 0x5a,
0x29, 0x97, 0x2e, 0x96, 0x35, 0x25, 0xba, 0x0a, 0x39, 0x51, 0x9e, 0x1d,
0x64, 0x95, 0xad, 0xc8, 0xc1, 0xa6, 0xfd, 0x61, 0xa1, 0x56, 0x40, 0x96,
0x85, 0x42, 0x83, 0x1e, 0x8f, 0xc8, 0xfa, 0x70, 0x2b, 0xea, 0xbd, 0xe6,
0x2d, 0x6f, 0x6a, 0x73, 0x00, 0x2a, 0x8f, 0x8e, 0x2c, 0x28, 0xdb, 0xc0,
0xa0, 0x23, 0x37, 0x6f, 0x67, 0xe3, 0x3d, 0x8f, 0xe6, 0x12, 0xbe, 0x8c,
0xdf, 0x67, 0xfb, 0xbf, 0xe2, 0x80, 0xd0, 0xdf, 0xe0, 0xf9, 0x68, 0xeb,
0x7f, 0x37, 0x4f, 0x17, 0xb8, 0x1e, 0x06, 0x46, 0x1a, 0x47, 0x6b, 0xd3,
0x40, 0x2c, 0x9a, 0xd1, 0xc5, 0x5c, 0xd2, 0x59, 0xad, 0x78, 0x82, 0x1b,
0x07, 0x49, 0x0e, 0x70, 0xa4, 0x69, 0x0c, 0xac, 0xf4, 0x78, 0x2e, 0x2d,
0x3e, 0x94, 0xc2, 0x3b, 0x80, 0xbc, 0x88, 0x91, 0xc9, 0xfe, 0x06, 0x1c,
0x19, 0xe3, 0x22, 0xbf, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,
0x00, 0x57, 0x8b, 0x07, 0x94, 0xc5, 0xec, 0x94, 0xf5, 0x9d, 0xa9, 0x93,
0x74, 0x1b, 0x06, 0xed, 0x48, 0x05, 0x63, 0x67, 0xc5, 0x67, 0x1e, 0xec,
0x45, 0xe5, 0x5a, 0x57, 0x03, 0xdf, 0xe0, 0xea, 0xb9, 0x9d, 0x7f, 0x3c,
0x2e, 0x99, 0x41, 0x12, 0xa1, 0x11, 0x0c, 0x05, 0x51, 0xcd, 0x8c, 0xc0,
0xfc, 0xe2, 0x04, 0xdf, 0xc0, 0xdb, 0xa8, 0xd2, 0xb9, 0x47, 0x85, 0x26,
0x50, 0x29, 0xe9, 0x73, 0x20, 0x8b, 0xca, 0x1c, 0x98, 0x3e, 0x22, 0x98,
0x56, 0x40, 0x10, 0xd5, 0x55, 0x59, 0xe7, 0x87, 0xe2, 0x01, 0x76, 0x40,
0x9b, 0x8a, 0x7c, 0x28, 0x8e, 0xed, 0x8b, 0x43, 0xa2, 0x1f, 0x2b, 0x67,
0x03, 0xcc, 0xdf, 0x38, 0xe4, 0x5b, 0x07, 0xd4, 0x1d, 0x74, 0xe9, 0x74,
0x34, 0x1e, 0x60, 0xf9, 0x41, 0x75, 0x19, 0x71, 0xe4, 0xe8, 0x8a, 0xab,
0xef, 0x13, 0xbc, 0x6b, 0xef, 0x17, 0x36, 0xfe, 0x4a, 0xf3, 0xe6, 0x17,
0x45, 0xd5, 0xfd, 0x7b, 0x82, 0xc6, 0x35, 0x72, 0x77, 0x91, 0x3d, 0x05,
0xd4, 0x00, 0xa3, 0x0d, 0xd5, 0x9a, 0x4e, 0x6b, 0xf4, 0x6f, 0xd5, 0xe9,
0x31, 0x58, 0x3e, 0x01, 0xfc, 0x7e, 0x7a, 0x80, 0x8f, 0x1e, 0x78, 0xbc,
0x31, 0x23, 0x03, 0x6a, 0x30, 0x31, 0x4e, 0xbb, 0x0e, 0x8f, 0xed, 0x26,
0x8d, 0x2d, 0x29, 0xc9, 0x83, 0xb8, 0x57, 0x39, 0x90, 0xd0, 0x43, 0x51,
0xb6, 0xf8, 0x5c, 0x20, 0xbe, 0x8e, 0x5d, 0xed, 0xde, 0x82, 0xe7, 0x0a,
0xf2, 0x7f, 0x76, 0x8c, 0x9d, 0x8a, 0x76, 0xa5, 0xb3, 0x63, 0x59, 0x4a,
0xcb, 0x90, 0x2b, 0x5f, 0xa4, 0xb9, 0x63, 0x10, 0x12, 0xaa, 0xa8, 0x87,
0xed, 0x60, 0x06, 0x2d, 0x1f, 0x0f, 0xad, 0x19, 0xde, 0xd0, 0xff, 0x6f,
0x2c, 0xc2, 0x4c, 0x9e, 0x1f, 0x89, 0xc8, 0x18, 0xa0, 0x42, 0xad, 0xa0,
0xa0, 0x37, 0x17, 0x68, 0x01, 0x02, 0x81, 0x81, 0x00, 0xcf, 0xcd, 0x4a,
0x0e, 0xcb, 0xe9, 0x19, 0x57, 0x2d, 0x42, 0x8a, 0xbf, 0xf9, 0x9b, 0xbc,
0xe1, 0x45, 0x87, 0x1c, 0xbe, 0xc4, 0x64, 0x9b, 0xbb, 0x40, 0x0c, 0xc5,
0x34, 0xbe, 0xbf, 0xcf, 0x6c, 0xc1, 0x4c, 0x5d, 0x72, 0x6b, 0x3f, 0xdf,
0x0c, 0x81, 0x7b, 0x2c, 0x30, 0xbf, 0x93, 0x49, 0x99, 0x28, 0xb1, 0x88,
0xf9, 0x76, 0x13, 0x6d, 0xe3, 0x1a, 0x85, 0xcf, 0x34, 0x77, 0x72, 0x76,
0x70, 0xe9, 0xe5, 0x5e, 0xc6, 0x1d, 0x7f, 0xec, 0x11, 0x6e, 0xf8, 0x50,
0x9d, 0xb3, 0x04, 0xd9, 0x0c, 0xc3, 0xf5, 0x40, 0x98, 0x8c, 0x77, 0x96,
0x89, 0x69, 0x10, 0xb3, 0xa8, 0x43, 0x99, 0x95, 0xc8, 0x6c, 0x21, 0x16,
0x36, 0x33, 0xf8, 0x6c, 0x4b, 0x99, 0x24, 0x64, 0x93, 0xbb, 0xbf, 0xa5,
0x3f, 0xed, 0xd4, 0x66, 0x9c, 0x3e, 0xd6, 0xf9, 0x62, 0x43, 0x41, 0xe5,
0xaf, 0xfe, 0x8e, 0x98, 0xbf, 0x02, 0x81, 0x81, 0x00, 0xc3, 0x05, 0xfc,
0x0e, 0xaa, 0x94, 0x58, 0xbe, 0x92, 0xdb, 0x0e, 0x89, 0x30, 0x18, 0x7e,
0xa2, 0x2c, 0x5f, 0x16, 0xad, 0x9f, 0xd2, 0x4b, 0x40, 0x8d, 0x60, 0x30,
0xfa, 0x9b, 0xaa, 0xcb, 0x20, 0xcd, 0x18, 0x63, 0x1d, 0x51, 0xda, 0xb3,
0x61, 0xb1, 0xcc, 0x82, 0x45, 0x2a, 0x84, 0x82, 0x7b, 0xb5, 0xc1, 0x0c,
0xd4, 0xe5, 0xe4, 0x0f, 0x03, 0xe7, 0x92, 0x48, 0x24, 0x85, 0x4c, 0xa6,
0x02, 0xd3, 0x7b, 0xe8, 0xb8, 0x9e, 0xf4, 0x92, 0xb9, 0x55, 0x71, 0x2e,
0x80, 0x45, 0x7c, 0x80, 0x62, 0x20, 0x1b, 0x9a, 0xbb, 0x18, 0x36, 0x36,
0x5d, 0x69, 0xf0, 0xea, 0x41, 0x5c, 0x4c, 0x75, 0x5c, 0x62, 0xc9, 0x4f,
0xae, 0xb0, 0xad, 0x98, 0xc5, 0x03, 0xf2, 0xf9, 0xde, 0x1f, 0x01, 0xe9,
0x1e, 0x3d, 0xe8, 0xf8, 0x84, 0xaf, 0x49, 0x61, 0x2f, 0x4e, 0x20, 0xb4,
0x18, 0x79, 0xb3, 0xf6, 0x01, 0x02, 0x81, 0x80, 0x72, 0xe2, 0x03, 0xf7,
0x7a, 0x34, 0x3c, 0x96, 0x3d, 0xa7, 0x74, 0x1d, 0xfe, 0x59, 0x63, 0x6b,
0x07, 0x8d, 0x53, 0x0f, 0x04, 0x74, 0xba, 0xc4, 0x22, 0xfc, 0xec, 0x69,
0xe4, 0xab, 0x16, 0x7a, 0x01, 0xc3, 0xbe, 0x45, 0xeb, 0x95, 0x3c, 0x33,
0x25, 0xc2, 0x7b, 0x03, 0xd8, 0x66, 0x0d, 0x62, 0x67, 0x64, 0xff, 0x5d,
0x2b, 0x32, 0x42, 0xa6, 0x33, 0x9b, 0x96, 0x9a, 0x63, 0x0f, 0x1c, 0xfb,
0xff, 0xd3, 0x97, 0x39, 0xe0, 0x45, 0x40, 0xb5, 0xc2, 0xab, 0xf5, 0xa5,
0xb9, 0xbb, 0x0c, 0x64, 0x4a, 0x51, 0xe4, 0x8c, 0x71, 0xdc, 0x0b, 0x95,
0x9c, 0x48, 0x67, 0x8a, 0xb7, 0x14, 0xca, 0x02, 0x2c, 0x05, 0x7e, 0xca,
0x28, 0xa1, 0x46, 0xfd, 0xe4, 0x84, 0x82, 0x36, 0x4a, 0xae, 0x01, 0x25,
0xfe, 0xce, 0x56, 0x8c, 0x3b, 0x11, 0x8e, 0x7e, 0x0c, 0xc0, 0xf9, 0xc2,
0xfa, 0xf0, 0xca, 0xf1, 0x02, 0x81, 0x80, 0x61, 0x53, 0x61, 0x40, 0xe8,
0x7b, 0xf3, 0xf5, 0xd7, 0x50, 0x1e, 0xe6, 0xf3, 0xeb, 0xa5, 0x76, 0xc5,
0x72, 0x06, 0xdd, 0x4a, 0xff, 0x25, 0xb2, 0xe7, 0x5a, 0xf3, 0xd6, 0x7d,
0x4d, 0x34, 0xe5, 0xff, 0xb4, 0x85, 0xf2, 0x21, 0xe1, 0x64, 0xd8, 0x02,
0x65, 0x2f, 0x35, 0xd9, 0x4c, 0x1b, 0xda, 0x25, 0x10, 0x5c, 0x98, 0xfa,
0xc9, 0x5f, 0x7c, 0xf1, 0x5a, 0x1d, 0x4a, 0xac, 0x83, 0x5d, 0xed, 0xd7,
0x20, 0xe5, 0x39, 0x0d, 0x8a, 0xbc, 0x96, 0x65, 0x3f, 0x80, 0x97, 0x5f,
0x16, 0x0c, 0xf3, 0xeb, 0x56, 0x1b, 0x57, 0xf7, 0x73, 0x46, 0x9a, 0x43,
0xbe, 0x89, 0x09, 0x69, 0x48, 0x76, 0xe1, 0x4e, 0x23, 0x6c, 0xf2, 0x9f,
0x15, 0x63, 0x42, 0x1f, 0x00, 0x69, 0x16, 0x22, 0x9f, 0x4f, 0x79, 0x5a,
0x28, 0x23, 0xae, 0x03, 0xd4, 0x38, 0xfd, 0xe4, 0x9d, 0x89, 0x83, 0x15,
0x69, 0x6c, 0x01, 0x02, 0x81, 0x81, 0x00, 0xc3, 0x8d, 0xfa, 0x78, 0xed,
0xb8, 0x99, 0xd3, 0xee, 0xd0, 0xbd, 0x74, 0xf3, 0x6e, 0xd1, 0xb4, 0x37,
0xc0, 0x89, 0x6c, 0xf0, 0x69, 0xbc, 0xbe, 0x5c, 0xd4, 0x6a, 0xa5, 0xba,
0x39, 0x3e, 0x68, 0x87, 0xeb, 0x35, 0x6d, 0x24, 0x3c, 0x3f, 0x11, 0xcd,
0x31, 0x60, 0x8b, 0xb6, 0x7f, 0x6c, 0x42, 0xe3, 0x8d, 0xc3, 0x90, 0x79,
0x9a, 0xba, 0x1c, 0xac, 0x72, 0x5d, 0x05, 0x8a, 0x50, 0x87, 0x34, 0x67,
0xba, 0x19, 0x2c, 0xd6, 0x9b, 0x3f, 0xd7, 0x32, 0x4f, 0x60, 0x9e, 0x19,
0x00, 0x1e, 0x29, 0xfd, 0x8f, 0xcd, 0xec, 0x75, 0xcd, 0x42, 0xcc, 0x5f,
0xad, 0x42, 0xa3, 0xf6, 0xc5, 0x5a, 0x14, 0xaa, 0x9f, 0x75, 0xe6, 0x13,
0x96, 0xdf, 0x73, 0xcd, 0xd8, 0x8b, 0x02, 0x9c, 0xeb, 0xa5, 0x2f, 0x06,
0x12, 0xc3, 0x0c, 0xf3, 0xbb, 0x9f, 0x16, 0xdb, 0xe6, 0xd2, 0x78, 0x58,
0x35, 0xb7, 0x4b
