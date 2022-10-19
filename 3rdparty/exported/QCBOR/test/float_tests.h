/*==============================================================================
 float_tests.h -- tests for float and conversion to/from half-precision

 Copyright (c) 2018-2020, Laurence Lundblade. All rights reserved.

 SPDX-License-Identifier: BSD-3-Clause

 See BSD-3-Clause license in README.md

 Created on 9/19/18
 =============================================================================*/

#ifndef float_tests_h
#define float_tests_h

#include <stdint.h>

#ifndef QCBOR_DISABLE_PREFERRED_FLOAT

int32_t HalfPrecisionDecodeBasicTests(void);

int32_t DoubleAsSmallestTest(void);

int32_t HalfPrecisionAgainstRFCCodeTest(void);

#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */

/*
 This calls each and every method for encoding
 floating-point numbers.
 */
int32_t GeneralFloatEncodeTests(void);

/*
 Tests basic float decoding.
 */
int32_t GeneralFloatDecodeTests(void);


#endif /* float_tests_h */
