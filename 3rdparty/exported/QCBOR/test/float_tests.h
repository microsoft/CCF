/*==============================================================================
 float_tests.h -- tests for floats and conversion to/from half-precision

 Copyright (c) 2018-2024, Laurence Lundblade. All rights reserved.

 SPDX-License-Identifier: BSD-3-Clause

 See BSD-3-Clause license in file named "LICENSE"

 Created on 9/19/18
 =============================================================================*/

#ifndef float_tests_h
#define float_tests_h

#include <stdint.h>

#ifndef QCBOR_DISABLE_PREFERRED_FLOAT

/* This tests a large number half-precision values
 * in the conversion to/from half/double against
 * the sample code in the CBOR RFC. */
int32_t HalfPrecisionAgainstRFCCodeTest(void);

#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */


/*
 * This tests floating point encoding, decoding
 * and conversion for lots of different values.
 * It covers Preferred Serialization processing
 * of floating point.  It's focus is on the numbers
 * not the encode/decode functions.
 */
int32_t FloatValuesTests(void);


/*
 * This calls each and every method for encoding
 * floating-point numbers.
 */
int32_t GeneralFloatEncodeTests(void);


/*
 * Tests float decoding, including error codes in scenarios
 * where various float features are disabled. This also
 * tests decoding using spiffy decode methods.
 */
int32_t GeneralFloatDecodeTests(void);


#endif /* float_tests_h */
