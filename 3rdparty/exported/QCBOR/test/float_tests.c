/* ==========================================================================
 * float_tests.c -- tests for float and conversion to/from half-precision
 *
 * Copyright (c) 2018-2024, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in file named "LICENSE"
 *
 * Created on 9/19/18
 * ========================================================================= */


#include "float_tests.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include <math.h> /* For INFINITY and NAN and isnan() */



/* Make a test results code that includes three components. Return code
 * is xxxyyyzzz where zz is the error code, yy is the test number and
 * zz is check being performed
 */
static inline int32_t
MakeTestResultCode(uint32_t   uTestCase,
                   uint32_t   uTestNumber,
                   QCBORError uErrorCode)
{
   uint32_t uCode = (uTestCase * 1000000) +
                    (uTestNumber * 1000) +
                    (uint32_t)uErrorCode;
   return (int32_t)uCode;
}


#ifndef QCBOR_DISABLE_PREFERRED_FLOAT

#include "half_to_double_from_rfc7049.h"


struct DoubleTestCase {
   double      dNumber;
   double      fNumber;
   UsefulBufC  Preferred;
   UsefulBufC  NotPreferred;
   UsefulBufC  CDE;
   UsefulBufC  DCBOR;
};

/* Boundaries for all destination conversions to test at.
 *
 * smallest subnormal single  1.401298464324817e-45   2^^-149
 * largest subnormal single   1.1754942106924411e-38  2^^-126
 * smallest normal single     1.1754943508222875e-38
 * largest single             3.4028234663852886E+38
 *
 * smallest subnormal half   5.9604644775390625E-8
 * largest subnormal half    6.097555160522461E-5
 * smallest normal half      6.103515625E-5
 * largest half              65504.0
 *
 * Boundaries for origin conversions
 * smallest subnormal double 5.0e-324  2^^-1074
 * largest subnormal double
 * smallest normal double 2.2250738585072014e-308  2^^-1022
 * largest normal double 1.7976931348623157e308 2^^-1023
 */

/* Always four lines per test case so shell scripts can process into
 * other formats.  CDE and DCBOR standards are not complete yet,
 * encodings are a guess.  C string literals are used because they
 * are the shortest notation. They are used __with a length__ . Null
 * termination doesn't work because there are zero bytes.
 */
static const struct DoubleTestCase DoubleTestCases[] =  {
   /* Zero */
   {0.0,                                         0.0f,
    {"\xF9\x00\x00", 3},                         {"\xFB\x00\x00\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\x00\x00", 3},                         {"\xF9\x00\x00", 3}},

   /* Negative Zero */
   {-0.0,                                        -0.0f,
    {"\xF9\x80\x00", 3},                         {"\xFB\x80\x00\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\x80\x00", 3},                         {"\xF9\x80\x00", 3}},

   /* NaN */
   {NAN,                                         NAN,
    {"\xF9\x7E\x00", 3},                         {"\xFB\x7F\xF8\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\x7E\x00", 3},                         {"\xF9\x7E\x00", 3}},

   /* Infinity */
   {INFINITY,                                    INFINITY,
    {"\xF9\x7C\x00", 3},                         {"\xFB\x7F\xF0\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\x7C\x00", 3},                         {"\xF9\x7C\x00", 3}},

   /* Negative Infinity */
   {-INFINITY,                                   -INFINITY,
    {"\xF9\xFC\x00", 3},                         {"\xFB\xFF\xF0\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\xFC\x00", 3},                         {"\xF9\xFC\x00", 3}},

   /* 1.0 */
   {1.0,                                         1.0f,
    {"\xF9\x3C\x00", 3},                         {"\xFB\x3F\xF0\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\x3C\x00", 3},                         {"\xF9\x3C\x00", 3}},

   /* -2.0 -- a negative number that is not zero */
   {-2.0,                                        -2.0f,
    {"\xF9\xC0\x00", 3},                         {"\xFB\xC0\x00\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\xC0\x00", 3},                         {"\xF9\x3C\x00", 3}},

   /* 1/3 */
   {0.333251953125,                              0.333251953125f,
    {"\xF9\x35\x55", 3},                         {"\xFB\x3F\xD5\x54\x00\x00\x00\x00\x00", 9},
    {"\xF9\x35\x55", 3},                         {"\xF9\x35\x55", 3}},

   /* 5.9604644775390625E-8 -- smallest half-precision subnormal */
   {5.9604644775390625E-8,                       0.0f,
    {"\xF9\x00\x01", 3},                         {"\xFB\x3E\x70\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\x00\x01", 3},                         {"\xF9\x00\x01", 3}},

   /* 3.0517578125E-5 -- a half-precision subnormal */
   {3.0517578125E-5,                             0.0f,
    {"\xF9\x02\x00", 3},                         {"\xFB\x3F\x00\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\x02\x00", 3},                         {"\xF9\x02\x00", 3}},

   /* 6.097555160522461E-5 -- largest half-precision subnormal */
   {6.097555160522461E-5,                        0.0f,
    {"\xF9\x03\xFF", 3},                         {"\xFB\x3F\x0F\xF8\x00\x00\x00\x00\x00", 9},
    {"\xF9\x03\xFF", 3},                         {"\xF9\04\00", 3}},

   /* 6.103515625E-5 -- smallest possible half-precision normal */
   {6.103515625E-5,                              0.0f,
    {"\xF9\04\00", 3},                           {"\xFB\x3F\x10\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\04\00", 3},                           {"\xF9\04\00", 3}},

   /* 6.1035156250000014E-5 -- slightly larger than smallest half-precision normal */
   {6.1035156250000014E-5,                       6.1035156250000014E-5f,
    {"\xFB\x3F\x10\x00\x00\x00\x00\x00\x01", 9}, {"\xFB\x3F\x10\x00\x00\x00\x00\x00\x01", 9},
    {"\xFB\x3F\x10\x00\x00\x00\x00\x00\x01", 9}, {"\xFB\x3F\x10\x00\x00\x00\x00\x00\x01", 9}},

   /* 6.1035156249999993E-5 -- slightly smaller than smallest half-precision normal */
   {6.1035156249999993E-5,  0.0f,
    {"\xFB\x3F\x0F\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\xFB\x3F\x0F\xFF\xFF\xFF\xFF\xFF\xFF", 9},
    {"\xFB\x3F\x0F\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\xFB\x3F\x0F\xFF\xFF\xFF\xFF\xFF\xFF", 9}},

   /* 65504.0 -- largest possible half-precision */
   {65504.0,                                     0.0f,
    {"\xF9\x7B\xFF", 3},                         {"\xFB\x40\xEF\xFC\x00\x00\x00\x00\x00", 9},
    {"\xF9\x7B\xFF", 3},                         {"\xF9\x7B\xFF", 3}},

   /* 65504.1 -- exponent too large and too much precision to convert */
   {65504.1,                                     0.0f,
    {"\xFB\x40\xEF\xFC\x03\x33\x33\x33\x33", 9}, {"\xFB\x40\xEF\xFC\x03\x33\x33\x33\x33", 9},
    {"\xFB\x40\xEF\xFC\x03\x33\x33\x33\x33", 9}, {"\xFB\x40\xEF\xFC\x03\x33\x33\x33\x33", 9}},

    /* 65536.0 -- exponent too large but not too much precision for single */
   {65536.0,                                     65536.0f,
    {"\xFA\x47\x80\x00\x00", 5},                 {"\xFB\x40\xF0\x00\x00\x00\x00\x00\x00", 9},
    {"\xFA\x47\x80\x00\x00", 5},                 {"\xFA\x47\x80\x00\x00", 5}},

   /* 1.401298464324817e-45 -- smallest single subnormal */
   {1.401298464324817e-45,                       1.40129846E-45f,
    {"\xFA\x00\x00\x00\x01", 5},                 {"\xFB\x36\xA0\x00\x00\x00\x00\x00\x00", 9},
    {"\xFA\x00\x00\x00\x01", 5},                 {"\xFA\x00\x00\x00\x01", 5}},

   /* 5.8774717541114375E-39 -- slightly smaller than the smallest
    // single normal */
   {5.8774717541114375E-39,                      5.87747175E-39f,
    {"\xFA\x00\x40\x00\x00", 5},                 {"\xFB\x38\x00\x00\x00\x00\x00\x00\x00", 9},
    {"\xFA\x00\x40\x00\x00", 5},                 {"\xFA\x00\x40\x00\x00", 5}},

   /* 1.1754942106924411e-38 -- largest single subnormal */
   {1.1754942106924411E-38,                      1.17549421E-38f,
    {"\xFA\x00\x7f\xff\xff", 5},                 {"\xFB\x38\x0f\xff\xff\xC0\x00\x00\x00", 9},
    {"\xFA\x00\x7f\xff\xff", 5},                 {"\xFA\x00\x7f\xff\xff", 5} },

   /* 1.1754943508222874E-38 -- slightly bigger than smallest single normal */
   {1.1754943508222874E-38,                      0.0f,
    {"\xFB\x38\x0f\xff\xff\xff\xff\xff\xff", 9}, {"\xFB\x38\x0f\xff\xff\xff\xff\xff\xff", 9},
    {"\xFB\x38\x0f\xff\xff\xff\xff\xff\xff", 9}, {"\xFB\x38\x0f\xff\xff\xff\xff\xff\xff", 9}},

   /* 1.1754943508222875e-38 -- smallest single normal */
   {1.1754943508222875e-38,                      1.17549435E-38f,
    {"\xFA\x00\x80\x00\x00", 5},                 {"\xFB\x38\x10\x00\x00\x00\x00\x00\x00", 9},
    {"\xFA\x00\x80\x00\x00", 5},                 {"\xFA\x00\x80\x00\x00", 5}},

   /* 1.1754943508222875e-38 -- slightly bigger than smallest single normal */
   {1.1754943508222878e-38,                      0.0f,
    {"\xFB\x38\x10\x00\x00\x00\x00\x00\x01", 9}, {"\xFB\x38\x10\x00\x00\x00\x00\x00\x01", 9},
    {"\xFB\x38\x10\x00\x00\x00\x00\x00\x01", 9}, {"\xFB\x38\x10\x00\x00\x00\x00\x00\x01", 9}},

   /* 16777216 -- converts to single without loss */
   {16777216,                                    16777216,
    {"\xFA\x4B\x80\x00\x00", 5},                 {"\xFB\x41\x70\x00\x00\x00\x00\x00\x00", 9},
    {"\xFA\x4B\x80\x00\x00", 5},                 {"\xFA\x4B\x80\x00\x00", 5}},

   /* 16777217 -- one more than above and fails conversion to single */
   {16777217,                                    16777216,
    {"\xFB\x41\x70\x00\x00\x10\x00\x00\x00", 9}, {"\xFB\x41\x70\x00\x00\x10\x00\x00\x00", 9},
    {"\xFB\x41\x70\x00\x00\x10\x00\x00\x00", 9}, {"\xFB\x41\x70\x00\x00\x10\x00\x00\x00", 9}},

   /* 3.4028234663852886E+38 -- largest possible single normal */
   {3.4028234663852886E+38,                      3.40282347E+38f,
    {"\xFA\x7F\x7F\xFF\xFF", 5},                 {"\xFB\x47\xEF\xFF\xFF\xE0\x00\x00\x00", 9},
    {"\xFA\x7F\x7F\xFF\xFF", 5},                 {"\xFA\x7F\x7F\xFF\xFF", 5}},

   /* 3.402823466385289E+38 -- slightly larger than largest possible single */
   {3.402823466385289E+38,                       0.0f,
    {"\xFB\x47\xEF\xFF\xFF\xE0\x00\x00\x01", 9}, {"\xFB\x47\xEF\xFF\xFF\xE0\x00\x00\x01", 9},
    {"\xFB\x47\xEF\xFF\xFF\xE0\x00\x00\x01", 9}, {"\xFB\x47\xEF\xFF\xFF\xE0\x00\x00\x01", 9}},

   /* 3.402823669209385e+38 -- exponent larger by one than largest possible single */
   {3.402823669209385e+38,                       0.0f,
    {"\xFB\x47\xF0\x00\x00\x00\x00\x00\x00", 9}, {"\xFB\x47\xF0\x00\x00\x00\x00\x00\x00", 9},
    {"\xFB\x47\xF0\x00\x00\x00\x00\x00\x00", 9}, {"\xFB\x47\xF0\x00\x00\x00\x00\x00\x00", 9}},

   /* 5.0e-324 -- smallest double subnormal normal */
   {5.0e-324,                                    0.0f,
    {"\xFB\x00\x00\x00\x00\x00\x00\x00\x01", 9}, {"\xFB\x00\x00\x00\x00\x00\x00\x00\x01", 9},
    {"\xFB\x00\x00\x00\x00\x00\x00\x00\x01", 9}, {"\xFB\x00\x00\x00\x00\x00\x00\x00\x01", 9}},

   /* 2.2250738585072009E−308 -- largest double subnormal */
   {2.2250738585072009e-308,                     0.0f,
    {"\xFB\x00\x0F\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\xFB\x00\x0F\xFF\xFF\xFF\xFF\xFF\xFF", 9},
    {"\xFB\x00\x0F\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\xFB\x00\x0F\xFF\xFF\xFF\xFF\xFF\xFF", 9}},

   /* 2.2250738585072014e-308 -- smallest double normal */
   {2.2250738585072014e-308,                     0.0f,
    {"\xFB\x00\x10\x00\x00\x00\x00\x00\x00", 9}, {"\xFB\x00\x10\x00\x00\x00\x00\x00\x00", 9},
    {"\xFB\x00\x10\x00\x00\x00\x00\x00\x00", 9}, {"\xFB\x00\x10\x00\x00\x00\x00\x00\x00", 9}},

   /* 1.7976931348623157E308 -- largest double normal */
   {1.7976931348623157e308,                      0.0f,
    {"\xFB\x7F\xEF\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\xFB\x7F\xEF\xFF\xFF\xFF\xFF\xFF\xFF", 9},
    {"\xFB\x7F\xEF\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\xFB\x7F\xEF\xFF\xFF\xFF\xFF\xFF\xFF", 9}},

   /* List terminator */
   {0.0, 0.0f, {NULL, 0}, {NULL, 0}, {NULL, 0}, {NULL, 0} }
};


struct NaNTestCase {
   uint64_t    uDouble;
   uint32_t    uSingle;
   UsefulBufC  Preferred;
   UsefulBufC  NotPreferred;
   UsefulBufC  CDE;
   UsefulBufC  DCBOR;
};

/* Always four lines per test case so shell scripts can process into
 * other formats. CDE and DCBOR standards are not complete yet,
 * encodings are a guess. C string literals are used because they
 * are the shortest notation. They are used __with a length__ . Null
 * termination doesn't work because there are zero bytes.
 */
static const struct NaNTestCase NaNTestCases[] =  {

   /* Payload with most significant bit set, a qNaN by most implementations */
   {0x7ff8000000000000,                          0x00000000,
    {"\xF9\x7E\x00", 3},                         {"\xFB\x7F\xF8\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\x7E\x00", 3},                         {"\xF9\x7E\x00", 3}},

   /* Payload with single rightmost set */
   {0x7ff8000000000001,                          0x00000000,
    {"\xFB\x7F\xF8\x00\x00\x00\x00\x00\x01", 9}, {"\xFB\x7F\xF8\x00\x00\x00\x00\x00\x01", 9},
    {"\xF9\x7E\x00", 3},                         {"\xF9\x7E\x00", 3}},

   /* Payload with 10 leftmost bits set -- converts to half */
   {0x7ffffc0000000000,                          0x00000000,
    {"\xF9\x7F\xFF", 3},                         {"\xFB\x7F\xFF\xFC\x00\x00\x00\x00\x00", 9},
    {"\xF9\x7E\x00", 3},                         {"\xF9\x7E\x00", 3}},

   /* Payload with 10 rightmost bits set -- cannot convert to half */
   {0x7ff80000000003ff,                          0x00000000,
    {"\xFB\x7F\xF8\x00\x00\x00\x00\x03\xFF", 9}, {"\xFB\x7F\xF8\x00\x00\x00\x00\x03\xFF", 9},
    {"\xF9\x7E\x00", 3},                         {"\xF9\x7E\x00", 3}},

   /* Payload with 23 leftmost bits set -- converts to a single */
   {0x7ffFFFFFE0000000,                          0x7fffffff,
    {"\xFA\x7F\xFF\xFF\xFF", 5},                 {"\xFB\x7F\xFF\xFF\xFF\xE0\x00\x00\x00", 9},
    {"\xF9\x7E\x00", 3},                         {"\xF9\x7E\x00", 3}},

   /* Payload with 24 leftmost bits set -- fails to convert to a single */
   {0x7ffFFFFFF0000000,                          0x00000000,
    {"\xFB\x7F\xFF\xFF\xFF\xF0\x00\x00\x00", 9}, {"\xFB\x7F\xFF\xFF\xFF\xF0\x00\x00\x00", 9},
    {"\xF9\x7E\x00", 3},                         {"\xF9\x7E\x00", 3}},

   /* Payload with all bits set */
   {0x7fffffffffffffff,                          0x00000000,
    {"\xFB\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\xFB\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 9},
    {"\xF9\x7E\x00", 3},                         {"\xFB\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 9}},

   /* List terminator */
   {0, 0, {NULL, 0}, {NULL, 0}, {NULL, 0}, {NULL, 0} }
};



/* Public function. See float_tests.h
 *
 * This is the main test of floating-point encoding / decoding. It is
 * data-driven by the above tables. It works better than tests below that
 * it mostly replaces because it tests one number at a time, rather than
 * putting them all in a map. It is much easier to debug test failures
 * and to add new tests. */
int32_t
FloatValuesTests(void)
{
   unsigned int                 uTestIndex;
   const struct DoubleTestCase *pTestCase;
   const struct NaNTestCase    *pNaNTestCase;
   MakeUsefulBufOnStack(        TestOutBuffer, 20);
   UsefulBufC                   TestOutput;
   QCBOREncodeContext           EnCtx;
   QCBORError                   uErr;
   QCBORDecodeContext           DCtx;
   QCBORItem                    Item;
   uint64_t                     uDecoded;
#ifdef QCBOR_DISABLE_FLOAT_HW_USE
   uint32_t                     uDecoded2;
#endif

   /* Test a variety of doubles */
   for(uTestIndex = 0; DoubleTestCases[uTestIndex].Preferred.len != 0; uTestIndex++) {
      pTestCase = &DoubleTestCases[uTestIndex];

     // if(pTestCase->dNumber == 1.1754943508222874E-38) {
         if(uTestIndex == 19) {
         uErr = 99; /* For setting break points for particular tests */
      }

      /* Number Encode of Preferred */
      QCBOREncode_Init(&EnCtx, TestOutBuffer);
      QCBOREncode_AddDouble(&EnCtx, pTestCase->dNumber);
      uErr = QCBOREncode_Finish(&EnCtx, &TestOutput);

      if(uErr != QCBOR_SUCCESS) {
         return MakeTestResultCode(uTestIndex, 1, uErr);;
      }
      if(UsefulBuf_Compare(TestOutput, pTestCase->Preferred)) {
         return MakeTestResultCode(uTestIndex, 1, 200);
      }

      /* Number Encode of Not Preferred */
      QCBOREncode_Init(&EnCtx, TestOutBuffer);
      QCBOREncode_AddDoubleNoPreferred(&EnCtx, pTestCase->dNumber);
      uErr = QCBOREncode_Finish(&EnCtx, &TestOutput);

      if(uErr != QCBOR_SUCCESS) {
         return MakeTestResultCode(uTestIndex, 2, uErr);;
      }
      if(UsefulBuf_Compare(TestOutput, pTestCase->NotPreferred)) {
         return MakeTestResultCode(uTestIndex, 2, 200);
      }

      /* Number Decode of Preferred */
      QCBORDecode_Init(&DCtx, pTestCase->Preferred, 0);
      uErr = QCBORDecode_GetNext(&DCtx, &Item);
      if(uErr != QCBOR_SUCCESS) {
         return MakeTestResultCode(uTestIndex, 3, uErr);;
      }
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
      if(Item.uDataType != QCBOR_TYPE_DOUBLE) {
         return MakeTestResultCode(uTestIndex, 4, 0);
      }
      if(isnan(pTestCase->dNumber)) {
         if(!isnan(Item.val.dfnum)) {
            return MakeTestResultCode(uTestIndex, 5, 0);
         }
      } else {
         if(Item.val.dfnum != pTestCase->dNumber) {
            return MakeTestResultCode(uTestIndex, 6, 0);
         }
      }
#else /* QCBOR_DISABLE_FLOAT_HW_USE */
      /* When QCBOR_DISABLE_FLOAT_HW_USE is set, single-precision is not
       * converted to double when decoding, so test differently. len == 5
       * indicates single-precision in the encoded CBOR. */
      if(pTestCase->Preferred.len == 5) {
         if(Item.uDataType != QCBOR_TYPE_FLOAT) {
            return MakeTestResultCode(uTestIndex, 4, 0);
         }
         if(isnan(pTestCase->dNumber)) {
            if(!isnan(Item.val.fnum)) {
               return MakeTestResultCode(uTestIndex, 5, 0);
            }
         } else {
            if(Item.val.fnum != pTestCase->fNumber) {
               return MakeTestResultCode(uTestIndex, 6, 0);
            }
         }
      } else {
         if(Item.uDataType != QCBOR_TYPE_DOUBLE) {
            return MakeTestResultCode(uTestIndex, 4, 0);
         }
         if(isnan(pTestCase->dNumber)) {
            if(!isnan(Item.val.dfnum)) {
               return MakeTestResultCode(uTestIndex, 5, 0);
            }
         } else {
            if(Item.val.dfnum != pTestCase->dNumber) {
               return MakeTestResultCode(uTestIndex, 6, 0);
            }
         }
      }
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */

      /* Number Decode of Not Preferred */
      QCBORDecode_Init(&DCtx, pTestCase->NotPreferred, 0);
      uErr = QCBORDecode_GetNext(&DCtx, &Item);
      if(uErr != QCBOR_SUCCESS) {
         return MakeTestResultCode(uTestIndex, 7, uErr);;
      }
      if(Item.uDataType != QCBOR_TYPE_DOUBLE) {
         return MakeTestResultCode(uTestIndex, 8, 0);
      }
      if(isnan(pTestCase->dNumber)) {
         if(!isnan(Item.val.dfnum)) {
            return MakeTestResultCode(uTestIndex, 9, 0);
         }
      } else {
         if(Item.val.dfnum != pTestCase->dNumber) {
            return MakeTestResultCode(uTestIndex, 10, 0);
         }
      }

   }

   /* Test a variety of NaNs with payloads */
   for(uTestIndex = 0; NaNTestCases[uTestIndex].Preferred.len != 0; uTestIndex++) {
      pNaNTestCase = &NaNTestCases[uTestIndex];


      if(uTestIndex == 4) {
         uErr = 99; /* For setting break points for particular tests */
      }

      /* NaN Encode of Preferred */
      QCBOREncode_Init(&EnCtx, TestOutBuffer);
      QCBOREncode_AddDouble(&EnCtx, UsefulBufUtil_CopyUint64ToDouble(pNaNTestCase->uDouble));
      uErr = QCBOREncode_Finish(&EnCtx, &TestOutput);
      if(uErr != QCBOR_SUCCESS) {
         return MakeTestResultCode(uTestIndex+100, 10, uErr);;
      }
      if(UsefulBuf_Compare(TestOutput, pNaNTestCase->Preferred)) {
         return MakeTestResultCode(uTestIndex+100, 10, 200);
      }

#ifdef QCBOR_COMPARE_TO_HW_NAN_CONVERSION
      {
         /* This test is off by default. It's purpose is to check
          * QCBOR's mask-n-shift implementation against the HW/CPU
          * instructions that do conversion between double and single.
          * It is off because it is only used on occasion to verify
          * QCBOR and because it is suspected that some HW/CPU does
          * implement this correctly. NaN payloads are an obscure
          * feature. */
         float f;
         double d, d2;

         d = UsefulBufUtil_CopyUint64ToDouble(pNaNTestCase->uNumber);

         /* Cast the double to a single and then back to a double and
          * see if they are equal. If so, then the NaN payload doesn't
          * have any bits that are lost when converting to single and
          * it can be safely converted.
          *
          * This test can't be done for half-precision because it is
          * not widely supported.
          */
         f = (float)d;
         d2 = (double)f;

         /* The length of encoded doubles is 9, singles 5 and halves
          * 3. If there are NaN payload bits that can't be converted,
          * then the length must be 9.
          */
         if((uint64_t)d != (uint64_t)d2 && pNaNTestCase->Preferred.len != 9) {
            /* QCBOR conversion not the same as HW conversion */
            return MakeTestResultCode(uTestIndex, 9, 200);
         }
      }
#endif /* QCBOR_COMPARE_TO_HW_NAN_CONVERSION */


      /* NaN Encode of Not Preferred */
      QCBOREncode_Init(&EnCtx, TestOutBuffer);
      QCBOREncode_AddDoubleNoPreferred(&EnCtx, UsefulBufUtil_CopyUint64ToDouble(pNaNTestCase->uDouble));
      uErr = QCBOREncode_Finish(&EnCtx, &TestOutput);
      if(uErr != QCBOR_SUCCESS) {
         return MakeTestResultCode(uTestIndex+100, 11, uErr);;
      }
      if(UsefulBuf_Compare(TestOutput, pNaNTestCase->NotPreferred)) {
         return MakeTestResultCode(uTestIndex+100, 11, 200);
      }

      /* NaN Decode of Preferred */
      QCBORDecode_Init(&DCtx, pNaNTestCase->Preferred, 0);
      uErr = QCBORDecode_GetNext(&DCtx, &Item);
      if(uErr != QCBOR_SUCCESS) {
         return MakeTestResultCode(uTestIndex+100, 12, uErr);
      }

#ifndef QCBOR_DISABLE_FLOAT_HW_USE

      uDecoded = UsefulBufUtil_CopyDoubleToUint64(Item.val.dfnum);
      if(uDecoded != pNaNTestCase->uDouble) {
         return MakeTestResultCode(uTestIndex+100, 12, 200);
      }
#else /* QCBOR_DISABLE_FLOAT_HW_USE */
      if(pNaNTestCase->Preferred.len == 5) {
         if(Item.uDataType != QCBOR_TYPE_FLOAT) {
            return MakeTestResultCode(uTestIndex, 4, 0);
         }

         uDecoded2 = UsefulBufUtil_CopyFloatToUint32(Item.val.fnum);

         if(uDecoded2 != pNaNTestCase->uSingle) {
            return MakeTestResultCode(uTestIndex, 4, 0);
         }
      } else {
         if(Item.uDataType != QCBOR_TYPE_DOUBLE) {
            return MakeTestResultCode(uTestIndex, 4, 0);
         }
         uDecoded = UsefulBufUtil_CopyDoubleToUint64(Item.val.dfnum);
         if(uDecoded != pNaNTestCase->uDouble) {
            return MakeTestResultCode(uTestIndex+100, 12, 200);
         }
      }
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */

      /* NaN Decode of Not Preferred */
      QCBORDecode_Init(&DCtx, pNaNTestCase->NotPreferred, 0);
      uErr = QCBORDecode_GetNext(&DCtx, &Item);
      if(uErr != QCBOR_SUCCESS) {
         return MakeTestResultCode(uTestIndex+100, 13, uErr);
      }
      uDecoded = UsefulBufUtil_CopyDoubleToUint64(Item.val.dfnum);
      if(uDecoded != pNaNTestCase->uDouble) {
         return MakeTestResultCode(uTestIndex+100, 13, 200);
      }
   }

   return 0;
}



/* Public function. See float_tests.h */
int32_t
HalfPrecisionAgainstRFCCodeTest(void)
{
   QCBORItem          Item;
   QCBORDecodeContext DC;
   unsigned char      pbHalfBytes[2];
   uint8_t            uHalfPrecInitialByte;
   double             d;
   UsefulBuf_MAKE_STACK_UB(EncodedBytes, 3);
   UsefulOutBuf      UOB;
   uint32_t          uHalfP;


   for(uHalfP = 0; uHalfP < 0xffff; uHalfP += 60) {
      pbHalfBytes[1] = (uint8_t)(uHalfP & 0xff);
      pbHalfBytes[0] = (uint8_t)(uHalfP >> 8); /* uHalfP is always less than 0xffff */
      d = decode_half(pbHalfBytes);

      /* Construct the CBOR for the half-precision float by hand */
      UsefulOutBuf_Init(&UOB, EncodedBytes);

      uHalfPrecInitialByte = (uint8_t)(HALF_PREC_FLOAT + (CBOR_MAJOR_TYPE_SIMPLE << 5)); /* 0xf9 */
      UsefulOutBuf_AppendByte(&UOB, uHalfPrecInitialByte); /* initial byte */
      UsefulOutBuf_AppendUint16(&UOB, (uint16_t)uHalfP);   /* argument */

      /* Now parse the hand-constructed CBOR. This will invoke the
       * conversion to a float
       */
      QCBORDecode_Init(&DC, UsefulOutBuf_OutUBuf(&UOB), 0);
      QCBORDecode_GetNext(&DC, &Item);
      if(Item.uDataType != QCBOR_TYPE_DOUBLE) {
         return -1;
      }

      if(isnan(d)) {
         /* The RFC code uses the native instructions which may or may not
          * handle sNaN, qNaN and NaN payloads correctly. This test just
          * makes sure it is a NaN and doesn't worry about the type of NaN
          */
         if(!isnan(Item.val.dfnum)) {
            return -3;
         }
      } else {
         if(Item.val.dfnum != d) {
            return -2;
         }
      }
   }
   return 0;
}

#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */


/*
 * Some encoded floating point numbers that are used for both
 * encode and decode tests.
 *
 * [0.0,  // Half
 *  3.14, // Double
 *  0.0,  // Double
 *  NaN,  // Double
 *  Infinity, // Double
 *  0.0,  // Half (Duplicate because of use in encode tests)
 *  3.140000104904175, // Single
 *  0.0,  // Single
 *  NaN,  // Single
 *  Infinity, // Single
 *  {100: 0.0, 101: 3.1415926, "euler": 2.718281828459045, 105: 0.0,
 *   102: 0.0, 103: 3.141592502593994, "euler2": 2.7182817459106445, 106: 0.0}]
 */
static const uint8_t spExpectedFloats[] = {
   0x8B,
      0xF9, 0x00, 0x00,
      0xFB, 0x40, 0x09, 0x1E, 0xB8, 0x51, 0xEB, 0x85, 0x1F,
      0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xFB, 0x7F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xFB, 0x7F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xF9, 0x00, 0x00,
      0xFA, 0x40, 0x48, 0xF5, 0xC3,
      0xFA, 0x00, 0x00, 0x00, 0x00,
      0xFA, 0x7F, 0xC0, 0x00, 0x00,
      0xFA, 0x7F, 0x80, 0x00, 0x00,
      0xA8,
         0x18, 0x64,
          0xF9, 0x00, 0x00,
         0x18, 0x65,
          0xFB, 0x40, 0x09, 0x21, 0xFB, 0x4D, 0x12, 0xD8, 0x4A,
         0x65, 0x65, 0x75, 0x6C, 0x65, 0x72,
          0xFB, 0x40, 0x05, 0xBF, 0x0A, 0x8B, 0x14, 0x57, 0x69,
         0x18, 0x69,
          0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x18, 0x66,
          0xF9, 0x00, 0x00,
         0x18, 0x67,
          0xFA, 0x40, 0x49, 0x0F, 0xDA,
         0x66, 0x65, 0x75, 0x6C, 0x65, 0x72, 0x32,
          0xFA, 0x40, 0x2D, 0xF8, 0x54,
         0x18, 0x6A,
          0xFA, 0x00, 0x00, 0x00, 0x00};

#ifndef USEFULBUF_DISABLE_ALL_FLOAT
static const uint8_t spExpectedFloatsNoHalf[] = {
   0x8B,
      0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xFB, 0x40, 0x09, 0x1E, 0xB8, 0x51, 0xEB, 0x85, 0x1F,
      0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xFB, 0x7F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xFB, 0x7F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xFA, 0x00, 0x00, 0x00, 0x00,
      0xFA, 0x40, 0x48, 0xF5, 0xC3,
      0xFA, 0x00, 0x00, 0x00, 0x00,
      0xFA, 0x7F, 0xC0, 0x00, 0x00,
      0xFA, 0x7F, 0x80, 0x00, 0x00,
      0xA8,
         0x18, 0x64,
          0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x18, 0x65,
          0xFB, 0x40, 0x09, 0x21, 0xFB, 0x4D, 0x12, 0xD8, 0x4A,
         0x65, 0x65, 0x75, 0x6C, 0x65, 0x72,
          0xFB, 0x40, 0x05, 0xBF, 0x0A, 0x8B, 0x14, 0x57, 0x69,
         0x18, 0x69,
          0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x18, 0x66,
          0xFA, 0x00, 0x00, 0x00, 0x00,
         0x18, 0x67,
          0xFA, 0x40, 0x49, 0x0F, 0xDA,
         0x66, 0x65, 0x75, 0x6C, 0x65, 0x72, 0x32,
          0xFA, 0x40, 0x2D, 0xF8, 0x54,
         0x18, 0x6A,
          0xFA, 0x00, 0x00, 0x00, 0x00};


/* Public function. See float_tests.h */
int32_t
GeneralFloatEncodeTests(void)
{
   /* See FloatNumberTests() for tests that really cover lots of float values.
    * Add new tests for new values or decode modes there.
    * This test is primarily to cover all the float encode methods. */

   UsefulBufC Encoded;
   UsefulBufC ExpectedFloats;
   QCBORError uErr;

#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
   UsefulBuf_MAKE_STACK_UB(OutBuffer, sizeof(spExpectedFloats));
   ExpectedFloats = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedFloats);
   (void)spExpectedFloatsNoHalf; /* Avoid unused variable error */
#else
   UsefulBuf_MAKE_STACK_UB(OutBuffer, sizeof(spExpectedFloatsNoHalf));
   ExpectedFloats = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedFloatsNoHalf);
   (void)spExpectedFloats; /* Avoid unused variable error */
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */

   QCBOREncodeContext EC;
   QCBOREncode_Init(&EC, OutBuffer);
   QCBOREncode_OpenArray(&EC);

   QCBOREncode_AddDouble(&EC, 0.0);
   QCBOREncode_AddDouble(&EC, 3.14);
   QCBOREncode_AddDoubleNoPreferred(&EC, 0.0);
   QCBOREncode_AddDoubleNoPreferred(&EC, NAN);
   QCBOREncode_AddDoubleNoPreferred(&EC, INFINITY);

   QCBOREncode_AddFloat(&EC, 0.0);
   QCBOREncode_AddFloat(&EC, 3.14f);
   QCBOREncode_AddFloatNoPreferred(&EC, 0.0f);
   QCBOREncode_AddFloatNoPreferred(&EC, NAN);
   QCBOREncode_AddFloatNoPreferred(&EC, INFINITY);

   QCBOREncode_OpenMap(&EC);

   QCBOREncode_AddDoubleToMapN(&EC, 100, 0.0);
   QCBOREncode_AddDoubleToMapN(&EC, 101, 3.1415926);
   QCBOREncode_AddDoubleToMap(&EC, "euler", 2.71828182845904523536);
   QCBOREncode_AddDoubleNoPreferredToMapN(&EC, 105, 0.0);

   QCBOREncode_AddFloatToMapN(&EC, 102, 0.0f);
   QCBOREncode_AddFloatToMapN(&EC, 103, 3.1415926f);
   QCBOREncode_AddFloatToMap(&EC, "euler2", 2.71828182845904523536f);
   QCBOREncode_AddFloatNoPreferredToMapN(&EC, 106, 0.0f);

   QCBOREncode_CloseMap(&EC);
   QCBOREncode_CloseArray(&EC);

   uErr = QCBOREncode_Finish(&EC, &Encoded);
   if(uErr) {
      return -1;
   }

   if(UsefulBuf_Compare(Encoded, ExpectedFloats)) {
      return -3;
   }

   return 0;
}

#endif /* USEFULBUF_DISABLE_ALL_FLOAT */


/* Public function. See float_tests.h */
int32_t
GeneralFloatDecodeTests(void)
{
   /* See FloatNumberTests() for tests that really cover lots of float values */

   QCBORItem          Item;
   QCBORError         uErr;
   QCBORDecodeContext DC;

   UsefulBufC TestData = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedFloats);
   QCBORDecode_Init(&DC, TestData, 0);

   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_ARRAY) {
      return MakeTestResultCode(0, 1, 0);
   }

   /* 0.0 half-precision */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_HALF_PREC(QCBOR_SUCCESS)
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || Item.val.dfnum != 0.0
#else /* QCBOR_DISABLE_PREFERRED_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
   ) {
      return MakeTestResultCode(0, 2, uErr);
   }

   /* 3.14 double-precision */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS)
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || Item.val.dfnum != 3.14
#else /* USEFULBUF_DISABLE_ALL_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   ) {
      return MakeTestResultCode(0, 3, uErr);
   }

   /* 0.0 double-precision */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS)
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || Item.val.dfnum != 0.0
#else /* USEFULBUF_DISABLE_ALL_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   ) {
      return MakeTestResultCode(0, 4, uErr);
   }

   /* NaN double-precision */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS)
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || !isnan(Item.val.dfnum)
#else /* USEFULBUF_DISABLE_ALL_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   ) {
      return MakeTestResultCode(0, 5, uErr);
   }

   /* Infinity double-precision */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS)
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || Item.val.dfnum != INFINITY
#else /* USEFULBUF_DISABLE_ALL_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   ) {
      return MakeTestResultCode(0, 6, uErr);
   }

   /* 0.0 half-precision (again) */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_HALF_PREC(QCBOR_SUCCESS)
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || Item.val.dfnum != 0.0
#else /* USEFULBUF_DISABLE_ALL_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
   ) {
      return MakeTestResultCode(0, 7, uErr);
   }

   /* 3.140000104904175 single-precision */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS)
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || 3.1400001049041748 != Item.val.dfnum
#else /* QCBOR_DISABLE_FLOAT_HW_USE */
      || Item.uDataType != QCBOR_TYPE_FLOAT
      || 3.140000f != Item.val.fnum
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
#else /* USEFULBUF_DISABLE_ALL_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   ) {
      return MakeTestResultCode(0, 8, uErr);
   }

   /* 0.0 single-precision */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS)
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || Item.val.dfnum != 0.0
#else /* QCBOR_DISABLE_FLOAT_HW_USE */
      || Item.uDataType != QCBOR_TYPE_FLOAT
      || Item.val.fnum != 0.0f
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
#else /* USEFULBUF_DISABLE_ALL_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   ) {
      return MakeTestResultCode(0, 9, uErr);
   }

   /* NaN single-precision */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS)
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || !isnan(Item.val.dfnum)
#else /* QCBOR_DISABLE_FLOAT_HW_USE */
      || Item.uDataType != QCBOR_TYPE_FLOAT
      || !isnan(Item.val.fnum)
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
#else /* USEFULBUF_DISABLE_ALL_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   ) {
      return MakeTestResultCode(0, 10, uErr);
   }

   /* Infinity single-precision */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS)
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || Item.val.dfnum != INFINITY
#else /* QCBOR_DISABLE_FLOAT_HW_USE */
      || Item.uDataType != QCBOR_TYPE_FLOAT
      || Item.val.fnum != INFINITY
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
#else /* USEFULBUF_DISABLE_ALL_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   ) {
      return MakeTestResultCode(0, 11, uErr);
   }
   /* Sufficent test coverage. Don't need to decode the rest. */


#ifndef USEFULBUF_DISABLE_ALL_FLOAT
   /* Now tests for spiffy decode main function */
   TestData = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedFloats);
   double d;
   QCBORDecode_Init(&DC, TestData, 0);
   QCBORDecode_EnterArray(&DC, NULL);

   /* 0.0 half-precision */
   QCBORDecode_GetDouble(&DC, &d);
   uErr = QCBORDecode_GetAndResetError(&DC);
   if(uErr != FLOAT_ERR_CODE_NO_HALF_PREC(QCBOR_SUCCESS)
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
      || d != 0.0
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
      ) {
      return MakeTestResultCode(1, 1, uErr);
   }

   /* 3.14 double-precision */
   QCBORDecode_GetDouble(&DC, &d);
   uErr = QCBORDecode_GetAndResetError(&DC);
   if(uErr != QCBOR_SUCCESS || d != 3.14) {
      return MakeTestResultCode(1, 2, uErr);
   }

   /* 0.0 double-precision */
   QCBORDecode_GetDouble(&DC, &d);
   uErr = QCBORDecode_GetAndResetError(&DC);
   if(uErr != QCBOR_SUCCESS || d != 0.0) {
      return MakeTestResultCode(1, 3, uErr);
   }

   /* NaN double-precision */
   QCBORDecode_GetDouble(&DC, &d);
   uErr = QCBORDecode_GetAndResetError(&DC);
   if(uErr != QCBOR_SUCCESS || !isnan(d)) {
      return MakeTestResultCode(1, 4, uErr);
   }

   /* Infinity double-precision */
   QCBORDecode_GetDouble(&DC, &d);
   uErr = QCBORDecode_GetAndResetError(&DC);
   if(uErr != QCBOR_SUCCESS || d != INFINITY) {
      return MakeTestResultCode(1, 5, uErr);
   }

   /* 0.0 half-precision */
   QCBORDecode_GetDouble(&DC, &d);
   uErr = QCBORDecode_GetAndResetError(&DC);
   if(uErr != FLOAT_ERR_CODE_NO_HALF_PREC(QCBOR_SUCCESS)
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
      || d != 0.0
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
      ) {
      return MakeTestResultCode(1, 6, uErr);
   }

   /* 3.140000104904175 single-precision */
   QCBORDecode_GetDouble(&DC, &d);
   uErr = QCBORDecode_GetAndResetError(&DC);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
      || d != 3.140000104904175
#endif
      ) {
      return MakeTestResultCode(1, 7, uErr);
   }

   /* 0.0 single-precision */
   QCBORDecode_GetDouble(&DC, &d);
   uErr = QCBORDecode_GetAndResetError(&DC);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
      || d != 0.0
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
      ) {
      return MakeTestResultCode(1, 8, uErr);
   }

   /* NaN single-precision */
   QCBORDecode_GetDouble(&DC, &d);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
      || !isnan(d)
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
      ) {
      return MakeTestResultCode(1, 9, uErr);
   }

   /* Infinity single-precision */
   QCBORDecode_GetDouble(&DC, &d);
   uErr = QCBORDecode_GetAndResetError(&DC);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
      || d != INFINITY
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
      ) {
      return MakeTestResultCode(1, 10, uErr);
   }

#endif /* USEFULBUF_DISABLE_ALL_FLOAT */

   return 0;
}



#ifdef NAN_EXPERIMENT
/*
 Code for checking what the double to float cast does with
 NaNs.  Not run as part of tests. Keep it around to
 be able to check various platforms and CPUs.
 */

#define DOUBLE_NUM_SIGNIFICAND_BITS (52)
#define DOUBLE_NUM_EXPONENT_BITS    (11)
#define DOUBLE_NUM_SIGN_BITS        (1)

#define DOUBLE_SIGNIFICAND_SHIFT    (0)
#define DOUBLE_EXPONENT_SHIFT       (DOUBLE_NUM_SIGNIFICAND_BITS)
#define DOUBLE_SIGN_SHIFT           (DOUBLE_NUM_SIGNIFICAND_BITS + DOUBLE_NUM_EXPONENT_BITS)

#define DOUBLE_SIGNIFICAND_MASK     (0xfffffffffffffULL) // The lower 52 bits
#define DOUBLE_EXPONENT_MASK        (0x7ffULL << DOUBLE_EXPONENT_SHIFT) // 11 bits of exponent
#define DOUBLE_SIGN_MASK            (0x01ULL << DOUBLE_SIGN_SHIFT) // 1 bit of sign
#define DOUBLE_QUIET_NAN_BIT        (0x01ULL << (DOUBLE_NUM_SIGNIFICAND_BITS-1))


static int NaNExperiments() {
    double dqNaN = UsefulBufUtil_CopyUint64ToDouble(DOUBLE_EXPONENT_MASK | DOUBLE_QUIET_NAN_BIT);
    double dsNaN = UsefulBufUtil_CopyUint64ToDouble(DOUBLE_EXPONENT_MASK | 0x01);
    double dqNaNPayload = UsefulBufUtil_CopyUint64ToDouble(DOUBLE_EXPONENT_MASK | DOUBLE_QUIET_NAN_BIT | 0xf00f);

    float f1 = (float)dqNaN;
    float f2 = (float)dsNaN;
    float f3 = (float)dqNaNPayload;


    uint32_t uqNaN = UsefulBufUtil_CopyFloatToUint32((float)dqNaN);
    uint32_t usNaN = UsefulBufUtil_CopyFloatToUint32((float)dsNaN);
    uint32_t uqNaNPayload = UsefulBufUtil_CopyFloatToUint32((float)dqNaNPayload);

    // Result of this on x86 is that every NaN is a qNaN. The intel
    // CVTSD2SS instruction ignores the NaN payload and even converts
    // a sNaN to a qNaN.

    return 0;
}
#endif /* NAN_EXPERIMENT */
