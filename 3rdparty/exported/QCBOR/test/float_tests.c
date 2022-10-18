/*==============================================================================
 float_tests.c -- tests for float and conversion to/from half-precision

 Copyright (c) 2018-2020, Laurence Lundblade. All rights reserved.
 Copyright (c) 2021, Arm Limited. All rights reserved.

 SPDX-License-Identifier: BSD-3-Clause

 See BSD-3-Clause license in README.md

 Created on 9/19/18
 =============================================================================*/


#include "float_tests.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include <math.h> // For INFINITY and NAN and isnan()


/* Make a test results code that includes three components
 * Return code is
 * xxxyyyzzz where zz is the error code, yy is the test number and zz is
 * check being performed
 */
static inline int32_t MakeTestResultCode(uint32_t   uTestCase,
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


/*
 Half-precision values that are input to test half-precision decoding

 As decoded by http://cbor.me
 {"zero": 0.0,
 "infinitity": Infinity,
 "negative infinitity": -Infinity,
 "NaN": NaN,
 "one": 1.0,
 "one third": 0.333251953125,
 "largest half-precision": 65504.0,
 "too-large half-precision": Infinity,
 "smallest subnormal": 5.960464477539063e-8,
 "smallest normal": 0.00006097555160522461,
 "biggest subnormal": 0.00006103515625,
 "subnormal single": 0.0,
 3: -2.0,
 4: NaN,
 5: NaN,
 6: NaN,
 7: NaN}
 */
static const uint8_t spExpectedHalf[] = {
    0xB1,
        0x64,
            0x7A, 0x65, 0x72, 0x6F,
        0xF9, 0x00, 0x00, // half-precision 0.000
        0x6A,
            0x69, 0x6E, 0x66, 0x69, 0x6E, 0x69, 0x74, 0x69, 0x74, 0x79,
        0xF9, 0x7C, 0x00, // Infinity
        0x73,
            0x6E, 0x65, 0x67, 0x61, 0x74, 0x69, 0x76, 0x65, 0x20, 0x69, 0x6E,
            0x66, 0x69, 0x6E, 0x69, 0x74, 0x69, 0x74, 0x79,
        0xF9, 0xFC, 0x00, // -Inifinity
        0x63,
            0x4E, 0x61, 0x4E,
        0xF9, 0x7E, 0x00, // NaN
        0x63,
            0x6F, 0x6E, 0x65,
        0xF9, 0x3C, 0x00, // 1.0
        0x69,
            0x6F, 0x6E, 0x65, 0x20, 0x74, 0x68, 0x69, 0x72, 0x64,
        0xF9, 0x35, 0x55, // half-precsion one third 0.333251953125
        0x76,
            0x6C, 0x61, 0x72, 0x67, 0x65, 0x73, 0x74, 0x20, 0x68, 0x61, 0x6C,
            0x66, 0x2D, 0x70, 0x72, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6F, 0x6E,
        0xF9, 0x7B, 0xFF, // largest half-precision 65504.0
        0x78, 0x18,
            0x74, 0x6F, 0x6F, 0x2D, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x20, 0x68,
            0x61, 0x6C, 0x66, 0x2D, 0x70, 0x72, 0x65, 0x63, 0x69, 0x73, 0x69,
            0x6F, 0x6E,
        0xF9, 0x7C, 0x00, // Infinity
        0x72,
            0x73, 0x6D, 0x61, 0x6C, 0x6C, 0x65, 0x73, 0x74, 0x20, 0x73, 0x75,
            0x62, 0x6E, 0x6F, 0x72, 0x6D, 0x61, 0x6C,
        0xF9, 0x00, 0x01, // Smallest half-precision subnormal 0.000000059604645
        0x71,
            0x62, 0x69, 0x67, 0x67, 0x65, 0x73, 0x74, 0x20, 0x73, 0x75, 0x62,
            0x6E, 0x6F, 0x72, 0x6D, 0x61, 0x6C,
        0xF9, 0x03, 0xFF, // Largest half-precision subnormal 0.0000609755516
        0x6F,
            0x73, 0x6D, 0x61, 0x6C, 0x6C, 0x65, 0x73, 0x74, 0x20, 0x6E, 0x6F,
            0x72, 0x6D, 0x61, 0x6C,
        0xF9, 0x04, 0x00,  // Smallest half-precision normal 0.000061988
        0x70,
            0x73, 0x75, 0x62, 0x6E, 0x6F, 0x72, 0x6D, 0x61, 0x6C, 0x20, 0x73,
            0x69, 0x6E, 0x67, 0x6C, 0x65,
        0xF9, 0x00, 0x00,
        0x03,
        0xF9, 0xC0, 0x00,    // -2
        0x04,
        0xF9, 0x7E, 0x00,    // qNaN
        0x05,
        0xF9, 0x7C, 0x01,    // sNaN
        0x06,
        0xF9, 0x7E, 0x0F,    // qNaN with payload 0x0f
        0x07,
        0xF9, 0x7C, 0x0F,    // sNaN with payload 0x0f
};


inline static bool CheckDouble(double d, uint64_t u)
{
   return UsefulBufUtil_CopyDoubleToUint64(d) != u;
}


int32_t HalfPrecisionDecodeBasicTests()
{
   UsefulBufC HalfPrecision = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedHalf);

   QCBORDecodeContext DC;
   QCBORDecode_Init(&DC, HalfPrecision, 0);

   QCBORItem Item;

   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_MAP) {
      return -1;
   }

   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != 0.0) {
      return -2;
   }

   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != INFINITY) {
      return -3;
   }

   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != -INFINITY) {
      return -4;
   }

   // TODO: NAN-related is this really converting right? It is carrying
   // payload, but this confuses things.
   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || !isnan(Item.val.dfnum)) {
      return -5;
   }

   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != 1.0) {
      return -6;
   }

   // Approximately 1/3
   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != 0.333251953125) {
      return -7;
   }

   // Largest half-precision
   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != 65504.0) {
      return -8;
   }

   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != INFINITY) {
      return -9;
   }

   // Smallest half-precision subnormal
   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != 0.00000005960464477539063) {
      return -10;
   }

   // Largest half-precision subnormal
   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != 0.00006097555160522461) {
      return -11;
   }

   // Smallest half-precision normal
   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != 0.00006103515625) {
      return -12;
   }

   // half-precision zero
   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != 0.0) {
      return -13;
   }

   // negative 2
   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != -2.0) {
      return -14;
   }

   // TODO: NAN-related double check these four tests
   QCBORDecode_GetNext(&DC, &Item); // qNaN
   if(Item.uDataType != QCBOR_TYPE_DOUBLE ||
      CheckDouble(Item.val.dfnum, 0x7ff8000000000000ULL)) {
      return -15;
   }
   QCBORDecode_GetNext(&DC, &Item); // sNaN
   if(Item.uDataType != QCBOR_TYPE_DOUBLE ||
      CheckDouble(Item.val.dfnum, 0x7ff0000000000001ULL)) {
      return -16;
   }
   QCBORDecode_GetNext(&DC, &Item); // qNaN with payload 0x0f
   if(Item.uDataType != QCBOR_TYPE_DOUBLE ||
      CheckDouble(Item.val.dfnum, 0x7ff800000000000fULL)) {
      return -17;
   }
   QCBORDecode_GetNext(&DC, &Item); // sNaN with payload 0x0f
   if(Item.uDataType != QCBOR_TYPE_DOUBLE ||
      CheckDouble(Item.val.dfnum, 0x7ff000000000000fULL)) {
      return -18;
   }

   if(QCBORDecode_Finish(&DC)) {
      return -19;
   }

   return 0;
}




int32_t HalfPrecisionAgainstRFCCodeTest()
{
    for(uint32_t uHalfP = 0; uHalfP < 0xffff; uHalfP += 60) {
        unsigned char x[2];
        x[1] = (uint8_t)(uHalfP & 0xff);
        x[0] = (uint8_t)(uHalfP >> 8); // uHalfP is always less than 0xffff
        double d = decode_half(x);

        // Contruct the CBOR for the half-precision float by hand
        UsefulBuf_MAKE_STACK_UB(__xx, 3);
        UsefulOutBuf UOB;
        UsefulOutBuf_Init(&UOB, __xx);

        const uint8_t uHalfPrecInitialByte = (uint8_t)(HALF_PREC_FLOAT + (CBOR_MAJOR_TYPE_SIMPLE << 5)); // 0xf9
        UsefulOutBuf_AppendByte(&UOB, uHalfPrecInitialByte); // The initial byte for a half-precision float
        UsefulOutBuf_AppendUint16(&UOB, (uint16_t)uHalfP);

        // Now parse the hand-constructed CBOR. This will invoke the
        // conversion to a float
        QCBORDecodeContext DC;
        QCBORDecode_Init(&DC, UsefulOutBuf_OutUBuf(&UOB), 0);

        QCBORItem Item;

        QCBORDecode_GetNext(&DC, &Item);
        if(Item.uDataType != QCBOR_TYPE_DOUBLE) {
            return -1;
        }

        //printf("%04x  QCBOR:%15.15f  RFC: %15.15f (%8x)\n",
        //       uHalfP, Item.val.fnum, d , UsefulBufUtil_CopyFloatToUint32(d));

        if(isnan(d)) {
            // The RFC code uses the native instructions which may or may not
            // handle sNaN, qNaN and NaN payloads correctly. This test just
            // makes sure it is a NaN and doesn't worry about the type of NaN
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


/*
 Expected output from preferred serialization of some of floating-point numbers
{"zero": 0.0,
 "negative zero": -0.0,
 "infinitity": Infinity,
 "negative infinitity": -Infinity,
 "NaN": NaN,
 "one": 1.0,
 "one third": 0.333251953125,
 "largest half-precision": 65504.0,
 "largest half-precision point one": 65504.1,
 "too-large half-precision": 65536.0,
 "smallest half subnormal": 5.960464477539063e-8,
 "smallest half normal": 0.00006103515625,
 "smallest half normal plus": 0.00006103515625000001,
 "smallest normal minus": 0.000030517578125,
 "largest single": 3.4028234663852886e+38,
 "largest single plus": 6.805646932770577e+38,
 "smallest single": 1.1754943508222875e-38,
 "smallest single plus": 1.1754943508222878e-38,
 "smallest single minus": 1.1754943508222874e-38,
 "smallest single minus more": 5.877471754111438e-39,
 3: -2.0, "single precision": 16777216.0,
 "single with precision loss": 16777217.0,
 1: "fin"}
 */
static const uint8_t spExpectedSmallest[] = {
   0xB8, 0x1A,
      0x64, 0x7A, 0x65, 0x72, 0x6F,
      0xF9, 0x00, 0x00,

      0x6D, 0x6E, 0x65, 0x67, 0x61, 0x74, 0x69, 0x76, 0x65, 0x20, 0x7A,
         0x65, 0x72, 0x6F,
      0xF9, 0x80, 0x00,

      0x6A, 0x69, 0x6E, 0x66, 0x69, 0x6E, 0x69, 0x74, 0x69, 0x74, 0x79,
      0xF9, 0x7C, 0x00,

      0x73, 0x6E, 0x65, 0x67, 0x61, 0x74, 0x69, 0x76, 0x65, 0x20, 0x69,
         0x6E, 0x66, 0x69, 0x6E, 0x69, 0x74, 0x69, 0x74, 0x79,
      0xF9, 0xFC, 0x00,

      0x63, 0x4E, 0x61, 0x4E,
      0xF9, 0x7E, 0x00,

      0x63, 0x6F, 0x6E, 0x65,
      0xF9, 0x3C, 0x00,

      0x69, 0x6F, 0x6E, 0x65, 0x20, 0x74, 0x68, 0x69, 0x72, 0x64,
      0xF9, 0x35, 0x55,

      0x76, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x73, 0x74, 0x20, 0x68, 0x61,
         0x6C, 0x66, 0x2D, 0x70, 0x72, 0x65, 0x63, 0x69, 0x73, 0x69,
         0x6F, 0x6E,
      0xF9, 0x7B, 0xFF,

      0x78, 0x20, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x73, 0x74, 0x20, 0x68,
         0x61, 0x6C, 0x66, 0x2D, 0x70, 0x72, 0x65, 0x63, 0x69, 0x73,
         0x69, 0x6F, 0x6E, 0x20, 0x70, 0x6F, 0x69, 0x6E, 0x74, 0x20,
         0x6F, 0x6E, 0x65,
      0xFB, 0x40, 0xEF, 0xFC, 0x03, 0x33, 0x33, 0x33, 0x33,

      0x78, 0x18, 0x74, 0x6F, 0x6F, 0x2D, 0x6C, 0x61, 0x72, 0x67, 0x65,
         0x20, 0x68, 0x61, 0x6C, 0x66, 0x2D, 0x70, 0x72, 0x65, 0x63,
         0x69, 0x73, 0x69, 0x6F, 0x6E,
      0xFA, 0x47, 0x80, 0x00, 0x00,

      0x77, 0x73, 0x6D, 0x61, 0x6C, 0x6C, 0x65, 0x73, 0x74,
         0x20, 0x68, 0x61, 0x6C, 0x66, 0x20, 0x73, 0x75, 0x62, 0x6E,
         0x6F, 0x72, 0x6D, 0x61, 0x6C,
      0xFA, 0x33, 0x80, 0x00, 0x00,

      0x74, 0x73, 0x6D, 0x61, 0x6C, 0x6C, 0x65, 0x73, 0x74, 0x20, 0x68,
         0x61, 0x6C, 0x66, 0x20, 0x6E, 0x6F, 0x72, 0x6D, 0x61, 0x6C,
      0xF9, 0x04, 0x00,

      0x78, 0x19, 0x73, 0x6D, 0x61, 0x6C, 0x6C, 0x65, 0x73, 0x74, 0x20,
         0x68, 0x61, 0x6C, 0x66, 0x20, 0x6E, 0x6F, 0x72, 0x6D, 0x61,
         0x6C, 0x20, 0x70, 0x6C, 0x75, 0x73,
      0xFB, 0x3F, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

      0x75, 0x73, 0x6D, 0x61, 0x6C, 0x6C, 0x65, 0x73, 0x74, 0x20, 0x6E,
         0x6F, 0x72, 0x6D, 0x61, 0x6C, 0x20, 0x6D, 0x69, 0x6E,
         0x75, 0x73,
      0xFB, 0x3F, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

      0x75, 0x73, 0x6D, 0x61, 0x6C, 0x6C, 0x65, 0x73, 0x74, 0x20, 0x6E,
         0x6F, 0x72, 0x6D, 0x61, 0x6C, 0x20, 0x6D, 0x69, 0x6E, 0x75,
         0x73,
      0xFA, 0x38, 0x00, 0x00, 0x00,

      0x6E, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x73, 0x74, 0x20, 0x73, 0x69,
         0x6E, 0x67, 0x6C, 0x65,
      0xFA, 0x7F, 0x7F, 0xFF, 0xFF,

      0x73, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x73, 0x74, 0x20, 0x73, 0x69,
         0x6E,0x67, 0x6C, 0x65, 0x20, 0x70, 0x6C, 0x75, 0x73,
      0xFB, 0x47, 0xEF, 0xFF, 0xFF, 0xE0, 0x00, 0x00, 0x01,

      0x73, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x73, 0x74, 0x20, 0x73, 0x69,
         0x6E, 0x67, 0x6C, 0x65, 0x20, 0x70, 0x6C, 0x75, 0x73,
      0xFB, 0x47, 0xFF, 0xFF, 0xFF, 0xE0, 0x00, 0x00, 0x00,

      0x6F, 0x73, 0x6D, 0x61, 0x6C, 0x6C, 0x65, 0x73, 0x74, 0x20, 0x73,
         0x69, 0x6E, 0x67, 0x6C, 0x65,
      0xFA, 0x00, 0x80, 0x00, 0x00,

      0x74, 0x73, 0x6D, 0x61, 0x6C, 0x6C, 0x65, 0x73, 0x74, 0x20, 0x73,
         0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x70, 0x6C, 0x75, 0x73,
      0xFB, 0x38, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

      0x75, 0x73, 0x6D, 0x61, 0x6C, 0x6C, 0x65, 0x73, 0x74, 0x20, 0x73,
         0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x6D, 0x69, 0x6E, 0x75,
         0x73,
      0xFB, 0x38, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

      0x78, 0x1A, 0x73, 0x6D, 0x61, 0x6C, 0x6C, 0x65, 0x73, 0x74, 0x20,
         0x73, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x6D, 0x69, 0x6E,
         0x75, 0x73, 0x20, 0x6D, 0x6F, 0x72, 0x65,
      0xFB, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

      0x03,
      0xF9, 0xC0, 0x00,

      0x70, 0x73, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x70, 0x72, 0x65,
         0x63, 0x69, 0x73, 0x69, 0x6F, 0x6E,
      0xFA, 0x4B, 0x80, 0x00, 0x00,

      0x78, 0x1A, 0x73, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x77, 0x69,
         0x74, 0x68, 0x20, 0x70, 0x72, 0x65, 0x63, 0x69, 0x73, 0x69,
         0x6F, 0x6E, 0x20, 0x6C, 0x6F, 0x73, 0x73,
      0xFB, 0x41, 0x70, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,

      0x01,
      0x63, 0x66, 0x69, 0x6E
};


/*
 Makes a double from a uint64_t by copying the bits, not
 by converting the value.
 */
#define MAKE_DOUBLE(x) UsefulBufUtil_CopyUint64ToDouble(x)


int32_t DoubleAsSmallestTest()
{
   UsefulBuf_MAKE_STACK_UB(EncodedHalfsMem, sizeof(spExpectedSmallest));

   QCBOREncodeContext EC;
   QCBOREncode_Init(&EC, EncodedHalfsMem);
   QCBOREncode_OpenMap(&EC);

   // Many of these are from
   // https://en.wikipedia.org/wiki/Half-precision_floating-point_format
   // and
   // https://en.wikipedia.org/wiki/Single-precision_floating-point_format

   // F9 0000                              # primitive(0)
   QCBOREncode_AddDoubleToMap(&EC, "zero", 0.00);

   // F9 8000                              # primitive(0)
   QCBOREncode_AddDoubleToMap(&EC, "negative zero", -0.00);

   // F9 7C00                              # primitive(31744)
   QCBOREncode_AddDoubleToMap(&EC, "infinitity", INFINITY);

   // F9 FC00                              # primitive(64512)
   QCBOREncode_AddDoubleToMap(&EC, "negative infinitity", -INFINITY);

   // F9 7E00                              # primitive(32256)
   QCBOREncode_AddDoubleToMap(&EC, "NaN", NAN);

   // TODO: test a few NaN variants

   // F9 3C00                              # primitive(15360)
   QCBOREncode_AddDoubleToMap(&EC, "one", 1.0);

   // F9 3555                              # primitive(13653)
   QCBOREncode_AddDoubleToMap(&EC, "one third", 0.333251953125);

   // 65504.0, converts to the large possible half-precision.
   // 0xF9, 0x7B, 0xFF,
   QCBOREncode_AddDoubleToMap(&EC, "largest half-precision", 65504.0);

   // 65504.1, the double that has both to large an exponent and too
   // much precision, so no conversion.
   // 0xFB, 0x40, 0xEF, 0xFC, 0x03, 0x33, 0x33, 0x33, 0x33,
   QCBOREncode_AddDoubleToMap(&EC, "largest half-precision point one", 65504.1);

   // 65536.0 has an exponent of 16, which is larger than 15, the
   // largest half-precision exponent. It is the exponent, not
   // precision loss that prevents conversion to half. It does convert
   // to single precision.
   // 0xFA, 0x47, 0x80, 0x00, 0x00,
   QCBOREncode_AddDoubleToMap(&EC, "too-large half-precision", 65536.0);

   // 5.9604644775390625E-8, the smallest possible half-precision
   // subnormal, digitis are lost converting to half, but not
   // when converting to a single
   // 0xFA, 0x33, 0x80, 0x00, 0x00,
   QCBOREncode_AddDoubleToMap(&EC,
                              "smallest half subnormal",
                              MAKE_DOUBLE(0x3e70000000000000));

   // 0.00006103515625, the double value that converts to the smallest
   // possible half-precision normal.  which is what should appear in
   // the output.
   // 0xF9, 0x04, 0x00,
   QCBOREncode_AddDoubleToMap(&EC,
                              "smallest half normal",
                              MAKE_DOUBLE(0x3f10000000000000));

   // 0.000061035156250000014 ,the double value that is a tiny bit
   // greater than smallest possible half-precision normal. It will be
   // output as a double because converting it will reduce precision.
   // 0xFB, 0x3F, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
   QCBOREncode_AddDoubleToMap(&EC,
                              "smallest half normal plus",
                              MAKE_DOUBLE(0x3f10000000000001));

   // 0.000061035156249999993, the double value that is a tiny bit
   // smaller than the smallest half-precision normal. This will fail
   // to convert to a half-precision because both the exponent is too
   // small and the precision is too large for a half-precision.
   // 0xFB, 0x3F, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   QCBOREncode_AddDoubleToMap(&EC,
                              "smallest normal minus",
                              MAKE_DOUBLE(0x3f0fffffffffffff));

   // 0.000030517578125, the double value that is too small to fit
   // into a half-precision because the exponent won't fit, not
   // because precision would be lost. (This would fit into a
   // half-precision subnormal, but there is no converstion to
   // that). This ends up encoded as a single-precision.
   // 0xFA, 0x38, 0x00, 0x00, 0x00,
   QCBOREncode_AddDoubleToMap(&EC,
                              "smallest normal minus",
                              MAKE_DOUBLE(0x3f00000000000000));

   // 3.4028234664e38, the value that converts to the largest possible
   // single-precision.
   // 0xFA, 0x7F, 0x7F, 0xFF, 0xFF,
   QCBOREncode_AddDoubleToMap(&EC,
                              "largest single",
                              MAKE_DOUBLE(0x47efffffe0000000));

   // 3.402823466385289E38, sightly larger than the largest possible
   // possible precision.  Conversion fails because precision would be
   // lost.
   // 0xFB, 0x47, 0xEF, 0xFF, 0xFF, 0xE0, 0x00, 0x00, 0x01,
   QCBOREncode_AddDoubleToMap(&EC,
                              "largest single plus",
                              MAKE_DOUBLE(0x47efffffe0000001));

   // 6.8056469327705772E38, slightly more larger than the largers
   // possible single precision.  Conversion fails because exponent is
   // too large.
   // 0xFB, 0x47, 0xFF, 0xFF, 0xFF, 0xE0, 0x00, 0x00, 0x00,
   QCBOREncode_AddDoubleToMap(&EC,
                              "largest single plus",
                              MAKE_DOUBLE(0x47ffffffe0000000));

   // 1.1754943508222875E-38, The double value that converts to the
   // smallest possible single-precision normal
   // 0xFA, 0x00, 0x80, 0x00, 0x00,
   QCBOREncode_AddDoubleToMap(&EC,
                              "smallest single",
                              MAKE_DOUBLE(0x3810000000000000));

   // 1.1754943508222878E-38, double value that is slightly larger
   // than the smallest single-precision normal. Conversion fails
   // because of precision
   // 0xFB, 0x38, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
   QCBOREncode_AddDoubleToMap(&EC,
                              "smallest single plus",
                              MAKE_DOUBLE(0x3810000000000001));

   // 1.1754943508222874E-38, slightly smaller than the smallest
   // single-precision normal.  Conversion fails because of precision
   // 0xFB, 0x38, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   QCBOREncode_AddDoubleToMap(&EC,
                              "smallest single minus",
                              MAKE_DOUBLE(0x380fffffffffffff));

   // 5.8774717541114375E-39, slightly smaller than the smallest
   // single-precision normal.  Conversion fails because the exponent
   // is too small.
   // 0xFB, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   QCBOREncode_AddDoubleToMap(&EC,
                              "smallest single minus more",
                              MAKE_DOUBLE(0x3800000000000000));

   // Just -2, which converts to a negative half-precision
   // F9 C000                              # primitive(49152)
   QCBOREncode_AddDoubleToMapN(&EC, 3, -2.0);

   // 16777216, No precision loss converting to single
   // FA 4B800000                          # primitive(1266679808)
   QCBOREncode_AddDoubleToMap(&EC, "single precision", 16777216);

   // 16777217, One more than above. Too much precision for a single
   // so no conversion.
   // 0xFB, 0x41, 0x70, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
   QCBOREncode_AddDoubleToMap(&EC, "single with precision loss", 16777217);

   // Just a convenient marker when cutting and pasting encoded CBOR
   QCBOREncode_AddSZStringToMapN(&EC, 1, "fin");

   QCBOREncode_CloseMap(&EC);

   UsefulBufC EncodedHalfs;
   QCBORError uErr = QCBOREncode_Finish(&EC, &EncodedHalfs);
   if(uErr) {
      return -1;
   }

   if(UsefulBuf_Compare(EncodedHalfs, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedSmallest))) {
      return -3;
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

int32_t GeneralFloatEncodeTests()
{
   UsefulBufC ExpectedFloats;
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
   UsefulBuf_MAKE_STACK_UB(OutBuffer, sizeof(spExpectedFloats));
   ExpectedFloats = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedFloats);
   (void)spExpectedFloatsNoHalf; // Avoid unused variable error
#else
   UsefulBuf_MAKE_STACK_UB(OutBuffer, sizeof(spExpectedFloatsNoHalf));
   ExpectedFloats = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedFloatsNoHalf);
   (void)spExpectedFloats; // Avoid unused variable error
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

   UsefulBufC Encoded;
   QCBORError uErr = QCBOREncode_Finish(&EC, &Encoded);
   if(uErr) {
      return -1;
   }

   if(UsefulBuf_Compare(Encoded, ExpectedFloats)) {
      return -3;
   }

   return 0;
}


/* returns 0 if equivalent, non-zero if not equivalent */
static int CHECK_EXPECTED_DOUBLE(double val, double expected)
{
   double diff = val - expected;

   diff = fabs(diff);

   if(diff > 0.000001) {
      return 1;
   } else {
      return 0;
   }
}
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */


int32_t GeneralFloatDecodeTests()
{
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
      || CHECK_EXPECTED_DOUBLE(3.14, Item.val.dfnum)
#else /* QCBOR_DISABLE_FLOAT_HW_USE */
      || Item.uDataType != QCBOR_TYPE_FLOAT
      || CHECK_EXPECTED_DOUBLE(3.14, Item.val.fnum)
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
      || Item.val.fnum != 0.0
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
