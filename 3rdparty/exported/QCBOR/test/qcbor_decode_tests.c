/*==============================================================================
 Copyright (c) 2016-2018, The Linux Foundation.
 Copyright (c) 2018-2022, Laurence Lundblade.
 Copyright (c) 2021, Arm Limited.
 All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.
    * Neither the name of The Linux Foundation nor the names of its
      contributors, nor the name "Laurence Lundblade" may be used to
      endorse or promote products derived from this software without
      specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 =============================================================================*/

#include "qcbor_decode_tests.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include <string.h>
#include <math.h> // for fabs()
#include "not_well_formed_cbor.h"

// Handy macro to compare a UsefulBuf to a C string
#define UsefulBufCompareToSZ(x, y) \
   UsefulBuf_Compare(x, UsefulBuf_FromSZ(y))

#ifdef  PRINT_FUNCTIONS_FOR_DEBUGGING
#include <stdio.h>

static void PrintUsefulBufC(const char *szLabel, UsefulBufC Buf)
{
   if(szLabel) {
      printf("%s ", szLabel);
   }

   size_t i;
   for(i = 0; i < Buf.len; i++) {
      uint8_t Z = ((uint8_t *)Buf.ptr)[i];
      printf("%02x ", Z);
   }
   printf("\n");

   fflush(stdout);
}
#endif /* PRINT_FUNCTIONS_FOR_DEBUGGING */

/*
   [
      -9223372036854775808,
      -4294967297,
      -4294967296,
      -4294967295,
      -4294967294,
      -2147483648,
      -2147483647,
      -65538,
      -65537,
      -65536,
      -65535,
      -65534,
      -257,
      -256,
      -255,
      -254,
      -25,
      -24,
      -23,
      -1,
      0,
      0,
      1,
      22,
      23,
      24,
      25,
      26,
      254,
      255,
      256,
      257,
      65534,
      65535,
      65536,
      65537,
      65538,
      2147483647,
      2147483647,
      2147483648,
      2147483649,
      4294967294,
      4294967295,
      4294967296,
      4294967297,
      9223372036854775807,
      18446744073709551615
    ]
 */

static const uint8_t spExpectedEncodedInts[] = {
   0x98, 0x2f, 0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff,
   0xff, 0xff, 0xff, 0x3b, 0x00, 0x00, 0x00, 0x01,
   0x00, 0x00, 0x00, 0x00, 0x3a, 0xff, 0xff, 0xff,
   0xff, 0x3a, 0xff, 0xff, 0xff, 0xfe, 0x3a, 0xff,
   0xff, 0xff, 0xfd, 0x3a, 0x7f, 0xff, 0xff, 0xff,
   0x3a, 0x7f, 0xff, 0xff, 0xfe, 0x3a, 0x00, 0x01,
   0x00, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x39,
   0xff, 0xff, 0x39, 0xff, 0xfe, 0x39, 0xff, 0xfd,
   0x39, 0x01, 0x00, 0x38, 0xff, 0x38, 0xfe, 0x38,
   0xfd, 0x38, 0x18, 0x37, 0x36, 0x20, 0x00, 0x00,
   0x01, 0x16, 0x17, 0x18, 0x18, 0x18, 0x19, 0x18,
   0x1a, 0x18, 0xfe, 0x18, 0xff, 0x19, 0x01, 0x00,
   0x19, 0x01, 0x01, 0x19, 0xff, 0xfe, 0x19, 0xff,
   0xff, 0x1a, 0x00, 0x01, 0x00, 0x00, 0x1a, 0x00,
   0x01, 0x00, 0x01, 0x1a, 0x00, 0x01, 0x00, 0x02,
   0x1a, 0x7f, 0xff, 0xff, 0xff, 0x1a, 0x7f, 0xff,
   0xff, 0xff, 0x1a, 0x80, 0x00, 0x00, 0x00, 0x1a,
   0x80, 0x00, 0x00, 0x01, 0x1a, 0xff, 0xff, 0xff,
   0xfe, 0x1a, 0xff, 0xff, 0xff, 0xff, 0x1b, 0x00,
   0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x1b,
   0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
   0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
   0xff, 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
   0xff, 0xff};


// return CBOR error or -1 if type of value doesn't match

static int32_t IntegerValuesParseTestInternal(QCBORDecodeContext *pDCtx)
{
   QCBORItem  Item;
   QCBORError nCBORError;

   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_ARRAY)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -9223372036854775807LL - 1)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -4294967297)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -4294967296)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -4294967295)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -4294967294)
      return -1;


   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -2147483648)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -2147483647)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -65538)
      return  -1;

   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -65537)
      return  -1;

   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -65536)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -65535)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -65534)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -257)
      return  -1;

   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -256)
      return  -1;

   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -255)
      return  -1;

   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -254)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -25)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -24)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -23)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -1)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 0)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 0)
      return  -1;

   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 1)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 22)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 23)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 24)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 25)
      return  -1;

   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 26)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 254)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 255)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 256)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 257)
      return  -1;

   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 65534)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 65535)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 65536)
      return  -1;

   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 65537)
      return  -1;

   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 65538)
      return  -1;

   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 2147483647)
      return  -1;

   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 2147483647)
      return  -1;

   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 2147483648)
      return  -1;

   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 2147483649)
      return  -1;

   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 4294967294)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 4294967295)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 4294967296)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 4294967297)
      return  -1;



   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 9223372036854775807LL)
      return  -1;


   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_UINT64 ||
      Item.val.uint64 != 18446744073709551615ULL)
      return  -1;


   if(QCBORDecode_Finish(pDCtx) != QCBOR_SUCCESS) {
      return -1;
   }

   return 0;
}


/* One less than the smallest negative integer allowed in C. Decoding
   this should fail.
   -9223372036854775809
 */
static const uint8_t spTooSmallNegative[] = {
   0x3b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};


/*
   Tests the decoding of lots of different integers sizes
   and values.
 */
int32_t IntegerValuesParseTest()
{
   int nReturn;
   QCBORDecodeContext DCtx;

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedEncodedInts),
                    QCBOR_DECODE_MODE_NORMAL);

   // The really big test of all successes
   nReturn = IntegerValuesParseTestInternal(&DCtx);
   if(nReturn) {
      return nReturn;
   }

   // The one large negative integer that can be parsed
   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spTooSmallNegative),
                    QCBOR_DECODE_MODE_NORMAL);

   QCBORItem item;
   if(QCBORDecode_GetNext(&DCtx, &item) != QCBOR_ERR_INT_OVERFLOW) {
      nReturn = -4000;
   }

   return(nReturn);
}


/*
   Creates a simple CBOR array and returns it in *pEncoded. The array is
   malloced and needs to be freed. This is used by several tests.

   Two of the inputs can be set. Two other items in the array are fixed.

 */

static uint8_t spSimpleArrayBuffer[50];

static int32_t CreateSimpleArray(int nInt1, int nInt2, uint8_t **pEncoded, size_t *pEncodedLen)
{
   QCBOREncodeContext ECtx;
   int nReturn = -1;

   *pEncoded = NULL;
   *pEncodedLen = INT32_MAX;

   // loop runs CBOR encoding twice. First with no buffer to
   // calculate the length so buffer can be allocated correctly,
   // and last with the buffer to do the actual encoding
   do {
      QCBOREncode_Init(&ECtx, (UsefulBuf){*pEncoded, *pEncodedLen});
      QCBOREncode_OpenArray(&ECtx);
      QCBOREncode_AddInt64(&ECtx, nInt1);
      QCBOREncode_AddInt64(&ECtx, nInt2);
      QCBOREncode_AddBytes(&ECtx, ((UsefulBufC) {"galactic", 8}));
      QCBOREncode_AddBytes(&ECtx, ((UsefulBufC) {"haven token", 11}));
      QCBOREncode_CloseArray(&ECtx);

      if(QCBOREncode_FinishGetSize(&ECtx, pEncodedLen))
         goto Done;

      if(*pEncoded != NULL) {
         nReturn = 0;
         goto Done;
      }

      // Use static buffer to avoid dependency on malloc()
      if(*pEncodedLen > sizeof(spSimpleArrayBuffer)) {
         goto Done;
      }
      *pEncoded = spSimpleArrayBuffer;

   } while(1);

Done:
   return nReturn;
}


/*
 Some basic CBOR with map and array used in a lot of tests.
 The map labels are all strings

   {
      "first integer": 42,
      "an array of two strings": [
         "string1", "string2"
      ],
      "map in a map": {
         "bytes 1": h'78787878',
         "bytes 2": h'79797979',
         "another int": 98,
         "text 2": "lies, damn lies and statistics"
      }
   }
 */
static const uint8_t pValidMapEncoded[] = {
   0xa3, 0x6d, 0x66, 0x69, 0x72, 0x73, 0x74, 0x20,
   0x69, 0x6e, 0x74, 0x65, 0x67, 0x65, 0x72, 0x18,
   0x2a, 0x77, 0x61, 0x6e, 0x20, 0x61, 0x72, 0x72,
   0x61, 0x79, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x77,
   0x6f, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67,
   0x73, 0x82, 0x67, 0x73, 0x74, 0x72, 0x69, 0x6e,
   0x67, 0x31, 0x67, 0x73, 0x74, 0x72, 0x69, 0x6e,
   0x67, 0x32, 0x6c, 0x6d, 0x61, 0x70, 0x20, 0x69,
   0x6e, 0x20, 0x61, 0x20, 0x6d, 0x61, 0x70, 0xa4,
   0x67, 0x62, 0x79, 0x74, 0x65, 0x73, 0x20, 0x31,
   0x44, 0x78, 0x78, 0x78, 0x78, 0x67, 0x62, 0x79,
   0x74, 0x65, 0x73, 0x20, 0x32, 0x44, 0x79, 0x79,
   0x79, 0x79, 0x6b, 0x61, 0x6e, 0x6f, 0x74, 0x68,
   0x65, 0x72, 0x20, 0x69, 0x6e, 0x74, 0x18, 0x62,
   0x66, 0x74, 0x65, 0x78, 0x74, 0x20, 0x32, 0x78,
   0x1e, 0x6c, 0x69, 0x65, 0x73, 0x2c, 0x20, 0x64,
   0x61, 0x6d, 0x6e, 0x20, 0x6c, 0x69, 0x65, 0x73,
   0x20, 0x61, 0x6e, 0x64, 0x20, 0x73, 0x74, 0x61,
   0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x73 };


#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
// Same as above, but with indefinite lengths.
static const uint8_t pValidMapIndefEncoded[] = {
   0xbf, 0x6d, 0x66, 0x69, 0x72, 0x73, 0x74, 0x20,
   0x69, 0x6e, 0x74, 0x65, 0x67, 0x65, 0x72, 0x18,
   0x2a, 0x77, 0x61, 0x6e, 0x20, 0x61, 0x72, 0x72,
   0x61, 0x79, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x77,
   0x6f, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67,
   0x73, 0x9f, 0x67, 0x73, 0x74, 0x72, 0x69, 0x6e,
   0x67, 0x31, 0x67, 0x73, 0x74, 0x72, 0x69, 0x6e,
   0x67, 0x32, 0xff, 0x6c, 0x6d, 0x61, 0x70, 0x20,
   0x69, 0x6e, 0x20, 0x61, 0x20, 0x6d, 0x61, 0x70,
   0xbf, 0x67, 0x62, 0x79, 0x74, 0x65, 0x73, 0x20,
   0x31, 0x44, 0x78, 0x78, 0x78, 0x78, 0x67, 0x62,
   0x79, 0x74, 0x65, 0x73, 0x20, 0x32, 0x44, 0x79,
   0x79, 0x79, 0x79, 0x6b, 0x61, 0x6e, 0x6f, 0x74,
   0x68, 0x65, 0x72, 0x20, 0x69, 0x6e, 0x74, 0x18,
   0x62, 0x66, 0x74, 0x65, 0x78, 0x74, 0x20, 0x32,
   0x78, 0x1e, 0x6c, 0x69, 0x65, 0x73, 0x2c, 0x20,
   0x64, 0x61, 0x6d, 0x6e, 0x20, 0x6c, 0x69, 0x65,
   0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x73, 0x74,
   0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x73,
   0xff, 0xff};
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */


static int32_t ParseOrderedArray(const uint8_t *pEncoded,
                                 size_t nLen,
                                 int64_t *pInt1,
                                 int64_t *pInt2,
                                 const uint8_t **pBuf3,
                                 size_t *pBuf3Len,
                                 const uint8_t **pBuf4,
                                 size_t *pBuf4Len)
{
   QCBORDecodeContext DCtx;
   QCBORItem          Item;
   int                nReturn = -1; // assume error until success

   QCBORDecode_Init(&DCtx,
                    (UsefulBufC){pEncoded, nLen},
                    QCBOR_DECODE_MODE_NORMAL);

   // Make sure the first thing is a map
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
      Item.uDataType != QCBOR_TYPE_ARRAY) {
      goto Done;
   }

   // First integer
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
      Item.uDataType != QCBOR_TYPE_INT64) {
      goto Done;
   }
   *pInt1 = Item.val.int64;

   // Second integer
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
      Item.uDataType != QCBOR_TYPE_INT64) {
      goto Done;
   }
   *pInt2 = Item.val.int64;

   // First string
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
      Item.uDataType != QCBOR_TYPE_BYTE_STRING) {
      goto Done;
   }
   *pBuf3 = Item.val.string.ptr;
   *pBuf3Len = Item.val.string.len;

   // Second string
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
      Item.uDataType != QCBOR_TYPE_BYTE_STRING) {
      goto Done;
   }
   *pBuf4 = Item.val.string.ptr;
   *pBuf4Len = Item.val.string.len;

   nReturn = 0;

Done:
   return(nReturn);
}




int32_t SimpleArrayTest()
{
   uint8_t *pEncoded;
   size_t  nEncodedLen;

   int64_t i1=0, i2=0;
   size_t i3=0, i4=0;
   const uint8_t *s3= (uint8_t *)"";
   const uint8_t *s4= (uint8_t *)"";


   if(CreateSimpleArray(23, 6000, &pEncoded, &nEncodedLen) < 0) {
      return(-1);
   }

   ParseOrderedArray(pEncoded, nEncodedLen, &i1, &i2, &s3, &i3, &s4, &i4);

   if(i1 != 23 ||
      i2 != 6000 ||
      i3 != 8 ||
      i4 != 11 ||
      memcmp("galactic", s3, 8) !=0 ||
      memcmp("haven token", s4, 11) !=0) {
      return(-1);
   }

   return(0);
}


/*
 [
    0,
    [],
    [
       [],
       [
          0
       ],
       {},
       {
          1: {},
          2: {},
          3: []
       }
    ]
 ]
 */
static uint8_t sEmpties[] = {
   0x83, 0x00, 0x80, 0x84, 0x80, 0x81, 0x00, 0xa0,
   0xa3, 0x01, 0xa0, 0x02, 0xa0, 0x03, 0x80};

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
/* Same as above, but with indefinte lengths */
static const uint8_t sEmptiesIndef[] = {
0x9F,
   0x00,
   0x9F,
      0xFF,
   0x9F,
      0x9F,
         0xFF,
      0x9F,
         0x00,
         0xFF,
      0xBF,
         0xFF,
      0xBF,
         0x01,
         0xBF,
            0xFF,
         0x02,
         0xBF,
            0xFF,
         0x03,
         0x9F,
            0xFF,
         0xFF,
      0xFF,
   0xFF};
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */


static int32_t CheckEmpties(UsefulBufC input, bool bCheckCounts)
{
   QCBORDecodeContext DCtx;
   QCBORItem Item;

   QCBORDecode_Init(&DCtx,
                    input,
                    QCBOR_DECODE_MODE_NORMAL);

   // Array with 3 items
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
      Item.uDataType != QCBOR_TYPE_ARRAY ||
      Item.uNestingLevel != 0 ||
      Item.uNextNestLevel != 1 ||
      (bCheckCounts && Item.val.uCount != 3)) {
      return -1;
   }

   // An integer 0
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
      Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.uNestingLevel != 1 ||
      Item.uNextNestLevel != 1 ||
      Item.val.uint64 != 0) {
      return -2;
   }

   // An empty array
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
      Item.uDataType != QCBOR_TYPE_ARRAY ||
      Item.uNestingLevel != 1 ||
      Item.uNextNestLevel != 1 ||
      (bCheckCounts && Item.val.uCount != 0)) {
      return -3;
   }

   // An array with 4 items
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
      Item.uDataType != QCBOR_TYPE_ARRAY ||
      Item.uNestingLevel != 1 ||
      Item.uNextNestLevel != 2 ||
      (bCheckCounts && Item.val.uCount != 4)) {
      return -4;
   }

   // An empty array
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
      Item.uDataType != QCBOR_TYPE_ARRAY ||
      Item.uNestingLevel != 2 ||
      Item.uNextNestLevel != 2 ||
      (bCheckCounts && Item.val.uCount != 0)) {
      return -5;
   }

   // An array with 1 item
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
      Item.uDataType != QCBOR_TYPE_ARRAY ||
      Item.uNestingLevel != 2 ||
      Item.uNextNestLevel != 3 ||
      (bCheckCounts && Item.val.uCount != 1)) {
      return -6;
   }

   // An integer 0
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
      Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.uNestingLevel != 3 ||
      Item.uNextNestLevel != 2 ||
      Item.val.uint64 != 0) {
      return -7;
   }

   // An empty map
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
      Item.uDataType != QCBOR_TYPE_MAP ||
      Item.uNestingLevel != 2 ||
      Item.uNextNestLevel != 2 ||
      (bCheckCounts && Item.val.uCount != 0)) {
      return -8;
   }

   // A map with 3 items
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
      Item.uDataType != QCBOR_TYPE_MAP ||
      Item.uNestingLevel != 2 ||
      Item.uNextNestLevel != 3 ||
      (bCheckCounts && Item.val.uCount != 3)) {
      return -9;
   }

   // An empty map
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
      Item.uDataType != QCBOR_TYPE_MAP ||
      Item.uNestingLevel != 3 ||
      Item.uNextNestLevel != 3 ||
      (bCheckCounts && Item.val.uCount != 0)) {
      return -10;
   }

   // An empty map
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
      Item.uDataType != QCBOR_TYPE_MAP ||
      Item.uNestingLevel != 3 ||
      Item.uNextNestLevel != 3 ||
      (bCheckCounts && Item.val.uCount != 0)) {
      return -11;
   }

   // An empty array
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
      Item.uDataType != QCBOR_TYPE_ARRAY ||
      Item.uNestingLevel != 3 ||
      Item.uNextNestLevel != 0 ||
      (bCheckCounts && Item.val.uCount != 0)) {
      return -12;
   }

   if(QCBORDecode_Finish(&DCtx) != QCBOR_SUCCESS) {
      return -13;
   }
   return 0;
}


int32_t EmptyMapsAndArraysTest()
{
   int nResult;
   nResult = CheckEmpties(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(sEmpties),
                     true);
   if(nResult) {
      return nResult;
   }

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   nResult = CheckEmpties(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(sEmptiesIndef),
                     false);

   if(nResult) {
      return nResult -100;
   }
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */

   return 0;
}


static const uint8_t sEmptyMap[] = {
                              0xA1,     //# map(1)
                              0x02,     //# unsigned(2)
                              0xA0,     //# map(0)
};

int32_t ParseEmptyMapInMapTest(void)
{
   QCBORDecodeContext DCtx;
   QCBORItem Item;
   int nReturn = 0;
   QCBORError uErr;

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(sEmptyMap),
                    QCBOR_DECODE_MODE_NORMAL);

   /* now open the first Map */
   uErr = QCBORDecode_GetNext(&DCtx, &Item);
    if(uErr != QCBOR_SUCCESS ||
       Item.uDataType != QCBOR_TYPE_MAP) {
      nReturn = -3;
      goto done;
    }

   if(QCBORDecode_GetNext(&DCtx, &Item) != 0) {
     nReturn = -1;
     goto done;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP ||
      Item.uNestingLevel != 1 ||
      Item.label.int64 != 2) {
     nReturn = -2;
     goto done;
   }

 done:
   return(nReturn);
}


/* [[[[[[[[[[]]]]]]]]]] */
static const uint8_t spDeepArrays[] = {
   0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81,
   0x81, 0x80};

int32_t ParseDeepArrayTest()
{
   QCBORDecodeContext DCtx;
   int nReturn = 0;
   int i;

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spDeepArrays),
                    QCBOR_DECODE_MODE_NORMAL);

   for(i = 0; i < 10; i++) {
      QCBORItem Item;

      if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
         Item.uDataType != QCBOR_TYPE_ARRAY ||
         Item.uNestingLevel != i) {
         nReturn = -1;
         break;
      }
   }

   return(nReturn);
}

/* Big enough to test nesting to the depth of 24
 [[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]
 */
static const uint8_t spTooDeepArrays[] = {
   0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81,
   0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81,
   0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81,
   0x80};

int32_t ParseTooDeepArrayTest()
{
   QCBORDecodeContext DCtx;
   int nReturn = 0;
   int i;
   QCBORItem Item;


   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spTooDeepArrays),
                    QCBOR_DECODE_MODE_NORMAL);

   for(i = 0; i < QCBOR_MAX_ARRAY_NESTING1; i++) {

      if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
         Item.uDataType != QCBOR_TYPE_ARRAY ||
         Item.uNestingLevel != i) {
         nReturn = -1;
         break;
      }
   }

   if(QCBORDecode_GetNext(&DCtx, &Item) != QCBOR_ERR_ARRAY_DECODE_NESTING_TOO_DEEP)
      nReturn = -1;

   return(nReturn);
}




int32_t ShortBufferParseTest()
{
   int nResult = 0;

   for(size_t nNum = sizeof(spExpectedEncodedInts)-1; nNum; nNum--) {
      QCBORDecodeContext DCtx;

      QCBORDecode_Init(&DCtx,
                       (UsefulBufC){spExpectedEncodedInts, nNum},
                       QCBOR_DECODE_MODE_NORMAL);

      const int nErr = IntegerValuesParseTestInternal(&DCtx);

      if(nErr != QCBOR_ERR_HIT_END && nErr != QCBOR_ERR_NO_MORE_ITEMS) {
         nResult = -1;
         goto Done;
      }
   }
Done:
   return nResult;
}



int32_t ShortBufferParseTest2()
{
   uint8_t *pEncoded;
   int      nReturn;
   size_t   nEncodedLen;

   int64_t i1, i2;
   size_t i3, i4;
   const uint8_t *s3, *s4;

   nReturn = 0;

   if(CreateSimpleArray(23, 6000, &pEncoded, &nEncodedLen) < 0) {
      return(-1);
   }

   for(nEncodedLen--; nEncodedLen; nEncodedLen--) {
      int nResult = ParseOrderedArray(pEncoded, (uint32_t)nEncodedLen, &i1,
                                      &i2, &s3, &i3, &s4, &i4);
      if(nResult == 0) {
         nReturn = -1;
      }
   }

   return(nReturn);
}

/*
 Decode and thoroughly check a moderately complex
 set of maps. Can be run in QCBOR_DECODE_MODE_NORMAL or in
 QCBOR_DECODE_MODE_MAP_STRINGS_ONLY.
 */
static int32_t ParseMapTest1(QCBORDecodeMode nMode)
{
   QCBORDecodeContext DCtx;
   QCBORItem Item;
   QCBORError nCBORError;

   QCBORDecode_Init(&DCtx,
                    (UsefulBufC){pValidMapEncoded, sizeof(pValidMapEncoded)},
                    nMode);

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP ||
      Item.val.uCount != 3)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }

   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 42 ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.label.string, "first integer")) {
      return -1;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.label.string, "an array of two strings") ||
      Item.uDataType != QCBOR_TYPE_ARRAY ||
      Item.val.uCount != 2)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "string1")) {
      return -1;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "string2")) {
      return -1;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.label.string, "map in a map") ||
      Item.uDataType != QCBOR_TYPE_MAP ||
      Item.val.uCount != 4) {
      return -1;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBuf_Compare(Item.label.string, UsefulBuf_FromSZ("bytes 1"))||
      Item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "xxxx")) {
      return -1;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBufCompareToSZ(Item.label.string, "bytes 2") ||
      Item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "yyyy")) {
      return -1;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.label.string, "another int") ||
      Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 98)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBuf_Compare(Item.label.string, UsefulBuf_FromSZ("text 2"))||
      Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "lies, damn lies and statistics")) {
      return -1;
   }

   return 0;
}


/*
 Decode and thoroughly check a moderately complex
 set of maps in the QCBOR_DECODE_MODE_MAP_AS_ARRAY mode.
 */
int32_t ParseMapAsArrayTest()
{
   QCBORDecodeContext DCtx;
   QCBORItem Item;
   QCBORError nCBORError;

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pValidMapEncoded),
                    QCBOR_DECODE_MODE_MAP_AS_ARRAY);

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP_AS_ARRAY ||
      Item.val.uCount != 6) {
      return -1;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      Item.uLabelType != QCBOR_TYPE_NONE ||
      UsefulBufCompareToSZ(Item.val.string, "first integer")) {
      return -2;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_NONE ||
      Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 42 ||
      Item.uDataAlloc ||
      Item.uLabelAlloc) {
      return -3;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_NONE ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "an array of two strings") ||
      Item.uDataType != QCBOR_TYPE_TEXT_STRING) {
      return -4;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_NONE ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      Item.uDataType != QCBOR_TYPE_ARRAY ||
      Item.val.uCount != 2) {
      return -5;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.val.string.len != 7 ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBuf_Compare(Item.val.string, UsefulBuf_FromSZ("string1"))) {
      return -6;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBuf_Compare(Item.val.string, UsefulBuf_FromSZ("string2"))) {
      return -7;
   }


   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_NONE ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "map in a map")) {
      return -8;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_NONE ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      Item.uDataType != QCBOR_TYPE_MAP_AS_ARRAY ||
      Item.val.uCount != 8) {
      return -9;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_NONE ||
      UsefulBufCompareToSZ(Item.val.string, "bytes 1") ||
      Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc) {
      return -10;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_NONE ||
      Item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "xxxx")) {
      return -11;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_NONE ||
      UsefulBufCompareToSZ(Item.val.string, "bytes 2") ||
      Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc) {
      return -12;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_NONE ||
      Item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "yyyy")) {
      return -13;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_NONE ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "another int") ||
      Item.uDataType != QCBOR_TYPE_TEXT_STRING) {
      return -14;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_NONE ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 98) {
      return -15;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_NONE ||
      UsefulBufCompareToSZ(Item.val.string, "text 2") ||
      Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc) {
      return -16;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_NONE ||
      Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "lies, damn lies and statistics")) {
      return -17;
   }


   /*
    Test with map that nearly QCBOR_MAX_ITEMS_IN_ARRAY items in a
    map that when interpreted as an array will be too many. Test
    data just has the start of the map, not all the items in the map.
    */
   static const uint8_t pTooLargeMap[] = {0xb9, 0xff, 0xfd};

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pTooLargeMap),
                    QCBOR_DECODE_MODE_MAP_AS_ARRAY);

   if((QCBOR_ERR_ARRAY_DECODE_TOO_LONG != QCBORDecode_GetNext(&DCtx, &Item))) {
      return -50;
   }

   // TODO: test decoding of labels that are arrays or such
   // TODO: test spiffy decoding of QCBOR_DECODE_MODE_MAP_AS_ARRAY

   return 0;
}


/*
 Fully or partially decode pValidMapEncoded. When
 partially decoding check for the right error code.
 How much partial decoding depends on nLevel.

 The partial decodes test error conditions of
 incomplete encoded input.

 This could be combined with the above test
 and made prettier and maybe a little more
 thorough.
 */
static int32_t ExtraBytesTest(int nLevel)
{
   QCBORDecodeContext DCtx;
   QCBORItem Item;
   QCBORError nCBORError;

   QCBORDecode_Init(&DCtx,
                    (UsefulBufC){pValidMapEncoded, sizeof(pValidMapEncoded)},
                    QCBOR_DECODE_MODE_NORMAL);

   if(nLevel < 1) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_EXTRA_BYTES) {
         return -1;
      } else {
         return 0;
      }
   }


   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP ||
      Item.val.uCount != 3)
      return -2;

   if(nLevel < 2) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED) {
         return -3;
      } else {
         return 0;
      }
   }


   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.uCount != 42 ||
      UsefulBufCompareToSZ(Item.label.string, "first integer")) {
      return -4;
   }

   if(nLevel < 3) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED) {
         return -5;
      } else {
         return 0;
      }
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBufCompareToSZ(Item.label.string, "an array of two strings") ||
      Item.uDataType != QCBOR_TYPE_ARRAY ||
      Item.val.uCount != 2) {
      return -6;
   }


   if(nLevel < 4) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED) {
         return -7;
      } else {
         return 0;
      }
   }


   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBufCompareToSZ(Item.val.string, "string1")) {
      return -8;
   }

   if(nLevel < 5) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED) {
         return -9;
      } else {
         return 0;
      }
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBufCompareToSZ(Item.val.string, "string2")) {
      return -10;
   }

   if(nLevel < 6) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED) {
         return -11;
      } else {
         return 0;
      }
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBufCompareToSZ(Item.label.string, "map in a map") ||
      Item.uDataType != QCBOR_TYPE_MAP ||
      Item.val.uCount != 4)
      return -12;

   if(nLevel < 7) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED) {
         return -13;
      } else {
         return 0;
      }
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBufCompareToSZ(Item.label.string, "bytes 1") ||
      Item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      UsefulBufCompareToSZ(Item.val.string, "xxxx")) {
      return -14;
   }

   if(nLevel < 8) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED) {
         return -15;
      } else {
         return 0;
      }
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBufCompareToSZ(Item.label.string, "bytes 2") ||
      Item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      UsefulBufCompareToSZ(Item.val.string, "yyyy")) {
      return -16;
   }

   if(nLevel < 9) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED) {
         return -17;
      } else {
         return 0;
      }
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBufCompareToSZ(Item.label.string, "another int") ||
      Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 98)
      return -18;

   if(nLevel < 10) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED) {
         return -19;
      } else {
         return 0;
      }
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBuf_Compare(Item.label.string, UsefulBuf_FromSZ("text 2"))||
      Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBufCompareToSZ(Item.val.string, "lies, damn lies and statistics")) {
      return -20;
   }

   if(QCBORDecode_Finish(&DCtx)) {
      return -21;
   }

   return 0;
}




int32_t ParseMapTest()
{
   // Parse a moderatly complex map structure very thoroughly
   int32_t nResult = ParseMapTest1(QCBOR_DECODE_MODE_NORMAL);
   if(nResult) {
      return nResult;
   }

   // Again, but in strings-only mode. It should succeed since the input
   // map has only string labels.
   nResult = ParseMapTest1(QCBOR_DECODE_MODE_MAP_STRINGS_ONLY);
   if(nResult) {
      return nResult;
   }

   // Again, but try to finish the decoding before the end of the
   // input at 10 different place and see that the right error code
   // is returned.
   for(int i = 0; i < 10; i++) {
      nResult = ExtraBytesTest(i);
      if(nResult) {
         break;
      }
   }

   return nResult;
}


/* The simple-values including some not well formed */
static const uint8_t spSimpleValues[] = {
   0x8a, 0xf4, 0xf5, 0xf6, 0xf7, 0xff, 0xe0, 0xf3,
   0xf8, 0x00, 0xf8, 0x13, 0xf8, 0x1f, 0xf8, 0x20,
   0xf8, 0xff};

int32_t ParseSimpleTest()
{
   QCBORDecodeContext DCtx;
   QCBORItem Item;
   QCBORError nCBORError;


   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spSimpleValues),
                    QCBOR_DECODE_MODE_NORMAL);


   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_ARRAY ||
      Item.val.uCount != 10)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_FALSE)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_TRUE)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_NULL)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_UNDEF)
      return -1;

   // A break
   if(QCBORDecode_GetNext(&DCtx, &Item) != QCBOR_ERR_BAD_BREAK)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_UKNOWN_SIMPLE || Item.val.uSimple != 0)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_UKNOWN_SIMPLE || Item.val.uSimple != 19)
      return -1;

   if(QCBORDecode_GetNext(&DCtx, &Item) != QCBOR_ERR_BAD_TYPE_7)
      return -1;

   if(QCBORDecode_GetNext(&DCtx, &Item) != QCBOR_ERR_BAD_TYPE_7)
      return -1;

   if(QCBORDecode_GetNext(&DCtx, &Item) != QCBOR_ERR_BAD_TYPE_7)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_UKNOWN_SIMPLE || Item.val.uSimple != 32)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return (int32_t)nCBORError;
   if(Item.uDataType != QCBOR_TYPE_UKNOWN_SIMPLE || Item.val.uSimple != 255)
      return -1;

   return 0;

}


int32_t NotWellFormedTests()
{
   // Loop over all the not-well-formed instance of CBOR
   // that are test vectors in not_well_formed_cbor.h
   const uint16_t nArraySize = C_ARRAY_COUNT(paNotWellFormedCBOR,
                                             struct someBinaryBytes);
   for(uint16_t nIterate = 0; nIterate < nArraySize; nIterate++) {
      const struct someBinaryBytes *pBytes = &paNotWellFormedCBOR[nIterate];
      const UsefulBufC Input = (UsefulBufC){pBytes->p, pBytes->n};

      // Set up decoder context. String allocator needed for indefinite
      // string test cases
      QCBORDecodeContext DCtx;
      QCBORDecode_Init(&DCtx, Input, QCBOR_DECODE_MODE_NORMAL);
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
      UsefulBuf_MAKE_STACK_UB(Pool, 100);
      QCBORDecode_SetMemPool(&DCtx, Pool, 0);
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */

      // Loop getting items until no more to get
      QCBORError uCBORError;
      do {
         QCBORItem Item;

         uCBORError = QCBORDecode_GetNext(&DCtx, &Item);
      } while(uCBORError == QCBOR_SUCCESS);

      // Every test vector must fail with
      // a not-well-formed error. If not
      // this test fails.
      if(!QCBORDecode_IsNotWellFormedError(uCBORError) &&
         uCBORError != QCBOR_ERR_NO_MORE_ITEMS) {
         /* Return index of failure and QCBOR error in the result */
         return (int32_t)(nIterate * 100 + uCBORError);
      }
   }
   return 0;
}


// TODO: add a test index and report it so it is eaier to figure out which test failed.
struct FailInput {
   UsefulBufC Input;
   QCBORError nError;
};


static int32_t ProcessFailures(const struct FailInput *pFailInputs, size_t nNumFails)
{
   for(const struct FailInput *pF = pFailInputs; pF < pFailInputs + nNumFails; pF++) {
      QCBORDecodeContext DCtx;
      QCBORError         uCBORError;

      QCBORDecode_Init(&DCtx, pF->Input, QCBOR_DECODE_MODE_NORMAL);

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
      // Set up the decoding context including a memory pool so that
      // indefinite length items can be checked
      UsefulBuf_MAKE_STACK_UB(Pool, 100);

      uCBORError = QCBORDecode_SetMemPool(&DCtx, Pool, 0);
      if(uCBORError) {
         return -9;
      }
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */


      // Iterate until there is an error of some sort error
      QCBORItem Item;
      do {
         // Set to something none-zero, something other than QCBOR_TYPE_NONE
         memset(&Item, 0x33, sizeof(Item));

         uCBORError = QCBORDecode_GetNext(&DCtx, &Item);
      } while(uCBORError == QCBOR_SUCCESS);



      // Must get the expected error or the this test fails
      // The data and label type must also be QCBOR_TYPE_NONE
      if(uCBORError != pF->nError ||
         Item.uDataType != QCBOR_TYPE_NONE ||
         Item.uLabelType != QCBOR_TYPE_NONE) {
         // return index of CBOR + 100
         const size_t nIndex = (size_t)(pF - pFailInputs);
         return (int32_t)(nIndex * 100 + uCBORError);
      }
   }

   return 0;
}


static const struct FailInput Failures[] = {
   // Most of this is copied from not_well_formed.h. Here the error code
   // returned is also checked.

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
   // Indefinite length strings must be closed off
   // An indefinite length byte string not closed off
   { {(uint8_t[]){0x5f, 0x41, 0x00}, 3}, QCBOR_ERR_HIT_END },
   // An indefinite length text string not closed off
   { {(uint8_t[]){0x7f, 0x61, 0x00}, 3}, QCBOR_ERR_HIT_END },


   // All the chunks in an indefinite length string must be of the type of
   // indefinite length string
   // indefinite length byte string with text string chunk
   { {(uint8_t[]){0x5f, 0x61, 0x00, 0xff}, 4}, QCBOR_ERR_INDEFINITE_STRING_CHUNK },
   // indefinite length text string with a byte string chunk
   { {(uint8_t[]){0x7f, 0x41, 0x00, 0xff}, 4}, QCBOR_ERR_INDEFINITE_STRING_CHUNK },
   // indefinite length byte string with an positive integer chunk
   { {(uint8_t[]){0x5f, 0x00, 0xff}, 3}, QCBOR_ERR_INDEFINITE_STRING_CHUNK },
   // indefinite length byte string with an negative integer chunk
   { {(uint8_t[]){0x5f, 0x21, 0xff}, 3}, QCBOR_ERR_INDEFINITE_STRING_CHUNK },
   // indefinite length byte string with an array chunk
   { {(uint8_t[]){0x5f, 0x80, 0xff}, 3}, QCBOR_ERR_INDEFINITE_STRING_CHUNK },
   // indefinite length byte string with an map chunk
   { {(uint8_t[]){0x5f, 0xa0, 0xff}, 3}, QCBOR_ERR_INDEFINITE_STRING_CHUNK },
   // indefinite length byte string with tagged integer chunk
   { {(uint8_t[]){0x5f, 0xc0, 0x00, 0xff}, 4}, QCBOR_ERR_INDEFINITE_STRING_CHUNK },
   // indefinite length byte string with an simple type chunk
   { {(uint8_t[]){0x5f, 0xe0, 0xff}, 3}, QCBOR_ERR_INDEFINITE_STRING_CHUNK },
   { {(uint8_t[]){0x5f, 0x5f, 0x41, 0x00, 0xff, 0xff}, 6}, QCBOR_ERR_INDEFINITE_STRING_CHUNK},
   // indefinite length text string with indefinite string inside
   { {(uint8_t[]){0x7f, 0x7f, 0x61, 0x00, 0xff, 0xff}, 6}, QCBOR_ERR_INDEFINITE_STRING_CHUNK},

#else /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */

   { {(uint8_t[]){0x5f, 0x41, 0x00}, 3}, QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED },
   // An indefinite length text string not closed off
   { {(uint8_t[]){0x7f, 0x61, 0x00}, 3}, QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED },


   // All the chunks in an indefinite length string must be of the type of
   // indefinite length string
   // indefinite length byte string with text string chunk
   { {(uint8_t[]){0x5f, 0x61, 0x00, 0xff}, 4}, QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED },
   // indefinite length text string with a byte string chunk
   { {(uint8_t[]){0x7f, 0x41, 0x00, 0xff}, 4}, QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED },
   // indefinite length byte string with an positive integer chunk
   { {(uint8_t[]){0x5f, 0x00, 0xff}, 3}, QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED },
   // indefinite length byte string with an negative integer chunk
   { {(uint8_t[]){0x5f, 0x21, 0xff}, 3}, QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED },
   // indefinite length byte string with an array chunk
   { {(uint8_t[]){0x5f, 0x80, 0xff}, 3}, QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED },
   // indefinite length byte string with an map chunk
   { {(uint8_t[]){0x5f, 0xa0, 0xff}, 3}, QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED },
   // indefinite length byte string with tagged integer chunk
   { {(uint8_t[]){0x5f, 0xc0, 0x00, 0xff}, 4}, QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED },
   // indefinite length byte string with an simple type chunk
   { {(uint8_t[]){0x5f, 0xe0, 0xff}, 3}, QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED },
   { {(uint8_t[]){0x5f, 0x5f, 0x41, 0x00, 0xff, 0xff}, 6}, QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED},
   // indefinite length text string with indefinite string inside
   { {(uint8_t[]){0x7f, 0x7f, 0x61, 0x00, 0xff, 0xff}, 6}, QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED},
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */


   // Definte length maps and arrays must be closed by having the right number of items
   // A definte length array that is supposed to have 1 item, but has none
   { {(uint8_t[]){0x81}, 1}, QCBOR_ERR_NO_MORE_ITEMS },
   // A definte length array that is supposed to have 2 items, but has only 1
   { {(uint8_t[]){0x82, 0x00}, 2}, QCBOR_ERR_NO_MORE_ITEMS },
   // A definte length array that is supposed to have 511 items, but has only 1
   { {(uint8_t[]){0x9a, 0x01, 0xff, 0x00}, 4}, QCBOR_ERR_HIT_END },
   // A definte length map that is supposed to have 1 item, but has none
   { {(uint8_t[]){0xa1}, 1}, QCBOR_ERR_NO_MORE_ITEMS },
   // A definte length map that is supposed to have s item, but has only 1
   { {(uint8_t[]){0xa2, 0x01, 0x02}, 3}, QCBOR_ERR_NO_MORE_ITEMS },

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   // Indefinte length maps and arrays must be ended by a break
   // Indefinite length array with zero items and no break
   { {(uint8_t[]){0x9f}, 1}, QCBOR_ERR_NO_MORE_ITEMS },
   // Indefinite length array with two items and no break
   { {(uint8_t[]){0x9f, 0x01, 0x02}, 3}, QCBOR_ERR_NO_MORE_ITEMS },
   // Indefinite length map with zero items and no break
   { {(uint8_t[]){0xbf}, 1}, QCBOR_ERR_NO_MORE_ITEMS },
   // Indefinite length map with two items and no break
   { {(uint8_t[]){0xbf, 0x01, 0x02, 0x01, 0x02}, 5}, QCBOR_ERR_NO_MORE_ITEMS },


   // Nested maps and arrays must be closed off (some extra nested test vectors)
   // Unclosed indefinite array containing a closed definite length array
   { {(uint8_t[]){0x9f, 0x80, 0x00}, 3}, QCBOR_ERR_NO_MORE_ITEMS },
   // Definite length array containing an unclosed indefinite length array
   { {(uint8_t[]){0x81, 0x9f}, 2}, QCBOR_ERR_NO_MORE_ITEMS },
   // Unclosed indefinite map containing a closed definite length array
   { {(uint8_t[]){0xbf, 0x01, 0x80, 0x00, 0xa0}, 5}, QCBOR_ERR_NO_MORE_ITEMS },
   // Definite length map containing an unclosed indefinite length array
   { {(uint8_t[]){0xa1, 0x02, 0x9f}, 3}, QCBOR_ERR_NO_MORE_ITEMS },
   // Deeply nested definite length arrays with deepest one unclosed
   { {(uint8_t[]){0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81}, 9}, QCBOR_ERR_NO_MORE_ITEMS },
   // Deeply nested indefinite length arrays with deepest one unclosed
   { {(uint8_t[]){0x9f, 0x9f, 0x9f, 0x9f, 0x9f, 0xff, 0xff, 0xff, 0xff}, 9}, QCBOR_ERR_NO_MORE_ITEMS },
   // Mixed nesting with indefinite unclosed
   { {(uint8_t[]){0x9f, 0x81, 0x9f, 0x81, 0x9f, 0x9f, 0xff, 0xff, 0xff}, 9}, QCBOR_ERR_NO_MORE_ITEMS },
   // Mixed nesting with definite unclosed
   { {(uint8_t[]){0x9f, 0x82, 0x9f, 0x81, 0x9f, 0x9f, 0xff, 0xff, 0xff, 0xff}, 10}, QCBOR_ERR_BAD_BREAK },
   // Unclosed indefinite length map in definite length maps
   { {(uint8_t[]){0xa1, 0x01, 0xa2, 0x02, 0xbf, 0xff, 0x02, 0xbf}, 8},
      QCBOR_ERR_NO_MORE_ITEMS},
   // Unclosed definite length map in indefinite length maps
   { {(uint8_t[]){0xbf, 0x01, 0xbf, 0x02, 0xa1}, 5}, QCBOR_ERR_NO_MORE_ITEMS},
   // Unclosed indefinite length array in definite length maps
   { {(uint8_t[]){0xa1, 0x01, 0xa2, 0x02, 0x9f, 0xff, 0x02, 0x9f}, 8},
      QCBOR_ERR_NO_MORE_ITEMS},
   // Unclosed definite length array in indefinite length maps
   { {(uint8_t[]){0xbf, 0x01, 0xbf, 0x02, 0x81}, 5}, QCBOR_ERR_NO_MORE_ITEMS},
   // Unclosed indefinite length map in definite length arrays
   { {(uint8_t[]){0x81, 0x82, 0xbf, 0xff, 0xbf}, 5}, QCBOR_ERR_NO_MORE_ITEMS},
   // Unclosed definite length map in indefinite length arrays
   { {(uint8_t[]){0x9f, 0x9f, 0xa1}, 3}, QCBOR_ERR_NO_MORE_ITEMS},
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */

   // The "argument" for the data item is incomplete
   // Positive integer missing 1 byte argument
   { {(uint8_t[]){0x18}, 1}, QCBOR_ERR_HIT_END },
   // Positive integer missing 2 byte argument
   { {(uint8_t[]){0x19}, 1}, QCBOR_ERR_HIT_END },
   // Positive integer missing 4 byte argument
   { {(uint8_t[]){0x1a}, 1}, QCBOR_ERR_HIT_END },
   // Positive integer missing 8 byte argument
   { {(uint8_t[]){0x1b}, 1}, QCBOR_ERR_HIT_END },
   // Positive integer missing 1 byte of 2 byte argument
   { {(uint8_t[]){0x19, 0x01}, 2}, QCBOR_ERR_HIT_END },
   // Positive integer missing 2 bytes of 4 byte argument
   { {(uint8_t[]){0x1a, 0x01, 0x02}, 3}, QCBOR_ERR_HIT_END },
   // Positive integer missing 1 bytes of 7 byte argument
   { {(uint8_t[]){0x1b, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, 8}, QCBOR_ERR_HIT_END },
   // Negative integer missing 1 byte argument
   { {(uint8_t[]){0x38}, 1}, QCBOR_ERR_HIT_END },
   // Binary string missing 1 byte argument
   { {(uint8_t[]){0x58}, 1}, QCBOR_ERR_HIT_END },
   // Text string missing 1 byte argument
   { {(uint8_t[]){0x78}, 1}, QCBOR_ERR_HIT_END },
   // Array missing 1 byte argument
   { {(uint8_t[]){0x98}, 1}, QCBOR_ERR_HIT_END },
   // Map missing 1 byte argument
   { {(uint8_t[]){0xb8}, 1}, QCBOR_ERR_HIT_END },
   // Tag missing 1 byte argument
   { {(uint8_t[]){0xd8}, 1}, QCBOR_ERR_HIT_END },
   // Simple missing 1 byte argument
   { {(uint8_t[]){0xf8}, 1}, QCBOR_ERR_HIT_END },
   // half-precision with 1 byte argument
   { {(uint8_t[]){0xf9, 0x00}, 2}, QCBOR_ERR_HIT_END },
   // single-precision with 2 byte argument
   { {(uint8_t[]){0xfa, 0x00, 0x00}, 3}, QCBOR_ERR_HIT_END },
   // double-precision with 3 byte argument
   { {(uint8_t[]){0xfb, 0x00, 0x00, 0x00}, 4}, QCBOR_ERR_HIT_END },


   // Tag with no content
   { {(uint8_t[]){0xc0}, 1}, QCBOR_ERR_HIT_END },


   // Breaks must not occur in definite length arrays and maps
   // Array of length 1 with sole member replaced by a break
   { {(uint8_t[]){0x81, 0xff}, 2}, QCBOR_ERR_BAD_BREAK },
   // Array of length 2 with 2nd member replaced by a break
   { {(uint8_t[]){0x82, 0x00, 0xff}, 3}, QCBOR_ERR_BAD_BREAK },
   // Map of length 1 with sole member label replaced by a break
   { {(uint8_t[]){0xa1, 0xff}, 2}, QCBOR_ERR_BAD_BREAK },
   // Map of length 1 with sole member label replaced by break
   // Alternate representation that some decoders handle differently
   { {(uint8_t[]){0xa1, 0xff, 0x00}, 3}, QCBOR_ERR_BAD_BREAK },
   // Array of length 1 with 2nd member value replaced by a break
   { {(uint8_t[]){0xa1, 0x00, 0xff}, 3}, QCBOR_ERR_BAD_BREAK },
   // Map of length 2 with 2nd member replaced by a break
   { {(uint8_t[]){0xa2, 0x00, 0x00, 0xff}, 4}, QCBOR_ERR_BAD_BREAK },


   // Breaks must not occur on their own out of an indefinite length data item
   // A bare break is not well formed
   { {(uint8_t[]){0xff}, 1}, QCBOR_ERR_BAD_BREAK },
   // A bare break after a zero length definite length array
   { {(uint8_t[]){0x80, 0xff}, 2}, QCBOR_ERR_BAD_BREAK },
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   // A bare break after a zero length indefinite length map
   { {(uint8_t[]){0x9f, 0xff, 0xff}, 3}, QCBOR_ERR_BAD_BREAK },
   // A break inside a definite length array inside an indefenite length array
   { {(uint8_t[]){0x9f, 0x81, 0xff}, 3}, QCBOR_ERR_BAD_BREAK },
   // Complicated mixed nesting with break outside indefinite length array
   { {(uint8_t[]){0x9f, 0x82, 0x9f, 0x81, 0x9f, 0x9f, 0xff, 0xff, 0xff, 0xff}, 10}, QCBOR_ERR_BAD_BREAK },
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */


   // Forbidden two byte encodings of simple types
   // Must use 0xe0 instead
   { {(uint8_t[]){0xf8, 0x00}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Should use 0xe1 instead
   { {(uint8_t[]){0xf8, 0x01}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Should use 0xe2 instead
   { {(uint8_t[]){0xf8, 0x02}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Should use 0xe3 instead
   { {(uint8_t[]){0xf8, 0x03}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Should use 0xe4 instead
   { {(uint8_t[]){0xf8, 0x04}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Should use 0xe5 instead
   { {(uint8_t[]){0xf8, 0x05}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Should use 0xe6 instead
   { {(uint8_t[]){0xf8, 0x06}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Should use 0xe7 instead
   { {(uint8_t[]){0xf8, 0x07}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Should use 0xe8 instead
   { {(uint8_t[]){0xf8, 0x08}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Should use 0xe9 instead
   { {(uint8_t[]){0xf8, 0x09}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Should use 0xea instead
   { {(uint8_t[]){0xf8, 0x0a}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Should use 0xeb instead
   { {(uint8_t[]){0xf8, 0x0b}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Should use 0xec instead
   { {(uint8_t[]){0xf8, 0x0c}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Should use 0xed instead
   { {(uint8_t[]){0xf8, 0x0d}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Should use 0xee instead
   { {(uint8_t[]){0xf8, 0x0e}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Should use 0xef instead
   { {(uint8_t[]){0xf8, 0x0f}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Should use 0xf0 instead
   { {(uint8_t[]){0xf8, 0x10}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Should use 0xf1 instead
   { {(uint8_t[]){0xf8, 0x11}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Should use 0xf2 instead
   { {(uint8_t[]){0xf8, 0x12}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Must use 0xf3 instead
   { {(uint8_t[]){0xf8, 0x13}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Must use 0xf4 instead
   { {(uint8_t[]){0xf8, 0x14}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Must use 0xf5 instead
   { {(uint8_t[]){0xf8, 0x15}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Must use 0xf6 instead
   { {(uint8_t[]){0xf8, 0x16}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Must use 0xf7 instead
   { {(uint8_t[]){0xf8, 0x17}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Must use 0xf8 instead
   { {(uint8_t[]){0xf8, 0x18}, 2}, QCBOR_ERR_BAD_TYPE_7 },
   // Reserved
   { {(uint8_t[]){0xf8, 0x1f}, 2}, QCBOR_ERR_BAD_TYPE_7 },

   // Integers with additional info indefinite length
   // Positive integer with additional info indefinite length
   { {(uint8_t[]){0x1f}, 1}, QCBOR_ERR_BAD_INT },
   // Negative integer with additional info indefinite length
   { {(uint8_t[]){0x3f}, 1}, QCBOR_ERR_BAD_INT },
   // CBOR tag with "argument" an indefinite length
   { {(uint8_t[]){0xdf, 0x00}, 2}, QCBOR_ERR_BAD_INT },
   // CBOR tag with "argument" an indefinite length alternate vector
   { {(uint8_t[]){0xdf}, 1}, QCBOR_ERR_BAD_INT },


   // Missing bytes from a deterministic length string
   // A byte string is of length 1 without the 1 byte
   { {(uint8_t[]){0x41}, 1}, QCBOR_ERR_HIT_END },
   // A text string is of length 1 without the 1 byte
   { {(uint8_t[]){0x61}, 1}, QCBOR_ERR_HIT_END },

#if SIZE_MAX > 2147483647
   // Byte string should have 2^32-15 bytes, but has one
   { {(uint8_t[]){0x5a, 0xff, 0xff, 0xff, 0xf0, 0x00}, 6}, QCBOR_ERR_HIT_END },
   // Byte string should have 2^32-15 bytes, but has one
   { {(uint8_t[]){0x7a, 0xff, 0xff, 0xff, 0xf0, 0x00}, 6}, QCBOR_ERR_HIT_END },
   // Byte string should have 2^64 bytes, but has 3
   { {(uint8_t[]){0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                  0x01, 0x02, 0x03}, 6}, QCBOR_ERR_HIT_END },
   // Text string should have 2^64 bytes, but has 3
   { {(uint8_t[]){0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                  0x01, 0x02, 0x03}, 6}, QCBOR_ERR_HIT_END },
#else
   // Byte string should have 2^32-15 bytes, but has one
   { {(uint8_t[]){0x5a, 0x00, 0x00, 0xff, 0xf0, 0x00}, 6}, QCBOR_ERR_HIT_END },
   // Byte string should have 2^32-15 bytes, but has one
   { {(uint8_t[]){0x7a, 0x00, 0x00, 0xff, 0xf0, 0x00}, 6}, QCBOR_ERR_HIT_END },
   // Byte string should have 2^16 bytes, but has 3
   { {(uint8_t[]){0x5b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x02, 0x03}, 6}, QCBOR_ERR_HIT_END },
   // Text string should have 2^64 bytes, but has 3
   { {(uint8_t[]){0x7b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x02, 0x03}, 6}, QCBOR_ERR_HIT_END },
#endif

   // Use of unassigned additional information values
   // Major type positive integer with reserved value 28
   { {(uint8_t[]){0x1c}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type positive integer with reserved value 29
   { {(uint8_t[]){0x1d}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type positive integer with reserved value 30
   { {(uint8_t[]){0x1e}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type negative integer with reserved value 28
   { {(uint8_t[]){0x3c}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type negative integer with reserved value 29
   { {(uint8_t[]){0x3d}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type negative integer with reserved value 30
   { {(uint8_t[]){0x3e}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type byte string with reserved value 28 length
   { {(uint8_t[]){0x5c}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type byte string with reserved value 29 length
   { {(uint8_t[]){0x5d}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type byte string with reserved value 30 length
   { {(uint8_t[]){0x5e}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type text string with reserved value 28 length
   { {(uint8_t[]){0x7c}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type text string with reserved value 29 length
   { {(uint8_t[]){0x7d}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type text string with reserved value 30 length
   { {(uint8_t[]){0x7e}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type array with reserved value 28 length
   { {(uint8_t[]){0x9c}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type array with reserved value 29 length
   { {(uint8_t[]){0x9d}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type array with reserved value 30 length
   { {(uint8_t[]){0x9e}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type map with reserved value 28 length
   { {(uint8_t[]){0xbc}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type map with reserved value 29 length
   { {(uint8_t[]){0xbd}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type map with reserved value 30 length
   { {(uint8_t[]){0xbe}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type tag with reserved value 28 length
   { {(uint8_t[]){0xdc}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type tag with reserved value 29 length
   { {(uint8_t[]){0xdd}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type tag with reserved value 30 length
   { {(uint8_t[]){0xde}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type simple with reserved value 28 length
   { {(uint8_t[]){0xfc}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type simple with reserved value 29 length
   { {(uint8_t[]){0xfd}, 1}, QCBOR_ERR_UNSUPPORTED },
   // Major type simple with reserved value 30 length
   { {(uint8_t[]){0xfe}, 1}, QCBOR_ERR_UNSUPPORTED },


   // Maps must have an even number of data items (key & value)
   // Map with 1 item when it should have 2
   { {(uint8_t[]){0xa1, 0x00}, 2}, QCBOR_ERR_HIT_END },
   // Map with 3 item when it should have 4
   { {(uint8_t[]){0xa2, 0x00, 0x00, 0x00}, 2}, QCBOR_ERR_HIT_END },
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   // Map with 1 item when it should have 2
   { {(uint8_t[]){0xbf, 0x00, 0xff}, 3}, QCBOR_ERR_BAD_BREAK },
   // Map with 3 item when it should have 4
   { {(uint8_t[]){0xbf, 0x00, 0x00, 0x00, 0xff}, 5}, QCBOR_ERR_BAD_BREAK },
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */


   // In addition to not-well-formed, some invalid CBOR
   // Text-based date, with an integer
   { {(uint8_t[]){0xc0, 0x00}, 2}, QCBOR_ERR_BAD_OPT_TAG },
   // Epoch date, with an byte string
   { {(uint8_t[]){0xc1, 0x41, 0x33}, 3}, QCBOR_ERR_BAD_OPT_TAG },
   // tagged as both epoch and string dates
   { {(uint8_t[]){0xc1, 0xc0, 0x00}, 3}, QCBOR_ERR_BAD_OPT_TAG },
   // big num tagged an int, not a byte string
   { {(uint8_t[]){0xc2, 0x00}, 2}, QCBOR_ERR_BAD_OPT_TAG },
};

int32_t DecodeFailureTests()
{
   int32_t nResult;

   nResult = ProcessFailures(Failures,C_ARRAY_COUNT(Failures,struct FailInput));
   if(nResult) {
      return nResult;
   }

   // Corrupt the UsefulInputBuf and see that
   // it reflected correctly for CBOR decoding
   QCBORDecodeContext DCtx;
   QCBORItem          Item;
   QCBORError         uQCBORError;

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spSimpleValues),
                    QCBOR_DECODE_MODE_NORMAL);

   if((uQCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)uQCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_ARRAY || Item.val.uCount != 10) {
      // This wasn't supposed to happen
      return -1;
   }

   DCtx.InBuf.magic = 0; // Reach in and corrupt the UsefulInputBuf

   uQCBORError = QCBORDecode_GetNext(&DCtx, &Item);
   if(uQCBORError != QCBOR_ERR_NO_MORE_ITEMS) {
      // Did not get back the error expected
      return -2;
   }


   /*
    The max size of a string for QCBOR is SIZE_MAX - 4 so this
    tests here can be performed to see that the max length
    error check works correctly. See DecodeBytes(). If the max
    size was SIZE_MAX, it wouldn't be possible to test this.

    This test will automatocally adapt the all CPU sizes
    through the use of SIZE_MAX.
   */

   UsefulBuf_MAKE_STACK_UB(  HeadBuf, QCBOR_HEAD_BUFFER_SIZE);
   UsefulBufC             EncodedHead;

   // This makes a CBOR head with a text string that is very long
   // but doesn't fill in the bytes of the text string as that is
   // not needed to test this part of QCBOR.
   EncodedHead = QCBOREncode_EncodeHead(HeadBuf, CBOR_MAJOR_TYPE_TEXT_STRING, 0, SIZE_MAX);

   QCBORDecode_Init(&DCtx, EncodedHead, QCBOR_DECODE_MODE_NORMAL);

   if(QCBOR_ERR_STRING_TOO_LONG != QCBORDecode_GetNext(&DCtx, &Item)) {
      return -4;
   }

   return 0;
}


/* Try all 256 values of the byte at nLen including recursing for
 each of the values to try values at nLen+1 ... up to nLenMax
 */
static void ComprehensiveInputRecurser(uint8_t *pBuf, size_t nLen, size_t nLenMax)
{
   if(nLen >= nLenMax) {
      return;
   }

   for(int inputByte = 0; inputByte < 256; inputByte++) {
      // Set up the input
      pBuf[nLen] = (uint8_t)inputByte;
      const UsefulBufC Input = {pBuf, nLen+1};

      // Get ready to parse
      QCBORDecodeContext DCtx;
      QCBORDecode_Init(&DCtx, Input, QCBOR_DECODE_MODE_NORMAL);

      // Parse by getting the next item until an error occurs
      // Just about every possible decoder error can occur here
      // The goal of this test is not to check for the correct
      // error since that is not really possible. It is to
      // see that there is no crash on hostile input.
      while(1) {
         QCBORItem Item;
         QCBORError nCBORError = QCBORDecode_GetNext(&DCtx, &Item);
         if(nCBORError != QCBOR_SUCCESS) {
            break;
         }
      }

      ComprehensiveInputRecurser(pBuf, nLen+1, nLenMax);
   }
}


int32_t ComprehensiveInputTest()
{
   // Size 2 tests 64K inputs and runs quickly
   uint8_t pBuf[2];

   ComprehensiveInputRecurser(pBuf, 0, sizeof(pBuf));

   return 0;
}


int32_t BigComprehensiveInputTest()
{
   // size 3 tests 16 million inputs and runs OK
   // in seconds on fast machines. Size 4 takes
   // 10+ minutes and 5 half a day on fast
   // machines. This test is kept separate from
   // the others so as to no slow down the use
   // of them as a very frequent regression.
   uint8_t pBuf[3]; //

   ComprehensiveInputRecurser(pBuf, 0, sizeof(pBuf));

   return 0;
}


static const uint8_t spDateTestInput[] = {
   /* 1. The valid date string "1985-04-12" */
   0xc0, // tag for string date
   0x6a, '1','9','8','5','-','0','4','-','1','2', // Date string

   /* 2. An invalid date string due to wrong tag content type */
   0xc0, // tag for string date
   0x00, // Wrong type for a string date

   /* 3. A valid epoch date, 1400000000; Tue, 13 May 2014 16:53:20 GMT */
   0xc1, // tag for epoch date
   0x1a, 0x53, 0x72, 0x4E, 0x00, // Epoch date 1400000000; Tue, 13 May 2014 16:53:20 GMT

   /* 4. An invalid epoch date due to wrong tag content type */
   0xc1,
   0x62, 'h', 'i', // wrong type tagged

   /* 5. Valid epoch date tag as content for a two other nested tags */
   // CBOR_TAG_ENC_AS_B64
   0xcf, 0xd8, 0x16, 0xc1, // Epoch date with extra tags
   0x1a, 0x53, 0x72, 0x4E, 0x01,

   /* 6. Epoch date with value to large to fit into int64 */
   0xc1, // tag for epoch date
   0x1b, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, // Too large integer

   /* 7. Epoch date with single-precision value of 1.1. */
   0xc1, // tag for epoch date
   0xfa, 0x3f, 0x8c, 0xcc, 0xcd, // single with value 1.1

   /* 8. Epoch date with too-large single precision float */
   0xc1, // tag for epoch date
   0xfa, 0x7f, 0x7f, 0xff, 0xff, // 3.4028234663852886e+38 too large

   /* 9. Epoch date with slightly too-large double precision value */
   0xc1, // tag for epoch date
   0xfb, 0x43, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 9223372036854775808.000000 just barely too large
   //0xfa, 0x7f, 0x7f, 0xff, 0xff // 3.4028234663852886e+38 too large

   /* 10. Epoch date with largest supported double precision value */
   0xc1, // tag for epoch date
   0xfb, 0x43, 0xdf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, // 9223372036854773760 largest supported

   /* 11. Epoch date with single-precision NaN */
   0xc1, // tag for epoch date
   0xfa, 0x7f, 0xc0, 0x00, 0x00, // Single-precision NaN

   /* 12. Epoch date with double precision plus infinity */
   0xc1,
   0xfb, 0x7f,  0xf0,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // +infinity

   /* 13. Epoch date with half-precision negative infinity */
   0xc1, // tag for epoch date
   0xf9, 0xfc, 0x00, // -Infinity
};



// have to check float expected only to within an epsilon
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
static int CHECK_EXPECTED_DOUBLE(double val, double expected) {

   double diff = val - expected;

   diff = fabs(diff);

   return diff > 0.0000001;
}
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */



int32_t DateParseTest()
{
   QCBORDecodeContext DCtx;
   QCBORItem          Item;
   QCBORError         uError;

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spDateTestInput),
                    QCBOR_DECODE_MODE_NORMAL);

   /* 1. The valid date string "1985-04-12" */
   if((uError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return -1;
   }
   if(Item.uDataType != QCBOR_TYPE_DATE_STRING ||
      UsefulBufCompareToSZ(Item.val.dateString, "1985-04-12")){
      return -2;
   }

   /* 2. An invalid date string due to wrong tag content type */
   uError = QCBORDecode_GetNext(&DCtx, &Item);
   if(uError != QCBOR_ERR_BAD_OPT_TAG) {
      return -3;
   }

   /* 3. A valid epoch date, 1400000000; Tue, 13 May 2014 16:53:20 GMT */
   uError = QCBORDecode_GetNext(&DCtx, &Item);
   if(uError != QCBOR_SUCCESS) {
      return -4;
   }
   if(uError == QCBOR_SUCCESS) {
      if(Item.uDataType != QCBOR_TYPE_DATE_EPOCH ||
         Item.val.epochDate.nSeconds != 1400000000
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
         || Item.val.epochDate.fSecondsFraction != 0
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
        ) {
         return -5;
      }
   }

   /* 4. An invalid epoch date due to wrong tag content type */
   if(QCBORDecode_GetNext(&DCtx, &Item) != QCBOR_ERR_BAD_OPT_TAG) {
      return -6;
   }

   /* 5. Valid epoch date tag as content for a two other nested tags */
   // Epoch date wrapped in an CBOR_TAG_ENC_AS_B64 and an unknown tag.
   // The date is decoded and the two tags are returned. This is to
   // make sure the wrapping of epoch date in another tag works OK.
   if((uError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return -7;
   }
   if(Item.uDataType != QCBOR_TYPE_DATE_EPOCH ||
      Item.val.epochDate.nSeconds != 1400000001 ||
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
      Item.val.epochDate.fSecondsFraction != 0 ||
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
      !QCBORDecode_IsTagged(&DCtx, &Item, CBOR_TAG_ENC_AS_B64)) {
      return -8;
   }

   /* 6. Epoch date with value to large to fit into int64 */
   if(QCBORDecode_GetNext(&DCtx, &Item) != QCBOR_ERR_DATE_OVERFLOW) {
      return -9;
   }

   /* 7. Epoch date with single-precision value of 1.1. */
   uError = QCBORDecode_GetNext(&DCtx, &Item);
   if(uError != FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)) {
      return -10;
   }
   if(uError == QCBOR_SUCCESS) {
      if(Item.uDataType != QCBOR_TYPE_DATE_EPOCH ||
         Item.val.epochDate.nSeconds != 1
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
         || CHECK_EXPECTED_DOUBLE(Item.val.epochDate.fSecondsFraction, 0.1)
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
        ) {
         return -11;
      }
   }

   /* 8. Epoch date with too-large single-precision float */
   uError = QCBORDecode_GetNext(&DCtx, &Item);
   if(uError != FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_ERR_DATE_OVERFLOW)) {
      return -12;
   }

   /* 9. Epoch date with slightly too-large double-precision value */
   uError = QCBORDecode_GetNext(&DCtx, &Item);
   if(uError != FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_ERR_DATE_OVERFLOW)) {
      return -13;
   }

   /* 10. Epoch date with largest supported double-precision value */
   uError = QCBORDecode_GetNext(&DCtx, &Item);
   if(uError != FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)) {
      return -14;
   }
   if(uError == QCBOR_SUCCESS) {
      if(Item.uDataType != QCBOR_TYPE_DATE_EPOCH ||
         Item.val.epochDate.nSeconds != 9223372036854773760
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
         || Item.val.epochDate.fSecondsFraction != 0.0
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
      ) {
         return -14;
      }
   }

   /* 11. Epoch date with single-precision NaN */
   if(QCBORDecode_GetNext(&DCtx, &Item) != FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_ERR_DATE_OVERFLOW)) {
      return -15;
   }

   /* 12. Epoch date with double-precision plus infinity */
   if(QCBORDecode_GetNext(&DCtx, &Item) != FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_ERR_DATE_OVERFLOW)) {
      return -16;
   }

   /* 13. Epoch date with half-precision negative infinity */
   uError = QCBORDecode_GetNext(&DCtx, &Item);
   if(uError != FLOAT_ERR_CODE_NO_HALF_PREC_NO_FLOAT_HW(QCBOR_ERR_DATE_OVERFLOW)) {
      return -17;
   }

   return 0;
}

/*
 Test cases covered here. Some items cover more than one of these.
   positive integer (zero counts as a positive integer)
   negative integer
   half-precision float
   single-precision float
   double-precision float

   float Overflow error
   Wrong type error for epoch
   Wrong type error for date string
   float disabled error
   half-precision disabled error
   -Infinity
   Slightly too large integer
   Slightly too far from zero

   Get epoch by int
   Get string by int
   Get epoch by string
   Get string by string
   Fail to get epoch by wrong int label
   Fail to get string by wrong string label
   Fail to get epoch by string because it is invalid
   Fail to get epoch by int because it is invalid

   Untagged values
 */
static const uint8_t spSpiffyDateTestInput[] = {
   0x86, // array of 6 items

   0xc1,
   0xfb, 0xc3, 0xdf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // -9.2233720368547748E+18, too negative

   0xc1, // tag for epoch date
   0x1b, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, // Too-large integer

   0xc1, // tag for epoch date
   0xf9, 0xfc, 0x00, // Half-precision -Infinity

   0xad, // Open a map for tests involving labels.

   0x00,
   0xc0, // tag for string date
   0x6a, '1','9','8','5','-','0','4','-','1','2', // Tagged date string

   0x01,
   0xda, 0x03, 0x03, 0x03, 0x03, // An additional tag
   0xc1, // tag for epoch date
   0x1a, 0x53, 0x72, 0x4E, 0x00, // Epoch date 1400000000; Tue, 13 May 2014 16:53:20 GMT

   // Untagged integer 0
   0x08,
   0x00,

   // Utagged date string with string label y
   0x61, 0x79,
   0x6a, '2','0','8','5','-','0','4','-','1','2', // Untagged date string

   // Untagged -1000 with label z
   0x61, 0x7a,
   0xda, 0x01, 0x01, 0x01, 0x01, // An additional tag
   0x39, 0x03, 0xe7,

   0x07,
   0xc1, // tag for epoch date
   0xfb, 0x43, 0xdf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, // 9223372036854773760 largest supported

   0x05,
   0xc1,
   0xfb, 0xc3, 0xdf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, // -9223372036854773760 largest negative

   // Untagged single-precision float with value 3.14 with string label x
   0x61, 0x78,
   0xFA, 0x40, 0x48, 0xF5, 0xC3,

   // Untagged half-precision float with value -2
   0x09,
   0xF9, 0xC0, 0x00,

   /* Tagged date-only date string */
   0x63, 0x53, 0x44, 0x53,
   0xD9, 0x03, 0xEC,
   0x6A, 0x31, 0x39, 0x38, 0x35, 0x2D, 0x30, 0x34, 0x2D, 0x31, 0x32, /* "1985-04-12" */

   /* Untagged date-only date string */
   0x18, 0x63,
   0x6A, 0x31, 0x39, 0x38, 0x35, 0x2D, 0x30, 0x34, 0x2D, 0x31, 0x32, /* "1985-04-12" */

   /* Tagged days-count epoch date */
   0x63, 0x53, 0x44, 0x45,
   0xD8, 0x64,  /* tag(100) */
   0x39, 0x29, 0xB3, /* -10676 */

   /* Untagged days-count epoch date */
   0x11,
   0x19, 0x0F, 0x9A, /* 3994 */

   // End of map, back to array

   // These two at the end because they are unrecoverable errors
   0xc1, // tag for epoch date
   0x80, // Erroneous empty array as content for date

   0xc0, // tag for string date
   0xa0 // Erroneous empty map as content for date

};

int32_t SpiffyDateDecodeTest()
{
   QCBORDecodeContext DC;
   QCBORError         uError;
   int64_t            nEpochDate2, nEpochDate3, nEpochDate5,
                      nEpochDate4, nEpochDate6, nEpochDateFail,
                      nEpochDate1400000000, nEpochDays1, nEpochDays2;
   UsefulBufC         StringDate1, StringDate2, StringDays1, StringDays2;
   uint64_t           uTag1, uTag2;

   QCBORDecode_Init(&DC,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spSpiffyDateTestInput),
                    QCBOR_DECODE_MODE_NORMAL);
   QCBORDecode_EnterArray(&DC, NULL);

   // Too-negative float, -9.2233720368547748E+18
   QCBORDecode_GetEpochDate(&DC, QCBOR_TAG_REQUIREMENT_TAG, &nEpochDateFail);
   uError = QCBORDecode_GetAndResetError(&DC);
   if(uError != FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_ERR_DATE_OVERFLOW)) {
      return 1111;
   }

   // Too-large integer
   QCBORDecode_GetEpochDate(&DC, QCBOR_TAG_REQUIREMENT_TAG, &nEpochDateFail);
   uError = QCBORDecode_GetAndResetError(&DC);
   if(uError != QCBOR_ERR_DATE_OVERFLOW) {
      return 1;
   }

   // Half-precision minus infinity
   QCBORDecode_GetEpochDate(&DC, QCBOR_TAG_REQUIREMENT_TAG, &nEpochDateFail);
   uError = QCBORDecode_GetAndResetError(&DC);
   if(uError != FLOAT_ERR_CODE_NO_HALF_PREC_NO_FLOAT_HW(QCBOR_ERR_DATE_OVERFLOW)) {
      return 2;
   }



   QCBORDecode_EnterMap(&DC, NULL);

   // Get largest negative double precision epoch date allowed
   QCBORDecode_GetEpochDateInMapN(&DC,
                                  5,
                                  QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG |
                                    QCBOR_TAG_REQUIREMENT_ALLOW_ADDITIONAL_TAGS,
                                  &nEpochDate2);
   uError = QCBORDecode_GetAndResetError(&DC);
   if(uError != FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)) {
      return 102;
   }
   if(uError == QCBOR_SUCCESS) {
      if(nEpochDate2 != -9223372036854773760LL) {
         return 101;
      }
   }

   // Get largest double precision epoch date allowed
   QCBORDecode_GetEpochDateInMapN(&DC, 7, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG,
                                  &nEpochDate2);
   uError = QCBORDecode_GetAndResetError(&DC);
   if(uError != FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)) {
      return 112;
   }
   if(uError == QCBOR_SUCCESS) {
      if(nEpochDate2 != 9223372036854773760ULL) {
         return 111;
      }
   }

   // A single-precision date
   QCBORDecode_GetEpochDateInMapSZ(&DC, "x", QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG,
                                   &nEpochDate5);
   uError = QCBORDecode_GetAndResetError(&DC);
   if(uError != FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)) {
      return 104;
   }
   if(uError == QCBOR_SUCCESS) {
      if(nEpochDate5 != 3) {
         return 103;
      }
   }

   // A half-precision date with value -2 FFF
   QCBORDecode_GetEpochDateInMapN(&DC, 9, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG,
                                  &nEpochDate4);
   uError = QCBORDecode_GetAndResetError(&DC);
   if(uError != FLOAT_ERR_CODE_NO_HALF_PREC_NO_FLOAT_HW(QCBOR_SUCCESS)) {
      return 106;
   }
   if(uError == QCBOR_SUCCESS) {
      if(nEpochDate4 != -2) {
         return 105;
      }
   }

   // Fail to get an epoch date by string label
   QCBORDecode_GetEpochDateInMapSZ(&DC, "no-label",
                                   QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
                                   &nEpochDate6);
   uError = QCBORDecode_GetAndResetError(&DC);
   if(uError != QCBOR_ERR_LABEL_NOT_FOUND) {
      return 107;
   }

   // Fail to get an epoch date by integer label
   QCBORDecode_GetEpochDateInMapN(&DC, 99999, QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
                                  &nEpochDate6);
   uError = QCBORDecode_GetAndResetError(&DC);
   if(uError != QCBOR_ERR_LABEL_NOT_FOUND) {
      return 108;
   }

   // Fail to get a string date by string label
   QCBORDecode_GetDateStringInMapSZ(&DC, "no-label",
                                    QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
                                    &StringDate1);
   uError = QCBORDecode_GetAndResetError(&DC);
   if(uError != QCBOR_ERR_LABEL_NOT_FOUND) {
      return 109;
   }

   // Fail to get a string date by integer label
   QCBORDecode_GetDateStringInMapN(&DC, 99999, QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
                                   &StringDate1);
   uError = QCBORDecode_GetAndResetError(&DC);
   if(uError != QCBOR_ERR_LABEL_NOT_FOUND) {
      return 110;
   }

   // The rest of these succeed even if float features are disabled

   // Epoch date 1400000000; Tue, 13 May 2014 16:53:20 GMT
   QCBORDecode_GetEpochDateInMapN(&DC,
                                  1,
                                  QCBOR_TAG_REQUIREMENT_TAG |
                                    QCBOR_TAG_REQUIREMENT_ALLOW_ADDITIONAL_TAGS,
                                  &nEpochDate1400000000);
   uTag1 = QCBORDecode_GetNthTagOfLast(&DC, 0);
   // Tagged date string
   QCBORDecode_GetDateStringInMapN(&DC, 0, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG,
                                   &StringDate1);
   // Untagged integer 0
   QCBORDecode_GetEpochDateInMapN(&DC, 8, QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
                                  &nEpochDate3);
   // Untagged date string
   QCBORDecode_GetDateStringInMapSZ(&DC, "y", QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
                                    &StringDate2);
   // Untagged -1000 with label z
   QCBORDecode_GetEpochDateInMapSZ(&DC,
                                   "z",
                                   QCBOR_TAG_REQUIREMENT_NOT_A_TAG |
                                    QCBOR_TAG_REQUIREMENT_ALLOW_ADDITIONAL_TAGS,
                                   &nEpochDate6);
   uTag2 = QCBORDecode_GetNthTagOfLast(&DC, 0);

   /* The days format is much simpler than the date format
    * because it can't be a floating point value. The test
    * of the spiffy decode functions sufficiently covers
    * the test of the non-spiffy decode days date decoding.
    * There is no full fan out of the error conditions
    * and decode options as that is implemented by code
    * that is tested well by the date testing above.
    */
   QCBORDecode_GetDaysStringInMapSZ(&DC, "SDS", QCBOR_TAG_REQUIREMENT_TAG,
                                    &StringDays1);

   QCBORDecode_GetDaysStringInMapN(&DC, 99, QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
                                   &StringDays2);

   QCBORDecode_GetEpochDaysInMapSZ(&DC, "SDE", QCBOR_TAG_REQUIREMENT_TAG,
                                   &nEpochDays1);

   QCBORDecode_GetEpochDaysInMapN(&DC, 17, QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
                                  &nEpochDays2);

   QCBORDecode_ExitMap(&DC);
   if(QCBORDecode_GetError(&DC) != QCBOR_SUCCESS) {
      return 3001;
   }

   // Bad content for epoch date
   QCBORDecode_GetEpochDate(&DC, QCBOR_TAG_REQUIREMENT_TAG, &nEpochDateFail);
   uError = QCBORDecode_GetAndResetError(&DC);
   if(uError != QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT) {
      return 3;
   }

   // Bad content for string date
   QCBORDecode_GetDateString(&DC, QCBOR_TAG_REQUIREMENT_TAG, &StringDate1);
   uError = QCBORDecode_GetAndResetError(&DC);
   if(uError != QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT) {
      return 4;
   }

   QCBORDecode_ExitArray(&DC);
   uError = QCBORDecode_Finish(&DC);
   if(uError != QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT) {
      return 1000 + (int32_t)uError;
   }

   if(nEpochDate1400000000 != 1400000000) {
      return 200;
   }

   if(uTag1 != 0x03030303) {
      return 201;
   }

   if(nEpochDate3 != 0) {
      return 202;
   }

   if(nEpochDate6 != -1000) {
      return 203;
   }

   if(uTag2 != 0x01010101) {
      return 204;
   }

   if(nEpochDays1 != -10676) {
      return 205;
   }

   if(nEpochDays2 != 3994) {
      return 206;
   }

   if(UsefulBuf_Compare(StringDate1, UsefulBuf_FromSZ("1985-04-12"))) {
      return 205;
   }

   if(UsefulBuf_Compare(StringDate2, UsefulBuf_FromSZ("2085-04-12"))) {
      return 206;
   }

   if(UsefulBuf_Compare(StringDays1, UsefulBuf_FromSZ("1985-04-12"))) {
      return 207;
   }

   if(UsefulBuf_Compare(StringDays2, UsefulBuf_FromSZ("1985-04-12"))) {
      return 208;
   }

   return 0;
}



// Input for one of the tagging tests
static const uint8_t spTagInput[] = {
   0xd9, 0xd9, 0xf7, // CBOR magic number
       0x81, // Array of one
          0xd8, 0x04, // non-preferred serialization of tag 4, decimal fraction
              0x82, // Array of two that is the faction 1/3
                 0x01,
                 0x03,

   /*
    More than 4 tags on an item 225(226(227(228(229([])))))
    */
   0xd8, 0xe1,
      0xd8, 0xe2,
          0xd8, 0xe3,
              0xd8, 0xe4,
                 0xd8, 0xe5,
                    0x80,

   /* tag 10489608748473423768(
             2442302356(
                21590(
                   240(
                      []))))
    */
   0xdb, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
      0xda, 0x91, 0x92, 0x93, 0x94,
         0xd9, 0x54, 0x56,
            0xd8, 0xf0,
               0x80,

   /* tag 21590(
             10489608748473423768(
                2442302357(
                   65534(
                       []))))
    */
   0xdb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x56,
      0xdb, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
         0xda, 0x91, 0x92, 0x93, 0x95,
            0xd9, 0xff, 0xfe,
               0x80,

   /* Make sure to blow past the limit of tags that must be mapped.
      works in conjuntion with entries above.
    269488144(269488145(269488146(269488147([]))))
    */
   0xda, 0x10, 0x10, 0x10, 0x10,
      0xda, 0x10, 0x10, 0x10, 0x11,
         0xda, 0x10, 0x10, 0x10, 0x12,
            0xda, 0x10, 0x10, 0x10, 0x13,
               0x80,

   /* An invalid decimal fraction with an additional tag */
   0xd9, 0xff, 0xfa,
      0xd8, 0x02, // non-preferred serialization of tag 2, a big num
         0x00, // the integer 0; should be a byte string
};

/*
 DB 9192939495969798 # tag(10489608748473423768)
   80                # array(0)
 */
static const uint8_t spEncodedLargeTag[] = {0xdb, 0x91, 0x92, 0x93, 0x94, 0x95,
                                      0x96, 0x97, 0x98, 0x80};

/*
DB 9192939495969798 # tag(10489608748473423768)
   D8 88            # tag(136)
      C6            # tag(6)
         C7         # tag(7)
            80      # array(0)
*/
static const uint8_t spLotsOfTags[] = {0xdb, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
                                 0x97, 0x98, 0xd8, 0x88, 0xc6, 0xc7, 0x80};

/*
   55799(55799(55799({
      6(7(-23)): 5859837686836516696(7({
          7(-20): 11({
             17(-18): 17(17(17("Organization"))),
              9(-17): 773("SSG"),
                 -15: 16(17(6(7("Confusion")))),
             17(-16): 17("San Diego"),
             17(-14): 17("US")
         }),
         23(-19): 19({
             -11: 9({
              -9: -7
         }),
         90599561(90599561(90599561(-10))): 12(h'0102030405060708090A')
       })
      })),
      16(-22): 23({
         11(8(7(-5))): 8(-3)
      })
   })))
 */
static const uint8_t spCSRWithTags[] = {
   0xd9, 0xd9, 0xf7, 0xd9, 0xd9, 0xf7, 0xd9, 0xd9, 0xf7, 0xa2,
      0xc6, 0xc7, 0x36,
      0xdb, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0xc7, 0xa2,
         0xda, 0x00, 0x00, 0x00, 0x07, 0x33,
         0xcb, 0xa5,
            0xd1, 0x31,
            0xd1, 0xd1, 0xd1, 0x6c,
               0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e,
            0xc9, 0x30,
            0xd9, 0x03, 0x05, 0x63,
               0x53, 0x53, 0x47,
            0x2e,
            0xd0, 0xd1, 0xc6, 0xc7,
               0x69,
                  0x43, 0x6f, 0x6e, 0x66, 0x75, 0x73, 0x69, 0x6f, 0x6e,
            0xd1, 0x2f,
            0xd1, 0x69,
               0x53, 0x61, 0x6e, 0x20, 0x44, 0x69, 0x65, 0x67, 0x6f,
            0xd1, 0x2d,
            0xd1, 0x62,
               0x55, 0x53,
         0xd7, 0x32,
         0xd3, 0xa2,
            0x2a,
            0xc9, 0xa1,
               0x28,
               0x26,
            0xda, 0x05, 0x66, 0x70, 0x89, 0xda, 0x05, 0x66, 0x70, 0x89, 0xda, 0x05, 0x66, 0x70, 0x89, 0x29,
            0xcc, 0x4a,
               0x01, 0x02, 0x03, 0x04, 0x05, 0x06,0x07, 0x08, 0x09, 0x0a,
   0xd0, 0x35,
   0xd7, 0xa1,
      0xcb, 0xc8, 0xc7, 0x24,
      0xc8, 0x22};


static const uint8_t spSpiffyTagInput[] = {
   0x85, // Open array

   0xc0, // tag for string date
   0x6a, '1','9','8','5','-','0','4','-','1','2', // Date string

   0x6a, '1','9','8','5','-','0','4','-','1','2', // Date string

   0x4a, '1','9','8','5','-','0','4','-','1','2', // Date string in byte string

   0xd8, 0x23, // tag for regex
   0x6a, '1','9','8','5','-','0','4','-','1','2', // Date string

   0xc0, // tag for string date
   0x4a, '1','9','8','5','-','0','4','-','1','2', // Date string in byte string

   // This last case makes the array untraversable because it is
   // an uncrecoverable error. Make sure it stays last and is the only
   // instance so the other tests can work.
};


static int32_t CheckCSRMaps(QCBORDecodeContext *pDC);


int32_t OptTagParseTest()
{
   QCBORDecodeContext DCtx;
   QCBORItem          Item;
   QCBORError         uError;

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spTagInput),
                    QCBOR_DECODE_MODE_NORMAL);

   /*
    This test matches the magic number tag and the fraction tag
    55799([...])
    */
   uError = QCBORDecode_GetNext(&DCtx, &Item);
   if(uError != QCBOR_SUCCESS) {
      return -2;
   }
   if(Item.uDataType != QCBOR_TYPE_ARRAY ||
      !QCBORDecode_IsTagged(&DCtx, &Item, CBOR_TAG_CBOR_MAGIC)) {
      return -3;
   }

   /*
    4([1,3])
    */
   uError = QCBORDecode_GetNext(&DCtx, &Item);
#ifdef QCBOR_DISABLE_EXP_AND_MANTISSA
   if(uError != QCBOR_SUCCESS ||
      Item.uDataType != QCBOR_TYPE_ARRAY ||
      !QCBORDecode_IsTagged(&DCtx, &Item, CBOR_TAG_DECIMAL_FRACTION) ||
      QCBORDecode_GetNthTag(&DCtx, &Item, 0) != CBOR_TAG_DECIMAL_FRACTION ||
      QCBORDecode_GetNthTag(&DCtx, &Item, 1) != CBOR_TAG_INVALID64 ||
      QCBORDecode_GetNthTag(&DCtx, &Item, 2) != CBOR_TAG_INVALID64 ||
      QCBORDecode_GetNthTag(&DCtx, &Item, 3) != CBOR_TAG_INVALID64 ||
      QCBORDecode_GetNthTag(&DCtx, &Item, 4) != CBOR_TAG_INVALID64 ||
      Item.val.uCount != 2) {
      return -4;
   }
   // consume the items in the array
   uError = QCBORDecode_GetNext(&DCtx, &Item);
   uError = QCBORDecode_GetNext(&DCtx, &Item);

#else /* QCBOR_DISABLE_EXP_AND_MANTISSA */
   if(uError != QCBOR_SUCCESS ||
      Item.uDataType != QCBOR_TYPE_DECIMAL_FRACTION ||
      QCBORDecode_GetNthTag(&DCtx, &Item, 0) != CBOR_TAG_INVALID64 ||
      QCBORDecode_GetNthTag(&DCtx, &Item, 1) != CBOR_TAG_INVALID64 ||
      QCBORDecode_GetNthTag(&DCtx, &Item, 2) != CBOR_TAG_INVALID64 ||
      QCBORDecode_GetNthTag(&DCtx, &Item, 3) != CBOR_TAG_INVALID64 ||
      QCBORDecode_GetNthTag(&DCtx, &Item, 4) != CBOR_TAG_INVALID64 ) {
      return -5;
   }
#endif /* QCBOR_DISABLE_EXP_AND_MANTISSA */

   /*
    More than 4 tags on an item 225(226(227(228(229([])))))
    */
   uError = QCBORDecode_GetNext(&DCtx, &Item);
   if(uError != QCBOR_ERR_TOO_MANY_TAGS) {
      return -6;
   }

   if(QCBORDecode_GetNthTag(&DCtx, &Item, 0) != CBOR_TAG_INVALID64) {
      return -106;
   }


   /* tag 10489608748473423768(
             2442302356(
                21590(
                   240(
                      []))))
    */
   uError = QCBORDecode_GetNext(&DCtx, &Item);
   if(uError != QCBOR_SUCCESS ||
      Item.uDataType != QCBOR_TYPE_ARRAY ||
      QCBORDecode_GetNthTag(&DCtx, &Item, 3) != 10489608748473423768ULL ||
      QCBORDecode_GetNthTag(&DCtx, &Item, 2) != 2442302356ULL ||
      QCBORDecode_GetNthTag(&DCtx, &Item, 1) != 21590ULL ||
      QCBORDecode_GetNthTag(&DCtx, &Item, 0) != 240ULL) {
      return -7;
   }

   /* tag 21590(
             10489608748473423768(
                2442302357(
                   21591(
                       []))))
    */
   uError = QCBORDecode_GetNext(&DCtx, &Item);
   if(uError != QCBOR_SUCCESS ||
      Item.uDataType != QCBOR_TYPE_ARRAY ||
      QCBORDecode_GetNthTag(&DCtx, &Item, 0) != 65534ULL ||
      QCBORDecode_GetNthTag(&DCtx, &Item, 1) != 2442302357ULL ||
      QCBORDecode_GetNthTag(&DCtx, &Item, 2) != 10489608748473423768ULL ||
      QCBORDecode_GetNthTag(&DCtx, &Item, 3) != 21590ULL) {
      return -8;
   }

   /* Make sure to blow past the limit of tags that must be mapped.
      works in conjuntion with entries above.
    269488144(269488145(269488146(269488147([]))))
    */
   uError = QCBORDecode_GetNext(&DCtx, &Item);
   if(uError != QCBOR_ERR_TOO_MANY_TAGS) {
      return -9;
   }

   uError = QCBORDecode_GetNext(&DCtx, &Item);
   if(uError == QCBOR_SUCCESS) {
      return -10;
   }

   // ----------------------------------
   // This test sets up a caller-config list that includes the very large
   // tage and then matches it. Caller-config lists are no longer
   // used or needed. This tests backwards compatibility with them.
   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spEncodedLargeTag),
                    QCBOR_DECODE_MODE_NORMAL);
   const uint64_t puList[] = {0x9192939495969798, 257};
   const QCBORTagListIn TL = {2, puList};
   QCBORDecode_SetCallerConfiguredTagList(&DCtx, &TL);

   if(QCBORDecode_GetNext(&DCtx, &Item)) {
      return -8;
   }
   if(Item.uDataType != QCBOR_TYPE_ARRAY ||
      !QCBORDecode_IsTagged(&DCtx, &Item, 0x9192939495969798) ||
      QCBORDecode_IsTagged(&DCtx, &Item, 257) ||
      QCBORDecode_IsTagged(&DCtx, &Item, CBOR_TAG_BIGFLOAT) ||
      Item.val.uCount != 0) {
      return -9;
   }

   //------------------------
   // Sets up a caller-configured list and look up something not in it
   // Another backwards compatibility test.
   const uint64_t puLongList[17] = {1,2,1};
   const QCBORTagListIn TLLong = {17, puLongList};
   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spEncodedLargeTag),
                    QCBOR_DECODE_MODE_NORMAL);
   QCBORDecode_SetCallerConfiguredTagList(&DCtx, &TLLong);
   if(QCBORDecode_GetNext(&DCtx, &Item)) {
      return -11;
   }

   uint64_t puTags[4];
   QCBORTagListOut Out = {0, 4, puTags};


   // This tests retrievel of the full tag list
   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spLotsOfTags),
                    QCBOR_DECODE_MODE_NORMAL);
   if(QCBORDecode_GetNextWithTags(&DCtx, &Item, &Out)) {
      return -12;
   }
   if(puTags[0] != 0x9192939495969798 ||
      puTags[1] != 0x88 ||
      puTags[2] != 0x06 ||
      puTags[3] != 0x07) {
      return -13;
   }

   // ----------------------
   // This tests too small of an out list
   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spLotsOfTags),
                    QCBOR_DECODE_MODE_NORMAL);
   QCBORTagListOut OutSmall = {0, 3, puTags};
   if(QCBORDecode_GetNextWithTags(&DCtx, &Item, &OutSmall) != QCBOR_ERR_TOO_MANY_TAGS) {
      return -14;
   }



   // ---------------
   // Decode a version of the "CSR" that has had a ton of tags randomly inserted
   // It is a bit of a messy test and maybe could be improved, but
   // it is retained as a backwards compatibility check.
   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spCSRWithTags),
                    QCBOR_DECODE_MODE_NORMAL);
   int n = CheckCSRMaps(&DCtx);
   if(n) {
      return n-2000;
   }

   Out = (QCBORTagListOut){0, 16, puTags};
   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spCSRWithTags),
                    QCBOR_DECODE_MODE_NORMAL);

   /* With the spiffy decode revision, this tag list is not used.
    It doesn't matter if a tag is in this list or not so some
    tests that couldn't process a tag because it isn't in this list
    now can process these unlisted tags. The tests have been
    adjusted for this. */
   const uint64_t puTagList[] = {773, 1, 90599561};
   const QCBORTagListIn TagList = {3, puTagList};
   QCBORDecode_SetCallerConfiguredTagList(&DCtx, &TagList);


   if(QCBORDecode_GetNextWithTags(&DCtx, &Item, &Out)) {
      return -100;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP ||
      !QCBORDecode_IsTagged(&DCtx, &Item, CBOR_TAG_CBOR_MAGIC) ||
      QCBORDecode_IsTagged(&DCtx, &Item, 90599561) ||
      QCBORDecode_IsTagged(&DCtx, &Item, CBOR_TAG_DATE_EPOCH) ||
      Item.val.uCount != 2 ||
      puTags[0] != CBOR_TAG_CBOR_MAGIC ||
      puTags[1] != CBOR_TAG_CBOR_MAGIC ||
      puTags[2] != CBOR_TAG_CBOR_MAGIC ||
      Out.uNumUsed != 3) {
      return -101;
   }

   if(QCBORDecode_GetNextWithTags(&DCtx, &Item, &Out)) {
      return -102;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP ||
      QCBORDecode_IsTagged(&DCtx, &Item, CBOR_TAG_CBOR_MAGIC) ||
      QCBORDecode_IsTagged(&DCtx, &Item, 6) ||
      !QCBORDecode_IsTagged(&DCtx, &Item, 7) ||
      Item.val.uCount != 2 ||
      puTags[0] != 5859837686836516696 ||
      puTags[1] != 7 ||
      Out.uNumUsed != 2) {
      return -103;
   }

   if(QCBORDecode_GetNextWithTags(&DCtx, &Item, &Out)) {
      return -104;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP ||
      Item.val.uCount != 5 ||
      puTags[0] != 0x0b ||
      Out.uNumUsed != 1) {
      return -105;
   }

   if(QCBORDecode_GetNextWithTags(&DCtx, &Item, &Out)) {
      return -106;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      !QCBORDecode_IsTagged(&DCtx, &Item, CBOR_TAG_COSE_MAC0) ||
      Item.val.string.len != 12 ||
      puTags[0] != CBOR_TAG_COSE_MAC0 ||
      puTags[1] != CBOR_TAG_COSE_MAC0 ||
      puTags[2] != CBOR_TAG_COSE_MAC0 ||
      Out.uNumUsed != 3) {
      return -105;
   }

   if(QCBORDecode_GetNextWithTags(&DCtx, &Item, &Out)) {
      return -107;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      !QCBORDecode_IsTagged(&DCtx, &Item, 773) ||
      Item.val.string.len != 3 ||
      puTags[0] != 773 ||
      Out.uNumUsed != 1) {
      return -108;
   }

   if(QCBORDecode_GetNextWithTags(&DCtx, &Item, &Out)) {
      return -109;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      !QCBORDecode_IsTagged(&DCtx, &Item, 16) ||
      Item.val.string.len != 9 ||
      puTags[0] != 16 ||
      puTags[3] != 7 ||
      Out.uNumUsed != 4) {
      return -110;
   }

   if(QCBORDecode_GetNextWithTags(&DCtx, &Item, &Out)) {
      return -111;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      !QCBORDecode_IsTagged(&DCtx, &Item, 17) ||
      Item.val.string.len != 9 ||
      puTags[0] != 17 ||
      Out.uNumUsed != 1) {
      return -112;
   }

   if(QCBORDecode_GetNextWithTags(&DCtx, &Item, &Out)) {
      return -111;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      !QCBORDecode_IsTagged(&DCtx, &Item, 17) ||
      Item.val.string.len != 2 ||
      puTags[0] != 17 ||
      Out.uNumUsed != 1) {
      return -112;
   }

   if(QCBORDecode_GetNextWithTags(&DCtx, &Item, &Out)) {
      return -113;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP ||
      !QCBORDecode_IsTagged(&DCtx, &Item, 19) ||
      Item.val.uCount != 2 ||
      puTags[0] != 19 ||
      Out.uNumUsed != 1) {
      return -114;
   }

   if(QCBORDecode_GetNextWithTags(&DCtx, &Item, &Out)) {
      return -115;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP ||
      !QCBORDecode_IsTagged(&DCtx, &Item, 9) ||
      Item.val.uCount != 1 ||
      puTags[0] != 9 ||
      Out.uNumUsed != 1) {
      return -116;
   }

   if(QCBORDecode_GetNextWithTags(&DCtx, &Item, &Out)) {
      return -116;
   }
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -7 ||
      Out.uNumUsed != 0) {
      return -117;
   }

   if(QCBORDecode_GetNextWithTags(&DCtx, &Item, &Out)) {
      return -118;
   }
   if(Item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      Item.val.string.len != 10 ||
      puTags[0] != 12 ||
      Out.uNumUsed != 1) {
      return -119;
   }

   if(QCBORDecode_GetNextWithTags(&DCtx, &Item, &Out)) {
      return -120;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP ||
      !QCBORDecode_IsTagged(&DCtx, &Item, CBOR_TAG_ENC_AS_B16) ||
      Item.val.uCount != 1 ||
      puTags[0] != 0x17 ||
      Out.uNumUsed != 1) {
      return -121;
   }

   if(QCBORDecode_GetNextWithTags(&DCtx, &Item, &Out)) {
      return -122;
   }
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      !QCBORDecode_IsTagged(&DCtx, &Item, 8) ||
      Item.val.int64 != -3 ||
      puTags[0] != 8 ||
      Out.uNumUsed != 1) {
      return -123;
   }

   if(QCBORDecode_Finish(&DCtx)) {
      return -124;
   }

   UsefulBufC DateString;
   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spSpiffyTagInput),
                    QCBOR_DECODE_MODE_NORMAL);

   QCBORDecode_EnterArray(&DCtx, NULL);
   // tagged date string
   QCBORDecode_GetDateString(&DCtx, QCBOR_TAG_REQUIREMENT_TAG, &DateString);
   // untagged date string
   QCBORDecode_GetDateString(&DCtx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &DateString);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_SUCCESS) {
      return 100;
   }
   // untagged byte string
   QCBORDecode_GetDateString(&DCtx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &DateString);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_UNEXPECTED_TYPE) {
      return 101;
   }
   // tagged regex
   QCBORDecode_GetDateString(&DCtx, QCBOR_TAG_REQUIREMENT_TAG, &DateString);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_UNEXPECTED_TYPE) {
      return 102;
   }
   // tagged date string with a byte string
   QCBORDecode_GetDateString(&DCtx, QCBOR_TAG_REQUIREMENT_TAG, &DateString);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT) {
      return 103;
   }
   // The exit errors out because the last item, the date string with
   // bad content makes the array untraversable (the bad date string
   // could have tag content of an array or such that is not consumed
   // by the date decoding).
   QCBORDecode_ExitArray(&DCtx);
   if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT) {
      return 104;
   }


   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spSpiffyTagInput),
                    QCBOR_DECODE_MODE_NORMAL);

   QCBORDecode_EnterArray(&DCtx, NULL);
   // tagged date string
   QCBORDecode_GetDateString(&DCtx, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, &DateString);
   // untagged date string
   QCBORDecode_GetDateString(&DCtx, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, &DateString);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_SUCCESS) {
      return 200;
   }
   // untagged byte string
   QCBORDecode_GetDateString(&DCtx, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, &DateString);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_UNEXPECTED_TYPE) {
      return 201;
   }
   // tagged regex
   QCBORDecode_GetDateString(&DCtx, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, &DateString);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_UNEXPECTED_TYPE) {
      return 202;
   }
   // tagged date string with a byte string
   QCBORDecode_GetDateString(&DCtx, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, &DateString);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT) {
      return 203;
   }
   // See comments above
   QCBORDecode_ExitArray(&DCtx);
   if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT) {
      return 204;
   }

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spSpiffyTagInput),
                    QCBOR_DECODE_MODE_NORMAL);

   QCBORDecode_EnterArray(&DCtx, NULL);
   // tagged date string
   QCBORDecode_GetDateString(&DCtx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &DateString);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_UNEXPECTED_TYPE) {
      return 300;
   }
   // untagged date string
   QCBORDecode_GetDateString(&DCtx, QCBOR_TAG_REQUIREMENT_TAG, &DateString);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_UNEXPECTED_TYPE) {
      return 301;
   }
   // untagged byte string
   QCBORDecode_GetDateString(&DCtx, QCBOR_TAG_REQUIREMENT_TAG, &DateString);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_UNEXPECTED_TYPE) {
      return 302;
   }
   // tagged regex
   QCBORDecode_GetDateString(&DCtx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &DateString);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_UNEXPECTED_TYPE) {
      return 303;
   }
   // tagged date string with a byte string
   QCBORDecode_GetDateString(&DCtx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &DateString);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT) {
      return 304;
   }
   // See comments above
   QCBORDecode_ExitArray(&DCtx);
   if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT) {
      return 305;
   }

   return 0;
}




static const uint8_t spBigNumInput[] = {
 0x83,
   0xC2, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0xC3, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0xA4,
     0x63, 0x42, 0x4E, 0x2B,
       0xC2, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x18, 0x40,
       0xC2, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x63, 0x42, 0x4E, 0x2D,
       0xC3, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x38, 0x3F,
       0xC3, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* The expected big num */
static const uint8_t spBigNum[] = {
   0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00};


int32_t BignumParseTest()
{
   QCBORDecodeContext DCtx;
   QCBORItem Item;
   QCBORError nCBORError;

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBigNumInput),
                    QCBOR_DECODE_MODE_NORMAL);


   //
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -1;
   if(Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -2;
   }

   //
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -3;
   if(Item.uDataType != QCBOR_TYPE_POSBIGNUM ||
      UsefulBuf_Compare(Item.val.bigNum, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBigNum))){
      return -4;
   }

   //
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -5;
   if(Item.uDataType != QCBOR_TYPE_NEGBIGNUM ||
      UsefulBuf_Compare(Item.val.bigNum, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBigNum))){
      return -6;
   }

   //
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -7;
   if(Item.uDataType != QCBOR_TYPE_MAP) {
      return -8;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -9;
   if(Item.uDataType != QCBOR_TYPE_POSBIGNUM ||
      Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBuf_Compare(Item.val.bigNum, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBigNum))){
      return -10;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -11;
   if(Item.uDataType != QCBOR_TYPE_POSBIGNUM ||
      Item.uLabelType != QCBOR_TYPE_INT64 ||
      Item.label.int64 != 64 ||
      UsefulBuf_Compare(Item.val.bigNum, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBigNum))){
      return -12;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -13;
   if(Item.uDataType != QCBOR_TYPE_NEGBIGNUM ||
      Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBuf_Compare(Item.val.bigNum, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBigNum))){
      return -14;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -15;
   if(Item.uDataType != QCBOR_TYPE_NEGBIGNUM ||
      Item.uLabelType != QCBOR_TYPE_INT64 ||
      Item.label.int64 != -64 ||
      UsefulBuf_Compare(Item.val.bigNum, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBigNum))){
      return -16;
   }

   return 0;
}



static int32_t CheckItemWithIntLabel(QCBORDecodeContext *pCtx,
                                 uint8_t uDataType,
                                 uint8_t uNestingLevel,
                                 uint8_t uNextNest,
                                 int64_t nLabel,
                                 QCBORItem *pItem)
{
   QCBORItem Item;
   QCBORError nCBORError;

   if((nCBORError = QCBORDecode_GetNext(pCtx, &Item))) return -1;
   if(Item.uDataType != uDataType) return -1;
   if(uNestingLevel > 0) {
      if(Item.uLabelType != QCBOR_TYPE_INT64 &&
         Item.uLabelType != QCBOR_TYPE_UINT64) {
         return -1;
      }
      if(Item.uLabelType == QCBOR_TYPE_INT64) {
         if(Item.label.int64 != nLabel) return -1;
      } else  {
         if(Item.label.uint64 != (uint64_t)nLabel) return -1;
      }
   }
   if(Item.uNestingLevel != uNestingLevel) return -1;
   if(Item.uNextNestLevel != uNextNest) return -1;

   if(pItem) {
      *pItem = Item;
   }
   return 0;
}


// Same code checks definite and indefinite length versions of the map
static int32_t CheckCSRMaps(QCBORDecodeContext *pDC)
{
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_MAP, 0, 1, 0, NULL)) return -1;

   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_MAP, 1, 2, -23, NULL)) return -2;

   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_MAP, 2, 3, -20, NULL)) return -3;

   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_TEXT_STRING, 3, 3, -18, NULL)) return -4;
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_TEXT_STRING, 3, 3, -17, NULL)) return -5;
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_TEXT_STRING, 3, 3, -15, NULL)) return -6;
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_TEXT_STRING, 3, 3, -16, NULL)) return -7;
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_TEXT_STRING, 3, 2, -14, NULL)) return -8;

   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_MAP, 2, 3, -19, NULL)) return -9;
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_MAP, 3, 4, -11, NULL)) return -10;

   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_INT64, 4, 3, -9, NULL)) return -11;
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_BYTE_STRING, 3, 1, -10, NULL)) return -12;

   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_MAP, 1, 2, -22, NULL)) return -13;
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_INT64, 2, 0, -5, NULL)) return -14;

   if(QCBORDecode_Finish(pDC)) return -20;

   return 0;
}


/*
{
    -23: {
        -20: {
            -18: "Organization",
            -17: "SSG",
            -15: "Confusion",
            -16: "San Diego",
            -14: "US"
        },
        -19: {
            -11: {
                -9: -7
            },
            -10: '\u0001\u0002\u0003\u0004\u0005\u0006\a\b\t\n'
        }
    },
    -22: {
        -5: -3
    }
}
*/
static const uint8_t spCSRInput[] = {
   0xa2, 0x36, 0xa2, 0x33, 0xa5, 0x31, 0x6c, 0x4f,
   0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74,
   0x69, 0x6f, 0x6e, 0x30, 0x63, 0x53, 0x53, 0x47,
   0x2e, 0x69, 0x43, 0x6f, 0x6e, 0x66, 0x75, 0x73,
   0x69, 0x6f, 0x6e, 0x2f, 0x69, 0x53, 0x61, 0x6e,
   0x20, 0x44, 0x69, 0x65, 0x67, 0x6f, 0x2d, 0x62,
   0x55, 0x53, 0x32, 0xa2, 0x2a, 0xa1, 0x28, 0x26,
   0x29, 0x4a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
   0x07, 0x08, 0x09, 0x0a, 0x35, 0xa1, 0x24, 0x22};

// Same map as above, but using indefinite lengths
static const uint8_t spCSRInputIndefLen[] = {
   0xbf, 0x36, 0xbf, 0x33, 0xbf, 0x31, 0x6c, 0x4f,
   0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74,
   0x69, 0x6f, 0x6e, 0x30, 0x63, 0x53, 0x53, 0x47,
   0x2e, 0x69, 0x43, 0x6f, 0x6e, 0x66, 0x75, 0x73,
   0x69, 0x6f, 0x6e, 0x2f, 0x69, 0x53, 0x61, 0x6e,
   0x20, 0x44, 0x69, 0x65, 0x67, 0x6f, 0x2d, 0x62,
   0x55, 0x53, 0xff, 0x32, 0xbf, 0x2a, 0xbf, 0x28,
   0x26, 0xff, 0x29, 0x4a, 0x01, 0x02, 0x03, 0x04,
   0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0xff, 0xff,
   0x35, 0xbf, 0x24, 0x22, 0xff, 0xff};


int32_t NestedMapTest()
{
   QCBORDecodeContext DCtx;

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spCSRInput),
                    QCBOR_DECODE_MODE_NORMAL);

   return CheckCSRMaps(&DCtx);
}



int32_t StringDecoderModeFailTest()
{
   QCBORDecodeContext DCtx;

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spCSRInput),
                    QCBOR_DECODE_MODE_MAP_STRINGS_ONLY);

   QCBORItem Item;
   QCBORError nCBORError;

   if(QCBORDecode_GetNext(&DCtx, &Item)) {
      return -1;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP) {
      return -2;
   }

   nCBORError = QCBORDecode_GetNext(&DCtx, &Item);
   if(nCBORError != QCBOR_ERR_MAP_LABEL_TYPE) {
      return -3;
   }

   return 0;
}



int32_t NestedMapTestIndefLen()
{
   QCBORDecodeContext DCtx;

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spCSRInputIndefLen),
                    QCBOR_DECODE_MODE_NORMAL);

   return CheckCSRMaps(&DCtx);
}



static UsefulBufC make_nested_indefinite_arrays(int n, UsefulBuf Storage)
{
   UsefulOutBuf UOB;
   UsefulOutBuf_Init(&UOB, Storage);

   int i;
   for(i = 0; i < n; i++) {
      UsefulOutBuf_AppendByte(&UOB, 0x9f);
   }

   for(i = 0; i < n; i++) {
      UsefulOutBuf_AppendByte(&UOB, 0xff);
   }
   return UsefulOutBuf_OutUBuf(&UOB);
}


static int32_t parse_indeflen_nested(UsefulBufC Nested, int nNestLevel)
{
   QCBORDecodeContext DC;
   QCBORDecode_Init(&DC, Nested, 0);

   int j;
   for(j = 0; j < nNestLevel; j++) {
      QCBORItem Item;
      QCBORError nReturn = QCBORDecode_GetNext(&DC, &Item);
      if(j >= QCBOR_MAX_ARRAY_NESTING) {
         // Should be in error
         if(nReturn != QCBOR_ERR_ARRAY_DECODE_NESTING_TOO_DEEP) {
            return -4;
         } else {
            return 0; // Decoding doesn't recover after an error
         }
      } else {
         // Should be no error
         if(nReturn) {
            return -9; // Should not have got an error
         }
      }
      if(Item.uDataType != QCBOR_TYPE_ARRAY) {
         return -7;
      }
   }
   QCBORError nReturn = QCBORDecode_Finish(&DC);
   if(nReturn) {
      return -3;
   }
   return 0;
}


int32_t IndefiniteLengthNestTest()
{
   UsefulBuf_MAKE_STACK_UB(Storage, 50);
   int i;
   for(i=1; i < QCBOR_MAX_ARRAY_NESTING+4; i++) {
      const UsefulBufC Nested = make_nested_indefinite_arrays(i, Storage);
      int nReturn = parse_indeflen_nested(Nested, i);
      if(nReturn) {
         return nReturn;
      }
   }
   return 0;
}

// [1, [2, 3]]
static const uint8_t spIndefiniteArray[]     = {0x9f, 0x01, 0x82, 0x02, 0x03, 0xff};
// No closing break
static const uint8_t spIndefiniteArrayBad1[] = {0x9f};
// Not enough closing breaks
static const uint8_t spIndefiniteArrayBad2[] = {0x9f, 0x9f, 0x02, 0xff};
// Too many closing breaks
static const uint8_t spIndefiniteArrayBad3[] = {0x9f, 0x02, 0xff, 0xff};
// Unclosed indeflen inside def len
static const uint8_t spIndefiniteArrayBad4[] = {0x81, 0x9f};
// confused tag
static const uint8_t spIndefiniteArrayBad5[] = {0x9f, 0xd1, 0xff};

int32_t IndefiniteLengthArrayMapTest()
{
   QCBORError nResult;
   // --- first test -----
    UsefulBufC IndefLen = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spIndefiniteArray);

    // Decode it and see if it is OK
    QCBORDecodeContext DC;
    QCBORItem Item;
    QCBORDecode_Init(&DC, IndefLen, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_GetNext(&DC, &Item);

    if(Item.uDataType != QCBOR_TYPE_ARRAY ||
       Item.uNestingLevel != 0 ||
       Item.uNextNestLevel != 1) {
       return -111;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_INT64 ||
       Item.uNestingLevel != 1 ||
       Item.uNextNestLevel != 1) {
        return -2;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_ARRAY ||
       Item.uNestingLevel != 1 ||
       Item.uNextNestLevel != 2) {
        return -3;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_INT64 ||
       Item.uNestingLevel != 2 ||
       Item.uNextNestLevel != 2) {
        return -4;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_INT64 ||
       Item.uNestingLevel != 2 ||
       Item.uNextNestLevel != 0) {
        return -5;
    }

    if(QCBORDecode_Finish(&DC)) {
        return -6;
    }

   // --- next test -----
   IndefLen = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spIndefiniteArrayBad1);

   QCBORDecode_Init(&DC, IndefLen, QCBOR_DECODE_MODE_NORMAL);

   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult || Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -7;
   }

   nResult = QCBORDecode_Finish(&DC);
   if(nResult != QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED) {
      return -8;
   }


   // --- next test -----
   IndefLen = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spIndefiniteArrayBad2);

   QCBORDecode_Init(&DC, IndefLen, QCBOR_DECODE_MODE_NORMAL);

   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult || Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -9;
   }

   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult || Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -10;
   }

   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult || Item.uDataType != QCBOR_TYPE_INT64) {
      return -11;
   }

   nResult = QCBORDecode_Finish(&DC);
   if(nResult != QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED) {
      return -12;
   }


   // --- next test -----
   IndefLen = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spIndefiniteArrayBad3);

   QCBORDecode_Init(&DC, IndefLen, QCBOR_DECODE_MODE_NORMAL);

   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult || Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -13;
   }

   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult != QCBOR_SUCCESS) {
      return -14;
   }

   nResult = QCBORDecode_GetNext(&DC, &Item);
    if(nResult != QCBOR_ERR_BAD_BREAK) {
       return -140;
    }


   // --- next test -----
   IndefLen = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spIndefiniteArrayBad4);

   QCBORDecode_Init(&DC, IndefLen, QCBOR_DECODE_MODE_NORMAL);

   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult || Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -15;
   }

   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult || Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -16;
   }

   nResult = QCBORDecode_Finish(&DC);
   if(nResult != QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED) {
      return -17;
   }

   // --- next test -----
   IndefLen = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spIndefiniteArrayBad5);

   QCBORDecode_Init(&DC, IndefLen, QCBOR_DECODE_MODE_NORMAL);

   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult || Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -18;
   }

   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult != QCBOR_ERR_BAD_BREAK) {
      return -19;
   }

    return 0;
}


#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS

static const uint8_t spIndefiniteLenString[] = {
   0x81, // Array of length one
   0x7f, // text string marked with indefinite length
   0x65, 0x73, 0x74, 0x72, 0x65, 0x61, // first segment
   0x64, 0x6d, 0x69, 0x6e, 0x67, // second segment
   0xff // ending break
};

static const uint8_t spIndefiniteLenStringBad2[] = {
   0x81, // Array of length one
   0x7f, // text string marked with indefinite length
   0x65, 0x73, 0x74, 0x72, 0x65, 0x61, // first segment
   0x44, 0x6d, 0x69, 0x6e, 0x67, // second segment of wrong type
   0xff // ending break
};

static const uint8_t spIndefiniteLenStringBad3[] = {
   0x81, // Array of length one
   0x7f, // text string marked with indefinite length
   0x01, 0x02, // Not a string
   0xff // ending break
};

static const uint8_t spIndefiniteLenStringBad4[] = {
   0x81, // Array of length one
   0x7f, // text string marked with indefinite length
   0x65, 0x73, 0x74, 0x72, 0x65, 0x61, // first segment
   0x64, 0x6d, 0x69, 0x6e, 0x67, // second segment
   // missing end of string
};

static const uint8_t spIndefiniteLenStringLabel[] = {
   0xa1, // Array of length one
   0x7f, // text string marked with indefinite length
   0x65, 0x73, 0x74, 0x72, 0x75, 0x75, // first segment
   0x64, 0x6d, 0x69, 0x6e, 0x67, // second segment
   0xff, // ending break
   0x01 // integer being labeled.
};

/**
 Make an indefinite length string

 @param Storage Storage for string, must be 144 bytes in size
 @return The indefinite length string

 This makes an array with one indefinite length string that has 7 chunks
 from size of 1 byte up to 64 bytes.
 */
static UsefulBufC MakeIndefiniteBigBstr(UsefulBuf Storage)
{
   UsefulOutBuf UOB;

   UsefulOutBuf_Init(&UOB, Storage);
   UsefulOutBuf_AppendByte(&UOB, 0x81);
   UsefulOutBuf_AppendByte(&UOB, 0x5f);

   uint8_t uStringByte = 0;
   // Use of type int is intentional
   for(int uChunkSize = 1; uChunkSize <= 128; uChunkSize *= 2) {
      // Not using preferred encoding here, but that is OK.
      UsefulOutBuf_AppendByte(&UOB, 0x58);
      UsefulOutBuf_AppendByte(&UOB, (uint8_t)uChunkSize);
      for(int j = 0; j < uChunkSize; j++) {
         UsefulOutBuf_AppendByte(&UOB, uStringByte);
         uStringByte++;
      }
   }
   UsefulOutBuf_AppendByte(&UOB, 0xff);

   return UsefulOutBuf_OutUBuf(&UOB);
}

static int CheckBigString(UsefulBufC BigString)
{
   if(BigString.len != 255) {
      return 1;
   }

   for(uint8_t i = 0; i < 255; i++){
      if(((const uint8_t *)BigString.ptr)[i] != i) {
         return 1;
      }
   }
   return 0;
}


int32_t IndefiniteLengthStringTest()
{
   QCBORDecodeContext DC;
   QCBORItem Item;
   // big enough for MakeIndefiniteBigBstr() + MemPool overhead
   UsefulBuf_MAKE_STACK_UB(MemPool, 350);

   // --- Simple normal indefinite length string ------
   UsefulBufC IndefLen = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spIndefiniteLenString);
   QCBORDecode_Init(&DC, IndefLen, QCBOR_DECODE_MODE_NORMAL);

   if(QCBORDecode_SetMemPool(&DC, MemPool, false)) {
      return -1;
   }

   if(QCBORDecode_GetNext(&DC, &Item)) {
      return -2;
   }
   if(Item.uDataType != QCBOR_TYPE_ARRAY || Item.uDataAlloc) {
      return -3;
   }

   if(QCBORDecode_GetNext(&DC, &Item)) {
      return -4;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING || !Item.uDataAlloc) {
      return -5;
   }
   if(QCBORDecode_Finish(&DC)) {
      return -6;
   }

   // ----- types mismatch ---
   QCBORDecode_Init(&DC,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spIndefiniteLenStringBad2),
                    QCBOR_DECODE_MODE_NORMAL);

   if(QCBORDecode_SetMemPool(&DC,  MemPool, false)) {
      return -7;
   }

   if(QCBORDecode_GetNext(&DC, &Item)) {
      return -8;
   }
   if(Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -9;
   }

   if(QCBORDecode_GetNext(&DC, &Item) != QCBOR_ERR_INDEFINITE_STRING_CHUNK) {
      return -10;
   }

   // ----- not a string ---
   QCBORDecode_Init(&DC,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spIndefiniteLenStringBad3),
                    QCBOR_DECODE_MODE_NORMAL);

   if(QCBORDecode_SetMemPool(&DC,  MemPool, false)) {
      return -11;
   }

   if(QCBORDecode_GetNext(&DC, &Item)) {
      return -12;
   }
   if(Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -13;
   }

   if(QCBORDecode_GetNext(&DC, &Item) != QCBOR_ERR_INDEFINITE_STRING_CHUNK) {
      return -14;
   }

   // ----- no end -----
   QCBORDecode_Init(&DC,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spIndefiniteLenStringBad4),
                    QCBOR_DECODE_MODE_NORMAL);

   if(QCBORDecode_SetMemPool(&DC,  MemPool, false)) {
      return -15;
   }

   if(QCBORDecode_GetNext(&DC, &Item)) {
      return -16;
   }
   if(Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -17;
   }

   if(QCBORDecode_GetNext(&DC, &Item) != QCBOR_ERR_HIT_END) {
      return -18;
   }

   // ------ Don't set a string allocator and see an error -----
   QCBORDecode_Init(&DC, IndefLen, QCBOR_DECODE_MODE_NORMAL);

   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -19;
   }

   if(QCBORDecode_GetNext(&DC, &Item) != QCBOR_ERR_NO_STRING_ALLOCATOR) {
      return -20;
   }

   // ----- Mempool is way too small -----
   UsefulBuf_MAKE_STACK_UB(MemPoolTooSmall, QCBOR_DECODE_MIN_MEM_POOL_SIZE-1);

   QCBORDecode_Init(&DC, IndefLen, QCBOR_DECODE_MODE_NORMAL);
   if(!QCBORDecode_SetMemPool(&DC,  MemPoolTooSmall, false)) {
      return -21;
   }

   // ----- Mempool is way too small -----
   UsefulBuf_MAKE_STACK_UB(BigIndefBStrStorage, 290);
   const UsefulBufC BigIndefBStr = MakeIndefiniteBigBstr(BigIndefBStrStorage);

   // 80 is big enough for MemPool overhead, but not BigIndefBStr
   UsefulBuf_MAKE_STACK_UB(MemPoolSmall, 80);

   QCBORDecode_Init(&DC, BigIndefBStr, QCBOR_DECODE_MODE_NORMAL);
   if(QCBORDecode_SetMemPool(&DC,  MemPoolSmall, false)) {
      return -22;
   }

   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -23;
   }
   if(QCBORDecode_GetNext(&DC, &Item) != QCBOR_ERR_STRING_ALLOCATE) {
      return -24;
   }

   // ---- big bstr -----
   QCBORDecode_Init(&DC, BigIndefBStr, QCBOR_DECODE_MODE_NORMAL);

   if(QCBORDecode_SetMemPool(&DC,  MemPool, false)) {
      return -25;
   }

   if(QCBORDecode_GetNext(&DC, &Item)) {
      return -26;
   }
   if(Item.uDataType != QCBOR_TYPE_ARRAY || Item.uDataAlloc) {
      return -26;
   }

   if(QCBORDecode_GetNext(&DC, &Item)) {
      return -27;
   }
   if(Item.uDataType != QCBOR_TYPE_BYTE_STRING || !Item.uDataAlloc || Item.uNestingLevel != 1) {
      return -28;
   }
   if(CheckBigString(Item.val.string)) {
      return -3;
   }
   if(QCBORDecode_Finish(&DC)) {
      return -29;
   }

   // --- label is an indefinite length string ------
   QCBORDecode_Init(&DC, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spIndefiniteLenStringLabel), QCBOR_DECODE_MODE_NORMAL);

   if(QCBORDecode_SetMemPool(&DC,  MemPool, false)) {
      return -30;
   }

   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_MAP) {
      return -31;
   }

   if(QCBORDecode_GetNext(&DC, &Item)){
      return -32;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.uDataAlloc || !Item.uLabelAlloc ||
      UsefulBuf_Compare(Item.label.string, UsefulBuf_FromSZ("struuming"))) {
      return -33;
   }

   if(QCBORDecode_Finish(&DC)) {
      return -34;
   }

   return 0;
}


int32_t AllocAllStringsTest()
{
   QCBORDecodeContext DC;
   QCBORError nCBORError;


   // First test, use the "CSRMap" as easy input and checking
   QCBORDecode_Init(&DC,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spCSRInput),
                    QCBOR_DECODE_MODE_NORMAL);

   UsefulBuf_MAKE_STACK_UB(Pool, sizeof(spCSRInput) + QCBOR_DECODE_MIN_MEM_POOL_SIZE);

   nCBORError = QCBORDecode_SetMemPool(&DC, Pool, 1); // Turn on copying.
   if(nCBORError) {
      return -1;
   }

   if(CheckCSRMaps(&DC)) {
      return -2;
   }

   // Next parse, save pointers to a few strings, destroy original and
   // see all is OK.
   UsefulBuf_MAKE_STACK_UB(CopyOfStorage, sizeof(pValidMapEncoded) + QCBOR_DECODE_MIN_MEM_POOL_SIZE);
   const UsefulBufC CopyOf = UsefulBuf_Copy(CopyOfStorage, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pValidMapEncoded));

   QCBORDecode_Init(&DC, CopyOf, QCBOR_DECODE_MODE_NORMAL);
   UsefulBuf_Set(Pool, '/');
   QCBORDecode_SetMemPool(&DC, Pool, 1); // Turn on copying.

   QCBORItem Item1, Item2, Item3, Item4;
   if((nCBORError = QCBORDecode_GetNext(&DC, &Item1)))
      return (int32_t)nCBORError;
   if(Item1.uDataType != QCBOR_TYPE_MAP ||
      Item1.val.uCount != 3)
      return -3;
   if((nCBORError = QCBORDecode_GetNext(&DC, &Item1)))
      return (int32_t)nCBORError;
   if((nCBORError = QCBORDecode_GetNext(&DC, &Item2)))
      return (int32_t)nCBORError;
   if((nCBORError = QCBORDecode_GetNext(&DC, &Item3)))
      return (int32_t)nCBORError;
   if((nCBORError = QCBORDecode_GetNext(&DC, &Item4)))
      return (int32_t)nCBORError;

   UsefulBuf_Set(CopyOfStorage, '_');

   if(Item1.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item1.uDataType != QCBOR_TYPE_INT64 ||
      Item1.val.int64 != 42 ||
      Item1.uDataAlloc != 0 ||
      Item1.uLabelAlloc == 0 ||
      UsefulBufCompareToSZ(Item1.label.string, "first integer")) {
      return -4;
   }


   if(Item2.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBufCompareToSZ(Item2.label.string, "an array of two strings") ||
      Item2.uDataType != QCBOR_TYPE_ARRAY ||
      Item2.uDataAlloc != 0 ||
      Item2.uLabelAlloc == 0 ||
      Item2.val.uCount != 2)
      return -5;

   if(Item3.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item3.uDataAlloc == 0 ||
      Item3.uLabelAlloc != 0 ||
      UsefulBufCompareToSZ(Item3.val.string, "string1")) {
      return -6;
   }

   if(Item4.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item4.uDataAlloc == 0 ||
      Item4.uLabelAlloc != 0 ||
      UsefulBufCompareToSZ(Item4.val.string, "string2")) {
      return -7;
   }

   // Next parse with a pool that is too small
   UsefulBuf_MAKE_STACK_UB(SmallPool, QCBOR_DECODE_MIN_MEM_POOL_SIZE + 1);
   QCBORDecode_Init(&DC,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pValidMapEncoded),
                    QCBOR_DECODE_MODE_NORMAL);
   QCBORDecode_SetMemPool(&DC, SmallPool, 1); // Turn on copying.
   if((nCBORError = QCBORDecode_GetNext(&DC, &Item1)))
      return -8;
   if(Item1.uDataType != QCBOR_TYPE_MAP ||
      Item1.val.uCount != 3) {
      return -9;
   }
   if(!(nCBORError = QCBORDecode_GetNext(&DC, &Item1))){
      if(!(nCBORError = QCBORDecode_GetNext(&DC, &Item2))) {
         if(!(nCBORError = QCBORDecode_GetNext(&DC, &Item3))) {
            nCBORError = QCBORDecode_GetNext(&DC, &Item4);
         }
      }
   }
   if(nCBORError != QCBOR_ERR_STRING_ALLOCATE) {
      return -10;
   }

   return 0;
}


int32_t MemPoolTest(void)
{
   // Set up the decoder with a tiny bit of CBOR to parse because
   // nothing can be done with it unless that is set up.
   QCBORDecodeContext DC;
   const uint8_t pMinimalCBOR[] = {0xa0}; // One empty map
   QCBORDecode_Init(&DC, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pMinimalCBOR),0);

   // Set up an memory pool of 100 bytes
   // Then fish into the internals of the decode context
   // to get the allocator function so it can be called directly.
   // Also figure out how much pool is available for use
   // buy subtracting out the overhead.
   UsefulBuf_MAKE_STACK_UB(Pool, 100);
   QCBORError nError = QCBORDecode_SetMemPool(&DC, Pool, 0);
   if(nError) {
      return -9;
   }
   QCBORStringAllocate pAlloc = DC.StringAllocator.pfAllocator;
   void *pAllocCtx            = DC.StringAllocator.pAllocateCxt;
   size_t uAvailPool = Pool.len - QCBOR_DECODE_MIN_MEM_POOL_SIZE;

   // First test -- ask for one more byte than available and see failure
   UsefulBuf Allocated = (*pAlloc)(pAllocCtx, NULL, uAvailPool+1);
   if(!UsefulBuf_IsNULL(Allocated)) {
      return -1;
   }

   // Re do the set up for the next test that will do a successful alloc,
   // a fail, a free and then success
   QCBORDecode_SetMemPool(&DC, Pool, 0);
   pAlloc    = DC.StringAllocator.pfAllocator;
   pAllocCtx = DC.StringAllocator.pAllocateCxt;
   uAvailPool = Pool.len - QCBOR_DECODE_MIN_MEM_POOL_SIZE;

   // Allocate one byte less than available and see success
   Allocated = (pAlloc)(pAllocCtx, NULL, uAvailPool-1);
   if(UsefulBuf_IsNULL(Allocated)) { // expected to succeed
      return -2;
   }
   // Ask for some more and see failure
   UsefulBuf Allocated2 = (*pAlloc)(pAllocCtx, NULL, uAvailPool/2);
   if(!UsefulBuf_IsNULL(Allocated2)) { // expected to fail
      return -3;
   }
   // Free the first allocate, retry the second and see success
   (*pAlloc)(pAllocCtx, Allocated.ptr, 0); // Free
   Allocated = (*pAlloc)(pAllocCtx, NULL, uAvailPool/2);
   if(UsefulBuf_IsNULL(Allocated)) { // succeed because of the free
      return -4;
   }

   // Re do set up for next test that involves a successful alloc,
   // and a successful realloc and a failed realloc
   QCBORDecode_SetMemPool(&DC, Pool, 0);
   pAlloc    = DC.StringAllocator.pfAllocator;
   pAllocCtx = DC.StringAllocator.pAllocateCxt;

   // Allocate half the pool and see success
   Allocated = (*pAlloc)(pAllocCtx, NULL, uAvailPool/2);
   if(UsefulBuf_IsNULL(Allocated)) { // expected to succeed
      return -5;
   }
   // Reallocate to take up the whole pool and see success
   Allocated2 = (*pAlloc)(pAllocCtx, Allocated.ptr, uAvailPool);
   if(UsefulBuf_IsNULL(Allocated2)) {
      return -6;
   }
   // Make sure its the same pointer and the size is right
   if(Allocated2.ptr != Allocated.ptr || Allocated2.len != uAvailPool) {
      return -7;
   }
   // Try to allocate more to be sure there is failure after a realloc
   UsefulBuf Allocated3 = (*pAlloc)(pAllocCtx, Allocated.ptr, uAvailPool+1);
   if(!UsefulBuf_IsNULL(Allocated3)) {
      return -8;
   }

   return 0;
}


/* Just enough of an allocator to test configuration of one */
static UsefulBuf AllocateTestFunction(void *pCtx, void *pOldMem, size_t uNewSize)
{
   (void)pOldMem; // unused variable

   if(uNewSize) {
      // Assumes the context pointer is the buffer and
      // nothing too big will ever be asked for.
      // This is only good for this basic test!
      return (UsefulBuf) {pCtx, uNewSize};
   } else {
      return NULLUsefulBuf;
   }
}


int32_t SetUpAllocatorTest(void)
{
   // Set up the decoder with a tiny bit of CBOR to parse because
   // nothing can be done with it unless that is set up.
   QCBORDecodeContext DC;
   const uint8_t pMinimalCBOR[] = {0x62, 0x48, 0x69}; // "Hi"
   QCBORDecode_Init(&DC, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pMinimalCBOR),0);

   uint8_t pAllocatorBuffer[50];

   // This is really just to test that this call works.
   // The full functionality of string allocators is tested
   // elsewhere with the MemPool internal allocator.
   QCBORDecode_SetUpAllocator(&DC, AllocateTestFunction, pAllocatorBuffer, 1);

   QCBORItem Item;
   if(QCBORDecode_GetNext(&DC, &Item) != QCBOR_SUCCESS) {
      return -1;
   }

   if(Item.uDataAlloc == 0 ||
      Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.val.string.ptr != pAllocatorBuffer) {
      return -2;
   }

   if(QCBORDecode_Finish(&DC) != QCBOR_SUCCESS) {
      return -3;
   }

   return 0;
}
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */


#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA

/*  exponent, mantissa
  [
    4([-1, 3]),
    4([-20,                   4759477275222530853136]),
    4([9223372036854775807,  -4759477275222530853137]),
    5([300, 100]),
    5([-20,                   4759477275222530853136]),
    5([-9223372036854775807, -4759477275222530853137])
    5([ 9223372036854775806, -4759477275222530853137])
    5([ 9223372036854775806,  9223372036854775806])]
  ]
 */
static const uint8_t spExpectedExponentsAndMantissas[] = {
   0x88,
   0xC4, 0x82, 0x20,
               0x03,
   0xC4, 0x82, 0x33,
               0xC2, 0x4A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
   0xC4, 0x82, 0x1B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
               0xC3, 0x4A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
   0xC5, 0x82, 0x19, 0x01, 0x2C,
               0x18, 0x64,
   0xC5, 0x82, 0x33,
               0xC2, 0x4A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
   0xC5, 0x82, 0x3B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
               0xC3, 0x4A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
   0xC5, 0x82, 0x1B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
               0xC3, 0x4A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
   0xC5, 0x82, 0x1B, 0x7f, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
               0x1B, 0x7f, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE
};


int32_t ExponentAndMantissaDecodeTests(void)
{
   QCBORDecodeContext DC;
   QCBORError         uErr;
   QCBORItem          item;

   static const uint8_t spBigNumMantissa[] = {0x01, 0x02, 0x03, 0x04, 0x05,
                                              0x06, 0x07, 0x08, 0x09, 0x010};
   UsefulBufC BN = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBigNumMantissa);


   QCBORDecode_Init(&DC,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedExponentsAndMantissas),
                    QCBOR_DECODE_MODE_NORMAL);

   uErr = QCBORDecode_GetNext(&DC, &item);
   if(uErr != QCBOR_SUCCESS) {
      return 1;
   }

   if(item.uDataType != QCBOR_TYPE_ARRAY) {
      return 2;
   }

   uErr = QCBORDecode_GetNext(&DC, &item);
   if(uErr != QCBOR_SUCCESS) {
      return 3;
   }

   if(item.uDataType != QCBOR_TYPE_DECIMAL_FRACTION ||
      item.val.expAndMantissa.Mantissa.nInt != 3 ||
      item.val.expAndMantissa.nExponent != -1) {
      return 4;
   }

   uErr = QCBORDecode_GetNext(&DC, &item);
   if(uErr != QCBOR_SUCCESS) {
      return 5;
   }

   if(item.uDataType != QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM ||
      item.val.expAndMantissa.nExponent != -20 ||
      UsefulBuf_Compare(item.val.expAndMantissa.Mantissa.bigNum, BN)) {
      return 6;
   }

   uErr = QCBORDecode_GetNext(&DC, &item);
   if(uErr != QCBOR_SUCCESS) {
      return 7;
   }

   if(item.uDataType != QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM ||
      item.val.expAndMantissa.nExponent != 9223372036854775807 ||
      UsefulBuf_Compare(item.val.expAndMantissa.Mantissa.bigNum, BN)) {
      return 8;
   }

   uErr = QCBORDecode_GetNext(&DC, &item);
   if(uErr != QCBOR_SUCCESS) {
      return 9;
   }

   if(item.uDataType != QCBOR_TYPE_BIGFLOAT ||
      item.val.expAndMantissa.Mantissa.nInt != 100 ||
      item.val.expAndMantissa.nExponent != 300) {
      return 10;
   }

   // 5([-20, 4759477275222530853136]),
   uErr = QCBORDecode_GetNext(&DC, &item);
   if(uErr != QCBOR_SUCCESS) {
      return 11;
   }
   if(item.uDataType != QCBOR_TYPE_BIGFLOAT_POS_BIGNUM ||
      item.val.expAndMantissa.nExponent != -20 ||
      UsefulBuf_Compare(item.val.expAndMantissa.Mantissa.bigNum, BN)) {
      return 12;
   }

   // 5([-9223372036854775807, -4759477275222530853137])
   uErr = QCBORDecode_GetNext(&DC, &item);
   if(uErr != QCBOR_SUCCESS) {
      return 13;
   }
   if(item.uDataType != QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM ||
      item.val.expAndMantissa.nExponent != -9223372036854775807 ||
      UsefulBuf_Compare(item.val.expAndMantissa.Mantissa.bigNum, BN)) {
      return 14;
   }

   // 5([ 9223372036854775806, -4759477275222530853137])
   uErr = QCBORDecode_GetNext(&DC, &item);
   if(uErr != QCBOR_SUCCESS) {
      return 15;
   }
   if(item.uDataType != QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM ||
      item.val.expAndMantissa.nExponent != 9223372036854775806 ||
      UsefulBuf_Compare(item.val.expAndMantissa.Mantissa.bigNum, BN)) {
      return 16;
   }

   // 5([ 9223372036854775806,  9223372036854775806])]
   uErr = QCBORDecode_GetNext(&DC, &item);
   if(uErr != QCBOR_SUCCESS) {
      return 17;
   }
   if(item.uDataType != QCBOR_TYPE_BIGFLOAT ||
      item.val.expAndMantissa.nExponent != 9223372036854775806 ||
      item.val.expAndMantissa.Mantissa.nInt!= 9223372036854775806 ) {
      return 18;
   }

   uErr = QCBORDecode_Finish(&DC);
   if(uErr != QCBOR_SUCCESS) {
      return 18;
   }

   /* Now encode some stuff and then decode it */
   uint8_t pBuf[40];
   QCBOREncodeContext EC;
   UsefulBufC Encoded;

   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(pBuf));
   QCBOREncode_OpenArray(&EC);
   QCBOREncode_AddDecimalFraction(&EC, 999, 1000); // 999 * (10 ^ 1000)
   QCBOREncode_AddBigFloat(&EC, 100, INT32_MIN);
   QCBOREncode_AddDecimalFractionBigNum(&EC, BN, false, INT32_MAX);
   QCBOREncode_CloseArray(&EC);
   QCBOREncode_Finish(&EC, &Encoded);


   QCBORDecode_Init(&DC, Encoded, QCBOR_DECODE_MODE_NORMAL);
   uErr = QCBORDecode_GetNext(&DC, &item);
   if(uErr != QCBOR_SUCCESS) {
      return 100;
   }

   uErr = QCBORDecode_GetNext(&DC, &item);
   if(uErr != QCBOR_SUCCESS) {
      return 101;
   }

   if(item.uDataType != QCBOR_TYPE_DECIMAL_FRACTION ||
      item.val.expAndMantissa.nExponent != 1000 ||
      item.val.expAndMantissa.Mantissa.nInt != 999) {
      return 102;
   }

   uErr = QCBORDecode_GetNext(&DC, &item);
   if(uErr != QCBOR_SUCCESS) {
      return 103;
   }

   if(item.uDataType != QCBOR_TYPE_BIGFLOAT ||
      item.val.expAndMantissa.nExponent != INT32_MIN ||
      item.val.expAndMantissa.Mantissa.nInt != 100) {
      return 104;
   }

   uErr = QCBORDecode_GetNext(&DC, &item);
   if(uErr != QCBOR_SUCCESS) {
      return 105;
   }

   if(item.uDataType != QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM ||
      item.val.expAndMantissa.nExponent != INT32_MAX ||
      UsefulBuf_Compare(item.val.expAndMantissa.Mantissa.bigNum, BN)) {
      return 106;
   }


   int64_t                   nExp, nMant;
   UsefulBuf_MAKE_STACK_UB(  MantBuf, 20);
   UsefulBufC                Mant;
   bool                      bIsNeg;

   QCBORDecode_Init(&DC,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedExponentsAndMantissas),
                    QCBOR_DECODE_MODE_NORMAL);
   QCBORDecode_EnterArray(&DC, NULL);

   // 4([-1, 3]),
   QCBORDecode_GetDecimalFraction(&DC, QCBOR_TAG_REQUIREMENT_TAG, &nExp, &nMant);

   // 4([-20,                   4759477275222530853136]),
   QCBORDecode_GetDecimalFractionBig(&DC, QCBOR_TAG_REQUIREMENT_TAG, MantBuf,
                                     &Mant, &bIsNeg, &nExp);

   // 4([9223372036854775807,  -4759477275222530853137]),
   QCBORDecode_GetDecimalFractionBig(&DC, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG,
                                     MantBuf, &Mant, &bIsNeg, &nExp);

   // 5([300, 100]),
   QCBORDecode_GetBigFloat(&DC, QCBOR_TAG_REQUIREMENT_TAG, &nExp, &nMant);

   // 5([-20,                   4759477275222530853136]),
   QCBORDecode_GetBigFloatBig(&DC, QCBOR_TAG_REQUIREMENT_TAG, MantBuf, &Mant,
                              &bIsNeg, &nExp);

   // 5([-9223372036854775807, -4759477275222530853137])
   QCBORDecode_GetBigFloatBig(&DC, QCBOR_TAG_REQUIREMENT_TAG, MantBuf, &Mant,
                              &bIsNeg, &nExp);

   // 5([ 9223372036854775806, -4759477275222530853137])
   QCBORDecode_GetBigFloatBig(&DC, QCBOR_TAG_REQUIREMENT_TAG, MantBuf, &Mant,
                              &bIsNeg, &nExp);

   // 5([ 9223372036854775806,  9223372036854775806])]
   QCBORDecode_GetBigFloatBig(&DC, QCBOR_TAG_REQUIREMENT_TAG, MantBuf, &Mant,
                              &bIsNeg, &nExp);

   QCBORDecode_ExitArray(&DC);

   uErr = QCBORDecode_Finish(&DC);
   if(uErr != QCBOR_SUCCESS) {
      return 200;
   }

   return 0;
}


static const struct FailInput ExponentAndMantissaFailures[] = {
   // Exponent > INT64_MAX
   { {(uint8_t[]){0xC4, 0x82, 0x1B, 0x7f, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                  0xFF, 0xFF, 0x1B, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                  0xFF, 0xFF,}, 20}, QCBOR_ERR_BAD_EXP_AND_MANTISSA},
   // Mantissa > INT64_MAX
   { {(uint8_t[]){0xC4, 0x82, 0x1B, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                  0xFF, 0xFF, 0xC3, 0x4A, 0x01, 0x02, 0x03, 0x04, 0x05,
                  0x06, 0x07, 0x08, 0x09, 0x10}, 23}, QCBOR_ERR_BAD_EXP_AND_MANTISSA},
   // End of input
   { {(uint8_t[]){0xC4, 0x82}, 2}, QCBOR_ERR_NO_MORE_ITEMS},
   // End of input
   { {(uint8_t[]){0xC4, 0x82, 0x01}, 3}, QCBOR_ERR_NO_MORE_ITEMS},
   // bad content for big num
   { {(uint8_t[]){0xC4, 0x82, 0x01, 0xc3, 0x01}, 5}, QCBOR_ERR_BAD_OPT_TAG},
   // bad content for big num
   { {(uint8_t[]){0xC4, 0x82, 0xc2, 0x01, 0x1f}, 5}, QCBOR_ERR_BAD_INT},
   // Bad integer for exponent
   { {(uint8_t[]){0xC4, 0x82, 0x01, 0x1f}, 4}, QCBOR_ERR_BAD_INT},
   // Bad integer for mantissa
   { {(uint8_t[]){0xC4, 0x82, 0x1f, 0x01}, 4}, QCBOR_ERR_BAD_INT},
   // 3 items in array
   { {(uint8_t[]){0xC4, 0x83, 0x03, 0x01, 02}, 5}, QCBOR_ERR_BAD_EXP_AND_MANTISSA},
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   // unterminated indefinite length array
   { {(uint8_t[]){0xC4, 0x9f, 0x03, 0x01, 0x02}, 5}, QCBOR_ERR_BAD_EXP_AND_MANTISSA},
#else /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */
   // unterminated indefinite length array
   { {(uint8_t[]){0xC4, 0x9f, 0x03, 0x01, 0x02}, 5}, QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED},
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */
   // Empty array
   { {(uint8_t[]){0xC4, 0x80}, 2}, QCBOR_ERR_NO_MORE_ITEMS},
   // Second is not an integer
   { {(uint8_t[]){0xC4, 0x82, 0x03, 0x40}, 4}, QCBOR_ERR_BAD_EXP_AND_MANTISSA},
   // First is not an integer
   { {(uint8_t[]){0xC4, 0x82, 0x40}, 3}, QCBOR_ERR_BAD_EXP_AND_MANTISSA},
   // Not an array
   { {(uint8_t[]){0xC4, 0xa2}, 2}, QCBOR_ERR_BAD_EXP_AND_MANTISSA}
};


int32_t ExponentAndMantissaDecodeFailTests()
{
   return ProcessFailures(ExponentAndMantissaFailures,
                          C_ARRAY_COUNT(ExponentAndMantissaFailures,
                                        struct FailInput));
}

#endif /* QCBOR_DISABLE_EXP_AND_MANTISSA */



/*
 Some basic CBOR with map and array used in a lot of tests.
 The map labels are all strings

 {
  "first integer": 42,
  "an array of two strings": [
      "string1", "string2"
  ],
  "map in a map": {
      "bytes 1": h'78787878',
      "bytes 2": h'79797979',
      "another int": 98,
      "text 2": "lies, damn lies and statistics"
   }
 }
 */

int32_t SpiffyDecodeBasicMap(UsefulBufC input)
{
     QCBORItem Item1, Item2, Item3;
     int64_t nDecodedInt1, nDecodedInt2;
     UsefulBufC B1, B2, S1, S2, S3;

     QCBORDecodeContext DCtx;
     QCBORError nCBORError;

     QCBORDecode_Init(&DCtx, input, 0);

     QCBORDecode_EnterMap(&DCtx, NULL);

        QCBORDecode_GetInt64InMapSZ(&DCtx, "first integer",  &nDecodedInt1);

        QCBORDecode_EnterMapFromMapSZ(&DCtx, "map in a map");
           QCBORDecode_GetInt64InMapSZ(&DCtx,  "another int",  &nDecodedInt2);
           QCBORDecode_GetByteStringInMapSZ(&DCtx, "bytes 1",  &B1);
           QCBORDecode_GetByteStringInMapSZ(&DCtx, "bytes 2",  &B2);
           QCBORDecode_GetTextStringInMapSZ(&DCtx, "text 2",  &S1);
        QCBORDecode_ExitMap(&DCtx);

        QCBORDecode_EnterArrayFromMapSZ(&DCtx, "an array of two strings");
           QCBORDecode_GetNext(&DCtx, &Item1);
           QCBORDecode_GetNext(&DCtx, &Item2);
           if(QCBORDecode_GetNext(&DCtx, &Item3) != QCBOR_ERR_NO_MORE_ITEMS) {
              return -400;
           }
        QCBORDecode_ExitArray(&DCtx);

        // Parse the same array again using GetText() instead of GetItem()
        QCBORDecode_EnterArrayFromMapSZ(&DCtx, "an array of two strings");
           QCBORDecode_GetTextString(&DCtx, &S2);
           QCBORDecode_GetTextString(&DCtx, &S3);
           if(QCBORDecode_GetError(&DCtx) != QCBOR_SUCCESS) {
              return 5000;
           }
      /*     QCBORDecode_GetText(&DCtx, &S3);
           if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_NO_MORE_ITEMS) {
               return 5001;
           } */

        QCBORDecode_ExitArray(&DCtx);

     QCBORDecode_ExitMap(&DCtx);

     nCBORError = QCBORDecode_Finish(&DCtx);

     if(nCBORError) {
        return (int32_t)nCBORError;
     }

     if(nDecodedInt1 != 42) {
        return 1001;
     }

     if(nDecodedInt2 != 98) {
        return 1002;
     }

     if(Item1.uDataType != QCBOR_TYPE_TEXT_STRING ||
        UsefulBufCompareToSZ(Item1.val.string, "string1")) {
        return 1003;
     }

     if(Item1.uDataType != QCBOR_TYPE_TEXT_STRING ||
        UsefulBufCompareToSZ(Item2.val.string, "string2")) {
        return 1004;
     }

     if(UsefulBufCompareToSZ(S1, "lies, damn lies and statistics")) {
        return 1005;
     }

     if(UsefulBuf_Compare(B1, UsefulBuf_FromSZ("xxxx"))){
        return 1006;
     }

     if(UsefulBuf_Compare(B2, UsefulBuf_FromSZ("yyyy"))){
        return 1007;
     }

     if(UsefulBuf_Compare(S2, UsefulBuf_FromSZ("string1"))){
        return 1008;
     }

     if(UsefulBuf_Compare(S3, UsefulBuf_FromSZ("string2"))){
        return 1009;
     }

   return 0;
}

/*
   {
      -75008: h'05083399',
      88: [],
      100100: {
         "sub1": {
            10: [
               0
            ],
            -75009: h'A46823990001',
            100100: {
               "json": "{ \"ueid\", \"xyz\"}",
               "subsub": {
                  100002: h'141813191001'
               }
            }
         }
      }
   }
 */

static const uint8_t spNestedCBOR[] = {
   0xa3, 0x3a, 0x00, 0x01, 0x24, 0xff, 0x44, 0x05,
   0x08, 0x33, 0x99, 0x18, 0x58, 0x80, 0x1a, 0x00,
   0x01, 0x87, 0x04, 0xa1, 0x64, 0x73, 0x75, 0x62,
   0x31, 0xa3, 0x0a, 0x81, 0x00, 0x3a, 0x00, 0x01,
   0x25, 0x00, 0x46, 0xa4, 0x68, 0x23, 0x99, 0x00,
   0x01, 0x1a, 0x00, 0x01, 0x87, 0x04, 0xa2, 0x64,
   0x6a, 0x73, 0x6f, 0x6e, 0x70, 0x7b, 0x20, 0x22,
   0x75, 0x65, 0x69, 0x64, 0x22, 0x2c, 0x20, 0x22,
   0x78, 0x79, 0x7a, 0x22, 0x7d, 0x66, 0x73, 0x75,
   0x62, 0x73, 0x75, 0x62, 0xa1, 0x1a, 0x00, 0x01,
   0x86, 0xa2, 0x46, 0x14, 0x18, 0x13, 0x19, 0x10,
   0x01
};

/*  Get item in multi-level nesting in spNestedCBOR */
static int32_t DecodeNestedGetSubSub(QCBORDecodeContext *pDCtx)
{
   UsefulBufC String;

   uint8_t test_oemid_bytes[] = {0x14, 0x18, 0x13, 0x19, 0x10, 0x01};
   const struct q_useful_buf_c test_oemid = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(test_oemid_bytes);

   QCBORDecode_EnterMapFromMapN(pDCtx, 100100);
   QCBORDecode_EnterMap(pDCtx, NULL);
   QCBORDecode_EnterMapFromMapN(pDCtx, 100100);
   QCBORDecode_EnterMapFromMapSZ(pDCtx, "subsub");
   QCBORDecode_GetByteStringInMapN(pDCtx, 100002, &String);
   if(QCBORDecode_GetError(pDCtx)) {
      return 4001;
   }
   if(UsefulBuf_Compare(String, test_oemid)) {
      return 4002;
   }
   QCBORDecode_ExitMap(pDCtx);
   QCBORDecode_ExitMap(pDCtx);
   QCBORDecode_ExitMap(pDCtx);
   QCBORDecode_ExitMap(pDCtx);

   return 0;
}

/*  Iterations on the zero-length array in spNestedCBOR */
static int32_t DecodeNestedGetEmpty(QCBORDecodeContext *pDCtx)
{
   QCBORItem Item;
   QCBORError         uErr;

   QCBORDecode_EnterArrayFromMapN(pDCtx, 88);
   for(int x = 0; x < 20; x++) {
      uErr = QCBORDecode_GetNext(pDCtx, &Item);
      if(uErr != QCBOR_ERR_NO_MORE_ITEMS) {
         return 4100;

      }
   }
   QCBORDecode_ExitArray(pDCtx);
   if(QCBORDecode_GetError(pDCtx)) {
      return 4101;
   }

   return 0;
}

/* Various iterations on the array that contains a zero in spNestedCBOR */
static int32_t DecodeNestedGetZero(QCBORDecodeContext *pDCtx)
{
   QCBORError         uErr;

   QCBORDecode_EnterMapFromMapN(pDCtx, 100100);
   QCBORDecode_EnterMapFromMapSZ(pDCtx, "sub1");
   QCBORDecode_EnterArrayFromMapN(pDCtx, 10);
   int64_t nInt = 99;
   QCBORDecode_GetInt64(pDCtx, &nInt);
   if(nInt != 0) {
      return 4200;
   }
   for(int x = 0; x < 20; x++) {
      QCBORItem Item;
      uErr = QCBORDecode_GetNext(pDCtx, &Item);
      if(uErr != QCBOR_ERR_NO_MORE_ITEMS) {
         return 4201;

      }
   }
   QCBORDecode_ExitArray(pDCtx);
   if(QCBORDecode_GetAndResetError(pDCtx)) {
      return 4202;
   }
   QCBORDecode_EnterArrayFromMapN(pDCtx, 10);
   UsefulBufC dD;
   QCBORDecode_GetByteString(pDCtx, &dD);
   if(QCBORDecode_GetAndResetError(pDCtx) != QCBOR_ERR_UNEXPECTED_TYPE) {
      return 4203;
   }
   for(int x = 0; x < 20; x++) {
      QCBORDecode_GetByteString(pDCtx, &dD);
      uErr = QCBORDecode_GetAndResetError(pDCtx);
      if(uErr != QCBOR_ERR_NO_MORE_ITEMS) {
         return 4204;
      }
   }
   QCBORDecode_ExitArray(pDCtx);
   QCBORDecode_ExitMap(pDCtx);
   QCBORDecode_ExitMap(pDCtx);

   return 0;
}

/* Repeatedly enter and exit maps and arrays, go off the end of maps
 and arrays and such. */
static int32_t DecodeNestedIterate(void)
{
   QCBORDecodeContext DCtx;
   int32_t            nReturn;
   QCBORError         uErr;

   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spNestedCBOR), 0);
   QCBORDecode_EnterMap(&DCtx, NULL);

   for(int j = 0; j < 5; j++) {
      for(int i = 0; i < 20; i++) {
         nReturn = DecodeNestedGetSubSub(&DCtx);
         if(nReturn) {
            return nReturn;
         }
      }

      for(int i = 0; i < 20; i++) {
         nReturn = DecodeNestedGetEmpty(&DCtx);
         if(nReturn ) {
            return nReturn;
         }
      }

      for(int i = 0; i < 20; i++) {
         nReturn = DecodeNestedGetZero(&DCtx);
         if(nReturn ) {
            return nReturn;
         }
      }
   }

   QCBORDecode_ExitMap(&DCtx);
   uErr = QCBORDecode_Finish(&DCtx);
   if(uErr) {
      return (int32_t)uErr + 4100;
   }

   return 0;
}


/*
   [
      23,
      6000,
      h'67616C6163746963',
      h'686176656E20746F6B656E'
   ]
 */
static const uint8_t spSimpleArray[] = {
   0x84,
   0x17,
   0x19, 0x17, 0x70,
   0x48, 0x67, 0x61, 0x6C, 0x61, 0x63, 0x74, 0x69, 0x63,
   0x4B, 0x68, 0x61, 0x76, 0x65, 0x6E, 0x20, 0x74, 0x6F, 0x6B, 0x65, 0x6E};

/* [h'', {}, [], 0] */
static const uint8_t spArrayOfEmpty[] = {0x84, 0x40, 0xa0, 0x80, 0x00};

/* {} */
static const uint8_t spEmptyMap[] = {0xa0};

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
/* {} */
static const uint8_t spEmptyInDefinteLengthMap[] = {0xbf, 0xff};


/*
   {
      0: [],
      9: [
         [],
         []
      ],
      8: {
         1: [],
         2: {},
         3: []
      },
      4: {},
      5: [],
      6: [
         [],
         []
      ]
   }
 */
static const uint8_t spMapOfEmpty[] = {
   0xa6, 0x00, 0x80, 0x09, 0x82, 0x80, 0x80, 0x08,
   0xa3, 0x01, 0x80, 0x02, 0xa0, 0x03, 0x80, 0x04,
   0xa0, 0x05, 0x9f, 0xff, 0x06, 0x9f, 0x80, 0x9f,
   0xff, 0xff};

#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */


/*
 Too many tags
 Duplicate label
 Integer overflow
 Date overflow

   {
      1: 224(225(226(227(4(0))))),
      3: -18446744073709551616,
      4: 1(1.0e+300),
      5: 0,
      8: 8
    }
 */
static const uint8_t spRecoverableMapErrors[] = {
   0xa6,
   0x01, 0xd8, 0xe0, 0xd8, 0xe1, 0xd8, 0xe2, 0xd8, 0xe3, 0xd8, 0x04, 0x00,
   0x03, 0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
   0x04, 0xc1, 0xfb, 0x7e, 0x37, 0xe4, 0x3c, 0x88, 0x00, 0x75, 0x9c,
   0x05, 0x00,
   0x05, 0x00,
   0x08, 0x08,
};

/* Bad break */
static const uint8_t spUnRecoverableMapError1[] = {
   0xa2, 0xff, 0x01, 0x00, 0x02, 0x00
};

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
/* No more items */
static const uint8_t spUnRecoverableMapError2[] = {
   0xbf, 0x02, 0xbf, 0xff, 0x01, 0x00, 0x02, 0x00
};

/* Hit end because string is too long */
static const uint8_t spUnRecoverableMapError3[] = {
   0xbf, 0x02, 0x69, 0x64, 0x64, 0xff
};

/* Hit end because string is too long */
static const uint8_t spUnRecoverableMapError4[] = {
   0xbf,
      0x02, 0x9f, 0x9f, 0x9f, 0x9f, 0x9f, 0x9f, 0x9f, 0x9f,
            0x9f, 0x9f, 0x9f, 0x9f, 0x9f, 0x9f, 0x9f, 0x9f,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
   0xff
};
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */

const unsigned char not_well_formed_submod_section[] = {
   0xa1, 0x14, 0x1f,
};


/* Array of length 3, but only two items. */
const unsigned char spBadConsumeInput[] = {
   0x83, 0x00, 0x00
};

/* Tag nesting too deep. */
const unsigned char spBadConsumeInput2[] = {
   0x81,
   0xD8, 0x37,
   0xD8, 0x2C,
      0xD8, 0x21,
         0xD6,
            0xCB,
               00
};

const unsigned char spBadConsumeInput3[] = {
   0x81, 0xc0, 0x81, 0x00
};

const unsigned char spBadConsumeInput4[] = {
   0x81, 0x9f, 0x00, 0xff
};

const unsigned char spBadConsumeInput5[] = {
   0xa1, 0x80, 0x00
};



int32_t EnterMapTest()
{
   QCBORItem          Item1;
   QCBORItem          ArrayItem;
   QCBORDecodeContext DCtx;
   int32_t            nReturn;
   QCBORError         uErr;

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spMapOfEmpty), 0);
   QCBORDecode_EnterMap(&DCtx, NULL);


   QCBORDecode_EnterArray(&DCtx, NULL); // Label 0
   QCBORDecode_ExitArray(&DCtx);

   QCBORDecode_EnterArray(&DCtx, NULL); // Label 9
   QCBORDecode_EnterArray(&DCtx, NULL);
   QCBORDecode_ExitArray(&DCtx);
   QCBORDecode_EnterArray(&DCtx, NULL);
   QCBORDecode_ExitArray(&DCtx);
   QCBORDecode_ExitArray(&DCtx);

   QCBORDecode_EnterMap(&DCtx, NULL);  // Label 8
   QCBORDecode_EnterArray(&DCtx, NULL);
   QCBORDecode_ExitArray(&DCtx);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_ExitMap(&DCtx);
   QCBORDecode_EnterArray(&DCtx, NULL);
   QCBORDecode_ExitArray(&DCtx);
   QCBORDecode_ExitMap(&DCtx);

   QCBORDecode_EnterMap(&DCtx, NULL);  // Label4
   QCBORDecode_ExitMap(&DCtx);

   QCBORDecode_EnterArray(&DCtx, NULL); // Label 5
   QCBORDecode_ExitArray(&DCtx);

   QCBORDecode_EnterArray(&DCtx, NULL); // Label 6
   QCBORDecode_EnterArray(&DCtx, NULL);
   QCBORDecode_ExitArray(&DCtx);
   QCBORDecode_EnterArray(&DCtx, NULL);
   QCBORDecode_ExitArray(&DCtx);
   QCBORDecode_ExitArray(&DCtx);

   QCBORDecode_ExitMap(&DCtx);

   uErr = QCBORDecode_Finish(&DCtx);
   if(uErr != QCBOR_SUCCESS){
      return 3011;
   }

   (void)pValidMapIndefEncoded;
   nReturn = SpiffyDecodeBasicMap(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pValidMapIndefEncoded));
   if(nReturn) {
      return nReturn + 20000;
   }
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */


   nReturn = SpiffyDecodeBasicMap(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pValidMapEncoded));
   if(nReturn) {
      return nReturn;
   }



   // These tests confirm the cursor is at the right place after entering
   // a map or array
   const UsefulBufC ValidEncodedMap = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pValidMapEncoded);

   // Confirm cursor is at right place
   QCBORDecode_Init(&DCtx, ValidEncodedMap, 0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetNext(&DCtx, &Item1);
   if(Item1.uDataType != QCBOR_TYPE_INT64) {
      return 2001;
   }


   QCBORDecode_Init(&DCtx, ValidEncodedMap, 0);
   QCBORDecode_VGetNext(&DCtx, &Item1);
   QCBORDecode_VGetNext(&DCtx, &Item1);
   QCBORDecode_EnterArray(&DCtx, &ArrayItem);
   if(ArrayItem.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBuf_Compare(ArrayItem.label.string,
                        UsefulBuf_FROM_SZ_LITERAL("an array of two strings"))) {
      return 2051;
   }
   QCBORDecode_GetNext(&DCtx, &Item1);
   if(Item1.uDataType != QCBOR_TYPE_TEXT_STRING) {
      return 2002;
   }
   QCBORDecode_ExitArray(&DCtx);
   QCBORDecode_EnterMap(&DCtx, &ArrayItem);
   if(ArrayItem.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBuf_Compare(ArrayItem.label.string,
                        UsefulBuf_FROM_SZ_LITERAL("map in a map"))) {
      return 2052;
   }


   QCBORDecode_Init(&DCtx, ValidEncodedMap, 0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetNext(&DCtx, &Item1);
   QCBORDecode_GetNext(&DCtx, &Item1);
   QCBORDecode_GetNext(&DCtx, &Item1);
   QCBORDecode_EnterMapFromMapSZ(&DCtx, "map in a map");
   QCBORDecode_GetNext(&DCtx, &Item1);
   if(Item1.uDataType != QCBOR_TYPE_BYTE_STRING) {
      return 2003;
   }

   QCBORDecode_Init(&DCtx, ValidEncodedMap, 0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetNext(&DCtx, &Item1);
   QCBORDecode_GetNext(&DCtx, &Item1);
   QCBORDecode_GetNext(&DCtx, &Item1);
   QCBORDecode_GetNext(&DCtx, &Item1);
   QCBORDecode_GetNext(&DCtx, &Item1);
   QCBORDecode_GetNext(&DCtx, &Item1);
   QCBORDecode_GetNext(&DCtx, &Item1);
   QCBORDecode_EnterArrayFromMapSZ(&DCtx, "an array of two strings");
   QCBORDecode_GetNext(&DCtx, &Item1);
   if(Item1.uDataType != QCBOR_TYPE_TEXT_STRING) {
      return 2004;
   }

   QCBORDecode_Init(&DCtx, ValidEncodedMap, 0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_EnterArrayFromMapSZ(&DCtx, "an array of two strings");
   QCBORDecode_ExitArray(&DCtx);
   QCBORDecode_GetNext(&DCtx, &Item1);
   if(Item1.uDataType != QCBOR_TYPE_MAP && Item1.uLabelAlloc != QCBOR_TYPE_TEXT_STRING) {
      return 2006;
   }
   QCBORDecode_ExitMap(&DCtx);
   if(QCBORDecode_GetNext(&DCtx, &Item1) != QCBOR_ERR_NO_MORE_ITEMS) {
      return 2007;
   }

   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spSimpleArray), 0);
   QCBORDecode_EnterArray(&DCtx, NULL);
   int64_t nDecodedInt2;
   QCBORDecode_GetInt64InMapSZ(&DCtx, "another int",  &nDecodedInt2);
   uErr = QCBORDecode_GetAndResetError(&DCtx);
   if(uErr != QCBOR_ERR_MAP_NOT_ENTERED){
      return 2008;
   }
   UsefulBufC String;
   QCBORDecode_GetTextStringInMapN(&DCtx, 88, &String);
   if(uErr != QCBOR_ERR_MAP_NOT_ENTERED){
      return 2009;
   }


   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spEmptyMap), 0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   // This will fail because the map is empty.
   QCBORDecode_GetInt64InMapSZ(&DCtx, "another int",  &nDecodedInt2);
   uErr = QCBORDecode_GetAndResetError(&DCtx);
   if(uErr != QCBOR_ERR_LABEL_NOT_FOUND){
      return 2010;
   }
   QCBORDecode_ExitMap(&DCtx);
   uErr = QCBORDecode_Finish(&DCtx);
   if(uErr != QCBOR_SUCCESS){
      return 2011;
   }


#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spEmptyInDefinteLengthMap), 0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   // This will fail because the map is empty.
   QCBORDecode_GetInt64InMapSZ(&DCtx, "another int",  &nDecodedInt2);
   uErr = QCBORDecode_GetAndResetError(&DCtx);
   if(uErr != QCBOR_ERR_LABEL_NOT_FOUND){
      return 2012;
   }
   QCBORDecode_ExitMap(&DCtx);
   uErr = QCBORDecode_Finish(&DCtx);
   if(uErr != QCBOR_SUCCESS){
      return 2013;
   }
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */


   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spArrayOfEmpty), 0);
   QCBORDecode_EnterArray(&DCtx, NULL);
   QCBORDecode_GetByteString(&DCtx, &String);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_ExitMap(&DCtx);
   QCBORDecode_EnterArray(&DCtx, NULL);
   QCBORDecode_ExitArray(&DCtx);
   QCBORDecode_GetInt64(&DCtx, &nDecodedInt2);
   QCBORDecode_ExitArray(&DCtx);
   uErr = QCBORDecode_Finish(&DCtx);
   if(uErr != QCBOR_SUCCESS) {
      return 2014;
   }

   int64_t nInt;
   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spRecoverableMapErrors), 0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetInt64InMapN(&DCtx, 0x01, &nInt);
   uErr = QCBORDecode_GetError(&DCtx);
   if(uErr != QCBOR_ERR_TOO_MANY_TAGS) {
      return 2021;
   }
   if(QCBORDecode_GetNthTagOfLast(&DCtx, 0) != CBOR_TAG_INVALID64) {
      return 2121;
   }
   (void)QCBORDecode_GetAndResetError(&DCtx);


   QCBORDecode_GetInt64InMapN(&DCtx, 0x03, &nInt);
   uErr = QCBORDecode_GetAndResetError(&DCtx);
   if(uErr != QCBOR_ERR_INT_OVERFLOW) {
      return 2023;
   }

   QCBORDecode_GetEpochDateInMapN(&DCtx, 0x04, QCBOR_TAG_REQUIREMENT_TAG, &nInt);
   uErr = QCBORDecode_GetAndResetError(&DCtx);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_ERR_DATE_OVERFLOW)) {
      return 2024;
   }

   QCBORDecode_GetInt64InMapN(&DCtx, 0x05, &nInt);
   uErr = QCBORDecode_GetAndResetError(&DCtx);
   if(uErr != QCBOR_ERR_DUPLICATE_LABEL) {
      return 2025;
   }

   QCBORDecode_GetInt64InMapN(&DCtx, 0x08, &nInt);

   QCBORDecode_ExitMap(&DCtx);
   uErr = QCBORDecode_Finish(&DCtx);
   if(uErr != QCBOR_SUCCESS) {
      return 2026;
   }

   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spUnRecoverableMapError1), 0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetInt64InMapN(&DCtx, 0x01, &nInt);
   uErr = QCBORDecode_GetAndResetError(&DCtx);
   if(uErr != QCBOR_ERR_BAD_BREAK) {
      return 2030;
   }

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spUnRecoverableMapError2), 0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetInt64InMapN(&DCtx, 0x01, &nInt);
   uErr = QCBORDecode_GetAndResetError(&DCtx);
   if(uErr != QCBOR_ERR_NO_MORE_ITEMS) {
      return 2031;
   }

   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spUnRecoverableMapError3), 0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetInt64InMapN(&DCtx, 0x01, &nInt);
   uErr = QCBORDecode_GetAndResetError(&DCtx);
   if(uErr != QCBOR_ERR_HIT_END) {
      return 2032;
   }

   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spUnRecoverableMapError4), 0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetInt64InMapN(&DCtx, 0x01, &nInt);
   uErr = QCBORDecode_GetAndResetError(&DCtx);
   if(uErr != QCBOR_ERR_ARRAY_DECODE_NESTING_TOO_DEEP) {
      return 2033;
   }
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */

   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pValidMapEncoded), 0);
   QCBORDecode_VGetNextConsume(&DCtx, &Item1);
   if(Item1.uDataType != QCBOR_TYPE_MAP) {
      return 2401;
   }
   if(QCBORDecode_GetError(&DCtx)) {
      return 2402;
   }

   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pValidMapEncoded), 0);
   QCBORDecode_VGetNext(&DCtx, &Item1);
   if(Item1.uDataType != QCBOR_TYPE_MAP ||
      Item1.val.uCount != 3 ||
      Item1.uNextNestLevel != 1) {
      return 2403;
   }
   if(QCBORDecode_GetError(&DCtx)) {
      return 2404;
   }
   QCBORDecode_VGetNextConsume(&DCtx, &Item1);
   if(Item1.uDataType != QCBOR_TYPE_INT64 ||
      Item1.uNextNestLevel != 1 ||
      Item1.val.int64 != 42) {
      return 2405;
   }
   if(QCBORDecode_GetError(&DCtx)) {
      return 2406;
   }
   QCBORDecode_VGetNextConsume(&DCtx, &Item1);
   if(Item1.uDataType != QCBOR_TYPE_ARRAY ||
      Item1.uNestingLevel != 1 ||
      Item1.uNextNestLevel != 1 ||
      Item1.val.uCount != 2) {
      return 2407;
   }
   if(QCBORDecode_GetError(&DCtx)) {
      return 2408;
   }
   QCBORDecode_VGetNextConsume(&DCtx, &Item1);
   if(Item1.uDataType != QCBOR_TYPE_MAP ||
      Item1.uNestingLevel != 1 ||
      Item1.uNextNestLevel != 0 ||
      Item1.val.uCount != 4) {
      return 2409;
   }
   if(QCBORDecode_GetError(&DCtx)) {
      return 2410;
   }

   nReturn = DecodeNestedIterate();


   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(not_well_formed_submod_section), 0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_EnterMapFromMapN(&DCtx, 20);
   if(QCBORDecode_GetError(&DCtx) != QCBOR_ERR_BAD_INT) {
      return 2500;
   }

   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBadConsumeInput), 0);
   QCBORDecode_VGetNextConsume(&DCtx, &Item1);
   if(QCBORDecode_GetError(&DCtx) != QCBOR_ERR_NO_MORE_ITEMS) {
      return 2600;
   }

   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBadConsumeInput2), 0);
   QCBORDecode_VGetNextConsume(&DCtx, &Item1);
   if(QCBORDecode_GetError(&DCtx) != QCBOR_SUCCESS) {
      return 2700;
   }

   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBadConsumeInput3), 0);
   QCBORDecode_VGetNextConsume(&DCtx, &Item1);
   if(QCBORDecode_GetError(&DCtx) != QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT) {
      return 2800;
   }

   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBadConsumeInput4), 0);
   QCBORDecode_VGetNextConsume(&DCtx, &Item1);
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   if(QCBORDecode_GetError(&DCtx) != QCBOR_SUCCESS) {
      return 2900;
   }
#else
   if(QCBORDecode_GetError(&DCtx) != QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED) {
      return 2901;
   }
#endif

   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBadConsumeInput5), 0);
   QCBORDecode_VGetNextConsume(&DCtx, &Item1);
   if(QCBORDecode_GetError(&DCtx) != QCBOR_ERR_MAP_LABEL_TYPE) {
      return 3000;
   }

   return nReturn;
}


struct NumberConversion {
   char       *szDescription;
   UsefulBufC  CBOR;
   int64_t     nConvertedToInt64;
   QCBORError  uErrorInt64;
   uint64_t    uConvertToUInt64;
   QCBORError  uErrorUint64;
   double      dConvertToDouble;
   QCBORError  uErrorDouble;
};

#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
#define EXP_AND_MANTISSA_ERROR(x) x
#else
#define EXP_AND_MANTISSA_ERROR(x) QCBOR_ERR_UNEXPECTED_TYPE
#endif


static const struct NumberConversion NumberConversions[] = {
   {
      "too large to fit into int64_t",
      {(uint8_t[]){0xc3, 0x48, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 10},
      0,
      QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW,
      0,
      QCBOR_ERR_NUMBER_SIGN_CONVERSION,
      ((double)INT64_MIN) + 1 ,
      FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)
   },
   {
      "largest negative int that fits in int64_t",
      {(uint8_t[]){0xc3, 0x48, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 10},
      INT64_MIN,
      QCBOR_SUCCESS,
      0,
      QCBOR_ERR_NUMBER_SIGN_CONVERSION,
      (double)INT64_MIN,
      FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)
   },
   {
      "negative bignum -1",
      {(uint8_t[]){0xc3, 0x41, 0x00}, 3},
      -1,
      QCBOR_SUCCESS,
      0,
      QCBOR_ERR_NUMBER_SIGN_CONVERSION,
      -1.0,
      FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)
   },
   {
      "Decimal Fraction with positive bignum 257 * 10e3",
      {(uint8_t[]){0xC4, 0x82, 0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                               0xC2, 0x42, 0x01, 0x01}, 15},
      257000,
      EXP_AND_MANTISSA_ERROR(QCBOR_SUCCESS),
      257000,
      EXP_AND_MANTISSA_ERROR(QCBOR_SUCCESS),
      257000.0,
      FLOAT_ERR_CODE_NO_FLOAT_HW(EXP_AND_MANTISSA_ERROR(QCBOR_SUCCESS))
   },
   {
      "bigfloat with negative bignum -258 * 2e3",
      {(uint8_t[]){0xC5, 0x82, 0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                               0xC3, 0x42, 0x01, 0x01}, 15},
      -2064,
      EXP_AND_MANTISSA_ERROR(QCBOR_SUCCESS),
      0,
      EXP_AND_MANTISSA_ERROR(QCBOR_ERR_NUMBER_SIGN_CONVERSION),
      -2064.0,
      FLOAT_ERR_CODE_NO_FLOAT_HW(EXP_AND_MANTISSA_ERROR(QCBOR_SUCCESS))
   },
   {
      "bigfloat with positive bignum 257 * 2e3",
      {(uint8_t[]){0xC5, 0x82, 0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                               0xC2, 0x42, 0x01, 0x01}, 15},
      2056,
      EXP_AND_MANTISSA_ERROR(QCBOR_SUCCESS),
      2056,
      EXP_AND_MANTISSA_ERROR(QCBOR_SUCCESS),
      2056.0,
      FLOAT_ERR_CODE_NO_FLOAT_HW(EXP_AND_MANTISSA_ERROR(QCBOR_SUCCESS))
   },
   {
      "negative bignum 0xc349010000000000000000 -18446744073709551617",
      {(uint8_t[]){0xc3, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 11},
      0,
      QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW,
      0,
      QCBOR_ERR_NUMBER_SIGN_CONVERSION,
      -18446744073709551617.0,
      FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)
   },
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
   {
      "Positive bignum 0x01020304 indefinite length string",
      {(uint8_t[]){0xC2, 0x5f, 0x42, 0x01, 0x02, 0x41, 0x03, 0x41, 0x04, 0xff}, 10},
      0x01020304,
      QCBOR_SUCCESS,
      0x01020304,
      QCBOR_SUCCESS,
      16909060.0,
      FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)
   },
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */
   {
      "Decimal Fraction with neg bignum [9223372036854775807, -4759477275222530853137]",
      {(uint8_t[]){0xC4, 0x82, 0x1B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                               0xC3, 0x4A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,}, 23},
      0,
      EXP_AND_MANTISSA_ERROR(QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW),
      0,
      EXP_AND_MANTISSA_ERROR(QCBOR_ERR_NUMBER_SIGN_CONVERSION),
      -INFINITY,
      FLOAT_ERR_CODE_NO_FLOAT_HW(EXP_AND_MANTISSA_ERROR(QCBOR_SUCCESS))
   },
   {
      "big float [9223372036854775806,  9223372036854775806]",
      {(uint8_t[]){0xC5, 0x82, 0x1B, 0x7f, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                               0x1B, 0x7f, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE}, 20},
      0,
      EXP_AND_MANTISSA_ERROR(QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW),
      0,
      EXP_AND_MANTISSA_ERROR(QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW),
      INFINITY,
      FLOAT_ERR_CODE_NO_FLOAT_HW(EXP_AND_MANTISSA_ERROR(QCBOR_SUCCESS))
   },
   {
      "Big float 3 * 2^^2",
      {(uint8_t[]){0xC5, 0x82, 0x02, 0x03}, 4},
      12,
      EXP_AND_MANTISSA_ERROR(QCBOR_SUCCESS),
      12,
      EXP_AND_MANTISSA_ERROR(QCBOR_SUCCESS),
      12.0,
      FLOAT_ERR_CODE_NO_FLOAT_HW(EXP_AND_MANTISSA_ERROR(QCBOR_SUCCESS))
   },
   {
      "Positive integer 18446744073709551615",
      {(uint8_t[]){0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 9},
      0,
      QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW,
      18446744073709551615ULL,
      QCBOR_SUCCESS,
      18446744073709551615.0,
      FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)
   },
   {
      "Positive bignum 0xffff",
      {(uint8_t[]){0xC2, 0x42, 0xff, 0xff}, 4},
      65536-1,
      QCBOR_SUCCESS,
      0xffff,
      QCBOR_SUCCESS,
      65535.0,
      FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)
   },
   {
      "Postive integer 0",
      {(uint8_t[]){0x0}, 1},
      0LL,
      QCBOR_SUCCESS,
      0ULL,
      QCBOR_SUCCESS,
      0.0,
      FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)
   },
   {
      "Negative integer -18446744073709551616",
      {(uint8_t[]){0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, 9},
      -9223372036854775807-1, // INT64_MIN
      QCBOR_SUCCESS,
      0ULL,
      QCBOR_ERR_NUMBER_SIGN_CONVERSION,
      -9223372036854775808.0,
      FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)
   },
   {
      "Double Floating point value 100.3",
      {(uint8_t[]){0xfb, 0x40, 0x59, 0x13, 0x33, 0x33, 0x33, 0x33, 0x33}, 9},
      100L,
      FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS),
      100ULL,
      FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS),
      100.3,
      FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS),
   },
   {
      "Floating point value NaN 0xfa7fc00000",
      {(uint8_t[]){0xfa, 0x7f, 0xc0, 0x00, 0x00}, 5},
      0,
      FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_ERR_FLOAT_EXCEPTION),
      0,
      FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_ERR_FLOAT_EXCEPTION),
      NAN,
      FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS),
   },
   {
      "half-precision Floating point value -4",
      {(uint8_t[]){0xf9, 0xc4, 0x00}, 3},
      // Normal case with all enabled.
      -4,
      FLOAT_ERR_CODE_NO_HALF_PREC_NO_FLOAT_HW(QCBOR_SUCCESS),
      0,
      FLOAT_ERR_CODE_NO_HALF_PREC_NO_FLOAT_HW(QCBOR_ERR_NUMBER_SIGN_CONVERSION),
      -4.0,
      FLOAT_ERR_CODE_NO_HALF_PREC(QCBOR_SUCCESS)
   },
   {
      "Decimal fraction 3/10",
      {(uint8_t[]){0xC4, 0x82, 0x20, 0x03}, 4},
      0,
      EXP_AND_MANTISSA_ERROR(QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW),
      0,
      EXP_AND_MANTISSA_ERROR(QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW),
      0.30000000000000004,
      FLOAT_ERR_CODE_NO_FLOAT_HW(EXP_AND_MANTISSA_ERROR(QCBOR_SUCCESS))
   },
   {
      "+inifinity single precision",
      {(uint8_t[]){0xfa, 0x7f, 0x80, 0x00, 0x00}, 5},
      0,
      FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_ERR_FLOAT_EXCEPTION),
      0,
      FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW),
      INFINITY,
      FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)
   },

   {
      "extreme pos bignum",
      {(uint8_t[]){0xc2, 0x59, 0x01, 0x90,
         // 50 rows of 8 is 400 digits.
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0},
         404},
      0,
      QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW,
      0,
      QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW,
      INFINITY,
      FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS),
   },

   {
      "extreme neg bignum",
      {(uint8_t[]){0xc3, 0x59, 0x01, 0x90,
         // 50 rows of 8 is 400 digits.
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
         0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0},
         404},
      0,
      QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW,
      0,
      QCBOR_ERR_NUMBER_SIGN_CONVERSION,
      -INFINITY,
      FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS)
   },

   {
      "big float underflow [9223372036854775806, -9223372036854775806]",
      {(uint8_t[]){
         0xC5, 0x82,
            0x3B, 0x7f, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0x1B, 0x7f, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE}, 20},
      0,
      EXP_AND_MANTISSA_ERROR(QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW),
      0,
      EXP_AND_MANTISSA_ERROR(QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW),
      0,
      FLOAT_ERR_CODE_NO_FLOAT_HW(EXP_AND_MANTISSA_ERROR(QCBOR_SUCCESS))
   },

   {
      "bigfloat that evaluates to -INFINITY",
      {(uint8_t[]){
         0xC5, 0x82,
            0x1B, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
            0xC3, 0x42, 0x01, 0x01}, 15},
      0,
      EXP_AND_MANTISSA_ERROR(QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW),
      0,
      EXP_AND_MANTISSA_ERROR(QCBOR_ERR_NUMBER_SIGN_CONVERSION),
      -INFINITY,
      FLOAT_ERR_CODE_NO_FLOAT_HW(EXP_AND_MANTISSA_ERROR(QCBOR_SUCCESS))
   },
};




static int32_t SetUpDecoder(QCBORDecodeContext *DCtx, UsefulBufC CBOR, UsefulBuf Pool)
{
   QCBORDecode_Init(DCtx, CBOR, QCBOR_DECODE_MODE_NORMAL);
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
   if(QCBORDecode_SetMemPool(DCtx, Pool, 0)) {
      return 1;
   }
#else /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */
   (void)Pool;
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */
   return 0;
}


int32_t IntegerConvertTest()
{
   const int nNumTests = C_ARRAY_COUNT(NumberConversions,
                                       struct NumberConversion);

   for(int nIndex = 0; nIndex < nNumTests; nIndex++) {
      const struct NumberConversion *pF = &NumberConversions[nIndex];

      // Set up the decoding context including a memory pool so that
      // indefinite length items can be checked
      QCBORDecodeContext DCtx;
      UsefulBuf_MAKE_STACK_UB(Pool, 100);

      /* ----- test conversion to int64_t ------ */
      if(SetUpDecoder(&DCtx, pF->CBOR, Pool)) {
         return (int32_t)(3333+nIndex);
      }

      int64_t nInt;
      QCBORDecode_GetInt64ConvertAll(&DCtx, 0xffff, &nInt);
      if(QCBORDecode_GetError(&DCtx) != pF->uErrorInt64) {
         return (int32_t)(2000+nIndex);
      }
      if(pF->uErrorInt64 == QCBOR_SUCCESS && pF->nConvertedToInt64 != nInt) {
         return (int32_t)(3000+nIndex);
      }

      /* ----- test conversion to uint64_t ------ */
      if(SetUpDecoder(&DCtx, pF->CBOR, Pool)) {
         return (int32_t)(3333+nIndex);
      }

      uint64_t uInt;
      QCBORDecode_GetUInt64ConvertAll(&DCtx, 0xffff, &uInt);
      if(QCBORDecode_GetError(&DCtx) != pF->uErrorUint64) {
         return (int32_t)(4000+nIndex);
      }
      if(pF->uErrorUint64 == QCBOR_SUCCESS && pF->uConvertToUInt64 != uInt) {
         return (int32_t)(5000+nIndex);
      }

      /* ----- test conversion to double ------ */
       if(SetUpDecoder(&DCtx, pF->CBOR, Pool)) {
         return (int32_t)(3333+nIndex);
      }

#ifndef USEFULBUF_DISABLE_ALL_FLOAT
      double d;
      QCBORDecode_GetDoubleConvertAll(&DCtx, 0xffff, &d);
      if(QCBORDecode_GetError(&DCtx) != pF->uErrorDouble) {
         return (int32_t)(6000+nIndex);
      }
      if(pF->uErrorDouble == QCBOR_SUCCESS) {
         if(isnan(pF->dConvertToDouble)) {
            // NaN's can't be compared for equality. A NaN is
            // never equal to anything including another NaN
            if(!isnan(d)) {
               return (int32_t)(7000+nIndex);
            }
         } else {
            if(pF->dConvertToDouble != d) {
               return (int32_t)(8000+nIndex);
            }
         }
      }
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   }

   return 0;
}

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS

int32_t CBORTestIssue134()
{
   QCBORDecodeContext DCtx;
   QCBORItem          Item;
   QCBORError         uCBORError;
   const uint8_t      spTestIssue134[] = { 0x5F, 0x40, 0xFF };

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spTestIssue134),
                    QCBOR_DECODE_MODE_NORMAL);

   UsefulBuf_MAKE_STACK_UB(StringBuf, 200);
   QCBORDecode_SetMemPool(&DCtx, StringBuf, false);
   
   do {
      uCBORError = QCBORDecode_GetNext(&DCtx, &Item);
   } while (QCBOR_SUCCESS == uCBORError);

   uCBORError = QCBORDecode_Finish(&DCtx);

   return (int32_t)uCBORError;
}

#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */

int32_t CBORSequenceDecodeTests(void)
{
   QCBORDecodeContext DCtx;
   QCBORItem          Item;
   QCBORError         uCBORError;
   size_t             uConsumed;

   // --- Test a sequence with extra bytes ---

   // The input for the date test happens to be a sequence so it
   // is reused. It is a sequence because it doesn't start as
   // an array or map.
   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spDateTestInput),
                    QCBOR_DECODE_MODE_NORMAL);

   // Get the first item
   uCBORError = QCBORDecode_GetNext(&DCtx, &Item);
   if(uCBORError != QCBOR_SUCCESS) {
      return 1;
   }
   if(Item.uDataType != QCBOR_TYPE_DATE_STRING) {
      return 2;
   }

   uCBORError = QCBORDecode_PartialFinish(&DCtx, &uConsumed);
   if(uCBORError != QCBOR_ERR_EXTRA_BYTES ||
      uConsumed != 12) {
      return 102;
   }

   // Get a second item
   uCBORError = QCBORDecode_GetNext(&DCtx, &Item);
   if(uCBORError != QCBOR_ERR_BAD_OPT_TAG) {
      return 66;
   }

   uCBORError = QCBORDecode_PartialFinish(&DCtx, &uConsumed);
   if(uCBORError != QCBOR_ERR_EXTRA_BYTES ||
      uConsumed != 14) {
      return 102;
   }

   // Get a third item
   uCBORError = QCBORDecode_GetNext(&DCtx, &Item);
   if(uCBORError != QCBOR_SUCCESS) {
      return 2;
   }
   if(Item.uDataType != QCBOR_TYPE_DATE_EPOCH) {
      return 3;
   }

   // A sequence can have stuff at the end that may
   // or may not be valid CBOR. The protocol decoder knows
   // when to stop by definition of the protocol, not
   // when the top-level map or array is ended.
   // Finish still has to be called to know that
   // maps and arrays (if there were any) were closed
   // off correctly. When called like this it
   // must return the error QCBOR_ERR_EXTRA_BYTES.
   uCBORError = QCBORDecode_Finish(&DCtx);
   if(uCBORError != QCBOR_ERR_EXTRA_BYTES) {
      return 4;
   }


   // --- Test an empty input ----
   uint8_t empty[1];
   UsefulBufC Empty = {empty, 0};
   QCBORDecode_Init(&DCtx,
                    Empty,
                    QCBOR_DECODE_MODE_NORMAL);

   uCBORError = QCBORDecode_Finish(&DCtx);
   if(uCBORError != QCBOR_SUCCESS) {
      return 5;
   }


   // --- Sequence with unclosed indefinite length array ---
   static const uint8_t xx[] = {0x01, 0x9f, 0x02};

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(xx),
                    QCBOR_DECODE_MODE_NORMAL);

   // Get the first item
   uCBORError = QCBORDecode_GetNext(&DCtx, &Item);
   if(uCBORError != QCBOR_SUCCESS) {
      return 7;
   }
   if(Item.uDataType != QCBOR_TYPE_INT64) {
      return 8;
   }

   // Get a second item
   uCBORError = QCBORDecode_GetNext(&DCtx, &Item);
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   if(uCBORError != QCBOR_SUCCESS) {
      return 9;
   }
   if(Item.uDataType != QCBOR_TYPE_ARRAY) {
      return 10;
   }

   // Try to finish before consuming all bytes to confirm
   // that the still-open error is returned.
   uCBORError = QCBORDecode_Finish(&DCtx);
   if(uCBORError != QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED) {
      return 11;
   }
#else /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */
   if(uCBORError != QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED) {
      return 20;
   }
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */


   // --- Sequence with a closed indefinite length array ---
   static const uint8_t yy[] = {0x01, 0x9f, 0xff};

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(yy),
                    QCBOR_DECODE_MODE_NORMAL);

   // Get the first item
   uCBORError = QCBORDecode_GetNext(&DCtx, &Item);
   if(uCBORError != QCBOR_SUCCESS) {
      return 12;
   }
   if(Item.uDataType != QCBOR_TYPE_INT64) {
      return 13;
   }

   // Get a second item
   uCBORError = QCBORDecode_GetNext(&DCtx, &Item);
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS

   if(uCBORError != QCBOR_SUCCESS) {
      return 14;
   }
   if(Item.uDataType != QCBOR_TYPE_ARRAY) {
      return 15;
   }

   // Try to finish before consuming all bytes to confirm
   // that the still-open error is returned.
   uCBORError = QCBORDecode_Finish(&DCtx);
   if(uCBORError != QCBOR_SUCCESS) {
      return 16;
   }
#else /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */
   if(uCBORError != QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED) {
      return 20;
   }
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */


   return 0;
}



int32_t IntToTests()
{
   int nErrCode;
   int32_t n32;
   int16_t n16;
   int8_t n8;
   uint32_t u32;
   uint16_t u16;
   uint8_t u8;
   uint64_t u64;

   nErrCode = QCBOR_Int64ToInt32(1, &n32);
   if(nErrCode == -1 || n32 != 1) {
      return 1;
   }

   nErrCode = QCBOR_Int64ToInt32((int64_t)INT32_MAX, &n32);
   if(nErrCode == -1 || n32 != INT32_MAX) {
      return 2;
   }

   nErrCode = QCBOR_Int64ToInt32((int64_t)INT32_MIN, &n32);
   if(nErrCode == -1 || n32 != INT32_MIN) {
      return 3;
   }

   nErrCode = QCBOR_Int64ToInt32(((int64_t)INT32_MAX)+1, &n32);
   if(nErrCode != -1) {
      return 4;
   }

   nErrCode = QCBOR_Int64ToInt32(((int64_t)INT32_MIN)-1, &n32);
   if(nErrCode != -1) {
      return 5;
   }


   nErrCode = QCBOR_Int64ToInt16((int64_t)INT16_MAX, &n16);
   if(nErrCode == -1 || n16 != INT16_MAX) {
      return 6;
   }

   nErrCode = QCBOR_Int64ToInt16((int64_t)INT16_MIN, &n16);
   if(nErrCode == -1 || n16 != INT16_MIN) {
      return 7;
   }

   nErrCode = QCBOR_Int64ToInt16(1, &n16);
   if(nErrCode == -1 || n16 != 1) {
      return 8;
   }

   nErrCode = QCBOR_Int64ToInt16(((int64_t)INT16_MAX)+1, &n16);
   if(nErrCode != -1) {
      return 9;
   }

   nErrCode = QCBOR_Int64ToInt16(((int64_t)INT16_MIN)-1, &n16);
   if(nErrCode != -1) {
      return 10;
   }


   nErrCode = QCBOR_Int64ToInt8(1, &n8);
   if(nErrCode == -1 || n8 != 1) {
      return 11;
   }

   nErrCode = QCBOR_Int64ToInt8((int64_t)INT8_MAX, &n8);
   if(nErrCode == -1 || n8 != INT8_MAX) {
      return 12;
   }

   nErrCode = QCBOR_Int64ToInt8((int64_t)INT8_MIN, &n8);
   if(nErrCode == -1 || n8 != INT8_MIN) {
      return 13;
   }

   nErrCode = QCBOR_Int64ToInt8(((int64_t)INT8_MAX)+1, &n8);
   if(nErrCode != -1) {
      return 14;
   }

   nErrCode = QCBOR_Int64ToInt8(((int64_t)INT8_MIN)-1, &n8);
   if(nErrCode != -1) {
      return 15;
   }


   nErrCode = QCBOR_Int64ToUInt32(1, &u32);
   if(nErrCode == -1 || u32 != 1) {
      return 16;
   }

   nErrCode = QCBOR_Int64ToUInt32((int64_t)UINT32_MAX, &u32);
   if(nErrCode == -1 || u32 != UINT32_MAX) {
      return 17;
   }

   nErrCode = QCBOR_Int64ToUInt32((int64_t)0, &u32);
   if(nErrCode == -1 || u32 != 0) {
      return 18;
   }

   nErrCode = QCBOR_Int64ToUInt32(((int64_t)UINT32_MAX)+1, &u32);
   if(nErrCode != -1) {
      return 19;
   }

   nErrCode = QCBOR_Int64ToUInt32((int64_t)-1, &u32);
   if(nErrCode != -1) {
      return 20;
   }


   nErrCode = QCBOR_Int64UToInt16((int64_t)UINT16_MAX, &u16);
   if(nErrCode == -1 || u16 != UINT16_MAX) {
      return 21;
   }

   nErrCode = QCBOR_Int64UToInt16((int64_t)0, &u16);
   if(nErrCode == -1 || u16 != 0) {
      return 22;
   }

   nErrCode = QCBOR_Int64UToInt16(1, &u16);
   if(nErrCode == -1 || u16 != 1) {
      return 23;
   }

   nErrCode = QCBOR_Int64UToInt16(((int64_t)UINT16_MAX)+1, &u16);
   if(nErrCode != -1) {
      return 24;
   }

   nErrCode = QCBOR_Int64UToInt16((int64_t)-1, &u16);
   if(nErrCode != -1) {
      return 25;
   }


   nErrCode = QCBOR_Int64ToUInt8((int64_t)UINT8_MAX, &u8);
   if(nErrCode == -1 || u8 != UINT8_MAX) {
      return 26;
   }

   nErrCode = QCBOR_Int64ToUInt8((int64_t)0, &u8);
   if(nErrCode == -1 || u8 != 0) {
      return 27;
   }

   nErrCode = QCBOR_Int64ToUInt8(1, &u8);
   if(nErrCode == -1 || u8 != 1) {
      return 28;
   }

   nErrCode = QCBOR_Int64ToUInt8(((int64_t)UINT16_MAX)+1, &u8);
   if(nErrCode != -1) {
      return 29;
   }

   nErrCode = QCBOR_Int64ToUInt8((int64_t)-1, &u8);
   if(nErrCode != -1) {
      return 30;
   }


   nErrCode = QCBOR_Int64ToUInt64(1, &u64);
   if(nErrCode == -1 || u64 != 1) {
      return 31;
   }

   nErrCode = QCBOR_Int64ToUInt64(INT64_MAX, &u64);
   if(nErrCode == -1 || u64 != INT64_MAX) {
      return 32;
   }

   nErrCode = QCBOR_Int64ToUInt64((int64_t)0, &u64);
   if(nErrCode == -1 || u64 != 0) {
      return 33;
   }

   nErrCode = QCBOR_Int64ToUInt64((int64_t)-1, &u64);
   if(nErrCode != -1) {
      return 34;
   }

   return 0;
}




/*
A sequence with
  A wrapping bstr
    containing a map
      1
      2
    A wrapping bstr
       containing an array
          3
          wrapping bstr
             4
          5
    6
  array
     7
     8
 */

static UsefulBufC EncodeBstrWrapTestData(UsefulBuf OutputBuffer)
{
   UsefulBufC         Encoded;
   QCBOREncodeContext EC;
   QCBORError         uErr;

   QCBOREncode_Init(&EC, OutputBuffer);

   QCBOREncode_BstrWrap(&EC);
     QCBOREncode_OpenMap(&EC);
       QCBOREncode_AddInt64ToMapN(&EC, 100, 1);
       QCBOREncode_AddInt64ToMapN(&EC, 200, 2);
     QCBOREncode_CloseMap(&EC);
     QCBOREncode_BstrWrap(&EC);
       QCBOREncode_OpenArray(&EC);
         QCBOREncode_AddInt64(&EC, 3);
         QCBOREncode_BstrWrap(&EC);
           QCBOREncode_AddInt64(&EC, 4);
         QCBOREncode_CloseBstrWrap(&EC, NULL);
         QCBOREncode_AddInt64(&EC, 5);
       QCBOREncode_CloseArray(&EC);
     QCBOREncode_CloseBstrWrap(&EC, NULL);
     QCBOREncode_AddInt64(&EC, 6);
   QCBOREncode_CloseBstrWrap(&EC, NULL);
   QCBOREncode_OpenArray(&EC);
     QCBOREncode_AddInt64(&EC, 7);
     QCBOREncode_AddInt64(&EC, 8);
   QCBOREncode_CloseArray(&EC);

   uErr = QCBOREncode_Finish(&EC, &Encoded);
   if(uErr) {
      Encoded = NULLUsefulBufC;
   }

   return Encoded;
}

/* h'FF' */
static const uint8_t spBreakInByteString[] = {
   0x41, 0xff
};


int32_t EnterBstrTest()
{
   UsefulBuf_MAKE_STACK_UB(OutputBuffer, 100);

   QCBORDecodeContext DC;

   QCBORDecode_Init(&DC, EncodeBstrWrapTestData(OutputBuffer), 0);

   int64_t n1, n2, n3, n4, n5, n6, n7, n8;


   QCBORDecode_EnterBstrWrapped(&DC, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
     QCBORDecode_EnterMap(&DC, NULL);
       QCBORDecode_GetInt64InMapN(&DC, 100, &n1);
       QCBORDecode_GetInt64InMapN(&DC, 200, &n2);
     QCBORDecode_ExitMap(&DC);
     QCBORDecode_EnterBstrWrapped(&DC, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
       QCBORDecode_EnterArray(&DC, NULL);
         QCBORDecode_GetInt64(&DC, &n3);
         QCBORDecode_EnterBstrWrapped(&DC, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
           QCBORDecode_GetInt64(&DC, &n4);
         QCBORDecode_ExitBstrWrapped(&DC);
         QCBORDecode_GetInt64(&DC, &n5);
       QCBORDecode_ExitArray(&DC);
     QCBORDecode_ExitBstrWrapped(&DC);
     QCBORDecode_GetInt64(&DC, &n6);
   QCBORDecode_ExitBstrWrapped(&DC);
   QCBORDecode_EnterArray(&DC, NULL);
     QCBORDecode_GetInt64(&DC, &n7);
     QCBORDecode_GetInt64(&DC, &n8);
   QCBORDecode_ExitArray(&DC);

   QCBORError uErr = QCBORDecode_Finish(&DC);
   if(uErr) {
      return (int32_t)uErr;
   }


   /* Enter and exit byte string wrapped CBOR that is bad. It has just a break.
    * Successful because no items are fetched from byte string.
    */
   QCBORDecode_Init(&DC,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBreakInByteString),
                    0);
   QCBORDecode_EnterBstrWrapped(&DC, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
   uErr = QCBORDecode_GetError(&DC);
   if(uErr) {
      return 100 + (int32_t)uErr;
   }

   QCBORDecode_ExitBstrWrapped(&DC);
   uErr = QCBORDecode_GetError(&DC);
   if(uErr) {
      return 200 + (int32_t)uErr;
   }

   /* Try to get item that is a break out of a byte string wrapped CBOR.
    * It fails because there should be no break.
    */
   QCBORDecode_Init(&DC,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBreakInByteString),
                    0);
   QCBORDecode_EnterBstrWrapped(&DC, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
   QCBORItem Item;
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != QCBOR_ERR_BAD_BREAK) {
      return 300 + (int32_t)uErr;
   }

   return 0;
}




static const uint8_t spTaggedTypes[] = {
   0xb2,

      // Date string
      0x00,
      0xc0, 0x74, 0x32, 0x30, 0x30, 0x33, 0x2D, 0x31, 0x32, 0x2D,
      0x31, 0x33, 0x54, 0x31, 0x38, 0x3A, 0x33, 0x30, 0x3A, 0x30,
      0x32, 0x5A,

      0x01,
      0x74, 0x32, 0x30, 0x30, 0x33, 0x2D, 0x31, 0x32, 0x2D, 0x31,
      0x33, 0x54, 0x31, 0x38, 0x3A, 0x33, 0x30, 0x3A, 0x30, 0x32,
      0x5A,

      // Bignum
      10,
      0xC2, 0x4A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x10,

      11,
      0xC3, 0x4A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x10,

      // URL
      20,
      0xd8, 0x20, 0x6f, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F,
      0x63, 0x62, 0x6F, 0x72, 0x2E, 0x6D, 0x65, 0x2F,

      21,
      0x6f, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x63, 0x62,
      0x6F, 0x72, 0x2E, 0x6D, 0x65, 0x2F,

      // B64
      0x18, 0x1e,
      0xd8, 0x22, 0x6c, 0x63, 0x47, 0x78, 0x6C, 0x59, 0x58, 0x4E,
      0x31, 0x63, 0x6D, 0x55, 0x75,

      0x18, 0x1f,
      0x6c, 0x63, 0x47, 0x78, 0x6C, 0x59, 0x58, 0x4E, 0x31, 0x63,
      0x6D, 0x55, 0x75,

      // B64URL
      0x18, 0x28,
      0xd8, 0x21, 0x6c, 0x63, 0x47, 0x78, 0x6C, 0x59, 0x58, 0x4E,
      0x31, 0x63, 0x6D, 0x55, 0x75,

      0x18, 0x29,
      0x6c, 0x63, 0x47, 0x78, 0x6C, 0x59, 0x58, 0x4E, 0x31, 0x63,
      0x6D, 0x55, 0x75,

      // Regex
      0x18, 0x32,
      0xd8, 0x23, 0x68, 0x31, 0x30, 0x30, 0x5C, 0x73, 0x2A, 0x6D,
      0x6B,

      0x18, 0x33,
      0x68, 0x31, 0x30, 0x30, 0x5C, 0x73, 0x2A, 0x6D, 0x6B,

      // MIME
      0x18, 0x3c,
      0xd8, 0x24, 0x72, 0x4D, 0x49, 0x4D, 0x45, 0x2D, 0x56, 0x65,
      0x72, 0x73, 0x69, 0x6F, 0x6E, 0x3A, 0x20, 0x31, 0x2E, 0x30,
      0x0A,

      0x18, 0x3d,
      0x72, 0x4D, 0x49, 0x4D, 0x45, 0x2D, 0x56, 0x65, 0x72, 0x73,
      0x69, 0x6F, 0x6E, 0x3A, 0x20, 0x31, 0x2E, 0x30, 0x0A,

      0x18, 0x3e,
      0xd9, 0x01, 0x01, 0x52, 0x4D, 0x49, 0x4D, 0x45, 0x2D, 0x56,
      0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x3A, 0x20, 0x31, 0x2E,
      0x30, 0x0A,

      0x18, 0x3f,
      0x52, 0x4D, 0x49, 0x4D, 0x45, 0x2D, 0x56, 0x65, 0x72, 0x73,
      0x69, 0x6F, 0x6E, 0x3A, 0x20, 0x31, 0x2E, 0x30, 0x0A,

      // UUID
      0x18, 0x46,
      0xd8, 0x25, 0x50, 0x53, 0x4D, 0x41, 0x52, 0x54, 0x43, 0x53,
      0x4C, 0x54, 0x54, 0x43, 0x46, 0x49, 0x43, 0x41, 0x32,

      0x18, 0x47,
      0x50, 0x53, 0x4D, 0x41, 0x52, 0x54, 0x43, 0x53, 0x4C, 0x54,
      0x54, 0x43, 0x46, 0x49, 0x43, 0x41, 0x32
};

int32_t DecodeTaggedTypeTests()
{
   QCBORDecodeContext DC;
   QCBORError         uErr;

   QCBORDecode_Init(&DC, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spTaggedTypes), 0);

   UsefulBufC String;
   bool       bNeg;

   QCBORDecode_EnterMap(&DC, NULL);
   QCBORDecode_GetDateStringInMapN(&DC, 0, QCBOR_TAG_REQUIREMENT_TAG, &String);
   QCBORDecode_GetDateStringInMapN(&DC, 0, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, &String);
   if(QCBORDecode_GetError(&DC) != QCBOR_SUCCESS) {
      return 1;
   }
   QCBORDecode_GetDateStringInMapN(&DC, 0, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_ERR_UNEXPECTED_TYPE) {
      return 2;
   }
   QCBORDecode_GetDateStringInMapN(&DC, 1, QCBOR_TAG_REQUIREMENT_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_ERR_UNEXPECTED_TYPE) {
      return 3;
   }
   QCBORDecode_GetDateStringInMapN(&DC, 1, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, &String);
   QCBORDecode_GetDateStringInMapN(&DC, 1, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_SUCCESS) {
      return 4;
   }
   QCBORDecode_GetDateStringInMapSZ(&DC, "xxx", QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_ERR_LABEL_NOT_FOUND) {
      return 5;
   }

   QCBORDecode_GetBignumInMapN(&DC, 10, QCBOR_TAG_REQUIREMENT_TAG, &String, &bNeg);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_SUCCESS ||
      bNeg != false) {
      return 10;
   }
   QCBORDecode_GetBignumInMapN(&DC, 11, QCBOR_TAG_REQUIREMENT_TAG, &String, &bNeg);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_SUCCESS ||
      bNeg != true) {
      return 11;
   }
   QCBORDecode_GetBignumInMapN(&DC, 11, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &String, &bNeg);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_ERR_UNEXPECTED_TYPE) {
      return 12;
   }
   QCBORDecode_GetBignumInMapN(&DC, 14, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &String, &bNeg);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_ERR_LABEL_NOT_FOUND) {
      return 13;
   }
   QCBORDecode_GetBignumInMapSZ(&DC, "xxx", QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &String, &bNeg);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_ERR_LABEL_NOT_FOUND) {
      return 14;
   }

   QCBORDecode_GetURIInMapN(&DC, 20, QCBOR_TAG_REQUIREMENT_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_SUCCESS) {
      return 20;
   }
   QCBORDecode_GetURIInMapN(&DC, 21, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_SUCCESS) {
      return 21;
   }
   QCBORDecode_GetURIInMapN(&DC, 22, QCBOR_TAG_REQUIREMENT_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_ERR_LABEL_NOT_FOUND) {
      return 22;
   }
   QCBORDecode_GetURIInMapSZ(&DC, "xxx", QCBOR_TAG_REQUIREMENT_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_ERR_LABEL_NOT_FOUND) {
      return 23;
   }

#ifndef QCBOR_DISABLE_UNCOMMON_TAGS
   QCBORDecode_GetB64InMapN(&DC, 30, QCBOR_TAG_REQUIREMENT_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_SUCCESS) {
      return 30;
   }
#endif
   QCBORDecode_GetB64InMapN(&DC, 31, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_SUCCESS) {
      return 31;
   }
   QCBORDecode_GetB64InMapN(&DC, 32, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_ERR_LABEL_NOT_FOUND) {
      return 32;
   }
   QCBORDecode_GetB64InMapSZ(&DC, "xxx", QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_ERR_LABEL_NOT_FOUND) {
      return 33;
   }

#ifndef QCBOR_DISABLE_UNCOMMON_TAGS
   QCBORDecode_GetB64URLInMapN(&DC, 40, QCBOR_TAG_REQUIREMENT_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_SUCCESS) {
      return 40;
   }
#endif
   QCBORDecode_GetB64URLInMapN(&DC, 41, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_SUCCESS) {
      return 41;
   }
   QCBORDecode_GetB64URLInMapN(&DC, 42, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_ERR_LABEL_NOT_FOUND) {
      return 42;
   }
   QCBORDecode_GetB64URLInMapSZ(&DC, "xxx", QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_ERR_LABEL_NOT_FOUND) {
      return 43;
   }

#ifndef QCBOR_DISABLE_UNCOMMON_TAGS
   QCBORDecode_GetRegexInMapN(&DC, 50, QCBOR_TAG_REQUIREMENT_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_SUCCESS) {
      return 50;
   }
#endif
   QCBORDecode_GetRegexInMapN(&DC, 51, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_SUCCESS) {
      return 51;
   }
   QCBORDecode_GetRegexInMapN(&DC, 52, QCBOR_TAG_REQUIREMENT_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_ERR_LABEL_NOT_FOUND) {
      return 52;
   }
   QCBORDecode_GetRegexInMapSZ(&DC, "xxx", QCBOR_TAG_REQUIREMENT_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_ERR_LABEL_NOT_FOUND) {
      return 53;
   }

#ifndef QCBOR_DISABLE_UNCOMMON_TAGS
   // MIME
   bool bIsNot7Bit;
   QCBORDecode_GetMIMEMessageInMapN(&DC, 60, QCBOR_TAG_REQUIREMENT_TAG, &String, &bIsNot7Bit);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_SUCCESS ||
      bIsNot7Bit == true) {
      return 60;
   }
   QCBORDecode_GetMIMEMessageInMapN(&DC, 61, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &String, &bIsNot7Bit);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_SUCCESS ||
      bIsNot7Bit == true) {
      return 61;
   }
   QCBORDecode_GetMIMEMessageInMapN(&DC, 62, QCBOR_TAG_REQUIREMENT_TAG, &String, &bIsNot7Bit);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_SUCCESS ||
      bIsNot7Bit == false) {
      return 62;
   }
   QCBORDecode_GetMIMEMessageInMapN(&DC, 63, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &String, &bIsNot7Bit);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_SUCCESS ||
      bIsNot7Bit == false) {
      return 63;
   }
   QCBORDecode_GetMIMEMessageInMapN(&DC, 64, QCBOR_TAG_REQUIREMENT_TAG, &String, &bNeg);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_ERR_LABEL_NOT_FOUND) {
      return 64;
   }
   QCBORDecode_GetMIMEMessageInMapSZ(&DC, "zzz", QCBOR_TAG_REQUIREMENT_TAG, &String, &bNeg);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_ERR_LABEL_NOT_FOUND) {
      return 65;
   }


   QCBORDecode_GetBinaryUUIDInMapN(&DC, 70, QCBOR_TAG_REQUIREMENT_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_SUCCESS) {
      return 70;
   }
#endif /* #ifndef QCBOR_DISABLE_UNCOMMON_TAGS */

   QCBORDecode_GetBinaryUUIDInMapN(&DC, 71, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_SUCCESS) {
      return 71;
   }
   QCBORDecode_GetBinaryUUIDInMapN(&DC, 72, QCBOR_TAG_REQUIREMENT_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_ERR_LABEL_NOT_FOUND) {
      return 72;
   }
   QCBORDecode_GetBinaryUUIDInMapSZ(&DC, "xxx", QCBOR_TAG_REQUIREMENT_TAG, &String);
   if(QCBORDecode_GetAndResetError(&DC) != QCBOR_ERR_LABEL_NOT_FOUND) {
      return 73;
   }

   // Improvement: add some more error test cases

   QCBORDecode_ExitMap(&DC);

   uErr = QCBORDecode_Finish(&DC);
   if(uErr != QCBOR_SUCCESS) {
      return 100;
   }

   return 0;
}




/*
   [
      "aaaaaaaaaa",
      {}
   ]
 */
static const uint8_t spTooLarge1[] = {
   0x9f,
   0x6a, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
   0xa0,
   0xff
};

/*
   [
      {
         0: "aaaaaaaaaa"
      }
    ]
 */
static const uint8_t spTooLarge2[] = {
   0x9f,
   0xa1,
   0x00,
   0x6a, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
   0xff
};

/*
   h'A1006A61616161616161616161'

   {
      0: "aaaaaaaaaa"
   }
 */
static const uint8_t spTooLarge3[] = {
   0x4d,
   0xa1,
   0x00,
   0x6a, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
};

int32_t TooLargeInputTest(void)
{
   QCBORDecodeContext DC;
   QCBORError         uErr;
   UsefulBufC         String;

   // These tests require a build with QCBOR_MAX_DECODE_INPUT_SIZE set
   // to 10 There's not really any way to test this error
   // condition. The error condition is not complex, so setting
   // QCBOR_MAX_DECODE_INPUT_SIZE gives an OK test.

   // The input CBOR is only too large because the
   // QCBOR_MAX_DECODE_INPUT_SIZE is 10.
   //
   // This test is disabled for the normal test runs because of the
   // special build requirement.


   // Tests the start of a map being too large
   QCBORDecode_Init(&DC, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spTooLarge1), QCBOR_DECODE_MODE_NORMAL);
   QCBORDecode_EnterArray(&DC, NULL);
   QCBORDecode_GetTextString(&DC, &String);
   uErr = QCBORDecode_GetError(&DC);
   if(uErr != QCBOR_SUCCESS) {
      return 1;
   }
   QCBORDecode_EnterMap(&DC, NULL);
   uErr = QCBORDecode_GetError(&DC);
   if(uErr != QCBOR_ERR_INPUT_TOO_LARGE) {
      return 2;
   }

   // Tests the end of a map being too large
   QCBORDecode_Init(&DC, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spTooLarge2), QCBOR_DECODE_MODE_NORMAL);
   QCBORDecode_EnterArray(&DC, NULL);
   QCBORDecode_EnterMap(&DC, NULL);
   uErr = QCBORDecode_GetError(&DC);
   if(uErr != QCBOR_SUCCESS) {
      return 3;
   }
   QCBORDecode_ExitMap(&DC);
   uErr = QCBORDecode_GetError(&DC);
   if(uErr != QCBOR_ERR_INPUT_TOO_LARGE) {
      return 4;
   }

   // Tests the entire input CBOR being too large when processing bstr wrapping
   QCBORDecode_Init(&DC, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spTooLarge3), QCBOR_DECODE_MODE_NORMAL);
   QCBORDecode_EnterBstrWrapped(&DC, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
   uErr = QCBORDecode_GetError(&DC);
   if(uErr != QCBOR_ERR_INPUT_TOO_LARGE) {
      return 5;
   }

   return 0;
}


#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS

static const uint8_t spMapWithIndefLenStrings[] = {
   0xa3,
      0x7f, 0x61, 'l', 0x64, 'a', 'b', 'e', 'l' , 0x61, '1', 0xff,
      0x5f, 0x42, 0x01, 0x02, 0x43, 0x03, 0x04, 0x05, 0xff,
      0x7f, 0x62, 'd', 'y', 0x61, 'm', 0x61, 'o', 0xff,
      0x03,
      0x7f, 0x62, 'l', 'a', 0x63, 'b', 'e', 'l', 0x61, '2', 0xff,
      0xc3,
          0x5f, 0x42, 0x00, 0x01, 0x42, 0x00, 0x01, 0x41, 0x01, 0xff,
};

int32_t SpiffyIndefiniteLengthStringsTests()
{
   QCBORDecodeContext DCtx;

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spMapWithIndefLenStrings),
                    QCBOR_DECODE_MODE_NORMAL);

   UsefulBuf_MAKE_STACK_UB(StringBuf, 200);
   QCBORDecode_SetMemPool(&DCtx, StringBuf, false);

   UsefulBufC ByteString;
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetByteStringInMapSZ(&DCtx, "label1", &ByteString);
   if(QCBORDecode_GetAndResetError(&DCtx)) {
      return 1;
   }

   const uint8_t pExectedBytes[] = {0x01, 0x02, 0x03, 0x04, 0x05};
   if(UsefulBuf_Compare(ByteString, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pExectedBytes))) {
      return 2;
   }

   uint64_t uInt;
   QCBORDecode_GetUInt64InMapSZ(&DCtx, "dymo", &uInt);
   if(QCBORDecode_GetAndResetError(&DCtx)) {
      return 3;
   }
   if(uInt != 3) {
      return 4;
   }

#ifndef USEFULBUF_DISABLE_ALL_FLOAT
   double uDouble;
   QCBORDecode_GetDoubleConvertAllInMapSZ(&DCtx,
                                          "label2",
                                          0xff,
                                          &uDouble);
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
   if(QCBORDecode_GetAndResetError(&DCtx)) {
      return 5;
   }
   if(uDouble != -16777474) {
      return 6;
   }
#else /* QCBOR_DISABLE_FLOAT_HW_USE */
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_HW_FLOAT_DISABLED) {
      return 7;
   }
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */


   QCBORDecode_ExitMap(&DCtx);

   if(QCBORDecode_Finish(&DCtx)) {
      return 99;
   }

   return 0;
}
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */


/*
 * An array of an integer and an array. The second array contains
 * a bstr-wrapped map.
 *
 * [7, [h'A36D6669... (see next lines) 73']]
 *
 * {"first integer": 42,
 *   "an array of two strings": ["string1", "string2"],
 *    "map in a map":
 *      { "bytes 1": h'78787878',
 *        "bytes 2": h'79797979',
 *        "another int": 98,
 *        "text 2": "lies, damn lies and statistics"
 *      }
 *   }
 */

static const uint8_t pValidWrappedMapEncoded[] = {
   0x82, 0x07, 0x81, 0x58, 0x97,
   0xa3, 0x6d, 0x66, 0x69, 0x72, 0x73, 0x74, 0x20, 0x69, 0x6e,
   0x74, 0x65, 0x67, 0x65, 0x72, 0x18, 0x2a, 0x77, 0x61, 0x6e,
   0x20, 0x61, 0x72, 0x72, 0x61, 0x79, 0x20, 0x6f, 0x66, 0x20,
   0x74, 0x77, 0x6f, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67,
   0x73, 0x82, 0x67, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x31,
   0x67, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x32, 0x6c, 0x6d,
   0x61, 0x70, 0x20, 0x69, 0x6e, 0x20, 0x61, 0x20, 0x6d, 0x61,
   0x70, 0xa4, 0x67, 0x62, 0x79, 0x74, 0x65, 0x73, 0x20, 0x31,
   0x44, 0x78, 0x78, 0x78, 0x78, 0x67, 0x62, 0x79, 0x74, 0x65,
   0x73, 0x20, 0x32, 0x44, 0x79, 0x79, 0x79, 0x79, 0x6b, 0x61,
   0x6e, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x69, 0x6e, 0x74,
   0x18, 0x62, 0x66, 0x74, 0x65, 0x78, 0x74, 0x20, 0x32, 0x78,
   0x1e, 0x6c, 0x69, 0x65, 0x73, 0x2c, 0x20, 0x64, 0x61, 0x6d,
   0x6e, 0x20, 0x6c, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64,
   0x20, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63,
   0x73
};

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS

/* As above, but the arrays are indefinite length */
static const uint8_t pValidIndefWrappedMapEncoded[] = {
   0x9f, 0x07, 0x9f, 0x58, 0x97,
   0xa3, 0x6d, 0x66, 0x69, 0x72, 0x73, 0x74, 0x20, 0x69, 0x6e,
   0x74, 0x65, 0x67, 0x65, 0x72, 0x18, 0x2a, 0x77, 0x61, 0x6e,
   0x20, 0x61, 0x72, 0x72, 0x61, 0x79, 0x20, 0x6f, 0x66, 0x20,
   0x74, 0x77, 0x6f, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67,
   0x73, 0x82, 0x67, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x31,
   0x67, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x32, 0x6c, 0x6d,
   0x61, 0x70, 0x20, 0x69, 0x6e, 0x20, 0x61, 0x20, 0x6d, 0x61,
   0x70, 0xa4, 0x67, 0x62, 0x79, 0x74, 0x65, 0x73, 0x20, 0x31,
   0x44, 0x78, 0x78, 0x78, 0x78, 0x67, 0x62, 0x79, 0x74, 0x65,
   0x73, 0x20, 0x32, 0x44, 0x79, 0x79, 0x79, 0x79, 0x6b, 0x61,
   0x6e, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x69, 0x6e, 0x74,
   0x18, 0x62, 0x66, 0x74, 0x65, 0x78, 0x74, 0x20, 0x32, 0x78,
   0x1e, 0x6c, 0x69, 0x65, 0x73, 0x2c, 0x20, 0x64, 0x61, 0x6d,
   0x6e, 0x20, 0x6c, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64,
   0x20, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63,
   0x73,
   0xff, 0xff
};
#endif


static const uint8_t pWithEmptyMap[] = {0x82, 0x18, 0x64, 0xa0};

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
static const uint8_t pWithEmptyMapInDef[] = {0x9f, 0x18, 0x64, 0xbf, 0xff, 0xff};
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
static const uint8_t pWrappedByIndefiniteLength[] = {
   0x81,
   0xd8, 0x18,
   0x5f,
   0x41, 0x83,
   0x41, 0x18,
   0x43, 0x2A, 0x18, 0x2B,
   0x42, 0x18, 0x2C,
   0xff
};
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */


int32_t PeekAndRewindTest()
{
   QCBORItem          Item;
   QCBORError         nCBORError;
   QCBORDecodeContext DCtx;

   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pValidMapEncoded), 0);

   if((nCBORError = QCBORDecode_PeekNext(&DCtx, &Item))) {
      return 100+(int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP || Item.val.uCount != 3) {
      return 200;
   }

   QCBORDecode_VPeekNext(&DCtx, &Item);
   if((nCBORError = QCBORDecode_GetError(&DCtx))) {
      return 150+(int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP || Item.val.uCount != 3) {
      return 250;
   }

   if((nCBORError = QCBORDecode_PeekNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP || Item.val.uCount != 3) {
      return 300;
   }

   if((nCBORError = QCBORDecode_PeekNext(&DCtx, &Item))) {
      return 400 + (int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP || Item.val.uCount != 3) {
      return 500;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP || Item.val.uCount != 3) {
      return 600;
   }

   if((nCBORError = QCBORDecode_PeekNext(&DCtx, &Item))) {
      return 900 + (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 42 ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.label.string, "first integer")) {
      return 1000;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return 1100 + (int32_t)nCBORError;
   }

   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 42 ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.label.string, "first integer")) {
      return 1200;
   }


   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return 1300 + (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.label.string, "an array of two strings") ||
      Item.uDataType != QCBOR_TYPE_ARRAY ||
      Item.val.uCount != 2) {
      return 1400;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return 1500 + (int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "string1")) {
      return 1600;
   }

   if((nCBORError = QCBORDecode_PeekNext(&DCtx, &Item))) {
      return 1700 + (int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "string2")) {
      return 1800;
   }

   if((nCBORError = QCBORDecode_PeekNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "string2")) {
      return 1900;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "string2")) {
      return 2000;
   }


   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return 2100 + (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.label.string, "map in a map") ||
      Item.uDataType != QCBOR_TYPE_MAP ||
      Item.val.uCount != 4) {
      return 2100;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return 2200 + (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBuf_Compare(Item.label.string, UsefulBuf_FromSZ("bytes 1"))||
      Item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "xxxx")) {
      return 2300;
   }

   if((nCBORError = QCBORDecode_PeekNext(&DCtx, &Item))) {
      return 2400 + (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBufCompareToSZ(Item.label.string, "bytes 2") ||
      Item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "yyyy")) {
      return 2500;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return 2600 + (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBufCompareToSZ(Item.label.string, "bytes 2") ||
      Item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "yyyy")) {
      return 2700;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return 2800 + (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.label.string, "another int") ||
      Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 98) {
      return 2900;
   }

   if((nCBORError = QCBORDecode_PeekNext(&DCtx, &Item))) {
      return 3000 + (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBuf_Compare(Item.label.string, UsefulBuf_FromSZ("text 2"))||
      Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "lies, damn lies and statistics")) {
      return 3100;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return 3200 + (int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBuf_Compare(Item.label.string, UsefulBuf_FromSZ("text 2"))||
      Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "lies, damn lies and statistics")) {
      return 3300;
   }

   nCBORError = QCBORDecode_PeekNext(&DCtx, &Item);
   if(nCBORError != QCBOR_ERR_NO_MORE_ITEMS) {
      return 3300 + (int32_t)nCBORError;
   }

   QCBORDecode_VPeekNext(&DCtx, &Item);
   nCBORError = QCBORDecode_GetError(&DCtx);
   if(nCBORError != QCBOR_ERR_NO_MORE_ITEMS) {
      return 3400 + (int32_t)nCBORError;
   }

   QCBORDecode_VPeekNext(&DCtx, &Item);
   nCBORError = QCBORDecode_GetError(&DCtx);
   if(nCBORError != QCBOR_ERR_NO_MORE_ITEMS) {
      return 3500 + (int32_t)nCBORError;
   }


   // Rewind to top level after entering several maps
   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pValidMapEncoded), 0);

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
       return (int32_t)nCBORError;
    }
    if(Item.uDataType != QCBOR_TYPE_MAP ||
       Item.val.uCount != 3) {
       return 400;
    }

    if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
       return 4000+(int32_t)nCBORError;
    }

    if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
       Item.uDataType != QCBOR_TYPE_INT64 ||
       Item.val.int64 != 42 ||
       Item.uDataAlloc ||
       Item.uLabelAlloc ||
       UsefulBufCompareToSZ(Item.label.string, "first integer")) {
       return 4100;
    }

    if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
       return 4100+(int32_t)nCBORError;
    }
    if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
       Item.uDataAlloc ||
       Item.uLabelAlloc ||
       UsefulBufCompareToSZ(Item.label.string, "an array of two strings") ||
       Item.uDataType != QCBOR_TYPE_ARRAY ||
       Item.val.uCount != 2) {
       return 4200;
    }

    if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
       return 4200+(int32_t)nCBORError;
    }
    if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
       Item.uDataAlloc ||
       Item.uLabelAlloc ||
       UsefulBufCompareToSZ(Item.val.string, "string1")) {
       return 4300;
    }

    if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
       return 4300+(int32_t)nCBORError;
    }
    if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
       Item.uDataAlloc ||
       Item.uLabelAlloc ||
       UsefulBufCompareToSZ(Item.val.string, "string2")) {
       return 4400;
    }

   QCBORDecode_Rewind(&DCtx);

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
       return 4400+(int32_t)nCBORError;
    }
    if(Item.uDataType != QCBOR_TYPE_MAP ||
       Item.val.uCount != 3) {
       return 4500;
    }

    if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
       return (int32_t)nCBORError;
    }

    if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
       Item.uDataType != QCBOR_TYPE_INT64 ||
       Item.val.int64 != 42 ||
       Item.uDataAlloc ||
       Item.uLabelAlloc ||
       UsefulBufCompareToSZ(Item.label.string, "first integer")) {
       return 4600;
    }

    if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
       return (int32_t)nCBORError;
    }
    if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
       Item.uDataAlloc ||
       Item.uLabelAlloc ||
       UsefulBufCompareToSZ(Item.label.string, "an array of two strings") ||
       Item.uDataType != QCBOR_TYPE_ARRAY ||
       Item.val.uCount != 2) {
       return 4700;
    }

    if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
       return (int32_t)nCBORError;
    }
    if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
       Item.uDataAlloc ||
       Item.uLabelAlloc ||
       UsefulBufCompareToSZ(Item.val.string, "string1")) {
       return 4800;
    }

    if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
       return 4900+(int32_t)nCBORError;
    }
    if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
       Item.uDataAlloc ||
       Item.uLabelAlloc ||
       UsefulBufCompareToSZ(Item.val.string, "string2")) {
       return 5000;
    }


   // Rewind an entered map
   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pValidMapEncoded), 0);

   QCBORDecode_EnterMap(&DCtx, NULL);

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
       return 5100+(int32_t)nCBORError;
   }

   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
       Item.uDataType != QCBOR_TYPE_INT64 ||
       Item.val.int64 != 42 ||
       Item.uDataAlloc ||
       Item.uLabelAlloc ||
       UsefulBufCompareToSZ(Item.label.string, "first integer")) {
       return 5200;
    }

    if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
       return 5200+(int32_t)nCBORError;
    }
    if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
       Item.uDataAlloc ||
       Item.uLabelAlloc ||
       UsefulBufCompareToSZ(Item.label.string, "an array of two strings") ||
       Item.uDataType != QCBOR_TYPE_ARRAY ||
       Item.val.uCount != 2) {
       return -5300;
    }

   QCBORDecode_Rewind(&DCtx);

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
       return 5300+(int32_t)nCBORError;
   }

   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 42 ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.label.string, "first integer")) {
      return 5400;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return 5400+(int32_t)nCBORError;
   }
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.label.string, "an array of two strings") ||
      Item.uDataType != QCBOR_TYPE_ARRAY ||
      Item.val.uCount != 2) {
      return 5500;
   }


   // Rewind and entered array inside an entered map
   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pValidMapEncoded), 0);

   QCBORDecode_EnterMap(&DCtx, NULL);

   QCBORDecode_EnterArrayFromMapSZ(&DCtx, "an array of two strings");

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return 5600+(int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "string1")) {
      return 5700;
   }

   QCBORDecode_Rewind(&DCtx);

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return 5700+(int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "string1")) {
      return 5800;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "string2")) {
      return 5900;
   }

   QCBORDecode_Rewind(&DCtx);

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return 5900+(int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.uDataAlloc ||
      Item.uLabelAlloc ||
      UsefulBufCompareToSZ(Item.val.string, "string1")) {
      return 6000;
   }


   // Rewind a byte string inside an array inside an array
   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pValidWrappedMapEncoded), 0);

   QCBORDecode_EnterArray(&DCtx, NULL);

   uint64_t i;
   QCBORDecode_GetUInt64(&DCtx, &i);

   QCBORDecode_EnterArray(&DCtx, NULL);

   QCBORDecode_EnterBstrWrapped(&DCtx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
   if(QCBORDecode_GetError(&DCtx)) {
      return 6100;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return (int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP || Item.val.uCount != 3) {
      return 6200;
   }

   QCBORDecode_Rewind(&DCtx);

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return 6300+(int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP || Item.val.uCount != 3) {
      return 6400;
   }

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   // Rewind a byte string inside an indefinite-length array inside
   // indefinite-length array

   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pValidIndefWrappedMapEncoded), 0);

   QCBORDecode_EnterArray(&DCtx, NULL);

   QCBORDecode_GetUInt64(&DCtx, &i);

   QCBORDecode_EnterArray(&DCtx, NULL);

   QCBORDecode_EnterBstrWrapped(&DCtx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
   if(QCBORDecode_GetError(&DCtx)) {
      return 6500;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return 6600+(int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP || Item.val.uCount != 3) {
      return 6700;
   }

   QCBORDecode_Rewind(&DCtx);

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item))) {
      return 6800+(int32_t)nCBORError;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP || Item.val.uCount != 3) {
      return 6900;
   }
#endif

   // Rewind an empty map
   // [100, {}]
   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pWithEmptyMap), 0);
   QCBORDecode_EnterArray(&DCtx, NULL);
   QCBORDecode_GetUInt64(&DCtx, &i);
   if(i != 100) {
      return 7010;
   }
   QCBORDecode_EnterMap(&DCtx, NULL);

   /* Do it 5 times to be sure multiple rewinds work */
   for(int n = 0; n < 5; n++) {
      nCBORError = QCBORDecode_GetNext(&DCtx, &Item);
      if(nCBORError != QCBOR_ERR_NO_MORE_ITEMS) {
         return 7000 + n;
      }
      QCBORDecode_Rewind(&DCtx);
   }
   QCBORDecode_ExitMap(&DCtx);
   QCBORDecode_Rewind(&DCtx);
   QCBORDecode_GetUInt64(&DCtx, &i);
   if(i != 100) {
      return 7010;
   }
   QCBORDecode_ExitArray(&DCtx);
   QCBORDecode_Rewind(&DCtx);
   QCBORDecode_EnterArray(&DCtx, NULL);
   i = 9;
   QCBORDecode_GetUInt64(&DCtx, &i);
   if(i != 100) {
      return 7020;
   }
   if(QCBORDecode_GetError(&DCtx)){
      return 7030;
   }

   // Rewind an empty indefinite length map
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   QCBORDecode_Init(&DCtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pWithEmptyMapInDef), 0);
   QCBORDecode_EnterArray(&DCtx, NULL);
   QCBORDecode_GetUInt64(&DCtx, &i);
   if(i != 100) {
      return 7810;
   }
   QCBORDecode_EnterMap(&DCtx, NULL);

   /* Do it 5 times to be sure multiple rewinds work */
   for(int n = 0; n < 5; n++) {
      nCBORError = QCBORDecode_GetNext(&DCtx, &Item);
      if(nCBORError != QCBOR_ERR_NO_MORE_ITEMS) {
         return 7800 + n;
      }
      QCBORDecode_Rewind(&DCtx);
   }
   QCBORDecode_ExitMap(&DCtx);
   QCBORDecode_Rewind(&DCtx);
   QCBORDecode_GetUInt64(&DCtx, &i);
   if(i != 100) {
      return 7810;
   }
   QCBORDecode_ExitArray(&DCtx);
   QCBORDecode_Rewind(&DCtx);
   QCBORDecode_EnterArray(&DCtx, NULL);
   i = 9;
   QCBORDecode_GetUInt64(&DCtx, &i);
   if(i != 100) {
      return 7820;
   }
   if(QCBORDecode_GetError(&DCtx)){
      return 7830;
   }
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */

   // Rewind an indefnite length byte-string wrapped sequence
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pWrappedByIndefiniteLength),
                    0);
   UsefulBuf_MAKE_STACK_UB(Pool, 100);
   QCBORDecode_SetMemPool(&DCtx, Pool, 0);

   QCBORDecode_EnterArray(&DCtx, NULL);
   QCBORDecode_EnterBstrWrapped(&DCtx, 2, NULL);
   if(QCBORDecode_GetError(&DCtx) != QCBOR_ERR_INPUT_TOO_LARGE) {
      /* this is what happens when trying to enter
       indefinite-length byte string
       wrapped CBOR.  Tolerate for now. Eventually it needs
       to be fixed so this works, but that is not simple. */
      return 7300;
   }

   /*
   QCBORDecode_GetUInt64(&DCtx, &i);
   if(i != 42) {
      return 7110;
   }
   QCBORDecode_Rewind(&DCtx);
   QCBORDecode_GetUInt64(&DCtx, &i);
   if(i != 42) {
      return 7220;
   }*/
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */


   // Rewind an indefnite length byte-string wrapped sequence

   return 0;
}




static const uint8_t spBooleansInMap[] =
{
   0xa1, 0x08, 0xf5
};

static const uint8_t spBooleansInMapWrongType[] =
{
   0xa1, 0x08, 0xf6
};

static const uint8_t spBooleansInMapNWF[] =
{
   0xa1, 0x08, 0x1a
};

static const uint8_t spNullInMap[] =
{
   0xa1, 0x08, 0xf6
};

static const uint8_t spUndefinedInMap[] =
{
   0xa1, 0x08, 0xf7
};


int32_t BoolTest(void)
{
   QCBORDecodeContext DCtx;
   bool               b;

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBooleansInMap),
                    0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetBool(&DCtx, &b);
   if(QCBORDecode_GetAndResetError(&DCtx) || !b) {
      return 1;
   }

   QCBORDecode_GetBoolInMapN(&DCtx, 7, &b);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_LABEL_NOT_FOUND) {
       return 2;
   }

   QCBORDecode_GetBoolInMapN(&DCtx, 8, &b);
   if(QCBORDecode_GetAndResetError(&DCtx) || !b) {
      return 3;
   }


   QCBORDecode_GetBoolInMapSZ(&DCtx, "xx", &b);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_LABEL_NOT_FOUND) {
       return 4;
    }

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBooleansInMapWrongType),
                    0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetBool(&DCtx, &b);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_UNEXPECTED_TYPE) {
      return 5;
   }

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBooleansInMapNWF),
                    0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetBool(&DCtx, &b);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_HIT_END) {
      return 6;
   }


   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spNullInMap),
                    0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetNull(&DCtx);
   if(QCBORDecode_GetAndResetError(&DCtx)) {
      return 7;
   }

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBooleansInMap),
                    0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetNull(&DCtx);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_UNEXPECTED_TYPE) {
      return 8;
   }

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spNullInMap),
                    0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetNullInMapN(&DCtx, 8);
   if(QCBORDecode_GetAndResetError(&DCtx)) {
      return 9;
   }

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBooleansInMap),
                    0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetNullInMapN(&DCtx, 8);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_UNEXPECTED_TYPE) {
      return 10;
   }

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBooleansInMapNWF),
                    0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetUndefined(&DCtx);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_HIT_END) {
      return 11;
   }

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spUndefinedInMap),
                    0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetUndefined(&DCtx);
   if(QCBORDecode_GetAndResetError(&DCtx)) {
      return 12;
   }

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBooleansInMap),
                    0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetUndefined(&DCtx);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_UNEXPECTED_TYPE) {
      return 13;
   }

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spUndefinedInMap),
                    0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetUndefinedInMapN(&DCtx, 8);
   if(QCBORDecode_GetAndResetError(&DCtx)) {
      return 14;
   }

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBooleansInMap),
                    0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetUndefinedInMapN(&DCtx, 8);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_UNEXPECTED_TYPE) {
      return 15;
   }

   QCBORDecode_Init(&DCtx,
                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBooleansInMapNWF),
                    0);
   QCBORDecode_EnterMap(&DCtx, NULL);
   QCBORDecode_GetUndefined(&DCtx);
   if(QCBORDecode_GetAndResetError(&DCtx) != QCBOR_ERR_HIT_END) {
      return 15;
   }

   return 0;
}
