/* =========================================================================
   example.c -- Example code for QCBOR

   Copyright (c) 2020-2021, Laurence Lundblade. All rights reserved.
   Copyright (c) 2021, Arm Limited. All rights reserved.

   SPDX-License-Identifier: BSD-3-Clause

   See BSD-3-Clause license in README.md

   Created on 6/30/2020
  ========================================================================== */

#include <stdio.h>
#include "example.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"


/**
 * This is a simple example of encoding and decoding some CBOR from
 * and to a C structure.
 *
 * This also includes a comparison between the original structure
 * and the one decoded from the CBOR to confirm correctness.
 */


#define MAX_CYLINDERS 16

/**
 * The data structure representing a car engine that is encoded and
 * decoded in this example.
 */
typedef struct
{
   UsefulBufC Manufacturer;
   int64_t    uDisplacement;
   int64_t    uHorsePower;
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
   double     dDesignedCompresion;
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   int64_t    uNumCylinders;
   bool       bTurboCharged;
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
   struct {
      double dMeasuredCompression;
   } cylinders[MAX_CYLINDERS];
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
} CarEngine;


/**
 * @brief Initialize the Engine data structure with values to encode.
 *
 * @param[out] pE   The Engine structure to fill in
 */
void EngineInit(CarEngine *pE)
{
   pE->Manufacturer        = UsefulBuf_FROM_SZ_LITERAL("Porsche");
   pE->uDisplacement       = 3296;
   pE->uHorsePower         = 210;
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
   pE->dDesignedCompresion = 9.1;
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   pE->uNumCylinders       = 6;
   pE->bTurboCharged       = false;

#ifndef USEFULBUF_DISABLE_ALL_FLOAT
   pE->cylinders[0].dMeasuredCompression = 9.0;
   pE->cylinders[1].dMeasuredCompression = 9.2;
   pE->cylinders[2].dMeasuredCompression = 8.9;
   pE->cylinders[3].dMeasuredCompression = 8.9;
   pE->cylinders[4].dMeasuredCompression = 9.1;
   pE->cylinders[5].dMeasuredCompression = 9.0;
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
}


/**
 * @brief Compare two Engine structure for equality.
 *
 * @param[in] pE1  First Engine to compare.
 * @param[in] pE2  Second Engine to compare.
 *
 * @retval Return @c true if the two Engine data structures are exactly the
 *         same.
 */
static bool EngineCompare(const CarEngine *pE1, const CarEngine *pE2)
{
   if(pE1->uNumCylinders != pE2->uNumCylinders) {
      return false;
   }
   if(pE1->bTurboCharged != pE2->bTurboCharged) {
      return false;
   }
   if(pE1->uDisplacement != pE2->uDisplacement) {
      return false;
   }
   if(pE1->uHorsePower != pE2->uHorsePower) {
      return false;
   }
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
   if(pE1->dDesignedCompresion != pE2->dDesignedCompresion) {
      return false;
   }
   for(int64_t i = 0; i < pE2->uNumCylinders; i++) {
      if(pE1->cylinders[i].dMeasuredCompression !=
         pE2->cylinders[i].dMeasuredCompression) {
         return false;
      }
   }
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */

   if(UsefulBuf_Compare(pE1->Manufacturer, pE2->Manufacturer)) {
      return false;
   }

    return true;
}


/**
 * @brief Encode an initialized CarEngine data structure in CBOR.
 *
 * @param[in] pEngine  The data structure to encode.
 * @param[in] Buffer   Pointer and length of buffer to output to.
 *
 * @return  The pointer and length of the encoded CBOR or
 *          @ref NULLUsefulBufC on error.
 *
 * This encodes the input structure \c pEngine as a CBOR map of
 * label-value pairs. An array of float is one of the items in the
 * map.
 *
 * This uses the UsefulBuf convention of passing in a non-const empty
 * buffer to be filled in and returning a filled in const buffer. The
 * buffer to write into is given as a pointer and length in a
 * UsefulBuf. The buffer returned with the encoded CBOR is a
 * UsefulBufC also a pointer and length. In this implementation the
 * pointer to the returned data is exactly the same as that of the
 * empty buffer. The returned length will be smaller than or equal to
 * that of the empty buffer. This gives correct const-ness for the
 * buffer passed in and the data returned.
 *
 * @c Buffer must be big enough to hold the output. If it is not @ref
 * NULLUsefulBufC will be returned. @ref NULLUsefulBufC will be
 * returned for any other encoding errors.
 *
 * This can be called with @c Buffer set to @ref SizeCalculateUsefulBuf
 * in which case the size of the encoded engine will be calculated,
 * but no actual encoded CBOR will be output. The calculated size is
 * in @c .len of the returned @ref UsefulBufC.
 */
UsefulBufC EncodeEngine(const CarEngine *pEngine, UsefulBuf Buffer)
{
   /* Set up the encoding context with the output buffer */
    QCBOREncodeContext EncodeCtx;
    QCBOREncode_Init(&EncodeCtx, Buffer);

    /* Proceed to output all the items, letting the internal error
     * tracking do its work */
    QCBOREncode_OpenMap(&EncodeCtx);
    QCBOREncode_AddTextToMap(&EncodeCtx, "Manufacturer", pEngine->Manufacturer);
    QCBOREncode_AddInt64ToMap(&EncodeCtx, "NumCylinders", pEngine->uNumCylinders);
    QCBOREncode_AddInt64ToMap(&EncodeCtx, "Displacement", pEngine->uDisplacement);
    QCBOREncode_AddInt64ToMap(&EncodeCtx, "Horsepower", pEngine->uHorsePower);
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
    QCBOREncode_AddDoubleToMap(&EncodeCtx, "DesignedCompression", pEngine->dDesignedCompresion);
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
    QCBOREncode_OpenArrayInMap(&EncodeCtx, "Cylinders");
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
    for(int64_t i = 0 ; i < pEngine->uNumCylinders; i++) {
        QCBOREncode_AddDouble(&EncodeCtx,
                              pEngine->cylinders[i].dMeasuredCompression);
    }
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
    QCBOREncode_CloseArray(&EncodeCtx);
    QCBOREncode_AddBoolToMap(&EncodeCtx, "Turbo", pEngine->bTurboCharged);
    QCBOREncode_CloseMap(&EncodeCtx);

    /* Get the pointer and length of the encoded output. If there was
     * any encoding error, it will be returned here */
    UsefulBufC EncodedCBOR;
    QCBORError uErr;
    uErr = QCBOREncode_Finish(&EncodeCtx, &EncodedCBOR);
    if(uErr != QCBOR_SUCCESS) {
       return NULLUsefulBufC;
    } else {
       return EncodedCBOR;
    }
}


/**
 * Error results when decoding an Engine data structure.
 */
typedef enum  {
    EngineSuccess,
    CBORNotWellFormed,
    TooManyCylinders,
    EngineProtocolerror,
    WrongNumberOfCylinders
} EngineDecodeErrors;


/**
 * Convert @ref QCBORError to @ref EngineDecodeErrors.
 */
static EngineDecodeErrors ConvertError(QCBORError uErr)
{
    EngineDecodeErrors uReturn;

    switch(uErr)
    {
        case QCBOR_SUCCESS:
            uReturn = EngineSuccess;
            break;

        case QCBOR_ERR_HIT_END:
            uReturn = CBORNotWellFormed;
            break;

        default:
            uReturn = EngineProtocolerror;
            break;
    }

    return uReturn;
}


/**
 * @brief Simplest engine decode using spiffy decode features.
 *
 * @param[in] EncodedEngine  Pointer and length of CBOR-encoded engine.
 * @param[out] pE            The structure filled in from the decoding.
 *
 * @return The decode error or success.
 *
 * This decodes the CBOR into the engine structure.
 *
 * As QCBOR automatically supports both definite and indefinite maps
 * and arrays, this will decode either.
 *
 * This uses QCBOR's spiffy decode functions, so the implementation is
 * simple and closely parallels the encode implementation in
 * EncodeEngineDefiniteLength().
 *
 * Another way to decode without using spiffy decode functions is to
 * use QCBORDecode_GetNext() to traverse the whole tree.  This
 * requires a more complex implementation, but is faster and will pull
 * in less code from the CBOR library. The speed advantage is likely
 * of consequence when decoding much much larger CBOR on slow small
 * CPUs.
 *
 * A middle way is to use the spiffy decode
 * QCBORDecode_GetItemsInMap().  The implementation has middle
 * complexity and uses less CPU.
 */
EngineDecodeErrors DecodeEngineSpiffy(UsefulBufC EncodedEngine, CarEngine *pE)
{
    QCBORError         uErr;
    QCBORDecodeContext DecodeCtx;

    /* Let QCBORDecode internal error tracking do its work. */
    QCBORDecode_Init(&DecodeCtx, EncodedEngine, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&DecodeCtx, NULL);
    QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "Manufacturer", &(pE->Manufacturer));
    QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "Displacement", &(pE->uDisplacement));
    QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "Horsepower", &(pE->uHorsePower));
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
    QCBORDecode_GetDoubleInMapSZ(&DecodeCtx, "DesignedCompression", &(pE->dDesignedCompresion));
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
    QCBORDecode_GetBoolInMapSZ(&DecodeCtx, "Turbo", &(pE->bTurboCharged));

    QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "NumCylinders", &(pE->uNumCylinders));

    /* Check the internal tracked error now before going on to
     * reference any of the decoded data, particularly
     * pE->uNumCylinders */
    uErr = QCBORDecode_GetError(&DecodeCtx);
    if(uErr != QCBOR_SUCCESS) {
        goto Done;
    }

    if(pE->uNumCylinders > MAX_CYLINDERS) {
        return TooManyCylinders;
    }

    QCBORDecode_EnterArrayFromMapSZ(&DecodeCtx, "Cylinders");
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
    for(int64_t i = 0; i < pE->uNumCylinders; i++) {
        QCBORDecode_GetDouble(&DecodeCtx,
                              &(pE->cylinders[i].dMeasuredCompression));
    }
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
    QCBORDecode_ExitArray(&DecodeCtx);
    QCBORDecode_ExitMap(&DecodeCtx);

    /* Catch further decoding error here */
    uErr = QCBORDecode_Finish(&DecodeCtx);

Done:
    return ConvertError(uErr);
}


int32_t RunQCborExample()
{
   CarEngine                 InitialEngine;
   CarEngine                 DecodedEngine;

   /* For every buffer used by QCBOR a pointer and a length are always
    * carried in a UsefulBuf. This is a secure coding and hygene
    * practice to help make sure code never runs off the end of a
    * buffer.
    *
    * UsefulBuf structures are passed as a stack parameter to make the
    * code prettier. The object code generated isn't much different
    * from passing a pointer parameter and a length parameter.
    *
    * This macro is equivalent to:
    *    uint8_t    __pBufEngineBuffer[300];
    *    UsefulBuf  EngineBuffer = {__pBufEngineBuffer, 300};
    */
   UsefulBuf_MAKE_STACK_UB(  EngineBuffer, 300);

   /* The pointer in UsefulBuf is not const and used for representing
    * a buffer to be written to. For UsefulbufC, the pointer is const
    * and is used to represent a buffer that has been written to.
    */
   UsefulBufC                EncodedEngine;
   EngineDecodeErrors        uErr;

   /* Initialize the structure with some values. */
   EngineInit(&InitialEngine);

   /* Encode the engine structure. */
   EncodedEngine = EncodeEngine(&InitialEngine, EngineBuffer);
   if(UsefulBuf_IsNULLC(EncodedEngine)) {
      printf("Engine encode failed\n");
      goto Done;
   }
   printf("Example: Definite Length Engine Encoded in %zu bytes\n",
          EncodedEngine.len);

   /* Decode the CBOR */
   uErr = DecodeEngineSpiffy(EncodedEngine, &DecodedEngine);
   printf("Example: Spiffy Engine Decode Result: %d\n", uErr);
   if(uErr) {
      goto Done;
   }

   /* Check the results */
   if(!EngineCompare(&InitialEngine, &DecodedEngine)) {
      printf("Example: Spiffy Engine Decode comparison fail\n");
   }


   /* Further example of how to calculate the encoded size, then allocate */
   UsefulBufC EncodedEngineSize;
   EncodedEngineSize = EncodeEngine(&InitialEngine, SizeCalculateUsefulBuf);
   if(UsefulBuf_IsNULLC(EncodedEngine)) {
      printf("Engine encode size calculation failed\n");
      goto Done;
   }
   (void)EncodedEngineSize; /* Supress unsed variable warning */
   /* Here malloc could be called to allocate a buffer. Then
    * EncodeEngine() can be called a second time to actually
    * encode. (The actual code is not live here to avoid a
    * dependency on malloc()).
    *  UsefulBuf  MallocedBuffer;
    *  MallocedBuffer.len = EncodedEngineSize.len;
    *  MallocedBuffer.ptr = malloc(EncodedEngineSize.len);
    *  EncodedEngine = EncodeEngine(&InitialEngine, MallocedBuffer);
    */

Done:
   printf("\n");

   return 0;
}
