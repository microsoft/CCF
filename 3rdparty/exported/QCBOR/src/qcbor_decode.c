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


#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "ieee754.h" /* Does not use math.h */

#ifndef QCBOR_DISABLE_FLOAT_HW_USE

#include <math.h> /* For isnan(), llround(), llroudf(), round(), roundf(),
                   * pow(), exp2()
                   */
#include <fenv.h> /* feclearexcept(), fetestexcept() */

#endif /* QCBOR_DISABLE_FLOAT_HW_USE */



#define SIZEOF_C_ARRAY(array,type) (sizeof(array)/sizeof(type))




static inline bool
QCBORItem_IsMapOrArray(const QCBORItem *pMe)
{
   const uint8_t uDataType = pMe->uDataType;
   return uDataType == QCBOR_TYPE_MAP ||
          uDataType == QCBOR_TYPE_ARRAY ||
          uDataType == QCBOR_TYPE_MAP_AS_ARRAY;
}

static inline bool
QCBORItem_IsEmptyDefiniteLengthMapOrArray(const QCBORItem *pMe)
{
   if(!QCBORItem_IsMapOrArray(pMe)){
      return false;
   }

   if(pMe->val.uCount != 0) {
      return false;
   }
   return true;
}

static inline bool
QCBORItem_IsIndefiniteLengthMapOrArray(const QCBORItem *pMe)
{
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   if(!QCBORItem_IsMapOrArray(pMe)){
      return false;
   }

   if(pMe->val.uCount != QCBOR_COUNT_INDICATES_INDEFINITE_LENGTH) {
      return false;
   }
   return true;
#else /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */
   (void)pMe;
   return false;
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */
}


/*===========================================================================
   DecodeNesting -- Tracking array/map/sequence/bstr-wrapped nesting
  ===========================================================================*/

/*
 * See comments about and typedef of QCBORDecodeNesting in qcbor_private.h,
 * the data structure all these functions work on.
 */


static inline uint8_t
DecodeNesting_GetCurrentLevel(const QCBORDecodeNesting *pNesting)
{
   const ptrdiff_t nLevel = pNesting->pCurrent - &(pNesting->pLevels[0]);
   /* Limit in DecodeNesting_Descend against more than
    * QCBOR_MAX_ARRAY_NESTING gaurantees cast is safe
    */
   return (uint8_t)nLevel;
}


static inline uint8_t
DecodeNesting_GetBoundedModeLevel(const QCBORDecodeNesting *pNesting)
{
   const ptrdiff_t nLevel = pNesting->pCurrentBounded - &(pNesting->pLevels[0]);
   /* Limit in DecodeNesting_Descend against more than
    * QCBOR_MAX_ARRAY_NESTING gaurantees cast is safe
    */
   return (uint8_t)nLevel;
}


static inline uint32_t
DecodeNesting_GetMapOrArrayStart(const QCBORDecodeNesting *pNesting)
{
   return pNesting->pCurrentBounded->u.ma.uStartOffset;
}


static inline bool
DecodeNesting_IsBoundedEmpty(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrentBounded->u.ma.uCountCursor == QCBOR_COUNT_INDICATES_ZERO_LENGTH) {
      return true;
   } else {
      return false;
   }
}


static inline bool
DecodeNesting_IsCurrentAtTop(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrent == &(pNesting->pLevels[0])) {
      return true;
   } else {
      return false;
   }
}


static inline bool
DecodeNesting_IsCurrentDefiniteLength(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrent->uLevelType == QCBOR_TYPE_BYTE_STRING) {
      /* Not a map or array */
      return false;
   }

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   if(pNesting->pCurrent->u.ma.uCountTotal == QCBOR_COUNT_INDICATES_INDEFINITE_LENGTH) {
      /* Is indefinite */
      return false;
   }

#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */

   /* All checks passed; is a definte length map or array */
   return true;
}

static inline bool
DecodeNesting_IsCurrentBstrWrapped(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrent->uLevelType == QCBOR_TYPE_BYTE_STRING) {
      /* is a byte string */
      return true;
   }
   return false;
}


static inline bool DecodeNesting_IsCurrentBounded(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrent->uLevelType == QCBOR_TYPE_BYTE_STRING) {
      return true;
   }
   if(pNesting->pCurrent->u.ma.uStartOffset != QCBOR_NON_BOUNDED_OFFSET) {
      return true;
   }
   return false;
}


static inline void DecodeNesting_SetMapOrArrayBoundedMode(QCBORDecodeNesting *pNesting, bool bIsEmpty, size_t uStart)
{
   /* Should be only called on maps and arrays */
   /*
    * DecodeNesting_EnterBoundedMode() checks to be sure uStart is not
    * larger than DecodeNesting_EnterBoundedMode which keeps it less than
    * uin32_t so the cast is safe.
    */
   pNesting->pCurrent->u.ma.uStartOffset = (uint32_t)uStart;

   if(bIsEmpty) {
      pNesting->pCurrent->u.ma.uCountCursor = QCBOR_COUNT_INDICATES_ZERO_LENGTH;
   }
}


static inline void DecodeNesting_ClearBoundedMode(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrent->u.ma.uStartOffset = QCBOR_NON_BOUNDED_OFFSET;
}


static inline bool
DecodeNesting_IsAtEndOfBoundedLevel(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrentBounded == NULL) {
      /* No bounded map or array set up */
      return false;
   }
   if(pNesting->pCurrent->uLevelType == QCBOR_TYPE_BYTE_STRING) {
      /* Not a map or array; end of those is by byte count */
      return false;
   }
   if(!DecodeNesting_IsCurrentBounded(pNesting)) {
      /* In a traveral at a level deeper than the bounded level */
      return false;
   }
   /* Works for both definite- and indefinitelength maps/arrays */
   if(pNesting->pCurrentBounded->u.ma.uCountCursor != 0 &&
      pNesting->pCurrentBounded->u.ma.uCountCursor != QCBOR_COUNT_INDICATES_ZERO_LENGTH) {
      /* Count is not zero, still unconsumed item */
      return false;
   }
   /* All checks passed, got to the end of an array or map*/
   return true;
}


static inline bool
DecodeNesting_IsEndOfDefiniteLengthMapOrArray(const QCBORDecodeNesting *pNesting)
{
   /* Must only be called on map / array */
   if(pNesting->pCurrent->u.ma.uCountCursor == 0) {
      return true;
   } else {
      return false;
   }
}


static inline bool
DecodeNesting_IsCurrentTypeMap(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrent->uLevelType == CBOR_MAJOR_TYPE_MAP) {
      return true;
   } else {
      return false;
   }
}


static inline bool
DecodeNesting_IsBoundedType(const QCBORDecodeNesting *pNesting, uint8_t uType)
{
   if(pNesting->pCurrentBounded == NULL) {
      return false;
   }

   if(pNesting->pCurrentBounded->uLevelType != uType) {
      return false;
   }

   return true;
}


static inline void
DecodeNesting_DecrementDefiniteLengthMapOrArrayCount(QCBORDecodeNesting *pNesting)
{
   /* Only call on a definite-length array / map */
   pNesting->pCurrent->u.ma.uCountCursor--;
}


static inline void
DecodeNesting_ReverseDecrement(QCBORDecodeNesting *pNesting)
{
   /* Only call on a definite-length array / map */
   pNesting->pCurrent->u.ma.uCountCursor++;
}


static inline void
DecodeNesting_Ascend(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrent--;
}


static QCBORError
DecodeNesting_Descend(QCBORDecodeNesting *pNesting, uint8_t uType)
{
   /* Error out if nesting is too deep */
   if(pNesting->pCurrent >= &(pNesting->pLevels[QCBOR_MAX_ARRAY_NESTING])) {
      return QCBOR_ERR_ARRAY_DECODE_NESTING_TOO_DEEP;
   }

   /* The actual descend */
   pNesting->pCurrent++;

   pNesting->pCurrent->uLevelType = uType;

   return QCBOR_SUCCESS;
}


static inline QCBORError
DecodeNesting_EnterBoundedMapOrArray(QCBORDecodeNesting *pNesting,
                                     bool                bIsEmpty,
                                     size_t              uOffset)
{
   /*
    * Should only be called on map/array.
    *
    * Have descended into this before this is called. The job here is
    * just to mark it in bounded mode.
    *
    * Check against QCBOR_MAX_DECODE_INPUT_SIZE make sure that
    * uOffset doesn't collide with QCBOR_NON_BOUNDED_OFFSET.
    *
    * Cast of uOffset to uint32_t for cases where SIZE_MAX < UINT32_MAX.
    */
   if((uint32_t)uOffset >= QCBOR_MAX_DECODE_INPUT_SIZE) {
      return QCBOR_ERR_INPUT_TOO_LARGE;
   }

   pNesting->pCurrentBounded = pNesting->pCurrent;

   DecodeNesting_SetMapOrArrayBoundedMode(pNesting, bIsEmpty, uOffset);

   return QCBOR_SUCCESS;
}


static inline QCBORError
DecodeNesting_DescendMapOrArray(QCBORDecodeNesting *pNesting,
                                uint8_t             uQCBORType,
                                uint64_t            uCount)
{
   QCBORError uError = QCBOR_SUCCESS;

   if(uCount == 0) {
      /* Nothing to do for empty definite-length arrays. They are just are
       * effectively the same as an item that is not a map or array.
       */
      goto Done;
      /* Empty indefinite-length maps and arrays are handled elsewhere */
   }

   /* Error out if arrays is too long to handle */
   if(uCount != QCBOR_COUNT_INDICATES_INDEFINITE_LENGTH &&
      uCount > QCBOR_MAX_ITEMS_IN_ARRAY) {
      uError = QCBOR_ERR_ARRAY_DECODE_TOO_LONG;
      goto Done;
   }

   uError = DecodeNesting_Descend(pNesting, uQCBORType);
   if(uError != QCBOR_SUCCESS) {
      goto Done;
   }

   /* Fill in the new map/array level. Check above makes casts OK. */
   pNesting->pCurrent->u.ma.uCountCursor  = (uint16_t)uCount;
   pNesting->pCurrent->u.ma.uCountTotal   = (uint16_t)uCount;

   DecodeNesting_ClearBoundedMode(pNesting);

Done:
   return uError;;
}


static inline void
DecodeNesting_LevelUpCurrent(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrent = pNesting->pCurrentBounded - 1;
}


static inline void
DecodeNesting_LevelUpBounded(QCBORDecodeNesting *pNesting)
{
   while(pNesting->pCurrentBounded != &(pNesting->pLevels[0])) {
      pNesting->pCurrentBounded--;
      if(DecodeNesting_IsCurrentBounded(pNesting)) {
         break;
      }
   }
}


static inline void
DecodeNesting_SetCurrentToBoundedLevel(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrent = pNesting->pCurrentBounded;
}


static inline QCBORError
DecodeNesting_DescendIntoBstrWrapped(QCBORDecodeNesting *pNesting,
                                     uint32_t            uEndOffset,
                                     uint32_t            uStartOffset)
{
   QCBORError uError;

   uError = DecodeNesting_Descend(pNesting, QCBOR_TYPE_BYTE_STRING);
   if(uError != QCBOR_SUCCESS) {
      goto Done;
   }

   /* Fill in the new byte string level */
   pNesting->pCurrent->u.bs.uSavedEndOffset  = uEndOffset;
   pNesting->pCurrent->u.bs.uBstrStartOffset = uStartOffset;

   /* Bstr wrapped levels are always bounded */
   pNesting->pCurrentBounded = pNesting->pCurrent;

Done:
   return uError;;
}


static inline void
DecodeNesting_ZeroMapOrArrayCount(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrent->u.ma.uCountCursor = 0;
}


static inline void
DecodeNesting_ResetMapOrArrayCount(QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrent->u.ma.uCountCursor != QCBOR_COUNT_INDICATES_ZERO_LENGTH) {
      pNesting->pCurrentBounded->u.ma.uCountCursor = pNesting->pCurrentBounded->u.ma.uCountTotal;
   }
}


static inline void
DecodeNesting_Init(QCBORDecodeNesting *pNesting)
{
   /* Assumes that *pNesting has been zero'd before this call. */
   pNesting->pLevels[0].uLevelType = QCBOR_TYPE_BYTE_STRING;
   pNesting->pCurrent = &(pNesting->pLevels[0]);
}


static inline void
DecodeNesting_PrepareForMapSearch(QCBORDecodeNesting *pNesting,
                                  QCBORDecodeNesting *pSave)
{
   *pSave = *pNesting;
}


static inline void
DecodeNesting_RestoreFromMapSearch(QCBORDecodeNesting *pNesting,
                                   const QCBORDecodeNesting *pSave)
{
   *pNesting = *pSave;
}


static inline uint32_t
DecodeNesting_GetPreviousBoundedEnd(const QCBORDecodeNesting *pMe)
{
   return pMe->pCurrentBounded->u.bs.uSavedEndOffset;
}




#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
/*===========================================================================
   QCBORStringAllocate -- STRING ALLOCATOR INVOCATION

   The following four functions are pretty wrappers for invocation of
   the string allocator supplied by the caller.

  ===========================================================================*/

static inline void
StringAllocator_Free(const QCBORInternalAllocator *pMe, const void *pMem)
{
   /* These pragmas allow the "-Wcast-qual" warnings flag to be set for
    * gcc and clang. This is the one place where the const needs to be
    * cast away so const can be use in the rest of the code.
    */
#ifndef _MSC_VER
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif
   (pMe->pfAllocator)(pMe->pAllocateCxt, (void *)pMem, 0);
#ifndef _MSC_VER
#pragma GCC diagnostic pop
#endif
}

// StringAllocator_Reallocate called with pMem NULL is
// equal to StringAllocator_Allocate()
static inline UsefulBuf
StringAllocator_Reallocate(const QCBORInternalAllocator *pMe,
                           const void *pMem,
                           size_t uSize)
{
   /* See comment in StringAllocator_Free() */
#ifndef _MSC_VER
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif
   return (pMe->pfAllocator)(pMe->pAllocateCxt, (void *)pMem, uSize);
#ifndef _MSC_VER
#pragma GCC diagnostic pop
#endif
}

static inline UsefulBuf
StringAllocator_Allocate(const QCBORInternalAllocator *pMe, size_t uSize)
{
   return (pMe->pfAllocator)(pMe->pAllocateCxt, NULL, uSize);
}

static inline void
StringAllocator_Destruct(const QCBORInternalAllocator *pMe)
{
   /* See comment in StringAllocator_Free() */
#ifndef _MSC_VER
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif
   if(pMe->pfAllocator) {
      (pMe->pfAllocator)(pMe->pAllocateCxt, NULL, 0);
   }
#ifndef _MSC_VER
#pragma GCC diagnostic pop
#endif
}
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */




/*===========================================================================
 QCBORDecode -- The main implementation of CBOR decoding

 See qcbor/qcbor_decode.h for definition of the object
 used here: QCBORDecodeContext
  ===========================================================================*/
/*
 * Public function, see header file
 */
void QCBORDecode_Init(QCBORDecodeContext *pMe,
                      UsefulBufC          EncodedCBOR,
                      QCBORDecodeMode     nDecodeMode)
{
   memset(pMe, 0, sizeof(QCBORDecodeContext));
   UsefulInputBuf_Init(&(pMe->InBuf), EncodedCBOR);
   /* Don't bother with error check on decode mode. If a bad value is
    * passed it will just act as if the default normal mode of 0 was set.
    */
   pMe->uDecodeMode = (uint8_t)nDecodeMode;
   DecodeNesting_Init(&(pMe->nesting));

   /* Inialize me->auMappedTags to CBOR_TAG_INVALID16. See
    * GetNext_TaggedItem() and MapTagNumber(). */
   memset(pMe->auMappedTags, 0xff, sizeof(pMe->auMappedTags));
}


#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS

/*
 * Public function, see header file
 */
void QCBORDecode_SetUpAllocator(QCBORDecodeContext *pMe,
                                QCBORStringAllocate pfAllocateFunction,
                                void               *pAllocateContext,
                                bool                bAllStrings)
{
   pMe->StringAllocator.pfAllocator   = pfAllocateFunction;
   pMe->StringAllocator.pAllocateCxt  = pAllocateContext;
   pMe->bStringAllocateAll            = bAllStrings;
}
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */




/*
 * Deprecated public function, see header file
 */
void QCBORDecode_SetCallerConfiguredTagList(QCBORDecodeContext   *pMe,
                                            const QCBORTagListIn *pTagList)
{
   /* This does nothing now. It is retained for backwards compatibility */
   (void)pMe;
   (void)pTagList;
}




/*
 * Decoding items is done in six layers, one calling the next one
 * down. If a layer has no work to do for a particular item, it
 * returns quickly.
 *
 * 1. QCBORDecode_GetNextTagContent - The top layer processes tagged
 * data items, turning them into the local C representation.  For the
 * most simple it is just associating a QCBOR_TYPE with the data. For
 * the complex ones that an aggregate of data items, there is some
 * further decoding and some limited recursion.
 *
 * 2. QCBORDecode_GetNextMapOrArray - This manages the beginnings and
 * ends of maps and arrays. It tracks descending into and ascending
 * out of maps/arrays. It processes breaks that terminate
 * indefinite-length maps and arrays.
 *
 * 3. QCBORDecode_GetNextMapEntry - This handles the combining of two
 * items, the label and the data, that make up a map entry.  It only
 * does work on maps. It combines the label and data items into one
 * labeled item.
 *
 * 4. QCBORDecode_GetNextTagNumber - This decodes type 6 tag
 * numbers. It turns the tag numbers into bit flags associated with
 * the data item. No actual decoding of the contents of the tag is
 * performed here.
 *
 * 5. QCBORDecode_GetNextFullString - This assembles the sub-items
 * that make up an indefinite-length string into one string item. It
 * uses the string allocator to create contiguous space for the
 * item. It processes all breaks that are part of indefinite-length
 * strings.
 *
 * 6. DecodeAtomicDataItem - This decodes the atomic data items in
 * CBOR. Each atomic data item has a "major type", an integer
 * "argument" and optionally some content. For text and byte strings,
 * the content is the bytes that make up the string. These are the
 * smallest data items that are considered to be well-formed.  The
 * content may also be other data items in the case of aggregate
 * types. They are not handled in this layer.
 *
 * Roughly this takes 300 bytes of stack for vars. TODO: evaluate this
 * more carefully and correctly.
 */


/*
 * Note about use of int and unsigned variables.
 *
 * See http://www.unix.org/whitepapers/64bit.html for reasons int is
 * used carefully here, and in particular why it isn't used in the
 * public interface.  Also see
 * https://stackoverflow.com/questions/17489857/why-is-int-typically-32-bit-on-64-bit-compilers
 *
 * Int is used for values that need less than 16-bits and would be
 * subject to integer promotion and result in complaining from static
 * analyzers.
 */


/**
 * @brief Decode the CBOR head, the type and argument.
 *
 * @param[in] pUInBuf            The input buffer to read from.
 * @param[out] pnMajorType       The decoded major type.
 * @param[out] puArgument        The decoded argument.
 * @param[out] pnAdditionalInfo  The decoded Lower 5 bits of initial byte.
 *
 * @retval QCBOR_ERR_UNSUPPORTED
 * @retval QCBOR_ERR_HIT_END
 *
 * This decodes the CBOR "head" that every CBOR data item has. See
 * longer explaination of the head in documentation for
 * QCBOREncode_EncodeHead().
 *
 * This does the network->host byte order conversion. The conversion
 * here also results in the conversion for floats in addition to that
 * for lengths, tags and integer values.
 *
 * The int type is preferred to uint8_t for some variables as this
 * avoids integer promotions, can reduce code size and makes static
 * analyzers happier.
 */
static inline QCBORError
DecodeHead(UsefulInputBuf *pUInBuf,
           int            *pnMajorType,
           uint64_t       *puArgument,
           int            *pnAdditionalInfo)
{
   QCBORError uReturn;

   /* Get the initial byte that every CBOR data item has and break it
    * down. */
   const int nInitialByte    = (int)UsefulInputBuf_GetByte(pUInBuf);
   const int nTmpMajorType   = nInitialByte >> 5;
   const int nAdditionalInfo = nInitialByte & 0x1f;

   /* Where the argument accumulates */
   uint64_t uArgument;

   if(nAdditionalInfo >= LEN_IS_ONE_BYTE && nAdditionalInfo <= LEN_IS_EIGHT_BYTES) {
      /* Need to get 1,2,4 or 8 additional argument bytes. Map
       * LEN_IS_ONE_BYTE..LEN_IS_EIGHT_BYTES to actual length.
       */
      static const uint8_t aIterate[] = {1,2,4,8};

      /* Loop getting all the bytes in the argument */
      uArgument = 0;
      for(int i = aIterate[nAdditionalInfo - LEN_IS_ONE_BYTE]; i; i--) {
         /* This shift and add gives the endian conversion. */
         uArgument = (uArgument << 8) + UsefulInputBuf_GetByte(pUInBuf);
      }
   } else if(nAdditionalInfo >= ADDINFO_RESERVED1 && nAdditionalInfo <= ADDINFO_RESERVED3) {
      /* The reserved and thus-far unused additional info values */
      uReturn = QCBOR_ERR_UNSUPPORTED;
      goto Done;
   } else {
      /* Less than 24, additional info is argument or 31, an
       * indefinite-length.  No more bytes to get.
       */
      uArgument = (uint64_t)nAdditionalInfo;
   }

   if(UsefulInputBuf_GetError(pUInBuf)) {
      uReturn = QCBOR_ERR_HIT_END;
      goto Done;
   }

   /* All successful if arrived here. */
   uReturn           = QCBOR_SUCCESS;
   *pnMajorType      = nTmpMajorType;
   *puArgument       = uArgument;
   *pnAdditionalInfo = nAdditionalInfo;

Done:
   return uReturn;
}


/**
 * @brief Decode integer types, major types 0 and 1.
 *
 * @param[in] nMajorType     The CBOR major type (0 or 1).
 * @param[in] uArgument      The argument from the head.
 * @param[out] pDecodedItem  The filled in decoded item.
 *
 * @retval QCBOR_ERR_INT_OVERFLOW
 *
 * Must only be called when major type is 0 or 1.
 *
 * CBOR doesn't explicitly specify two's compliment for integers but
 * all CPUs use it these days and the test vectors in the RFC are
 * so. All integers in the CBOR structure are positive and the major
 * type indicates positive or negative.  CBOR can express positive
 * integers up to 2^x - 1 where x is the number of bits and negative
 * integers down to 2^x.  Note that negative numbers can be one more
 * away from zero than positive.  Stdint, as far as I can tell, uses
 * two's compliment to represent negative integers.
 */
static inline QCBORError
DecodeInteger(int nMajorType, uint64_t uArgument, QCBORItem *pDecodedItem)
{
   QCBORError uReturn = QCBOR_SUCCESS;

   if(nMajorType == CBOR_MAJOR_TYPE_POSITIVE_INT) {
      if (uArgument <= INT64_MAX) {
         pDecodedItem->val.int64 = (int64_t)uArgument;
         pDecodedItem->uDataType = QCBOR_TYPE_INT64;

      } else {
         pDecodedItem->val.uint64 = uArgument;
         pDecodedItem->uDataType  = QCBOR_TYPE_UINT64;
      }

   } else {
      if(uArgument <= INT64_MAX) {
         /* CBOR's representation of negative numbers lines up with
          * the two-compliment representation. A negative integer has
          * one more in range than a positive integer. INT64_MIN is
          * equal to (-INT64_MAX) - 1.
          */
         pDecodedItem->val.int64 = (-(int64_t)uArgument) - 1;
         pDecodedItem->uDataType = QCBOR_TYPE_INT64;

      } else {
         /* C can't represent a negative integer in this range so it
          * is an error.
          */
         uReturn = QCBOR_ERR_INT_OVERFLOW;
      }
   }

   return uReturn;
}


/* Make sure #define value line up as DecodeSimple counts on this. */
#if QCBOR_TYPE_FALSE != CBOR_SIMPLEV_FALSE
#error QCBOR_TYPE_FALSE macro value wrong
#endif

#if QCBOR_TYPE_TRUE != CBOR_SIMPLEV_TRUE
#error QCBOR_TYPE_TRUE macro value wrong
#endif

#if QCBOR_TYPE_NULL != CBOR_SIMPLEV_NULL
#error QCBOR_TYPE_NULL macro value wrong
#endif

#if QCBOR_TYPE_UNDEF != CBOR_SIMPLEV_UNDEF
#error QCBOR_TYPE_UNDEF macro value wrong
#endif

#if QCBOR_TYPE_BREAK != CBOR_SIMPLE_BREAK
#error QCBOR_TYPE_BREAK macro value wrong
#endif

#if QCBOR_TYPE_DOUBLE != DOUBLE_PREC_FLOAT
#error QCBOR_TYPE_DOUBLE macro value wrong
#endif

#if QCBOR_TYPE_FLOAT != SINGLE_PREC_FLOAT
#error QCBOR_TYPE_FLOAT macro value wrong
#endif


/**
 * @brief Decode major type 7 -- true, false, floating-point, break...
 *
 * @param[in] nAdditionalInfo   The lower five bits from the initial byte.
 * @param[in] uArgument         The argument from the head.
 * @param[out] pDecodedItem     The filled in decoded item.
 *
 * @retval QCBOR_ERR_HALF_PRECISION_DISABLED
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED
 * @retval QCBOR_ERR_BAD_TYPE_7
 */

static inline QCBORError
DecodeType7(int nAdditionalInfo, uint64_t uArgument, QCBORItem *pDecodedItem)
{
   QCBORError uReturn = QCBOR_SUCCESS;

   /* uAdditionalInfo is 5 bits from the initial byte. Compile time
    * checks above make sure uAdditionalInfo values line up with
    * uDataType values.  DecodeHead() never returns an AdditionalInfo
    * > 0x1f so cast is safe.
    */
   pDecodedItem->uDataType = (uint8_t)nAdditionalInfo;

   switch(nAdditionalInfo) {
      /* No check for ADDINFO_RESERVED1 - ADDINFO_RESERVED3 as they
       * are caught before this is called.
       */

      case HALF_PREC_FLOAT: /* 25 */
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
         /* Half-precision is returned as a double.  The cast to
          * uint16_t is safe because the encoded value was 16 bits. It
          * was widened to 64 bits to be passed in here.
          */
         pDecodedItem->val.dfnum = IEEE754_HalfToDouble((uint16_t)uArgument);
         pDecodedItem->uDataType = QCBOR_TYPE_DOUBLE;
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
         uReturn = FLOAT_ERR_CODE_NO_HALF_PREC(QCBOR_SUCCESS);
         break;
      case SINGLE_PREC_FLOAT: /* 26 */
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
         /* Single precision is normally returned as a double since
          * double is widely supported, there is no loss of precision,
          * it makes it easy for the caller in most cases and it can
          * be converted back to single with no loss of precision
          *
          * The cast to uint32_t is safe because the encoded value was
          * 32 bits. It was widened to 64 bits to be passed in here.
          */
         {
            const float f = UsefulBufUtil_CopyUint32ToFloat((uint32_t)uArgument);
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
            /* In the normal case, use HW to convert float to
             * double. */
            pDecodedItem->val.dfnum = (double)f;
            pDecodedItem->uDataType = QCBOR_TYPE_DOUBLE;
#else /* QCBOR_DISABLE_FLOAT_HW_USE */
            /* Use of float HW is disabled, return as a float. */
            pDecodedItem->val.fnum = f;
            pDecodedItem->uDataType = QCBOR_TYPE_FLOAT;

            /* IEEE754_FloatToDouble() could be used here to return as
             * a double, but it adds object code and most likely
             * anyone disabling FLOAT HW use doesn't care about floats
             * and wants to save object code.
             */
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
         }
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
         uReturn = FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS);
         break;

      case DOUBLE_PREC_FLOAT: /* 27 */
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
         pDecodedItem->val.dfnum = UsefulBufUtil_CopyUint64ToDouble(uArgument);
         pDecodedItem->uDataType = QCBOR_TYPE_DOUBLE;
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
         uReturn = FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS);
         break;

      case CBOR_SIMPLEV_FALSE: /* 20 */
      case CBOR_SIMPLEV_TRUE:  /* 21 */
      case CBOR_SIMPLEV_NULL:  /* 22 */
      case CBOR_SIMPLEV_UNDEF: /* 23 */
      case CBOR_SIMPLE_BREAK:  /* 31 */
         break; /* nothing to do */

      case CBOR_SIMPLEV_ONEBYTE: /* 24 */
         if(uArgument <= CBOR_SIMPLE_BREAK) {
            /* This takes out f8 00 ... f8 1f which should be encoded
             * as e0 … f7
             */
            uReturn = QCBOR_ERR_BAD_TYPE_7;
            goto Done;
         }
         /* FALLTHROUGH */

      default: /* 0-19 */
         pDecodedItem->uDataType   = QCBOR_TYPE_UKNOWN_SIMPLE;
         /* DecodeHead() will make uArgument equal to
          * nAdditionalInfo when nAdditionalInfo is < 24. This cast is
          * safe because the 2, 4 and 8 byte lengths of uNumber are in
          * the double/float cases above
          */
         pDecodedItem->val.uSimple = (uint8_t)uArgument;
         break;
   }

Done:
   return uReturn;
}


/**
 * @brief Decode text and byte strings
 *
 * @param[in] pAllocator     The string allocator or NULL.
 * @param[in] uStrLen        The length of the string.
 * @param[in] pUInBuf        The surce from which to read the string's bytes.
 * @param[out] pDecodedItem  The filled in decoded item.
 *
 * @retval QCBOR_ERR_HIT_END
 * @retval QCBOR_ERR_STRING_ALLOCATE
 * @retval QCBOR_ERR_STRING_TOO_LONG
 *
 * The reads @c uStrlen bytes from @c pUInBuf and fills in @c
 * pDecodedItem. If @c pAllocator is not NULL then memory for the
 * string is allocated.
 */
static inline QCBORError
DecodeBytes(const QCBORInternalAllocator *pAllocator,
            uint64_t                      uStrLen,
            UsefulInputBuf               *pUInBuf,
            QCBORItem                    *pDecodedItem)
{
   QCBORError uReturn = QCBOR_SUCCESS;

   /* CBOR lengths can be 64 bits, but size_t is not 64 bits on all
    * CPUs.  This check makes the casts to size_t below safe.
    *
    * The max is 4 bytes less than the largest sizeof() so this can be
    * tested by putting a SIZE_MAX length in the CBOR test input (no
    * one will care the limit on strings is 4 bytes shorter).
    */
   if(uStrLen > SIZE_MAX-4) {
      uReturn = QCBOR_ERR_STRING_TOO_LONG;
      goto Done;
   }

   const UsefulBufC Bytes = UsefulInputBuf_GetUsefulBuf(pUInBuf, (size_t)uStrLen);
   if(UsefulBuf_IsNULLC(Bytes)) {
      /* Failed to get the bytes for this string item */
      uReturn = QCBOR_ERR_HIT_END;
      goto Done;
   }

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
   /* Note that this is not where allocation to coalesce
    * indefinite-length strings is done. This is for when the caller
    * has requested all strings be allocated. Disabling indefinite
    * length strings also disables this allocate-all option.
    */
   if(pAllocator) {
      /* request to use the string allocator to make a copy */
      UsefulBuf NewMem = StringAllocator_Allocate(pAllocator, (size_t)uStrLen);
      if(UsefulBuf_IsNULL(NewMem)) {
         uReturn = QCBOR_ERR_STRING_ALLOCATE;
         goto Done;
      }
      pDecodedItem->val.string = UsefulBuf_Copy(NewMem, Bytes);
      pDecodedItem->uDataAlloc = 1;
      goto Done;
   }
#else /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */
   (void)pAllocator;
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */

   /* Normal case with no string allocator */
   pDecodedItem->val.string = Bytes;

Done:
   return uReturn;
}


/**
 * @brief Map the CBOR major types for strings to the QCBOR types.
 *
 * @param[in] nCBORMajorType  The CBOR major type to convert.
 * @retturns QCBOR type number.
 *
 * This only works for the two string types.
 */
static inline uint8_t ConvertStringMajorTypes(int nCBORMajorType)
{
   #if CBOR_MAJOR_TYPE_BYTE_STRING + 4 != QCBOR_TYPE_BYTE_STRING
   #error QCBOR_TYPE_BYTE_STRING no lined up with major type
   #endif

   #if CBOR_MAJOR_TYPE_TEXT_STRING + 4 != QCBOR_TYPE_TEXT_STRING
   #error QCBOR_TYPE_TEXT_STRING no lined up with major type
   #endif

   return (uint8_t)(nCBORMajorType + 4);
}


/**
 * @brief Map the CBOR major types  for arrays/maps  to the QCBOR types.
 *
 * @param[in] nCBORMajorType  The CBOR major type to convert.
 * @retturns QCBOR type number.
 *
 * This only works for the two aggregate types.
 */
static inline uint8_t ConvertArrayOrMapType(int nCBORMajorType)
{
   #if QCBOR_TYPE_ARRAY != CBOR_MAJOR_TYPE_ARRAY
   #error QCBOR_TYPE_ARRAY value not lined up with major type
   #endif

   #if QCBOR_TYPE_MAP != CBOR_MAJOR_TYPE_MAP
   #error QCBOR_TYPE_MAP value not lined up with major type
   #endif

   return (uint8_t)(nCBORMajorType);
}


/**
 * @brief Decode a single primitive data item (decode layer 6).
 *
 * @param[in] pUInBuf       Input buffer to read data item from.
 * @param[out] pDecodedItem  The filled-in decoded item.
 * @param[in] pAllocator    The allocator to use for strings or NULL.
 *
 * @retval QCBOR_ERR_UNSUPPORTED
 * @retval QCBOR_ERR_HIT_END
 * @retval QCBOR_ERR_INT_OVERFLOW
 * @retval QCBOR_ERR_STRING_ALLOCATE
 * @retval QCBOR_ERR_STRING_TOO_LONG
 * @retval QCBOR_ERR_HALF_PRECISION_DISABLED
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED
 * @retval QCBOR_ERR_BAD_TYPE_7
 * @retval QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED
 *
 * This decodes the most primitive / atomic data item. It does
 * no combing of data items.
 */
static QCBORError
DecodeAtomicDataItem(UsefulInputBuf               *pUInBuf,
                     QCBORItem                    *pDecodedItem,
                     const QCBORInternalAllocator *pAllocator)
{
   QCBORError uReturn;

   /* Get the major type and the argument. The argument could be
    * length of more bytes or the value depending on the major
    * type. nAdditionalInfo is an encoding of the length of the
    * uNumber and is needed to decode floats and doubles.
    */
   int      nMajorType = 0;
   uint64_t uArgument = 0;
   int      nAdditionalInfo = 0;

   memset(pDecodedItem, 0, sizeof(QCBORItem));

   uReturn = DecodeHead(pUInBuf, &nMajorType, &uArgument, &nAdditionalInfo);
   if(uReturn) {
      goto Done;
   }

   /* At this point the major type and the argument are valid. We've
    * got the type and the argument that starts every CBOR data item.
    */
   switch (nMajorType) {
      case CBOR_MAJOR_TYPE_POSITIVE_INT: /* Major type 0 */
      case CBOR_MAJOR_TYPE_NEGATIVE_INT: /* Major type 1 */
         if(nAdditionalInfo == LEN_IS_INDEFINITE) {
            uReturn = QCBOR_ERR_BAD_INT;
         } else {
            uReturn = DecodeInteger(nMajorType, uArgument, pDecodedItem);
         }
         break;

      case CBOR_MAJOR_TYPE_BYTE_STRING: /* Major type 2 */
      case CBOR_MAJOR_TYPE_TEXT_STRING: /* Major type 3 */
         pDecodedItem->uDataType = ConvertStringMajorTypes(nMajorType);
         if(nAdditionalInfo == LEN_IS_INDEFINITE) {
            pDecodedItem->val.string = (UsefulBufC){NULL, QCBOR_STRING_LENGTH_INDEFINITE};
         } else {
            uReturn = DecodeBytes(pAllocator, uArgument, pUInBuf, pDecodedItem);
         }
         break;

      case CBOR_MAJOR_TYPE_ARRAY: /* Major type 4 */
      case CBOR_MAJOR_TYPE_MAP:   /* Major type 5 */
         if(nAdditionalInfo == LEN_IS_INDEFINITE) {
            /* Indefinite-length string. */
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
            pDecodedItem->val.uCount = QCBOR_COUNT_INDICATES_INDEFINITE_LENGTH;
#else /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */
            uReturn = QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED;
            break;
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */
         } else {
            /* Definite-length string. */
            if(uArgument > QCBOR_MAX_ITEMS_IN_ARRAY) {
                uReturn = QCBOR_ERR_ARRAY_DECODE_TOO_LONG;
                goto Done;
             }
            /* cast OK because of check above */
            pDecodedItem->val.uCount = (uint16_t)uArgument;
         }
         pDecodedItem->uDataType = ConvertArrayOrMapType(nMajorType);
         break;

      case CBOR_MAJOR_TYPE_TAG: /* Major type 6, tag numbers */
         if(nAdditionalInfo == LEN_IS_INDEFINITE) {
            uReturn = QCBOR_ERR_BAD_INT;
         } else {
            pDecodedItem->val.uTagV = uArgument;
            pDecodedItem->uDataType = QCBOR_TYPE_TAG;
         }
         break;

      case CBOR_MAJOR_TYPE_SIMPLE:
         /* Major type 7: float, double, true, false, null... */
         uReturn = DecodeType7(nAdditionalInfo, uArgument, pDecodedItem);
         break;

      default:
         /* Never happens because DecodeHead() should never return > 7 */
         uReturn = QCBOR_ERR_UNSUPPORTED;
         break;
   }

Done:
   return uReturn;
}


/**
 * @brief Process indefinite-length strings (decode layer 5).
 *
 * @param[in] pMe   Decoder context
 * @param[out] pDecodedItem  The decoded item that work is done on.
 *
 * @retval QCBOR_ERR_UNSUPPORTED
 * @retval QCBOR_ERR_HIT_END
 * @retval QCBOR_ERR_INT_OVERFLOW
 * @retval QCBOR_ERR_STRING_ALLOCATE
 * @retval QCBOR_ERR_STRING_TOO_LONG
 * @retval QCBOR_ERR_HALF_PRECISION_DISABLED
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED
 * @retval QCBOR_ERR_BAD_TYPE_7
 * @retval QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED
 * @retval QCBOR_ERR_NO_STRING_ALLOCATOR
 * @retval QCBOR_ERR_INDEFINITE_STRING_CHUNK
 * @retval QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED
 *
 * If @c pDecodedItem is not an indefinite-length string, this does nothing.
 *
 * If it is, this loops getting the subsequent chunk data items that
 * make up the string.  The string allocator is used to make a
 * contiguous buffer for the chunks.  When this completes @c
 * pDecodedItem contains the put-together string.
 *
 * Code Reviewers: THIS FUNCTION DOES A LITTLE POINTER MATH
 */
static inline QCBORError
QCBORDecode_GetNextFullString(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   /* Aproximate stack usage
    *                                             64-bit      32-bit
    *   local vars                                    32          16
    *   2 UsefulBufs                                  32          16
    *   QCBORItem                                     56          52
    *   TOTAL                                        120          74
    */

   /* The string allocator is used here for two purposes: 1)
    * coalescing the chunks of an indefinite-length string, 2)
    * allocating storage for every string returned when requested.
    *
    * The first use is below in this function. Indefinite-length
    * strings cannot be processed at all without a string allocator.
    *
    * The second used is in DecodeBytes() which is called by
    * GetNext_Item() below. This second use unneccessary for most use
    * and only happens when requested in the call to
    * QCBORDecode_SetMemPool(). If the second use not requested then
    * NULL is passed for the string allocator to GetNext_Item().
    *
    * QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS disables the string
    * allocator altogether and thus both of these uses. It reduced the
    * decoder object code by about 400 bytes.
    */
   const QCBORInternalAllocator *pAllocatorForGetNext = NULL;

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
   const QCBORInternalAllocator *pAllocator = NULL;

   if(pMe->StringAllocator.pfAllocator) {
      pAllocator = &(pMe->StringAllocator);
      if(pMe->bStringAllocateAll) {
         pAllocatorForGetNext = pAllocator;
      }
   }
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */

   QCBORError uReturn;
   uReturn = DecodeAtomicDataItem(&(pMe->InBuf), pDecodedItem, pAllocatorForGetNext);
   if(uReturn != QCBOR_SUCCESS) {
      goto Done;
   }

   /* Only do indefinite-length processing on strings */
   const uint8_t uStringType = pDecodedItem->uDataType;
   if(uStringType!= QCBOR_TYPE_BYTE_STRING && uStringType != QCBOR_TYPE_TEXT_STRING) {
      goto Done;
   }

   /* Is this a string with an indefinite length? */
   if(pDecodedItem->val.string.len != QCBOR_STRING_LENGTH_INDEFINITE) {
      goto Done;
   }

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
   /* Can't decode indefinite-length strings without a string allocator */
   if(pAllocator == NULL) {
      uReturn = QCBOR_ERR_NO_STRING_ALLOCATOR;
      goto Done;
   }

   /* Loop getting chunks of the indefinite-length string */
   UsefulBufC FullString = NULLUsefulBufC;

   for(;;) {
      /* Get QCBORItem for next chunk */
      QCBORItem StringChunkItem;
      /* Pass a NULL string allocator to GetNext_Item() because the
       * individual string chunks in an indefinite-length should not
       * be allocated. They are always copied in the the contiguous
       * buffer allocated here.
       */
      uReturn = DecodeAtomicDataItem(&(pMe->InBuf), &StringChunkItem, NULL);
      if(uReturn) {
         break;
      }

      /* Is item is the marker for end of the indefinite-length string? */
      if(StringChunkItem.uDataType == QCBOR_TYPE_BREAK) {
         /* String is complete */
         pDecodedItem->val.string = FullString;
         pDecodedItem->uDataAlloc = 1;
         break;
      }

      /* All chunks must be of the same type, the type of the item
       * that introduces the indefinite-length string. This also
       * catches errors where the chunk is not a string at all and an
       * indefinite-length string inside an indefinite-length string.
       */
      if(StringChunkItem.uDataType != uStringType ||
         StringChunkItem.val.string.len == QCBOR_STRING_LENGTH_INDEFINITE) {
         uReturn = QCBOR_ERR_INDEFINITE_STRING_CHUNK;
         break;
      }

      if (StringChunkItem.val.string.len > 0) {
         /* The first time throurgh FullString.ptr is NULL and this is
          * equivalent to StringAllocator_Allocate(). Subsequently it is
          * not NULL and a reallocation happens.
          */
         UsefulBuf NewMem = StringAllocator_Reallocate(pAllocator,
                                                       FullString.ptr,
                                                       FullString.len + StringChunkItem.val.string.len);

         if(UsefulBuf_IsNULL(NewMem)) {
            uReturn = QCBOR_ERR_STRING_ALLOCATE;
            break;
         }
 
         /* Copy new string chunk to the end of accumulated string */
         FullString = UsefulBuf_CopyOffset(NewMem, FullString.len, StringChunkItem.val.string);
      }
   }

   if(uReturn != QCBOR_SUCCESS && !UsefulBuf_IsNULLC(FullString)) {
      /* Getting the item failed, clean up the allocated memory */
      StringAllocator_Free(pAllocator, FullString.ptr);
   }
#else /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */
   uReturn = QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED;
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */

Done:
   return uReturn;
}


/**
 * @brief This converts a tag number to a shorter mapped value for storage.
 *
 * @param[in] pMe                The decode context.
 * @param[in] uUnMappedTag       The tag number to map
 * @param[out] puMappedTagNumer  The stored tag number.
 *
 * @return error code.
 *
 * The main point of mapping tag numbers is make QCBORItem
 * smaller. With this mapping storage of 4 tags takes up 8
 * bytes. Without, it would take up 32 bytes.
 *
 * This maps tag numbers greater than QCBOR_LAST_UNMAPPED_TAG.
 * QCBOR_LAST_UNMAPPED_TAG is a little smaller than MAX_UINT16.
 *
 * See also UnMapTagNumber() and @ref QCBORItem.
 */
static inline QCBORError
MapTagNumber(QCBORDecodeContext *pMe, uint64_t uUnMappedTag, uint16_t *puMappedTagNumer)
{
   if(uUnMappedTag > QCBOR_LAST_UNMAPPED_TAG) {
      unsigned uTagMapIndex;
      /* Is there room in the tag map, or is it in it already? */
      for(uTagMapIndex = 0; uTagMapIndex < QCBOR_NUM_MAPPED_TAGS; uTagMapIndex++) {
         if(pMe->auMappedTags[uTagMapIndex] == CBOR_TAG_INVALID64) {
            break;
         }
         if(pMe->auMappedTags[uTagMapIndex] == uUnMappedTag) {
            break;
         }
      }
      if(uTagMapIndex >= QCBOR_NUM_MAPPED_TAGS) {
         return QCBOR_ERR_TOO_MANY_TAGS;
      }

      /* Covers the cases where tag is new and were it is already in the map */
      pMe->auMappedTags[uTagMapIndex] = uUnMappedTag;
      *puMappedTagNumer = (uint16_t)(uTagMapIndex + QCBOR_LAST_UNMAPPED_TAG + 1);

   } else {
      *puMappedTagNumer = (uint16_t)uUnMappedTag;
   }

   return QCBOR_SUCCESS;
}


/**
 * @brief This converts a mapped tag number to the actual tag number.
 *
 * @param[in] pMe               The decode context.
 * @param[in] uMappedTagNumber  The stored tag number.
 *
 * @return The actual tag number is returned or
 *         @ref CBOR_TAG_INVALID64 on error.
 *
 * This is the reverse of MapTagNumber()
 */
static uint64_t
UnMapTagNumber(const QCBORDecodeContext *pMe, uint16_t uMappedTagNumber)
{
   if(uMappedTagNumber <= QCBOR_LAST_UNMAPPED_TAG) {
      return uMappedTagNumber;
   } else if(uMappedTagNumber == CBOR_TAG_INVALID16) {
      return CBOR_TAG_INVALID64;
   } else {
      /* This won't be negative because of code below in
       * MapTagNumber()
       */
      const unsigned uIndex = uMappedTagNumber - (QCBOR_LAST_UNMAPPED_TAG + 1);
      return pMe->auMappedTags[uIndex];
   }
}


/**
 * @brief Aggregate all tags wrapping a data item (decode layer 4).
 *
 * @param[in] pMe            Decoder context
 * @param[out] pDecodedItem  The decoded item that work is done on.

 * @retval QCBOR_ERR_UNSUPPORTED
 * @retval QCBOR_ERR_HIT_END
 * @retval QCBOR_ERR_INT_OVERFLOW
 * @retval QCBOR_ERR_STRING_ALLOCATE
 * @retval QCBOR_ERR_STRING_TOO_LONG
 * @retval QCBOR_ERR_HALF_PRECISION_DISABLED
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED
 * @retval QCBOR_ERR_BAD_TYPE_7
 * @retval QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED
 * @retval QCBOR_ERR_NO_STRING_ALLOCATOR
 * @retval QCBOR_ERR_INDEFINITE_STRING_CHUNK
 * @retval QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED
 * @retval QCBOR_ERR_TOO_MANY_TAGS
 *
 * This loops getting atomic data items until one is not a tag
 * number.  Usually this is largely pass-through because most
 * item are not tag numbers.
 */
static QCBORError
QCBORDecode_GetNextTagNumber(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   /* Accummulate the tags from multiple items here and then copy them
    * into the last item, the non-tag item.
    */
   uint16_t auItemsTags[QCBOR_MAX_TAGS_PER_ITEM];

   /* Initialize to CBOR_TAG_INVALID16 */
   #if CBOR_TAG_INVALID16 != 0xffff
   /* Be sure the memset does the right thing. */
   #err CBOR_TAG_INVALID16 tag not defined as expected
   #endif
   memset(auItemsTags, 0xff, sizeof(auItemsTags));

   QCBORError uReturn = QCBOR_SUCCESS;

   /* Loop fetching data items until the item fetched is not a tag */
   for(;;) {
      QCBORError uErr = QCBORDecode_GetNextFullString(pMe, pDecodedItem);
      if(uErr != QCBOR_SUCCESS) {
         uReturn = uErr;
         goto Done;
      }

      if(pDecodedItem->uDataType != QCBOR_TYPE_TAG) {
         /* Successful exit from loop; maybe got some tags, maybe not */
         memcpy(pDecodedItem->uTags, auItemsTags, sizeof(auItemsTags));
         break;
      }

      if(auItemsTags[QCBOR_MAX_TAGS_PER_ITEM - 1] != CBOR_TAG_INVALID16) {
         /* No room in the tag list */
         uReturn = QCBOR_ERR_TOO_MANY_TAGS;
         /* Continue on to get all tags wrapping this item even though
          * it is erroring out in the end. This allows decoding to
          * continue. This is a resource limit error, not a problem
          * with being well-formed CBOR.
          */
         continue;
      }
      /* Slide tags over one in the array to make room at index 0.
       * Must use memmove because the move source and destination
       * overlap.
       */
      memmove(&auItemsTags[1],
              auItemsTags,
              sizeof(auItemsTags) - sizeof(auItemsTags[0]));

      /* Map the tag */
      uint16_t uMappedTagNumber = 0;
      uReturn = MapTagNumber(pMe, pDecodedItem->val.uTagV, &uMappedTagNumber);
      /* Continue even on error so as to consume all tags wrapping
       * this data item so decoding can go on. If MapTagNumber()
       * errors once it will continue to error.
       */
      auItemsTags[0] = uMappedTagNumber;
   }

Done:
   return uReturn;
}


/**
 * @brief Combine a map entry label and value into one item (decode layer 3).
 *
 * @param[in] pMe            Decoder context
 * @param[out] pDecodedItem  The decoded item that work is done on.
 *
 * @retval QCBOR_ERR_UNSUPPORTED
 * @retval QCBOR_ERR_HIT_END
 * @retval QCBOR_ERR_INT_OVERFLOW
 * @retval QCBOR_ERR_STRING_ALLOCATE
 * @retval QCBOR_ERR_STRING_TOO_LONG
 * @retval QCBOR_ERR_HALF_PRECISION_DISABLED
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED
 * @retval QCBOR_ERR_BAD_TYPE_7
 * @retval QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED
 * @retval QCBOR_ERR_NO_STRING_ALLOCATOR
 * @retval QCBOR_ERR_INDEFINITE_STRING_CHUNK
 * @retval QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED
 * @retval QCBOR_ERR_TOO_MANY_TAGS
 * @retval QCBOR_ERR_ARRAY_DECODE_TOO_LONG
 * @retval QCBOR_ERR_MAP_LABEL_TYPE
 *
 * If a the current nesting level is a map, then this
 * combines pairs of items into one data item with a label
 * and value.
 *
 * This is passthrough if the current nesting level is
 * not a map.
 *
 * This also implements maps-as-array mode where a map
 * is treated like an array to allow caller to do their
 * own label processing.
 */
static inline QCBORError
QCBORDecode_GetNextMapEntry(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   QCBORError uReturn = QCBORDecode_GetNextTagNumber(pMe, pDecodedItem);
   if(uReturn != QCBOR_SUCCESS) {
      goto Done;
   }

   if(pDecodedItem->uDataType == QCBOR_TYPE_BREAK) {
      /* Break can't be a map entry */
      goto Done;
   }

   if(pMe->uDecodeMode != QCBOR_DECODE_MODE_MAP_AS_ARRAY) {
      /* Normal decoding of maps -- combine label and value into one item. */

      if(DecodeNesting_IsCurrentTypeMap(&(pMe->nesting))) {
         /* Save label in pDecodedItem and get the next which will
          * be the real data item.
          */
         QCBORItem LabelItem = *pDecodedItem;
         uReturn = QCBORDecode_GetNextTagNumber(pMe, pDecodedItem);
         if(QCBORDecode_IsUnrecoverableError(uReturn)) {
            goto Done;
         }

         pDecodedItem->uLabelAlloc = LabelItem.uDataAlloc;

         if(LabelItem.uDataType == QCBOR_TYPE_TEXT_STRING) {
            /* strings are always good labels */
            pDecodedItem->label.string = LabelItem.val.string;
            pDecodedItem->uLabelType = QCBOR_TYPE_TEXT_STRING;
         } else if (QCBOR_DECODE_MODE_MAP_STRINGS_ONLY == pMe->uDecodeMode) {
            /* It's not a string and we only want strings */
            uReturn = QCBOR_ERR_MAP_LABEL_TYPE;
            goto Done;
         } else if(LabelItem.uDataType == QCBOR_TYPE_INT64) {
            pDecodedItem->label.int64 = LabelItem.val.int64;
            pDecodedItem->uLabelType = QCBOR_TYPE_INT64;
         } else if(LabelItem.uDataType == QCBOR_TYPE_UINT64) {
            pDecodedItem->label.uint64 = LabelItem.val.uint64;
            pDecodedItem->uLabelType = QCBOR_TYPE_UINT64;
         } else if(LabelItem.uDataType == QCBOR_TYPE_BYTE_STRING) {
            pDecodedItem->label.string = LabelItem.val.string;
            pDecodedItem->uLabelAlloc = LabelItem.uDataAlloc;
            pDecodedItem->uLabelType = QCBOR_TYPE_BYTE_STRING;
         } else {
            /* label is not an int or a string. It is an arrray
             * or a float or such and this implementation doesn't handle that.
             * Also, tags on labels are ignored.
             */
            uReturn = QCBOR_ERR_MAP_LABEL_TYPE;
            goto Done;
         }
      }
   } else {
      /* Decoding of maps as arrays to let the caller decide what to do
       * about labels, particularly lables that are not integers or
       * strings.
       */
      if(pDecodedItem->uDataType == QCBOR_TYPE_MAP) {
         if(pDecodedItem->val.uCount > QCBOR_MAX_ITEMS_IN_ARRAY/2) {
            uReturn = QCBOR_ERR_ARRAY_DECODE_TOO_LONG;
            goto Done;
         }
         pDecodedItem->uDataType = QCBOR_TYPE_MAP_AS_ARRAY;
         /* Cast is safe because of check against QCBOR_MAX_ITEMS_IN_ARRAY/2.
          * Cast is needed because of integer promotion.
          */
         pDecodedItem->val.uCount = (uint16_t)(pDecodedItem->val.uCount * 2);
      }
   }

Done:
   return uReturn;
}


#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
/**
 * @brief Peek and see if next data item is a break;
 *
 * @param[in]  pUIB            UsefulInputBuf to read from.
 * @param[out] pbNextIsBreak   Indicate if next was a break or not.
 *
 * @return  Any decoding error.
 *
 * See if next item is a CBOR break. If it is, it is consumed,
 * if not it is not consumed.
*/
static inline QCBORError
NextIsBreak(UsefulInputBuf *pUIB, bool *pbNextIsBreak)
{
   *pbNextIsBreak = false;
   if(UsefulInputBuf_BytesUnconsumed(pUIB) != 0) {
      QCBORItem Peek;
      size_t uPeek = UsefulInputBuf_Tell(pUIB);
      QCBORError uReturn = DecodeAtomicDataItem(pUIB, &Peek, NULL);
      if(uReturn != QCBOR_SUCCESS) {
         return uReturn;
      }
      if(Peek.uDataType != QCBOR_TYPE_BREAK) {
         /* It is not a break, rewind so it can be processed normally. */
         UsefulInputBuf_Seek(pUIB, uPeek);
      } else {
         *pbNextIsBreak = true;
      }
   }

   return QCBOR_SUCCESS;
}
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */


/**
 * @brief Ascend up nesting levels if all items in them have been consumed.
 *
 * @param[in] pMe       The decode context.
 * @param[in] bMarkEnd  If true mark end of maps/arrays with count of zero.
 *
 * An item was just consumed, now figure out if it was the
 * end of an array/map map that can be closed out. That
 * may in turn close out the above array/map...
*/
static QCBORError
QCBORDecode_NestLevelAscender(QCBORDecodeContext *pMe, bool bMarkEnd)
{
   QCBORError uReturn;

   /* Loop ascending nesting levels as long as there is ascending to do */
   while(!DecodeNesting_IsCurrentAtTop(&(pMe->nesting))) {

      if(DecodeNesting_IsCurrentBstrWrapped(&(pMe->nesting))) {
         /* Nesting level is bstr-wrapped CBOR */

         /* Ascent for bstr-wrapped CBOR is always by explicit call
          * so no further ascending can happen.
          */
         break;

      } else if(DecodeNesting_IsCurrentDefiniteLength(&(pMe->nesting))) {
         /* Level is a definite-length array/map */

         /* Decrement the item count the definite-length array/map */
         DecodeNesting_DecrementDefiniteLengthMapOrArrayCount(&(pMe->nesting));
         if(!DecodeNesting_IsEndOfDefiniteLengthMapOrArray(&(pMe->nesting))) {
             /* Didn't close out array/map, so all work here is done */
             break;
          }
          /* All items in a definite-length array were consumed so it
           * is time to ascend one level. This happens below.
           */

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
      } else {
         /* Level is an indefinite-length array/map. */

         /* Check for a break which is what ends indefinite-length arrays/maps */
         bool bIsBreak = false;
         uReturn = NextIsBreak(&(pMe->InBuf), &bIsBreak);
         if(uReturn != QCBOR_SUCCESS) {
            goto Done;
         }

         if(!bIsBreak) {
            /* Not a break so array/map does not close out. All work is done */
            break;
         }

         /* It was a break in an indefinitelength map / array so
          * it is time to ascend one level.
          */

#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */
      }


      /* All items in the array/map have been consumed. */

      /* But ascent in bounded mode is only by explicit call to
       * QCBORDecode_ExitBoundedMode().
       */
      if(DecodeNesting_IsCurrentBounded(&(pMe->nesting))) {
         /* Set the count to zero for definite-length arrays to indicate
         * cursor is at end of bounded array/map */
         if(bMarkEnd) {
            /* Used for definite and indefinite to signal end */
            DecodeNesting_ZeroMapOrArrayCount(&(pMe->nesting));

         }
         break;
      }

      /* Finally, actually ascend one level. */
      DecodeNesting_Ascend(&(pMe->nesting));
   }

   uReturn = QCBOR_SUCCESS;

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
Done:
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */

   return uReturn;
}


/**
 * @brief Ascending & Descending out of nesting levels (decode layer 2).
 *
 * @param[in] pMe            Decoder context
 * @param[out] pDecodedItem  The decoded item that work is done on.
 *
 * @retval QCBOR_ERR_UNSUPPORTED
 * @retval QCBOR_ERR_HIT_END
 * @retval QCBOR_ERR_INT_OVERFLOW
 * @retval QCBOR_ERR_STRING_ALLOCATE
 * @retval QCBOR_ERR_STRING_TOO_LONG
 * @retval QCBOR_ERR_HALF_PRECISION_DISABLED
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED
 * @retval QCBOR_ERR_BAD_TYPE_7
 * @retval QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED
 * @retval QCBOR_ERR_NO_STRING_ALLOCATOR
 * @retval QCBOR_ERR_INDEFINITE_STRING_CHUNK
 * @retval QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED
 * @retval QCBOR_ERR_TOO_MANY_TAGS
 * @retval QCBOR_ERR_ARRAY_DECODE_TOO_LONG
 * @retval QCBOR_ERR_MAP_LABEL_TYPE
 * @retval QCBOR_ERR_NO_MORE_ITEMS
 * @retval QCBOR_ERR_BAD_BREAK
 * @retval QCBOR_ERR_ARRAY_DECODE_NESTING_TOO_DEEP
 *
 * This handles the traversal descending into and asecnding out of
 * maps, arrays and bstr-wrapped CBOR. It figures out the ends of
 * definite- and indefinte-length maps and arrays by looking at the
 * item count or finding CBOR breaks.  It detects the ends of the
 * top-level sequence and of bstr-wrapped CBOR by byte count.
 */
static QCBORError
QCBORDecode_GetNextMapOrArray(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   QCBORError uReturn;
   /* ==== First: figure out if at the end of a traversal ==== */

   /* If out of bytes to consume, it is either the end of the
    * top-level sequence of some bstr-wrapped CBOR that was entered.
    *
    * In the case of bstr-wrapped CBOR, the length of the
    * UsefulInputBuf was set to that of the bstr-wrapped CBOR. When
    * the bstr-wrapped CBOR is exited, the length is set back to the
    * top-level's length or to the next highest bstr-wrapped CBOR.
   */
   if(UsefulInputBuf_BytesUnconsumed(&(pMe->InBuf)) == 0) {
      uReturn = QCBOR_ERR_NO_MORE_ITEMS;
      goto Done;
   }

   /* Check to see if at the end of a bounded definite-length map or
    * array. The check for a break ending indefinite-length array is
    * later in QCBORDecode_NestLevelAscender().
    */
   if(DecodeNesting_IsAtEndOfBoundedLevel(&(pMe->nesting))) {
      uReturn = QCBOR_ERR_NO_MORE_ITEMS;
      goto Done;
   }

   /* ==== Next: not at the end, so get another item ==== */
   uReturn = QCBORDecode_GetNextMapEntry(pMe, pDecodedItem);
   if(QCBORDecode_IsUnrecoverableError(uReturn)) {
      /* Error is so bad that traversal is not possible. */
      goto Done;
   }

   /* Breaks ending arrays/maps are processed later in the call to
    * QCBORDecode_NestLevelAscender(). They should never show up here.
    */
   if(pDecodedItem->uDataType == QCBOR_TYPE_BREAK) {
      uReturn = QCBOR_ERR_BAD_BREAK;
      goto Done;
   }

   /* Record the nesting level for this data item before processing
    * any of decrementing and descending.
    */
   pDecodedItem->uNestingLevel = DecodeNesting_GetCurrentLevel(&(pMe->nesting));


   /* ==== Next: Process the item for descent, ascent, decrement... ==== */
   if(QCBORItem_IsMapOrArray(pDecodedItem)) {
      /* If the new item is a map or array, descend.
       *
       * Empty indefinite-length maps and arrays are descended into,
       * but then ascended out of in the next chunk of code.
       *
       * Maps and arrays do count as items in the map/array that
       * encloses them so a decrement needs to be done for them too,
       * but that is done only when all the items in them have been
       * processed, not when they are opened with the exception of an
       * empty map or array.
       */
      QCBORError uDescendErr;
      uDescendErr = DecodeNesting_DescendMapOrArray(&(pMe->nesting),
                                                pDecodedItem->uDataType,
                                                pDecodedItem->val.uCount);
      if(uDescendErr != QCBOR_SUCCESS) {
         /* This error is probably a traversal error and it overrides
          * the non-traversal error.
          */
         uReturn = uDescendErr;
         goto Done;
      }
   }

   if(!QCBORItem_IsMapOrArray(pDecodedItem) ||
       QCBORItem_IsEmptyDefiniteLengthMapOrArray(pDecodedItem) ||
       QCBORItem_IsIndefiniteLengthMapOrArray(pDecodedItem)) {
      /* The following cases are handled here:
       *  - A non-aggregate item like an integer or string
       *  - An empty definite-length map or array
       *  - An indefinite-length map or array that might be empty or might not.
       *
       * QCBORDecode_NestLevelAscender() does the work of decrementing the count
       * for an definite-length map/array and break detection for an
       * indefinite-0length map/array. If the end of the map/array was
       * reached, then it ascends nesting levels, possibly all the way
       * to the top level.
       */
      QCBORError uAscendErr;
      uAscendErr = QCBORDecode_NestLevelAscender(pMe, true);
      if(uAscendErr != QCBOR_SUCCESS) {
         /* This error is probably a traversal error and it overrides
          * the non-traversal error.
          */
         uReturn = uAscendErr;
         goto Done;
      }
   }

   /* ==== Last: tell the caller the nest level of the next item ==== */
   /* Tell the caller what level is next. This tells them what
    * maps/arrays were closed out and makes it possible for them to
    * reconstruct the tree with just the information returned in a
    * QCBORItem.
   */
   if(DecodeNesting_IsAtEndOfBoundedLevel(&(pMe->nesting))) {
      /* At end of a bounded map/array; uNextNestLevel 0 to indicate this */
      pDecodedItem->uNextNestLevel = 0;
   } else {
      pDecodedItem->uNextNestLevel = DecodeNesting_GetCurrentLevel(&(pMe->nesting));
   }

Done:
   return uReturn;
}


/**
 * @brief Shift 0th tag out of the tag list.
 *
 * pDecodedItem[in,out]  The data item to convert.
 *
 * The 0th tag is discarded. \ref CBOR_TAG_INVALID16 is
 * shifted into empty slot at the end of the tag list.
 */
static inline void ShiftTags(QCBORItem *pDecodedItem)
{
   for(int i = 0; i < QCBOR_MAX_TAGS_PER_ITEM-1; i++) {
      pDecodedItem->uTags[i] = pDecodedItem->uTags[i+1];
   }
   pDecodedItem->uTags[QCBOR_MAX_TAGS_PER_ITEM-1] = CBOR_TAG_INVALID16;
}


/**
 * @brief Convert different epoch date formats in to the QCBOR epoch date format
 *
 * pDecodedItem[in,out]  The data item to convert.
 *
 * @retval QCBOR_ERR_DATE_OVERFLOW
 * @retval QCBOR_ERR_FLOAT_DATE_DISABLED
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED
 * @retval QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT
 *
 * The epoch date tag defined in QCBOR allows for floating-point
 * dates. It even allows a protocol to flop between date formats when
 * ever it wants.  Floating-point dates aren't that useful as they are
 * only needed for dates beyond the age of the earth.
 *
 * This converts all the date formats into one format of an unsigned
 * integer plus a floating-point fraction.
 */
static QCBORError DecodeDateEpoch(QCBORItem *pDecodedItem)
{
   QCBORError uReturn = QCBOR_SUCCESS;

#ifndef USEFULBUF_DISABLE_ALL_FLOAT
   pDecodedItem->val.epochDate.fSecondsFraction = 0;
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */

   switch (pDecodedItem->uDataType) {

      case QCBOR_TYPE_INT64:
         pDecodedItem->val.epochDate.nSeconds = pDecodedItem->val.int64;
         break;

      case QCBOR_TYPE_UINT64:
         /* This only happens for CBOR type 0 > INT64_MAX so it is
          * always an overflow.
          */
         uReturn = QCBOR_ERR_DATE_OVERFLOW;
         goto Done;
         break;

      case QCBOR_TYPE_DOUBLE:
      case QCBOR_TYPE_FLOAT:
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
      {
         /* Convert working value to double if input was a float */
         const double d = pDecodedItem->uDataType == QCBOR_TYPE_DOUBLE ?
                   pDecodedItem->val.dfnum :
                   (double)pDecodedItem->val.fnum;

         /* The conversion from float to integer requires overflow
          * detection since floats can be much larger than integers.
          * This implementation errors out on these large float values
          * since they are beyond the age of the earth.
          *
          * These constants for the overflow check are computed by the
          * compiler. They are not computed at run time.
          *
          * The factor of 0x7ff is added/subtracted to avoid a
          * rounding error in the wrong direction when the compiler
          * computes these constants. There is rounding because a
          * 64-bit integer has 63 bits of precision where a double
          * only has 53 bits. Without the 0x7ff factor, the compiler
          * may round up and produce a double for the bounds check
          * that is larger than can be stored in a 64-bit integer. The
          * amount of 0x7ff is picked because it has 11 bits set.
          *
          * Without the 0x7ff there is a ~30 minute range of time
          * values 10 billion years in the past and in the future
          * where this code could go wrong. Some compilers
          * generate a warning or error without the 0x7ff.
          */
         const double dDateMax = (double)(INT64_MAX - 0x7ff);
         const double dDateMin = (double)(INT64_MIN + 0x7ff);

         if(isnan(d) || d > dDateMax || d < dDateMin) {
            uReturn = QCBOR_ERR_DATE_OVERFLOW;
            goto Done;
         }

         /* The actual conversion */
         pDecodedItem->val.epochDate.nSeconds = (int64_t)d;
         pDecodedItem->val.epochDate.fSecondsFraction =
                           d - (double)pDecodedItem->val.epochDate.nSeconds;
      }
#else /* QCBOR_DISABLE_FLOAT_HW_USE */

         uReturn = QCBOR_ERR_HW_FLOAT_DISABLED;
         goto Done;

#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
         break;

      default:
         /* It's the arrays and maps that are unrecoverable because
          * they are not consumed here. Since this is just an error
          * condition, no extra code is added here to make the error
          * recoverable for non-arrays and maps like strings. */
         uReturn = QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT;
         goto Done;
   }

   pDecodedItem->uDataType = QCBOR_TYPE_DATE_EPOCH;

Done:
   return uReturn;
}


/**
 * @brief Convert the days epoch date.
 *
 * pDecodedItem[in,out]  The data item to convert.
 *
 * @retval QCBOR_ERR_DATE_OVERFLOW
 * @retval QCBOR_ERR_FLOAT_DATE_DISABLED
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED
 * @retval QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT
 *
 * This is much simpler than the other epoch date format because
 * floating-porint is not allowed. This is mostly a simple type check.
 */
static QCBORError DecodeDaysEpoch(QCBORItem *pDecodedItem)
{
   QCBORError uReturn = QCBOR_SUCCESS;

   switch (pDecodedItem->uDataType) {

      case QCBOR_TYPE_INT64:
         pDecodedItem->val.epochDays = pDecodedItem->val.int64;
         break;

      case QCBOR_TYPE_UINT64:
         /* This only happens for CBOR type 0 > INT64_MAX so it is
          * always an overflow.
          */
         uReturn = QCBOR_ERR_DATE_OVERFLOW;
         goto Done;
         break;

      default:
         /* It's the arrays and maps that are unrecoverable because
          * they are not consumed here. Since this is just an error
          * condition, no extra code is added here to make the error
          * recoverable for non-arrays and maps like strings. */
         uReturn = QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT;
         goto Done;
         break;
   }

   pDecodedItem->uDataType = QCBOR_TYPE_DAYS_EPOCH;

Done:
   return uReturn;
}


#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
/**
 * @brief Decode decimal fractions and big floats.
 *
 * @param[in] pMe               The decode context.
 * @param[in,out] pDecodedItem  On input the array data item that
 *                              holds the mantissa and exponent.  On
 *                              output the decoded mantissa and
 *                              exponent.
 *
 * @returns  Decoding errors from getting primitive data items or
 *           \ref QCBOR_ERR_BAD_EXP_AND_MANTISSA.
 *
 * When called pDecodedItem must be the array that is tagged as a big
 * float or decimal fraction, the array that has the two members, the
 * exponent and mantissa.
 *
 * This will fetch and decode the exponent and mantissa and put the
 * result back into pDecodedItem.
 */
static inline QCBORError
QCBORDecode_MantissaAndExponent(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   QCBORError uReturn;

   /* --- Make sure it is an array; track nesting level of members --- */
   if(pDecodedItem->uDataType != QCBOR_TYPE_ARRAY) {
      uReturn = QCBOR_ERR_BAD_EXP_AND_MANTISSA;
      goto Done;
   }

   /* A check for pDecodedItem->val.uCount == 2 would work for
    * definite-length arrays, but not for indefnite.  Instead remember
    * the nesting level the two integers must be at, which is one
    * deeper than that of the array.
    */
   const int nNestLevel = pDecodedItem->uNestingLevel + 1;

   /* --- Which is it, decimal fraction or a bigfloat? --- */
   const bool bIsTaggedDecimalFraction = QCBORDecode_IsTagged(pMe, pDecodedItem, CBOR_TAG_DECIMAL_FRACTION);
   pDecodedItem->uDataType = bIsTaggedDecimalFraction ? QCBOR_TYPE_DECIMAL_FRACTION : QCBOR_TYPE_BIGFLOAT;

   /* --- Get the exponent --- */
   QCBORItem exponentItem;
   uReturn = QCBORDecode_GetNextMapOrArray(pMe, &exponentItem);
   if(uReturn != QCBOR_SUCCESS) {
      goto Done;
   }
   if(exponentItem.uNestingLevel != nNestLevel) {
      /* Array is empty or a map/array encountered when expecting an int */
      uReturn = QCBOR_ERR_BAD_EXP_AND_MANTISSA;
      goto Done;
   }
   if(exponentItem.uDataType == QCBOR_TYPE_INT64) {
     /* Data arriving as an unsigned int < INT64_MAX has been
      * converted to QCBOR_TYPE_INT64 and thus handled here. This is
      * also means that the only data arriving here of type
      * QCBOR_TYPE_UINT64 data will be too large for this to handle
      * and thus an error that will get handled in the next else.
      */
     pDecodedItem->val.expAndMantissa.nExponent = exponentItem.val.int64;
   } else {
      /* Wrong type of exponent or a QCBOR_TYPE_UINT64 > INT64_MAX */
      uReturn = QCBOR_ERR_BAD_EXP_AND_MANTISSA;
      goto Done;
   }

   /* --- Get the mantissa --- */
   QCBORItem mantissaItem;
   uReturn = QCBORDecode_GetNextWithTags(pMe, &mantissaItem, NULL);
   if(uReturn != QCBOR_SUCCESS) {
      goto Done;
   }
   if(mantissaItem.uNestingLevel != nNestLevel) {
      /* Mantissa missing or map/array encountered when expecting number */
      uReturn = QCBOR_ERR_BAD_EXP_AND_MANTISSA;
      goto Done;
   }
   if(mantissaItem.uDataType == QCBOR_TYPE_INT64) {
      /* Data arriving as an unsigned int < INT64_MAX has been
       * converted to QCBOR_TYPE_INT64 and thus handled here. This is
       * also means that the only data arriving here of type
       * QCBOR_TYPE_UINT64 data will be too large for this to handle
       * and thus an error that will get handled in an else below.
       */
      pDecodedItem->val.expAndMantissa.Mantissa.nInt = mantissaItem.val.int64;
   }  else if(mantissaItem.uDataType == QCBOR_TYPE_POSBIGNUM ||
              mantissaItem.uDataType == QCBOR_TYPE_NEGBIGNUM) {
      /* Got a good big num mantissa */
      pDecodedItem->val.expAndMantissa.Mantissa.bigNum = mantissaItem.val.bigNum;
      /* Depends on numbering of QCBOR_TYPE_XXX */
      pDecodedItem->uDataType = (uint8_t)(pDecodedItem->uDataType +
                                          mantissaItem.uDataType - QCBOR_TYPE_POSBIGNUM +
                                          1);
   } else {
      /* Wrong type of mantissa or a QCBOR_TYPE_UINT64 > INT64_MAX */
      uReturn = QCBOR_ERR_BAD_EXP_AND_MANTISSA;
      goto Done;
   }

   /* --- Check that array only has the two numbers --- */
   if(mantissaItem.uNextNestLevel == nNestLevel) {
      /* Extra items in the decimal fraction / big float */
      uReturn = QCBOR_ERR_BAD_EXP_AND_MANTISSA;
      goto Done;
   }
   pDecodedItem->uNextNestLevel = mantissaItem.uNextNestLevel;

Done:
  return uReturn;
}
#endif /* QCBOR_DISABLE_EXP_AND_MANTISSA */


#ifndef QCBOR_DISABLE_UNCOMMON_TAGS
/**
 * @brief Decode the MIME type tag
 *
 * @param[in,out] pDecodedItem   The item to decode.
 *
 *  Handle the text and binary MIME type tags. Slightly too complicated
 *  f or ProcessTaggedString() because the RFC 7049 MIME type was
 *  incorreclty text-only.
 */
static inline QCBORError DecodeMIME(QCBORItem *pDecodedItem)
{
   if(pDecodedItem->uDataType == QCBOR_TYPE_TEXT_STRING) {
      pDecodedItem->uDataType = QCBOR_TYPE_MIME;
   } else if(pDecodedItem->uDataType == QCBOR_TYPE_BYTE_STRING) {
      pDecodedItem->uDataType = QCBOR_TYPE_BINARY_MIME;
   } else {
      /* It's the arrays and maps that are unrecoverable because
       * they are not consumed here. Since this is just an error
       * condition, no extra code is added here to make the error
       * recoverable for non-arrays and maps like strings. */
      return QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT;
   }

   return QCBOR_SUCCESS;
}
#endif /* QCBOR_DISABLE_UNCOMMON_TAGS */


/**
 * Table of CBOR tags whose content is either a text string or a byte
 * string. The table maps the CBOR tag to the QCBOR type. The high-bit
 * of uQCBORtype indicates the content should be a byte string rather
 * than a text string
 */
struct StringTagMapEntry {
   uint16_t uTagNumber;
   uint8_t  uQCBORtype;
};

#define IS_BYTE_STRING_BIT 0x80
#define QCBOR_TYPE_MASK   ~IS_BYTE_STRING_BIT

static const struct StringTagMapEntry StringTagMap[] = {
   {CBOR_TAG_DATE_STRING,   QCBOR_TYPE_DATE_STRING},
   {CBOR_TAG_DAYS_STRING,   QCBOR_TYPE_DAYS_STRING},
   {CBOR_TAG_POS_BIGNUM,    QCBOR_TYPE_POSBIGNUM | IS_BYTE_STRING_BIT},
   {CBOR_TAG_NEG_BIGNUM,    QCBOR_TYPE_NEGBIGNUM | IS_BYTE_STRING_BIT},
   {CBOR_TAG_CBOR,          QBCOR_TYPE_WRAPPED_CBOR | IS_BYTE_STRING_BIT},
   {CBOR_TAG_URI,           QCBOR_TYPE_URI},
#ifndef QCBOR_DISABLE_UNCOMMON_TAGS
   {CBOR_TAG_B64URL,        QCBOR_TYPE_BASE64URL},
   {CBOR_TAG_B64,           QCBOR_TYPE_BASE64},
   {CBOR_TAG_REGEX,         QCBOR_TYPE_REGEX},
   {CBOR_TAG_BIN_UUID,      QCBOR_TYPE_UUID | IS_BYTE_STRING_BIT},
#endif /* QCBOR_DISABLE_UNCOMMON_TAGS */
   {CBOR_TAG_CBOR_SEQUENCE, QBCOR_TYPE_WRAPPED_CBOR_SEQUENCE | IS_BYTE_STRING_BIT},
   {CBOR_TAG_INVALID16,     QCBOR_TYPE_NONE}
};


/**
 * @brief Process standard CBOR tags whose content is a string
 *
 * @param[in] uTag              The tag.
 * @param[in,out] pDecodedItem  The data item.
 *
 * @returns  This returns QCBOR_SUCCESS if the tag was procssed,
 *           \ref QCBOR_ERR_UNSUPPORTED if the tag was not processed and
 *           \ref QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT if the content type was wrong for the tag.
 *
 * Process the CBOR tags that whose content is a byte string or a text
 * string and for which the string is just passed on to the caller.
 *
 * This maps the CBOR tag to the QCBOR type and checks the content
 * type.  Nothing more. It may not be the most important
 * functionality, but it part of implementing as much of RFC 8949 as
 * possible.
 */
static inline QCBORError
ProcessTaggedString(uint16_t uTag, QCBORItem *pDecodedItem)
{
   /* This only works on tags that were not mapped; no need for other yet */
   if(uTag > QCBOR_LAST_UNMAPPED_TAG) {
      return QCBOR_ERR_UNSUPPORTED;
   }

   unsigned uIndex;
   for(uIndex = 0; StringTagMap[uIndex].uTagNumber != CBOR_TAG_INVALID16; uIndex++) {
      if(StringTagMap[uIndex].uTagNumber == uTag) {
         break;
      }
   }

   const uint8_t uQCBORType = StringTagMap[uIndex].uQCBORtype;
   if(uQCBORType == QCBOR_TYPE_NONE) {
      /* repurpose this error to mean not handled here */
      return QCBOR_ERR_UNSUPPORTED;
   }

   uint8_t uExpectedType = QCBOR_TYPE_TEXT_STRING;
   if(uQCBORType & IS_BYTE_STRING_BIT) {
      uExpectedType = QCBOR_TYPE_BYTE_STRING;
   }

   if(pDecodedItem->uDataType != uExpectedType) {
      /* It's the arrays and maps that are unrecoverable because
       * they are not consumed here. Since this is just an error
       * condition, no extra code is added here to make the error
       * recoverable for non-arrays and maps like strings. */
      return QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT;
   }

   pDecodedItem->uDataType = (uint8_t)(uQCBORType & QCBOR_TYPE_MASK);
   return QCBOR_SUCCESS;
}


/**
 * @brief Decode tag content for select tags (decoding layer 1).
 *
 * @param[in] pMe            The decode context.
 * @param[out] pDecodedItem  The decoded item.
 *
 * @return Decoding error code.
 *
 * CBOR tag numbers for the item were decoded in GetNext_TaggedItem(),
 * but the whole tag was not decoded. Here, the whole tags (tag number
 * and tag content) that are supported by QCBOR are decoded. This is a
 * quick pass through for items that are not tags.
 */
static QCBORError
QCBORDecode_GetNextTagContent(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   QCBORError uReturn;

   uReturn = QCBORDecode_GetNextMapOrArray(pMe, pDecodedItem);
   if(uReturn != QCBOR_SUCCESS) {
      goto Done;
   }

   /* When there are no tag numbers for the item, this exits first
    * thing and effectively does nothing.
    *
    * This loops over all the tag numbers accumulated for this item
    * trying to decode and interpret them. This stops at the end of
    * the list or at the first tag number that can't be interpreted by
    * this code. This is effectively a recursive processing of the
    * tags number list that handles nested tags.
    */
   while(1) {
      /* Don't bother to unmap tags via QCBORITem.uTags since this
       * code only works on tags less than QCBOR_LAST_UNMAPPED_TAG.
       */
      const uint16_t uTagToProcess = pDecodedItem->uTags[0];

      if(uTagToProcess == CBOR_TAG_INVALID16) {
         /* Hit the end of the tag list. A successful exit. */
         break;

      } else if(uTagToProcess == CBOR_TAG_DATE_EPOCH) {
         uReturn = DecodeDateEpoch(pDecodedItem);

      } else if(uTagToProcess == CBOR_TAG_DAYS_EPOCH) {
         uReturn = DecodeDaysEpoch(pDecodedItem);

#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
      } else if(uTagToProcess == CBOR_TAG_DECIMAL_FRACTION ||
                uTagToProcess == CBOR_TAG_BIGFLOAT) {
         uReturn = QCBORDecode_MantissaAndExponent(pMe, pDecodedItem);
#endif /* QCBOR_DISABLE_EXP_AND_MANTISSA */
#ifndef QCBOR_DISABLE_UNCOMMON_TAGS
      } else if(uTagToProcess == CBOR_TAG_MIME ||
                uTagToProcess == CBOR_TAG_BINARY_MIME) {
         uReturn = DecodeMIME(pDecodedItem);
#endif /* QCBOR_DISABLE_UNCOMMON_TAGS */

      } else {
         /* See if it is a passthrough byte/text string tag; process if so */
         uReturn = ProcessTaggedString(pDecodedItem->uTags[0], pDecodedItem);

         if(uReturn == QCBOR_ERR_UNSUPPORTED) {
            /* It wasn't a passthrough byte/text string tag so it is
             * an unknown tag. This is the exit from the loop on the
             * first unknown tag.  It is a successful exit.
             */
            uReturn = QCBOR_SUCCESS;
            break;
         }
      }

      if(uReturn != QCBOR_SUCCESS) {
         /* Error exit from the loop */
         break;
      }

      /* A tag was successfully processed, shift it out of the list of
       * tags returned. This is the loop increment.
       */
      ShiftTags(pDecodedItem);
   }

Done:
   return uReturn;
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError
QCBORDecode_GetNext(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   QCBORError uErr;
   uErr = QCBORDecode_GetNextTagContent(pMe, pDecodedItem);
   if(uErr != QCBOR_SUCCESS) {
      pDecodedItem->uDataType  = QCBOR_TYPE_NONE;
      pDecodedItem->uLabelType = QCBOR_TYPE_NONE;
   }
   return uErr;
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError
QCBORDecode_PeekNext(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   const QCBORDecodeNesting SaveNesting = pMe->nesting;
   const UsefulInputBuf Save = pMe->InBuf;

   QCBORError uErr = QCBORDecode_GetNext(pMe, pDecodedItem);

   pMe->nesting = SaveNesting;
   pMe->InBuf = Save;

   return uErr;
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_VPeekNext(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)QCBORDecode_PeekNext(pMe, pDecodedItem);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void QCBORDecode_VGetNext(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)QCBORDecode_GetNext(pMe, pDecodedItem);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError
QCBORDecode_GetNextWithTags(QCBORDecodeContext *pMe,
                            QCBORItem          *pDecodedItem,
                            QCBORTagListOut    *pTags)
{
   QCBORError uReturn;

   uReturn = QCBORDecode_GetNext(pMe, pDecodedItem);
   if(uReturn != QCBOR_SUCCESS) {
      return uReturn;
   }

   if(pTags != NULL) {
      pTags->uNumUsed = 0;
      /* Reverse the order because pTags is reverse of QCBORItem.uTags. */
      for(int nTagIndex = QCBOR_MAX_TAGS_PER_ITEM-1; nTagIndex >=0; nTagIndex--) {
         if(pDecodedItem->uTags[nTagIndex] == CBOR_TAG_INVALID16) {
            continue;
         }
         if(pTags->uNumUsed >= pTags->uNumAllocated) {
            return QCBOR_ERR_TOO_MANY_TAGS;
         }
         pTags->puTags[pTags->uNumUsed] = UnMapTagNumber(pMe,pDecodedItem->uTags[nTagIndex]);
         pTags->uNumUsed++;
      }
   }

   return QCBOR_SUCCESS;
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
bool QCBORDecode_IsTagged(QCBORDecodeContext *pMe,
                          const QCBORItem   *pItem,
                          uint64_t           uTag)
{
   for(unsigned uTagIndex = 0; uTagIndex < QCBOR_MAX_TAGS_PER_ITEM; uTagIndex++) {
      if(pItem->uTags[uTagIndex] == CBOR_TAG_INVALID16) {
         break;
      }
      if(UnMapTagNumber(pMe, pItem->uTags[uTagIndex]) == uTag) {
         return true;
      }
   }

   return false;
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError QCBORDecode_PartialFinish(QCBORDecodeContext *pMe, size_t *puConsumed)
{
   if(puConsumed != NULL) {
      *puConsumed = pMe->InBuf.cursor;
   }

   QCBORError uReturn = pMe->uLastError;

   if(uReturn != QCBOR_SUCCESS) {
      goto Done;
   }

   /* Error out if all the maps/arrays are not closed out */
   if(!DecodeNesting_IsCurrentAtTop(&(pMe->nesting))) {
      uReturn = QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED;
      goto Done;
   }

   /* Error out if not all the bytes are consumed */
   if(UsefulInputBuf_BytesUnconsumed(&(pMe->InBuf))) {
      uReturn = QCBOR_ERR_EXTRA_BYTES;
   }

Done:
   return uReturn;
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError QCBORDecode_Finish(QCBORDecodeContext *pMe)
{
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
   /* Call the destructor for the string allocator if there is one.
    * Always called, even if there are errors; always have to clean up.
    */
   StringAllocator_Destruct(&(pMe->StringAllocator));
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */

   return QCBORDecode_PartialFinish(pMe, NULL);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
// Improvement: make these inline?
uint64_t QCBORDecode_GetNthTag(QCBORDecodeContext *pMe,
                               const QCBORItem    *pItem,
                               uint32_t            uIndex)
{
   if(pItem->uDataType == QCBOR_TYPE_NONE) {
      return CBOR_TAG_INVALID64;
   }
   if(uIndex >= QCBOR_MAX_TAGS_PER_ITEM) {
      return CBOR_TAG_INVALID64;
   } else {
      return UnMapTagNumber(pMe, pItem->uTags[uIndex]);
   }
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
uint64_t QCBORDecode_GetNthTagOfLast(const QCBORDecodeContext *pMe,
                                     uint32_t                  uIndex)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return CBOR_TAG_INVALID64;
   }
   if(uIndex >= QCBOR_MAX_TAGS_PER_ITEM) {
      return CBOR_TAG_INVALID64;
   } else {
      return UnMapTagNumber(pMe, pMe->uLastTags[uIndex]);
   }
}




#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS

/* ===========================================================================
   MemPool -- BUILT-IN SIMPLE STRING ALLOCATOR

   This implements a simple sting allocator for indefinite-length
   strings that can be enabled by calling QCBORDecode_SetMemPool(). It
   implements the function type QCBORStringAllocate and allows easy
   use of it.

   This particular allocator is built-in for convenience. The caller
   can implement their own.  All of this following code will get
   dead-stripped if QCBORDecode_SetMemPool() is not called.

   This is a very primitive memory allocator. It does not track
   individual allocations, only a high-water mark. A free or
   reallocation must be of the last chunk allocated.

   The size of the pool and offset to free memory are packed into the
   first 8 bytes of the memory pool so we don't have to keep them in
   the decode context. Since the address of the pool may not be
   aligned, they have to be packed and unpacked as if they were
   serialized data of the wire or such.

   The sizes packed in are uint32_t to be the same on all CPU types
   and simplify the code.
   ========================================================================== */


static inline int
MemPool_Unpack(const void *pMem, uint32_t *puPoolSize, uint32_t *puFreeOffset)
{
   // Use of UsefulInputBuf is overkill, but it is convenient.
   UsefulInputBuf UIB;

   // Just assume the size here. It was checked during SetUp so
   // the assumption is safe.
   UsefulInputBuf_Init(&UIB, (UsefulBufC){pMem,QCBOR_DECODE_MIN_MEM_POOL_SIZE});
   *puPoolSize     = UsefulInputBuf_GetUint32(&UIB);
   *puFreeOffset   = UsefulInputBuf_GetUint32(&UIB);
   return UsefulInputBuf_GetError(&UIB);
}


static inline int
MemPool_Pack(UsefulBuf Pool, uint32_t uFreeOffset)
{
   // Use of UsefulOutBuf is overkill, but convenient. The
   // length check performed here is useful.
   UsefulOutBuf UOB;

   UsefulOutBuf_Init(&UOB, Pool);
   UsefulOutBuf_AppendUint32(&UOB, (uint32_t)Pool.len); // size of pool
   UsefulOutBuf_AppendUint32(&UOB, uFreeOffset); // first free position
   return UsefulOutBuf_GetError(&UOB);
}


/*
 Internal function for an allocation, reallocation free and destuct.

 Having only one function rather than one each per mode saves space in
 QCBORDecodeContext.

 Code Reviewers: THIS FUNCTION DOES POINTER MATH
 */
static UsefulBuf
MemPool_Function(void *pPool, void *pMem, size_t uNewSize)
{
   UsefulBuf ReturnValue = NULLUsefulBuf;

   uint32_t uPoolSize;
   uint32_t uFreeOffset;

   if(uNewSize > UINT32_MAX) {
      // This allocator is only good up to 4GB.  This check should
      // optimize out if sizeof(size_t) == sizeof(uint32_t)
      goto Done;
   }
   const uint32_t uNewSize32 = (uint32_t)uNewSize;

   if(MemPool_Unpack(pPool, &uPoolSize, &uFreeOffset)) {
      goto Done;
   }

   if(uNewSize) {
      if(pMem) {
         // REALLOCATION MODE
         // Calculate pointer to the end of the memory pool.  It is
         // assumed that pPool + uPoolSize won't wrap around by
         // assuming the caller won't pass a pool buffer in that is
         // not in legitimate memory space.
         const void *pPoolEnd = (uint8_t *)pPool + uPoolSize;

         // Check that the pointer for reallocation is in the range of the
         // pool. This also makes sure that pointer math further down
         // doesn't wrap under or over.
         if(pMem >= pPool && pMem < pPoolEnd) {
            // Offset to start of chunk for reallocation. This won't
            // wrap under because of check that pMem >= pPool.  Cast
            // is safe because the pool is always less than UINT32_MAX
            // because of check in QCBORDecode_SetMemPool().
            const uint32_t uMemOffset = (uint32_t)((uint8_t *)pMem - (uint8_t *)pPool);

            // Check to see if the allocation will fit. uPoolSize -
            // uMemOffset will not wrap under because of check that
            // pMem is in the range of the uPoolSize by check above.
            if(uNewSize <= uPoolSize - uMemOffset) {
               ReturnValue.ptr = pMem;
               ReturnValue.len = uNewSize;

               // Addition won't wrap around over because uNewSize was
               // checked to be sure it is less than the pool size.
               uFreeOffset = uMemOffset + uNewSize32;
            }
         }
      } else {
         // ALLOCATION MODE
         // uPoolSize - uFreeOffset will not underflow because this
         // pool implementation makes sure uFreeOffset is always
         // smaller than uPoolSize through this check here and
         // reallocation case.
         if(uNewSize <= uPoolSize - uFreeOffset) {
            ReturnValue.len = uNewSize;
            ReturnValue.ptr = (uint8_t *)pPool + uFreeOffset;
            uFreeOffset    += (uint32_t)uNewSize;
         }
      }
   } else {
      if(pMem) {
         // FREE MODE
         // Cast is safe because of limit on pool size in
         // QCBORDecode_SetMemPool()
         uFreeOffset = (uint32_t)((uint8_t *)pMem - (uint8_t *)pPool);
      } else {
         // DESTRUCT MODE
         // Nothing to do for this allocator
      }
   }

   UsefulBuf Pool = {pPool, uPoolSize};
   MemPool_Pack(Pool, uFreeOffset);

Done:
   return ReturnValue;
}


/*
 Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError QCBORDecode_SetMemPool(QCBORDecodeContext *pMe,
                                  UsefulBuf Pool,
                                  bool bAllStrings)
{
   // The pool size and free mem offset are packed into the beginning
   // of the pool memory. This compile time check makes sure the
   // constant in the header is correct.  This check should optimize
   // down to nothing.
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4127) // conditional expression is constant
#endif
   if(QCBOR_DECODE_MIN_MEM_POOL_SIZE < 2 * sizeof(uint32_t)) {
      return QCBOR_ERR_MEM_POOL_SIZE;
   }
#ifdef _MSC_VER
#pragma warning(pop)
#endif

   // The pool size and free offset packed in to the beginning of pool
   // memory are only 32-bits. This check will optimize out on 32-bit
   // machines.
   if(Pool.len > UINT32_MAX) {
      return QCBOR_ERR_MEM_POOL_SIZE;
   }

   // This checks that the pool buffer given is big enough.
   if(MemPool_Pack(Pool, QCBOR_DECODE_MIN_MEM_POOL_SIZE)) {
      return QCBOR_ERR_MEM_POOL_SIZE;
   }

   QCBORDecode_SetUpAllocator(pMe, MemPool_Function, Pool.ptr, bAllStrings);

   return QCBOR_SUCCESS;
}
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */



static inline void CopyTags(QCBORDecodeContext *pMe, const QCBORItem *pItem)
{
   memcpy(pMe->uLastTags, pItem->uTags, sizeof(pItem->uTags));
}


/**
 * @brief Consume an entire map or array including its contents.
 *
 * @param[in]  pMe              The decoder context.
 * @param[in]  pItemToConsume   The array/map whose contents are to be
 *                              consumed.
 * @param[out] puNextNestLevel  The next nesting level after the item was
 *                              fully consumed.
 *
 * This may be called when @c pItemToConsume is not an array or
 * map. In that case, this is just a pass through for @c puNextNestLevel
 * since there is nothing to do.
 */
static inline QCBORError
ConsumeItem(QCBORDecodeContext *pMe,
            const QCBORItem    *pItemToConsume,
            uint8_t            *puNextNestLevel)
{
   QCBORError uReturn;
   QCBORItem  Item;

   /* If it is a map or array, this will tell if it is empty. */
   const bool bIsEmpty = (pItemToConsume->uNextNestLevel <= pItemToConsume->uNestingLevel);

   if(QCBORItem_IsMapOrArray(pItemToConsume) && !bIsEmpty) {
      /* There is only real work to do for non-empty maps and arrays */

      /* This works for definite- and indefinite-length maps and
       * arrays by using the nesting level
       */
      do {
         uReturn = QCBORDecode_GetNext(pMe, &Item);
         if(QCBORDecode_IsUnrecoverableError(uReturn) ||
            uReturn == QCBOR_ERR_NO_MORE_ITEMS) {
            goto Done;
         }
      } while(Item.uNextNestLevel >= pItemToConsume->uNextNestLevel);

      *puNextNestLevel = Item.uNextNestLevel;

      uReturn = QCBOR_SUCCESS;

   } else {
      /* pItemToConsume is not a map or array.  Just pass the nesting
       * level through. */
      *puNextNestLevel = pItemToConsume->uNextNestLevel;

      uReturn = QCBOR_SUCCESS;
   }

Done:
    return uReturn;
}


void QCBORDecode_VGetNextConsume(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   QCBORDecode_VGetNext(pMe, pDecodedItem);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      pMe->uLastError = (uint8_t)ConsumeItem(pMe, pDecodedItem,
         &pDecodedItem->uNextNestLevel);
   }
}



/* Call only on maps and arrays. Rewinds the cursor
 * to the start as if it was just entered.
 */
static void RewindMapOrArray(QCBORDecodeContext *pMe)
{
   /* Reset nesting tracking to the deepest bounded level */
   DecodeNesting_SetCurrentToBoundedLevel(&(pMe->nesting));

   DecodeNesting_ResetMapOrArrayCount(&(pMe->nesting));

   /* Reposition traversal cursor to the start of the map/array */
   UsefulInputBuf_Seek(&(pMe->InBuf),
                       DecodeNesting_GetMapOrArrayStart(&(pMe->nesting)));
}


/*
 Public function, see header qcbor/qcbor_decode.h file
 */
void QCBORDecode_Rewind(QCBORDecodeContext *pMe)
{
   if(pMe->nesting.pCurrentBounded != NULL) {
      /* In a bounded map, array or bstr-wrapped CBOR */

      if(DecodeNesting_IsBoundedType(&(pMe->nesting), QCBOR_TYPE_BYTE_STRING)) {
         /* In bstr-wrapped CBOR. */

         /* Reposition traversal cursor to start of wrapping byte string */
         UsefulInputBuf_Seek(&(pMe->InBuf),
                             pMe->nesting.pCurrentBounded->u.bs.uBstrStartOffset);
         DecodeNesting_SetCurrentToBoundedLevel(&(pMe->nesting));

      } else {
         /* In a map or array */
         RewindMapOrArray(pMe);
      }

   } else {
      /* Not in anything bounded */

      /* Reposition traversal cursor to the start of input CBOR */
      UsefulInputBuf_Seek(&(pMe->InBuf), 0ULL);

      /* Reset nesting tracking to beginning of input. */
      DecodeNesting_Init(&(pMe->nesting));
   }

   pMe->uLastError = QCBOR_SUCCESS;
}


/* Return true if the labels in Item1 and Item2 are the same.
   Works only for integer and string labels. Returns false
   for any other type. */
static inline bool
MatchLabel(QCBORItem Item1, QCBORItem Item2)
{
   if(Item1.uLabelType == QCBOR_TYPE_INT64) {
      if(Item2.uLabelType == QCBOR_TYPE_INT64 && Item1.label.int64 == Item2.label.int64) {
         return true;
      }
   } else if(Item1.uLabelType == QCBOR_TYPE_TEXT_STRING) {
      if(Item2.uLabelType == QCBOR_TYPE_TEXT_STRING && !UsefulBuf_Compare(Item1.label.string, Item2.label.string)) {
         return true;
      }
   } else if(Item1.uLabelType == QCBOR_TYPE_BYTE_STRING) {
      if(Item2.uLabelType == QCBOR_TYPE_BYTE_STRING && !UsefulBuf_Compare(Item1.label.string, Item2.label.string)) {
         return true;
      }
   } else if(Item1.uLabelType == QCBOR_TYPE_UINT64) {
      if(Item2.uLabelType == QCBOR_TYPE_UINT64 && Item1.label.uint64 == Item2.label.uint64) {
         return true;
      }
   }

   /* Other label types are never matched */
   return false;
}


/*
 Returns true if Item1 and Item2 are the same type
 or if either are of QCBOR_TYPE_ANY.
 */
static inline bool
MatchType(QCBORItem Item1, QCBORItem Item2)
{
   if(Item1.uDataType == Item2.uDataType) {
      return true;
   } else if(Item1.uDataType == QCBOR_TYPE_ANY) {
      return true;
   } else if(Item2.uDataType == QCBOR_TYPE_ANY) {
      return true;
   }
   return false;
}


/**
 @brief Search a map for a set of items.

 @param[in]  pMe           The decode context to search.
 @param[in,out] pItemArray The items to search for and the items found.
 @param[out] puOffset      Byte offset of last item matched.
 @param[in] pCBContext     Context for the not-found item call back.
 @param[in] pfCallback     Function to call on items not matched in pItemArray.

 @retval QCBOR_ERR_NOT_ENTERED Trying to search without having entered a map

 @retval QCBOR_ERR_DUPLICATE_LABEL Duplicate items (items with the same label)
                                   were found for one of the labels being
                                   search for. This duplicate detection is
                                   only performed for items in pItemArray,
                                   not every item in the map.

 @retval QCBOR_ERR_UNEXPECTED_TYPE A label was matched, but the type was
                                   wrong for the matchd label.

 @retval Also errors returned by QCBORDecode_GetNext().

 On input pItemArray contains a list of labels and data types
 of items to be found.

 On output the fully retrieved items are filled in with
 values and such. The label was matched, so it never changes.

 If an item was not found, its data type is set to QCBOR_TYPE_NONE.

 This also finds the ends of maps and arrays when they are exited.
 */
static QCBORError
MapSearch(QCBORDecodeContext *pMe,
          QCBORItem          *pItemArray,
          size_t             *puOffset,
          void               *pCBContext,
          QCBORItemCallback   pfCallback)
{
   QCBORError uReturn;
   uint64_t   uFoundItemBitMap = 0;

   if(pMe->uLastError != QCBOR_SUCCESS) {
      uReturn = pMe->uLastError;
      goto Done2;
   }

   if(!DecodeNesting_IsBoundedType(&(pMe->nesting), QCBOR_TYPE_MAP) &&
      pItemArray->uLabelType != QCBOR_TYPE_NONE) {
      /* QCBOR_TYPE_NONE as first item indicates just looking
         for the end of an array, so don't give error. */
      uReturn = QCBOR_ERR_MAP_NOT_ENTERED;
      goto Done2;
   }

   if(DecodeNesting_IsBoundedEmpty(&(pMe->nesting))) {
      // It is an empty bounded array or map
      if(pItemArray->uLabelType == QCBOR_TYPE_NONE) {
         // Just trying to find the end of the map or array
         pMe->uMapEndOffsetCache = DecodeNesting_GetMapOrArrayStart(&(pMe->nesting));
         uReturn = QCBOR_SUCCESS;
      } else {
         // Nothing is ever found in an empty array or map. All items
         // are marked as not found below.
         uReturn = QCBOR_SUCCESS;
      }
      goto Done2;
   }

   QCBORDecodeNesting SaveNesting;
   DecodeNesting_PrepareForMapSearch(&(pMe->nesting), &SaveNesting);

   /* Reposition to search from the start of the map / array */
   RewindMapOrArray(pMe);

   /*
    Loop over all the items in the map or array. Each item
    could be a map or array, but label matching is only at
    the main level. This handles definite- and indefinite-
    length maps and arrays. The only reason this is ever
    called on arrays is to find their end position.

    This will always run over all items in order to do
    duplicate detection.

    This will exit with failure if it encounters an
    unrecoverable error, but continue on for recoverable
    errors.

    If a recoverable error occurs on a matched item, then
    that error code is returned.
    */
   const uint8_t uMapNestLevel = DecodeNesting_GetBoundedModeLevel(&(pMe->nesting));
   uint8_t       uNextNestLevel;
   do {
      /* Remember offset of the item because sometimes it has to be returned */
      const size_t uOffset = UsefulInputBuf_Tell(&(pMe->InBuf));

      /* Get the item */
      QCBORItem Item;
      QCBORError uResult = QCBORDecode_GetNextTagContent(pMe, &Item);
      if(QCBORDecode_IsUnrecoverableError(uResult)) {
         /* Unrecoverable error so map can't even be decoded. */
         uReturn = uResult;
         goto Done;
      }
      if(uResult == QCBOR_ERR_NO_MORE_ITEMS) {
         // Unexpected end of map or array.
         uReturn = uResult;
         goto Done;
      }

      /* See if item has one of the labels that are of interest */
      bool bMatched = false;
      for(int nIndex = 0; pItemArray[nIndex].uLabelType != QCBOR_TYPE_NONE; nIndex++) {
         if(MatchLabel(Item, pItemArray[nIndex])) {
            /* A label match has been found */
            if(uFoundItemBitMap & (0x01ULL << nIndex)) {
               uReturn = QCBOR_ERR_DUPLICATE_LABEL;
               goto Done;
            }
            if(uResult != QCBOR_SUCCESS) {
               /* The label matches, but the data item is in error */
               uReturn = uResult;
               goto Done;
            }
            if(!MatchType(Item, pItemArray[nIndex])) {
               /* The data item is not of the type(s) requested */
               uReturn = QCBOR_ERR_UNEXPECTED_TYPE;
               goto Done;
            }

            /* Successful match. Return the item. */
            pItemArray[nIndex] = Item;
            uFoundItemBitMap |= 0x01ULL << nIndex;
            if(puOffset) {
               *puOffset = uOffset;
            }
            bMatched = true;
         }
      }


      if(!bMatched && pfCallback != NULL) {
         /*
          Call the callback on unmatched labels.
          (It is tempting to do duplicate detection here, but that would
          require dynamic memory allocation because the number of labels
          that might be encountered is unbounded.)
         */
         uReturn = (*pfCallback)(pCBContext, &Item);
         if(uReturn != QCBOR_SUCCESS) {
            goto Done;
         }
      }

      /*
       Consume the item whether matched or not. This
       does the work of traversing maps and array and
       everything in them. In this loop only the
       items at the current nesting level are examined
       to match the labels.
       */
      uReturn = ConsumeItem(pMe, &Item, &uNextNestLevel);
      if(uReturn != QCBOR_SUCCESS) {
         goto Done;
      }

   } while (uNextNestLevel >= uMapNestLevel);

   uReturn = QCBOR_SUCCESS;

   const size_t uEndOffset = UsefulInputBuf_Tell(&(pMe->InBuf));

   // Check here makes sure that this won't accidentally be
   // QCBOR_MAP_OFFSET_CACHE_INVALID which is larger than
   // QCBOR_MAX_DECODE_INPUT_SIZE.
   // Cast to uint32_t to possibly address cases where SIZE_MAX < UINT32_MAX
   if((uint32_t)uEndOffset >= QCBOR_MAX_DECODE_INPUT_SIZE) {
      uReturn = QCBOR_ERR_INPUT_TOO_LARGE;
      goto Done;
   }
   /* Cast OK because encoded CBOR is limited to UINT32_MAX */
   pMe->uMapEndOffsetCache = (uint32_t)uEndOffset;

 Done:
   DecodeNesting_RestoreFromMapSearch(&(pMe->nesting), &SaveNesting);

 Done2:
   /* For all items not found, set the data and label type to QCBOR_TYPE_NONE */
   for(int i = 0; pItemArray[i].uLabelType != 0; i++) {
      if(!(uFoundItemBitMap & (0x01ULL << i))) {
         pItemArray[i].uDataType  = QCBOR_TYPE_NONE;
         pItemArray[i].uLabelType = QCBOR_TYPE_NONE;
      }
   }

   return uReturn;
}


/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetItemInMapN(QCBORDecodeContext *pMe,
                               int64_t             nLabel,
                               uint8_t             uQcborType,
                               QCBORItem          *pItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSeach[0].label.int64 = nLabel;
   OneItemSeach[0].uDataType   = uQcborType;
   OneItemSeach[1].uLabelType  = QCBOR_TYPE_NONE; // Indicates end of array

   QCBORError uReturn = MapSearch(pMe, OneItemSeach, NULL, NULL, NULL);

   *pItem = OneItemSeach[0];

   if(uReturn != QCBOR_SUCCESS) {
      goto Done;
   }
   if(OneItemSeach[0].uDataType == QCBOR_TYPE_NONE) {
      uReturn = QCBOR_ERR_LABEL_NOT_FOUND;
   }

 Done:
   pMe->uLastError = (uint8_t)uReturn;
}


/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetItemInMapSZ(QCBORDecodeContext *pMe,
                                const char         *szLabel,
                                uint8_t             uQcborType,
                                QCBORItem          *pItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSeach[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSeach[0].uDataType    = uQcborType;
   OneItemSeach[1].uLabelType   = QCBOR_TYPE_NONE; // Indicates end of array

   QCBORError uReturn = MapSearch(pMe, OneItemSeach, NULL, NULL, NULL);
   if(uReturn != QCBOR_SUCCESS) {
      goto Done;
   }
   if(OneItemSeach[0].uDataType == QCBOR_TYPE_NONE) {
      uReturn = QCBOR_ERR_LABEL_NOT_FOUND;
      goto Done;
   }

   *pItem = OneItemSeach[0];

Done:
   pMe->uLastError = (uint8_t)uReturn;
}



static QCBORError
CheckTypeList(int uDataType, const uint8_t puTypeList[QCBOR_TAGSPEC_NUM_TYPES])
{
   for(size_t i = 0; i < QCBOR_TAGSPEC_NUM_TYPES; i++) {
      if(uDataType == puTypeList[i]) {
         return QCBOR_SUCCESS;
      }
   }
   return QCBOR_ERR_UNEXPECTED_TYPE;
}


/**
 @param[in] TagSpec  Specification for matching tags.
 @param[in] pItem    The item to check.

 @retval QCBOR_SUCCESS   \c uDataType is allowed by @c TagSpec
 @retval QCBOR_ERR_UNEXPECTED_TYPE \c uDataType is not allowed by @c TagSpec

 The data type must be one of the QCBOR_TYPEs, not the IETF CBOR Registered
 tag value.
 */
static QCBORError
CheckTagRequirement(const TagSpecification TagSpec, const QCBORItem *pItem)
{
   if(!(TagSpec.uTagRequirement & QCBOR_TAG_REQUIREMENT_ALLOW_ADDITIONAL_TAGS) &&
      pItem->uTags[0] != CBOR_TAG_INVALID16) {
      /* There are tags that QCBOR couldn't process on this item and
       the caller has told us there should not be. */
      return QCBOR_ERR_UNEXPECTED_TYPE;
   }

   const int nTagReq = TagSpec.uTagRequirement & ~QCBOR_TAG_REQUIREMENT_ALLOW_ADDITIONAL_TAGS;
   const int nItemType = pItem->uDataType;

   if(nTagReq == QCBOR_TAG_REQUIREMENT_TAG) {
      // Must match the tag and only the tag
      return CheckTypeList(nItemType, TagSpec.uTaggedTypes);
   }

   QCBORError uReturn = CheckTypeList(nItemType, TagSpec.uAllowedContentTypes);
   if(uReturn == QCBOR_SUCCESS) {
      return QCBOR_SUCCESS;
   }

   if(nTagReq == QCBOR_TAG_REQUIREMENT_NOT_A_TAG) {
      /* Must match the content type and only the content type.
       There was no match just above so it is a fail. */
      return QCBOR_ERR_UNEXPECTED_TYPE;
   }

   /* If here it can match either the tag or the content
    and it hasn't matched the content, so the end
    result is whether it matches the tag. This is
    also the case that the CBOR standard discourages. */

   return CheckTypeList(nItemType, TagSpec.uTaggedTypes);
}



// This could be semi-private if need be
static inline
void QCBORDecode_GetTaggedItemInMapN(QCBORDecodeContext *pMe,
                                     int64_t             nLabel,
                                     TagSpecification    TagSpec,
                                     QCBORItem          *pItem)
{
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)CheckTagRequirement(TagSpec, pItem);
}


// This could be semi-private if need be
static inline
void QCBORDecode_GetTaggedItemInMapSZ(QCBORDecodeContext *pMe,
                                     const char          *szLabel,
                                     TagSpecification    TagSpec,
                                     QCBORItem          *pItem)
{
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)CheckTagRequirement(TagSpec, pItem);
}

// Semi-private
void QCBORDecode_GetTaggedStringInMapN(QCBORDecodeContext *pMe,
                                       int64_t             nLabel,
                                       TagSpecification    TagSpec,
                                       UsefulBufC          *pString)
{
   QCBORItem Item;
   QCBORDecode_GetTaggedItemInMapN(pMe, nLabel, TagSpec, &Item);
   if(pMe->uLastError == QCBOR_SUCCESS) {
      *pString = Item.val.string;
   }
}

// Semi-private
void QCBORDecode_GetTaggedStringInMapSZ(QCBORDecodeContext *pMe,
                                        const char *        szLabel,
                                        TagSpecification    TagSpec,
                                        UsefulBufC          *pString)
{
   QCBORItem Item;
   QCBORDecode_GetTaggedItemInMapSZ(pMe, szLabel, TagSpec, &Item);
   if(pMe->uLastError == QCBOR_SUCCESS) {
      *pString = Item.val.string;
   }
}

/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetItemsInMap(QCBORDecodeContext *pMe, QCBORItem *pItemList)
{
   QCBORError uErr = MapSearch(pMe, pItemList, NULL, NULL, NULL);
   pMe->uLastError = (uint8_t)uErr;
}

/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetItemsInMapWithCallback(QCBORDecodeContext *pMe,
                                           QCBORItem          *pItemList,
                                           void               *pCallbackCtx,
                                           QCBORItemCallback   pfCB)
{
   QCBORError uErr = MapSearch(pMe, pItemList, NULL, pCallbackCtx, pfCB);
   pMe->uLastError = (uint8_t)uErr;
}


/**
 * @brief Search for a map/array by label and enter it
 *
 * @param[in] pMe  The decode context.
 * @param[in] pSearch The map/array to search for.
 *
 * @c pSearch is expected to contain one item of type map or array
 * with the label specified. The current bounded map will be searched for
 * this and if found  will be entered.
 *
 * If the label is not found, or the item found is not a map or array,
 * the error state is set.
 */
static void SearchAndEnter(QCBORDecodeContext *pMe, QCBORItem pSearch[])
{
   // The first item in pSearch is the one that is to be
   // entered. It should be the only one filled in. Any other
   // will be ignored unless it causes an error.
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   size_t uOffset;
   pMe->uLastError = (uint8_t)MapSearch(pMe, pSearch, &uOffset, NULL, NULL);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   if(pSearch->uDataType == QCBOR_TYPE_NONE) {
      pMe->uLastError = QCBOR_ERR_LABEL_NOT_FOUND;
      return;
   }


   /* The map or array was found. Now enter it.
    *
    * QCBORDecode_EnterBoundedMapOrArray() used here, requires the
    * next item for the pre-order traversal cursor to be the map/array
    * found by MapSearch(). The next few lines of code force the
    * cursor to that.
    *
    * There is no need to retain the old cursor because
    * QCBORDecode_EnterBoundedMapOrArray() will set it to the
    * beginning of the map/array being entered.
    *
    * The cursor is forced by: 1) setting the input buffer position to
    * the item offset found by MapSearch(), 2) setting the map/array
    * counter to the total in the map/array, 3) setting the nesting
    * level. Setting the map/array counter to the total is not
    * strictly correct, but this is OK because this cursor only needs
    * to be used to get one item and MapSearch() has already found it
    * confirming it exists.
    */
   UsefulInputBuf_Seek(&(pMe->InBuf), uOffset);

   DecodeNesting_ResetMapOrArrayCount(&(pMe->nesting));

   DecodeNesting_SetCurrentToBoundedLevel(&(pMe->nesting));

   QCBORDecode_EnterBoundedMapOrArray(pMe, pSearch->uDataType, NULL);
}


/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_EnterMapFromMapN(QCBORDecodeContext *pMe, int64_t nLabel)
{
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSeach[0].label.int64 = nLabel;
   OneItemSeach[0].uDataType   = QCBOR_TYPE_MAP;
   OneItemSeach[1].uLabelType  = QCBOR_TYPE_NONE;

   /* The map to enter was found, now finish off entering it. */
   SearchAndEnter(pMe, OneItemSeach);
}


/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_EnterMapFromMapSZ(QCBORDecodeContext *pMe, const char  *szLabel)
{
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSeach[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSeach[0].uDataType    = QCBOR_TYPE_MAP;
   OneItemSeach[1].uLabelType   = QCBOR_TYPE_NONE;

   SearchAndEnter(pMe, OneItemSeach);
}

/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_EnterArrayFromMapN(QCBORDecodeContext *pMe, int64_t nLabel)
{
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSeach[0].label.int64 = nLabel;
   OneItemSeach[0].uDataType   = QCBOR_TYPE_ARRAY;
   OneItemSeach[1].uLabelType  = QCBOR_TYPE_NONE;

   SearchAndEnter(pMe, OneItemSeach);
}

/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_EnterArrayFromMapSZ(QCBORDecodeContext *pMe, const char  *szLabel)
{
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSeach[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSeach[0].uDataType    = QCBOR_TYPE_ARRAY;
   OneItemSeach[1].uLabelType   = QCBOR_TYPE_NONE;

   SearchAndEnter(pMe, OneItemSeach);
}


// Semi-private function
void QCBORDecode_EnterBoundedMapOrArray(QCBORDecodeContext *pMe, uint8_t uType, QCBORItem *pItem)
{
    QCBORError uErr;

   /* Must only be called on maps and arrays. */
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state; do nothing.
      return;
   }

   /* Get the data item that is the map or array being entered. */
   QCBORItem Item;
   uErr = QCBORDecode_GetNext(pMe, &Item);
   if(uErr != QCBOR_SUCCESS) {
      goto Done;
   }
   if(Item.uDataType != uType) {
      uErr = QCBOR_ERR_UNEXPECTED_TYPE;
      goto Done;
   }

   CopyTags(pMe, &Item);


   const bool bIsEmpty = (Item.uNextNestLevel <= Item.uNestingLevel);
   if(bIsEmpty) {
      if(DecodeNesting_IsCurrentDefiniteLength(&(pMe->nesting))) {
         // Undo decrement done by QCBORDecode_GetNext() so the the
         // the decrement when exiting the map/array works correctly
         pMe->nesting.pCurrent->u.ma.uCountCursor++;
      }
      // Special case to increment nesting level for zero-length maps
      // and arrays entered in bounded mode.
      DecodeNesting_Descend(&(pMe->nesting), uType);
   }

   pMe->uMapEndOffsetCache = QCBOR_MAP_OFFSET_CACHE_INVALID;

   uErr = DecodeNesting_EnterBoundedMapOrArray(&(pMe->nesting), bIsEmpty,
                                               UsefulInputBuf_Tell(&(pMe->InBuf)));

   if(pItem != NULL) {
      *pItem = Item;
   }

Done:
   pMe->uLastError = (uint8_t)uErr;
}


/*
 This is the common work for exiting a level that is a bounded map,
 array or bstr wrapped CBOR.

 One chunk of work is to set up the pre-order traversal so it is at
 the item just after the bounded map, array or bstr that is being
 exited. This is somewhat complex.

 The other work is to level-up the bounded mode to next higest bounded
 mode or the top level if there isn't one.
 */
static QCBORError
ExitBoundedLevel(QCBORDecodeContext *pMe, uint32_t uEndOffset)
{
   QCBORError uErr;

   /*
    First the pre-order-traversal byte offset is positioned to the
    item just after the bounded mode item that was just consumed.
    */
   UsefulInputBuf_Seek(&(pMe->InBuf), uEndOffset);

   /*
    Next, set the current nesting level to one above the bounded level
    that was just exited.

    DecodeNesting_CheckBoundedType() is always called before this and
    makes sure pCurrentBounded is valid.
    */
   DecodeNesting_LevelUpCurrent(&(pMe->nesting));

   /*
    This does the complex work of leveling up the pre-order traversal
    when the end of a map or array or another bounded level is
    reached.  It may do nothing, or ascend all the way to the top
    level.
    */
   uErr = QCBORDecode_NestLevelAscender(pMe, false);
   if(uErr != QCBOR_SUCCESS) {
      goto Done;
   }

   /*
    This makes the next highest bounded level the current bounded
    level. If there is no next highest level, then no bounded mode is
    in effect.
    */
   DecodeNesting_LevelUpBounded(&(pMe->nesting));

   pMe->uMapEndOffsetCache = QCBOR_MAP_OFFSET_CACHE_INVALID;

Done:
   return uErr;
}


// Semi-private function
void QCBORDecode_ExitBoundedMapOrArray(QCBORDecodeContext *pMe, uint8_t uType)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      /* Already in error state; do nothing. */
      return;
   }

   QCBORError uErr;

   if(!DecodeNesting_IsBoundedType(&(pMe->nesting), uType)) {
      uErr = QCBOR_ERR_EXIT_MISMATCH;
      goto Done;
   }

   /*
    Have to set the offset to the end of the map/array
    that is being exited. If there is no cached value,
    from previous map search, then do a dummy search.
    */
   if(pMe->uMapEndOffsetCache == QCBOR_MAP_OFFSET_CACHE_INVALID) {
      QCBORItem Dummy;
      Dummy.uLabelType = QCBOR_TYPE_NONE;
      uErr = MapSearch(pMe, &Dummy, NULL, NULL, NULL);
      if(uErr != QCBOR_SUCCESS) {
         goto Done;
      }
   }

   uErr = ExitBoundedLevel(pMe, pMe->uMapEndOffsetCache);

Done:
   pMe->uLastError = (uint8_t)uErr;
}



static QCBORError InternalEnterBstrWrapped(QCBORDecodeContext *pMe,
                                           const QCBORItem    *pItem,
                                           uint8_t             uTagRequirement,
                                           UsefulBufC         *pBstr)
{
   if(pBstr) {
      *pBstr = NULLUsefulBufC;
   }

   if(pMe->uLastError != QCBOR_SUCCESS) {
      /* Already in error state; do nothing. */
      return pMe->uLastError;
   }

   QCBORError uError;

   const TagSpecification TagSpec =
      {
         uTagRequirement,
         {QBCOR_TYPE_WRAPPED_CBOR, QBCOR_TYPE_WRAPPED_CBOR_SEQUENCE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   uError = CheckTagRequirement(TagSpec, pItem);
   if(uError != QCBOR_SUCCESS) {
      goto Done;
   }

   if(DecodeNesting_IsCurrentDefiniteLength(&(pMe->nesting))) {
      /* Reverse the decrement done by GetNext() for the bstr so the
       * increment in QCBORDecode_NestLevelAscender() called by
       * ExitBoundedLevel() will work right.
       */
      DecodeNesting_ReverseDecrement(&(pMe->nesting));
   }

   if(pBstr) {
      *pBstr = pItem->val.string;
   }

   /* This saves the current length of the UsefulInputBuf and then
    * narrows the UsefulInputBuf to start and length of the wrapped
    * CBOR that is being entered.
    *
    * Most of these calls are simple inline accessors so this doesn't
    * amount to much code.
    */

   const size_t uPreviousLength = UsefulInputBuf_GetBufferLength(&(pMe->InBuf));
   /* This check makes the cast of uPreviousLength to uint32_t below safe. */
   if(uPreviousLength >= QCBOR_MAX_DECODE_INPUT_SIZE) {
      uError = QCBOR_ERR_INPUT_TOO_LARGE;
      goto Done;
   }

   const size_t uStartOfBstr = UsefulInputBuf_PointerToOffset(&(pMe->InBuf),
                                                              pItem->val.string.ptr);
   /* This check makes the cast of uStartOfBstr to uint32_t below safe. */
   if(uStartOfBstr == SIZE_MAX || uStartOfBstr > QCBOR_MAX_DECODE_INPUT_SIZE) {
      /* This should never happen because pItem->val.string.ptr should
       * always be valid since it was just returned.
       */
      uError = QCBOR_ERR_INPUT_TOO_LARGE;
      goto Done;
   }

   const size_t uEndOfBstr = uStartOfBstr + pItem->val.string.len;

   UsefulInputBuf_Seek(&(pMe->InBuf), uStartOfBstr);
   UsefulInputBuf_SetBufferLength(&(pMe->InBuf), uEndOfBstr);

   uError = DecodeNesting_DescendIntoBstrWrapped(&(pMe->nesting),
                                                 (uint32_t)uPreviousLength,
                                                 (uint32_t)uStartOfBstr);
Done:
   return uError;
}


/*
  Public function, see header qcbor/qcbor_decode.h file
 */
void QCBORDecode_EnterBstrWrapped(QCBORDecodeContext *pMe,
                                  uint8_t             uTagRequirement,
                                  UsefulBufC         *pBstr)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state; do nothing.
      return;
   }

   /* Get the data item that is the byte string being entered */
   QCBORItem Item;
   pMe->uLastError = (uint8_t)QCBORDecode_GetNext(pMe, &Item);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)InternalEnterBstrWrapped(pMe,
                                                       &Item,
                                                       uTagRequirement,
                                                       pBstr);
}


/*
  Public function, see header qcbor/qcbor_decode.h file
 */
void QCBORDecode_EnterBstrWrappedFromMapN(QCBORDecodeContext *pMe,
                                          int64_t             nLabel,
                                          uint8_t             uTagRequirement,
                                          UsefulBufC         *pBstr)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);

   pMe->uLastError = (uint8_t)InternalEnterBstrWrapped(pMe,
                                                       &Item,
                                                       uTagRequirement,
                                                       pBstr);
}


/*
  Public function, see header qcbor/qcbor_decode.h file
 */
void QCBORDecode_EnterBstrWrappedFromMapSZ(QCBORDecodeContext *pMe,
                                           const char         *szLabel,
                                           uint8_t             uTagRequirement,
                                           UsefulBufC         *pBstr)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);

   pMe->uLastError = (uint8_t)InternalEnterBstrWrapped(pMe,
                                                       &Item,
                                                       uTagRequirement,
                                                       pBstr);
}


/*
  Public function, see header qcbor/qcbor_decode.h file
 */
void QCBORDecode_ExitBstrWrapped(QCBORDecodeContext *pMe)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state; do nothing.
      return;
   }

   if(!DecodeNesting_IsBoundedType(&(pMe->nesting), QCBOR_TYPE_BYTE_STRING)) {
      pMe->uLastError = QCBOR_ERR_EXIT_MISMATCH;
      return;
   }

   const uint32_t uEndOfBstr = (uint32_t)UsefulInputBuf_GetBufferLength(&(pMe->InBuf));

   /*
    Reset the length of the UsefulInputBuf to what it was before
    the bstr wrapped CBOR was entered.
    */
   UsefulInputBuf_SetBufferLength(&(pMe->InBuf),
                               DecodeNesting_GetPreviousBoundedEnd(&(pMe->nesting)));


   QCBORError uErr = ExitBoundedLevel(pMe, uEndOfBstr);
   pMe->uLastError = (uint8_t)uErr;
}




static inline void
ProcessBool(QCBORDecodeContext *pMe, const QCBORItem *pItem, bool *pBool)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      /* Already in error state, do nothing */
      return;
   }

   switch(pItem->uDataType) {
      case QCBOR_TYPE_TRUE:
         *pBool = true;
         break;

      case QCBOR_TYPE_FALSE:
         *pBool = false;
         break;

      default:
         pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
         break;
   }
   CopyTags(pMe, pItem);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void QCBORDecode_GetBool(QCBORDecodeContext *pMe, bool *pValue)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      /* Already in error state, do nothing */
      return;
   }

   QCBORItem  Item;

   pMe->uLastError = (uint8_t)QCBORDecode_GetNext(pMe, &Item);

   ProcessBool(pMe, &Item, pValue);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void QCBORDecode_GetBoolInMapN(QCBORDecodeContext *pMe, int64_t nLabel, bool *pValue)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);

   ProcessBool(pMe, &Item, pValue);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void QCBORDecode_GetBoolInMapSZ(QCBORDecodeContext *pMe, const char *szLabel, bool *pValue)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);

   ProcessBool(pMe, &Item, pValue);
}




static void ProcessEpochDate(QCBORDecodeContext *pMe,
                             QCBORItem           *pItem,
                             uint8_t              uTagRequirement,
                             int64_t             *pnTime)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state, do nothing
      return;
   }

   QCBORError uErr;

   const TagSpecification TagSpec =
   {
      uTagRequirement,
      {QCBOR_TYPE_DATE_EPOCH, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
      {QCBOR_TYPE_INT64, QCBOR_TYPE_DOUBLE, QCBOR_TYPE_FLOAT, QCBOR_TYPE_UINT64}
   };

   uErr = CheckTagRequirement(TagSpec, pItem);
   if(uErr != QCBOR_SUCCESS) {
      goto Done;
   }

   if(pItem->uDataType != QCBOR_TYPE_DATE_EPOCH) {
      uErr = DecodeDateEpoch(pItem);
      if(uErr != QCBOR_SUCCESS) {
         goto Done;
      }
   }

   // Save the tags in the last item's tags in the decode context
   // for QCBORDecode_GetNthTagOfLast()
   CopyTags(pMe, pItem);

   *pnTime = pItem->val.epochDate.nSeconds;

Done:
   pMe->uLastError = (uint8_t)uErr;
}


void QCBORDecode_GetEpochDate(QCBORDecodeContext *pMe,
                              uint8_t             uTagRequirement,
                              int64_t            *pnTime)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state, do nothing
      return;
   }

   QCBORItem  Item;
   pMe->uLastError = (uint8_t)QCBORDecode_GetNext(pMe, &Item);

   ProcessEpochDate(pMe, &Item, uTagRequirement, pnTime);
}


void
QCBORDecode_GetEpochDateInMapN(QCBORDecodeContext *pMe,
                               int64_t             nLabel,
                               uint8_t             uTagRequirement,
                               int64_t            *pnTime)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);
   ProcessEpochDate(pMe, &Item, uTagRequirement, pnTime);
}


void
QCBORDecode_GetEpochDateInMapSZ(QCBORDecodeContext *pMe,
                                const char         *szLabel,
                                uint8_t             uTagRequirement,
                                int64_t            *pnTime)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);
   ProcessEpochDate(pMe, &Item, uTagRequirement, pnTime);
}



/*
 * Common processing for the RFC 8943 day-count tag. Mostly
 * make sure the tag content is correct and copy forward any
 * further other tag numbers.
 */
static void ProcessEpochDays(QCBORDecodeContext *pMe,
                             QCBORItem          *pItem,
                             uint8_t             uTagRequirement,
                             int64_t            *pnDays)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      /* Already in error state, do nothing */
      return;
   }

   QCBORError uErr;

   const TagSpecification TagSpec =
   {
      uTagRequirement,
      {QCBOR_TYPE_DAYS_EPOCH, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
      {QCBOR_TYPE_INT64, QCBOR_TYPE_UINT64, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
   };

   uErr = CheckTagRequirement(TagSpec, pItem);
   if(uErr != QCBOR_SUCCESS) {
      goto Done;
   }

   if(pItem->uDataType != QCBOR_TYPE_DAYS_EPOCH) {
      uErr = DecodeDaysEpoch(pItem);
      if(uErr != QCBOR_SUCCESS) {
         goto Done;
      }
   }

   /* Save the tags in the last item's tags in the decode context
    * for QCBORDecode_GetNthTagOfLast()
    */
   CopyTags(pMe, pItem);

   *pnDays = pItem->val.epochDays;

Done:
   pMe->uLastError = (uint8_t)uErr;
}


/*
 * Public function, see header qcbor/qcbor_decode.h
 */
void QCBORDecode_GetEpochDays(QCBORDecodeContext *pMe,
                              uint8_t             uTagRequirement,
                              int64_t            *pnDays)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      /* Already in error state, do nothing */
      return;
   }

   QCBORItem  Item;
   pMe->uLastError = (uint8_t)QCBORDecode_GetNext(pMe, &Item);

   ProcessEpochDays(pMe, &Item, uTagRequirement, pnDays);
}


/*
 * Public function, see header qcbor/qcbor_decode.h
 */
void
QCBORDecode_GetEpochDaysInMapN(QCBORDecodeContext *pMe,
                               int64_t             nLabel,
                               uint8_t             uTagRequirement,
                               int64_t            *pnDays)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);
   ProcessEpochDays(pMe, &Item, uTagRequirement, pnDays);
}


/*
 * Public function, see header qcbor/qcbor_decode.h
 */
void
QCBORDecode_GetEpochDaysInMapSZ(QCBORDecodeContext *pMe,
                                const char         *szLabel,
                                uint8_t             uTagRequirement,
                                int64_t            *pnDays)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);
   ProcessEpochDays(pMe, &Item, uTagRequirement, pnDays);
}




void QCBORDecode_GetTaggedStringInternal(QCBORDecodeContext *pMe,
                                         TagSpecification    TagSpec,
                                         UsefulBufC         *pBstr)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state, do nothing
      return;
   }

   QCBORError uError;
   QCBORItem  Item;

   uError = QCBORDecode_GetNext(pMe, &Item);
   if(uError != QCBOR_SUCCESS) {
      pMe->uLastError = (uint8_t)uError;
      return;
   }

   pMe->uLastError = (uint8_t)CheckTagRequirement(TagSpec, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      *pBstr = Item.val.string;
   } else {
      *pBstr = NULLUsefulBufC;
   }
}




static QCBORError ProcessBigNum(uint8_t          uTagRequirement,
                                const QCBORItem *pItem,
                                UsefulBufC      *pValue,
                                bool            *pbIsNegative)
{
   const TagSpecification TagSpec =
   {
      uTagRequirement,
      {QCBOR_TYPE_POSBIGNUM, QCBOR_TYPE_NEGBIGNUM, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
      {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
   };

   QCBORError uErr = CheckTagRequirement(TagSpec, pItem);
   if(uErr != QCBOR_SUCCESS) {
      return uErr;
   }

   *pValue = pItem->val.string;

   if(pItem->uDataType == QCBOR_TYPE_POSBIGNUM) {
      *pbIsNegative = false;
   } else if(pItem->uDataType == QCBOR_TYPE_NEGBIGNUM) {
      *pbIsNegative = true;
   }

   return QCBOR_SUCCESS;
}


/*
 Public function, see header qcbor/qcbor_decode.h
 */
void QCBORDecode_GetBignum(QCBORDecodeContext *pMe,
                           uint8_t             uTagRequirement,
                           UsefulBufC         *pValue,
                           bool               *pbIsNegative)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state, do nothing
      return;
   }

   QCBORItem  Item;
   QCBORError uError = QCBORDecode_GetNext(pMe, &Item);
   if(uError != QCBOR_SUCCESS) {
      pMe->uLastError = (uint8_t)uError;
      return;
   }

   pMe->uLastError = (uint8_t)ProcessBigNum(uTagRequirement, &Item, pValue, pbIsNegative);
}


/*
 Public function, see header qcbor/qcbor_decode.h
*/
void QCBORDecode_GetBignumInMapN(QCBORDecodeContext *pMe,
                                 int64_t             nLabel,
                                 uint8_t             uTagRequirement,
                                 UsefulBufC         *pValue,
                                 bool               *pbIsNegative)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)ProcessBigNum(uTagRequirement, &Item, pValue, pbIsNegative);
}


/*
 Public function, see header qcbor/qcbor_decode.h
*/
void QCBORDecode_GetBignumInMapSZ(QCBORDecodeContext *pMe,
                                  const char         *szLabel,
                                  uint8_t             uTagRequirement,
                                  UsefulBufC         *pValue,
                                  bool               *pbIsNegative)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)ProcessBigNum(uTagRequirement, &Item, pValue, pbIsNegative);
}




// Semi private
QCBORError QCBORDecode_GetMIMEInternal(uint8_t     uTagRequirement,
                                       const       QCBORItem *pItem,
                                       UsefulBufC *pMessage,
                                       bool       *pbIsTag257)
{
   const TagSpecification TagSpecText =
      {
         uTagRequirement,
         {QCBOR_TYPE_MIME, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };
   const TagSpecification TagSpecBinary =
      {
         uTagRequirement,
         {QCBOR_TYPE_BINARY_MIME, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORError uReturn;

   if(CheckTagRequirement(TagSpecText, pItem) == QCBOR_SUCCESS) {
      *pMessage = pItem->val.string;
      if(pbIsTag257 != NULL) {
         *pbIsTag257 = false;
      }
      uReturn = QCBOR_SUCCESS;
   } else if(CheckTagRequirement(TagSpecBinary, pItem) == QCBOR_SUCCESS) {
      *pMessage = pItem->val.string;
      if(pbIsTag257 != NULL) {
         *pbIsTag257 = true;
      }
      uReturn = QCBOR_SUCCESS;

   } else {
      uReturn = QCBOR_ERR_UNEXPECTED_TYPE;
   }

   return uReturn;
}

// Improvement: add methods for wrapped CBOR, a simple alternate
// to EnterBstrWrapped




#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA

typedef QCBORError (*fExponentiator)(uint64_t uMantissa, int64_t nExponent, uint64_t *puResult);


// The exponentiator that works on only positive numbers
static QCBORError
Exponentitate10(uint64_t uMantissa, int64_t nExponent, uint64_t *puResult)
{
   uint64_t uResult = uMantissa;

   if(uResult != 0) {
      /* This loop will run a maximum of 19 times because
       * UINT64_MAX < 10 ^^ 19. More than that will cause
       * exit with the overflow error
       */
      for(; nExponent > 0; nExponent--) {
         if(uResult > UINT64_MAX / 10) {
            return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW; // Error overflow
         }
         uResult = uResult * 10;
      }

      for(; nExponent < 0; nExponent++) {
         uResult = uResult / 10;
         if(uResult == 0) {
            return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW; // Underflow error
         }
      }
   }
   /* else, mantissa is zero so this returns zero */

   *puResult = uResult;

   return QCBOR_SUCCESS;
}


// The exponentiator that works on only positive numbers
static QCBORError
Exponentitate2(uint64_t uMantissa, int64_t nExponent, uint64_t *puResult)
{
   uint64_t uResult;

   uResult = uMantissa;

   /* This loop will run a maximum of 64 times because
    * INT64_MAX < 2^31. More than that will cause
    * exit with the overflow error
    */
   while(nExponent > 0) {
      if(uResult > UINT64_MAX >> 1) {
         return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW; // Error overflow
      }
      uResult = uResult << 1;
      nExponent--;
   }

   while(nExponent < 0 ) {
      if(uResult == 0) {
         return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW; // Underflow error
      }
      uResult = uResult >> 1;
      nExponent++;
   }

   *puResult = uResult;

   return QCBOR_SUCCESS;
}


/*
 Compute value with signed mantissa and signed result. Works with
 exponent of 2 or 10 based on exponentiator.
 */
static inline QCBORError ExponentiateNN(int64_t       nMantissa,
                                        int64_t       nExponent,
                                        int64_t       *pnResult,
                                        fExponentiator pfExp)
{
   uint64_t uResult;

   // Take the absolute value of the mantissa and convert to unsigned.
   // Improvement: this should be possible in one instruction
   uint64_t uMantissa = nMantissa > 0 ? (uint64_t)nMantissa : (uint64_t)-nMantissa;

   // Do the exponentiation of the positive mantissa
   QCBORError uReturn = (*pfExp)(uMantissa, nExponent, &uResult);
   if(uReturn) {
      return uReturn;
   }


   /* (uint64_t)INT64_MAX+1 is used to represent the absolute value
    of INT64_MIN. This assumes two's compliment representation where
    INT64_MIN is one increment farther from 0 than INT64_MAX.
    Trying to write -INT64_MIN doesn't work to get this because the
    compiler tries to work with an int64_t which can't represent
    -INT64_MIN.
    */
   uint64_t uMax = nMantissa > 0 ? INT64_MAX : (uint64_t)INT64_MAX+1;

   // Error out if too large
   if(uResult > uMax) {
      return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
   }

   // Casts are safe because of checks above
   *pnResult = nMantissa > 0 ? (int64_t)uResult : -(int64_t)uResult;

   return QCBOR_SUCCESS;
}


/*
 Compute value with signed mantissa and unsigned result. Works with
 exponent of 2 or 10 based on exponentiator.
 */
static inline QCBORError ExponentitateNU(int64_t       nMantissa,
                                         int64_t       nExponent,
                                         uint64_t      *puResult,
                                         fExponentiator pfExp)
{
   if(nMantissa < 0) {
      return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
   }

   // Cast to unsigned is OK because of check for negative
   // Cast to unsigned is OK because UINT64_MAX > INT64_MAX
   // Exponentiation is straight forward
   return (*pfExp)((uint64_t)nMantissa, nExponent, puResult);
}


/*
 Compute value with signed mantissa and unsigned result. Works with
 exponent of 2 or 10 based on exponentiator.
 */
static inline QCBORError ExponentitateUU(uint64_t       uMantissa,
                                         int64_t        nExponent,
                                         uint64_t      *puResult,
                                         fExponentiator pfExp)
{
   return (*pfExp)(uMantissa, nExponent, puResult);
}

#endif /* QCBOR_DISABLE_EXP_AND_MANTISSA */





static QCBORError ConvertBigNumToUnsigned(const UsefulBufC BigNum, uint64_t uMax, uint64_t *pResult)
{
   uint64_t uResult;

   uResult = 0;
   const uint8_t *pByte = BigNum.ptr;
   size_t uLen = BigNum.len;
   while(uLen--) {
      if(uResult > (uMax >> 8)) {
         return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
      }
      uResult = (uResult << 8) + *pByte++;
   }

   *pResult = uResult;
   return QCBOR_SUCCESS;
}


static inline QCBORError ConvertPositiveBigNumToUnsigned(const UsefulBufC BigNum, uint64_t *pResult)
{
   return ConvertBigNumToUnsigned(BigNum, UINT64_MAX, pResult);
}


static inline QCBORError ConvertPositiveBigNumToSigned(const UsefulBufC BigNum, int64_t *pResult)
{
   uint64_t uResult;
   QCBORError uError =  ConvertBigNumToUnsigned(BigNum, INT64_MAX, &uResult);
   if(uError) {
      return uError;
   }
   /* Cast is safe because ConvertBigNum is told to limit to INT64_MAX */
   *pResult = (int64_t)uResult;
   return QCBOR_SUCCESS;
}


static inline QCBORError ConvertNegativeBigNumToSigned(const UsefulBufC BigNum, int64_t *pnResult)
{
   uint64_t uResult;
   /* The negative integer furthest from zero for a C int64_t is
    INT64_MIN which is expressed as -INT64_MAX - 1. The value of a
    negative number in CBOR is computed as -n - 1 where n is the
    encoded integer, where n is what is in the variable BigNum. When
    converting BigNum to a uint64_t, the maximum value is thus
    INT64_MAX, so that when it -n - 1 is applied to it the result will
    never be further from 0 than INT64_MIN.

       -n - 1 <= INT64_MIN.
       -n - 1 <= -INT64_MAX - 1
        n     <= INT64_MAX.
    */
   QCBORError uError = ConvertBigNumToUnsigned(BigNum, INT64_MAX, &uResult);
   if(uError != QCBOR_SUCCESS) {
      return uError;
   }

   /// Now apply -n - 1. The cast is safe because
   // ConvertBigNumToUnsigned() is limited to INT64_MAX which does fit
   // is the largest positive integer that an int64_t can
   // represent. */
   *pnResult =  -(int64_t)uResult - 1;

   return QCBOR_SUCCESS;
}





/*
Convert integers and floats to an int64_t.

\param[in] uConvertTypes  Bit mask list of conversion options.

\retval QCBOR_ERR_UNEXPECTED_TYPE  Conversion, possible, but not requested
                                   in uConvertTypes.

\retval QCBOR_ERR_UNEXPECTED_TYPE  Of a type that can't be converted

\retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW  Conversion result is too large
                                              or too small.
*/
static QCBORError
ConvertInt64(const QCBORItem *pItem, uint32_t uConvertTypes, int64_t *pnValue)
{
   switch(pItem->uDataType) {
      case QCBOR_TYPE_FLOAT:
      case QCBOR_TYPE_DOUBLE:
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
         if(uConvertTypes & QCBOR_CONVERT_TYPE_FLOAT) {
            /* https://pubs.opengroup.org/onlinepubs/009695399/functions/llround.html
             http://www.cplusplus.com/reference/cmath/llround/
             */
            // Not interested in FE_INEXACT
            feclearexcept(FE_INVALID|FE_OVERFLOW|FE_UNDERFLOW|FE_DIVBYZERO);
            if(pItem->uDataType == QCBOR_TYPE_DOUBLE) {
               *pnValue = llround(pItem->val.dfnum);
            } else {
               *pnValue = lroundf(pItem->val.fnum);
            }
            if(fetestexcept(FE_INVALID|FE_OVERFLOW|FE_UNDERFLOW|FE_DIVBYZERO)) {
               // llround() shouldn't result in divide by zero, but catch
               // it here in case it unexpectedly does.  Don't try to
               // distinguish between the various exceptions because it seems
               // they vary by CPU, compiler and OS.
               return QCBOR_ERR_FLOAT_EXCEPTION;
            }
         } else {
            return  QCBOR_ERR_UNEXPECTED_TYPE;
         }
#else
         return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
         break;

      case QCBOR_TYPE_INT64:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_XINT64) {
            *pnValue = pItem->val.int64;
         } else {
            return  QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_UINT64:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_XINT64) {
            if(pItem->val.uint64 < INT64_MAX) {
               *pnValue = pItem->val.int64;
            } else {
               return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
            }
         } else {
            return  QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      default:
         return  QCBOR_ERR_UNEXPECTED_TYPE;
   }
   return QCBOR_SUCCESS;
}


void QCBORDecode_GetInt64ConvertInternal(QCBORDecodeContext *pMe,
                                         uint32_t            uConvertTypes,
                                         int64_t            *pnValue,
                                         QCBORItem          *pItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;
   QCBORError uError = QCBORDecode_GetNext(pMe, &Item);
   if(uError) {
      pMe->uLastError = (uint8_t)uError;
      return;
   }

   if(pItem) {
      *pItem = Item;
   }

   pMe->uLastError = (uint8_t)ConvertInt64(&Item, uConvertTypes, pnValue);
}


void QCBORDecode_GetInt64ConvertInternalInMapN(QCBORDecodeContext *pMe,
                                               int64_t             nLabel,
                                               uint32_t            uConvertTypes,
                                               int64_t            *pnValue,
                                               QCBORItem          *pItem)
{
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)ConvertInt64(pItem, uConvertTypes, pnValue);
}


void QCBORDecode_GetInt64ConvertInternalInMapSZ(QCBORDecodeContext *pMe,
                                               const char *         szLabel,
                                               uint32_t             uConvertTypes,
                                               int64_t             *pnValue,
                                               QCBORItem           *pItem)
{
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)ConvertInt64(pItem, uConvertTypes, pnValue);
}


/*
 Convert a large variety of integer types to an int64_t.

 \param[in] uConvertTypes  Bit mask list of conversion options.

 \retval QCBOR_ERR_UNEXPECTED_TYPE  Conversion, possible, but not requested
                                    in uConvertTypes.

 \retval QCBOR_ERR_UNEXPECTED_TYPE  Of a type that can't be converted

 \retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW  Conversion result is too large
                                               or too small.
 */
static QCBORError
Int64ConvertAll(const QCBORItem *pItem, uint32_t uConvertTypes, int64_t *pnValue)
{
   switch(pItem->uDataType) {

      case QCBOR_TYPE_POSBIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIG_NUM) {
            return ConvertPositiveBigNumToSigned(pItem->val.bigNum, pnValue);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_NEGBIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIG_NUM) {
            return ConvertNegativeBigNumToSigned(pItem->val.bigNum, pnValue);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
      case QCBOR_TYPE_DECIMAL_FRACTION:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            return ExponentiateNN(pItem->val.expAndMantissa.Mantissa.nInt,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                 &Exponentitate10);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIGFLOAT) {
            return ExponentiateNN(pItem->val.expAndMantissa.Mantissa.nInt,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                  Exponentitate2);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            int64_t    nMantissa;
            QCBORError uErr;
            uErr = ConvertPositiveBigNumToSigned(pItem->val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(uErr) {
               return uErr;
            }
            return ExponentiateNN(nMantissa,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                  Exponentitate10);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            int64_t    nMantissa;
            QCBORError uErr;
            uErr = ConvertNegativeBigNumToSigned(pItem->val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(uErr) {
               return uErr;
            }
            return ExponentiateNN(nMantissa,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                  Exponentitate10);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_POS_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            int64_t    nMantissa;
            QCBORError uErr;
            uErr = ConvertPositiveBigNumToSigned(pItem->val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(uErr) {
               return uErr;
            }
            return ExponentiateNN(nMantissa,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                  Exponentitate2);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            int64_t    nMantissa;
            QCBORError uErr;
            uErr = ConvertNegativeBigNumToSigned(pItem->val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(uErr) {
               return uErr;
            }
            return ExponentiateNN(nMantissa,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                  Exponentitate2);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;
#endif /* QCBOR_DISABLE_EXP_AND_MANTISSA */


      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;   }
}


/*
 Public function, see header qcbor/qcbor_decode.h file
 */
void QCBORDecode_GetInt64ConvertAll(QCBORDecodeContext *pMe, uint32_t uConvertTypes, int64_t *pnValue)
{
   QCBORItem Item;

   QCBORDecode_GetInt64ConvertInternal(pMe, uConvertTypes, pnValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)Int64ConvertAll(&Item, uConvertTypes, pnValue);
}


/*
Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetInt64ConvertAllInMapN(QCBORDecodeContext *pMe,
                                          int64_t             nLabel,
                                          uint32_t            uConvertTypes,
                                          int64_t            *pnValue)
{
   QCBORItem Item;

   QCBORDecode_GetInt64ConvertInternalInMapN(pMe,
                                             nLabel,
                                             uConvertTypes,
                                             pnValue,
                                             &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)Int64ConvertAll(&Item, uConvertTypes, pnValue);
}


/*
Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetInt64ConvertAllInMapSZ(QCBORDecodeContext *pMe,
                                           const char         *szLabel,
                                           uint32_t            uConvertTypes,
                                           int64_t            *pnValue)
{
   QCBORItem Item;
   QCBORDecode_GetInt64ConvertInternalInMapSZ(pMe,
                                              szLabel,
                                              uConvertTypes,
                                              pnValue,
                                              &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)Int64ConvertAll(&Item, uConvertTypes, pnValue);
}


static QCBORError ConvertUInt64(const QCBORItem *pItem, uint32_t uConvertTypes, uint64_t *puValue)
{
   switch(pItem->uDataType) {
      case QCBOR_TYPE_DOUBLE:
      case QCBOR_TYPE_FLOAT:
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
         if(uConvertTypes & QCBOR_CONVERT_TYPE_FLOAT) {
            // Can't use llround here because it will not convert values
            // greater than INT64_MAX and less than UINT64_MAX that
            // need to be converted so it is more complicated.
            feclearexcept(FE_INVALID|FE_OVERFLOW|FE_UNDERFLOW|FE_DIVBYZERO);
            if(pItem->uDataType == QCBOR_TYPE_DOUBLE) {
               if(isnan(pItem->val.dfnum)) {
                  return QCBOR_ERR_FLOAT_EXCEPTION;
               } else if(pItem->val.dfnum < 0) {
                  return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
               } else {
                  double dRounded = round(pItem->val.dfnum);
                  // See discussion in DecodeDateEpoch() for
                  // explanation of - 0x7ff
                  if(dRounded > (double)(UINT64_MAX- 0x7ff)) {
                     return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
                  }
                  *puValue = (uint64_t)dRounded;
               }
            } else {
               if(isnan(pItem->val.fnum)) {
                  return QCBOR_ERR_FLOAT_EXCEPTION;
               } else if(pItem->val.fnum < 0) {
                  return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
               } else {
                  float fRounded = roundf(pItem->val.fnum);
                  // See discussion in DecodeDateEpoch() for
                  // explanation of - 0x7ff
                  if(fRounded > (float)(UINT64_MAX- 0x7ff)) {
                     return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
                  }
                  *puValue = (uint64_t)fRounded;
               }
            }
            if(fetestexcept(FE_INVALID|FE_OVERFLOW|FE_UNDERFLOW|FE_DIVBYZERO)) {
               // round() and roundf() shouldn't result in exceptions here, but
               // catch them to be robust and thorough. Don't try to
               // distinguish between the various exceptions because it seems
               // they vary by CPU, compiler and OS.
               return QCBOR_ERR_FLOAT_EXCEPTION;
            }

         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
#else
         return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
         break;

      case QCBOR_TYPE_INT64:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_XINT64) {
            if(pItem->val.int64 >= 0) {
               *puValue = (uint64_t)pItem->val.int64;
            } else {
               return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
            }
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_UINT64:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_XINT64) {
            *puValue =  pItem->val.uint64;
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;
   }

   return QCBOR_SUCCESS;
}


void QCBORDecode_GetUInt64ConvertInternal(QCBORDecodeContext *pMe,
                                          uint32_t uConvertTypes,
                                          uint64_t *puValue,
                                          QCBORItem *pItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;

   QCBORError uError = QCBORDecode_GetNext(pMe, &Item);
   if(uError) {
      pMe->uLastError = (uint8_t)uError;
      return;
   }

   if(pItem) {
      *pItem = Item;
   }

   pMe->uLastError = (uint8_t)ConvertUInt64(&Item, uConvertTypes, puValue);
}


void QCBORDecode_GetUInt64ConvertInternalInMapN(QCBORDecodeContext *pMe,
                                               int64_t             nLabel,
                                               uint32_t            uConvertTypes,
                                               uint64_t            *puValue,
                                               QCBORItem          *pItem)
{
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)ConvertUInt64(pItem, uConvertTypes, puValue);
}


void QCBORDecode_GetUInt64ConvertInternalInMapSZ(QCBORDecodeContext *pMe,
                                               const char *         szLabel,
                                               uint32_t             uConvertTypes,
                                               uint64_t             *puValue,
                                               QCBORItem           *pItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)ConvertUInt64(pItem, uConvertTypes, puValue);
}



static QCBORError
UInt64ConvertAll(const QCBORItem *pItem, uint32_t uConvertTypes, uint64_t *puValue)
{
   switch(pItem->uDataType) {

      case QCBOR_TYPE_POSBIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIG_NUM) {
            return ConvertPositiveBigNumToUnsigned(pItem->val.bigNum, puValue);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_NEGBIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIG_NUM) {
            return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA

      case QCBOR_TYPE_DECIMAL_FRACTION:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            return ExponentitateNU(pItem->val.expAndMantissa.Mantissa.nInt,
                                   pItem->val.expAndMantissa.nExponent,
                                   puValue,
                                   Exponentitate10);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIGFLOAT) {
            return ExponentitateNU(pItem->val.expAndMantissa.Mantissa.nInt,
                                   pItem->val.expAndMantissa.nExponent,
                                   puValue,
                                   Exponentitate2);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            uint64_t   uMantissa;
            QCBORError uErr;
            uErr = ConvertPositiveBigNumToUnsigned(pItem->val.expAndMantissa.Mantissa.bigNum, &uMantissa);
            if(uErr != QCBOR_SUCCESS) {
               return uErr;
            }
            return ExponentitateUU(uMantissa,
                                   pItem->val.expAndMantissa.nExponent,
                                   puValue,
                                   Exponentitate10);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_POS_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            uint64_t   uMantissa;
            QCBORError uErr;
            uErr =  ConvertPositiveBigNumToUnsigned(pItem->val.expAndMantissa.Mantissa.bigNum, &uMantissa);
            if(uErr != QCBOR_SUCCESS) {
               return uErr;
            }
            return ExponentitateUU(uMantissa,
                                   pItem->val.expAndMantissa.nExponent,
                                   puValue,
                                   Exponentitate2);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;
#endif /* QCBOR_DISABLE_EXP_AND_MANTISSA */
      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;
   }
}


/*
  Public function, see header qcbor/qcbor_decode.h file
 */
void QCBORDecode_GetUInt64ConvertAll(QCBORDecodeContext *pMe, uint32_t uConvertTypes, uint64_t *puValue)
{
   QCBORItem Item;

   QCBORDecode_GetUInt64ConvertInternal(pMe, uConvertTypes, puValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)UInt64ConvertAll(&Item, uConvertTypes, puValue);
}


/*
  Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetUInt64ConvertAllInMapN(QCBORDecodeContext *pMe,
                                           int64_t             nLabel,
                                           uint32_t            uConvertTypes,
                                           uint64_t           *puValue)
{
   QCBORItem Item;

   QCBORDecode_GetUInt64ConvertInternalInMapN(pMe,
                                              nLabel,
                                              uConvertTypes,
                                              puValue,
                                              &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)UInt64ConvertAll(&Item, uConvertTypes, puValue);
}


/*
  Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetUInt64ConvertAllInMapSZ(QCBORDecodeContext *pMe,
                                            const char         *szLabel,
                                            uint32_t            uConvertTypes,
                                            uint64_t           *puValue)
{
   QCBORItem Item;
   QCBORDecode_GetUInt64ConvertInternalInMapSZ(pMe,
                                               szLabel,
                                               uConvertTypes,
                                               puValue,
                                               &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)UInt64ConvertAll(&Item, uConvertTypes, puValue);
}




#ifndef USEFULBUF_DISABLE_ALL_FLOAT
static QCBORError ConvertDouble(const QCBORItem *pItem,
                                uint32_t         uConvertTypes,
                                double          *pdValue)
{
   switch(pItem->uDataType) {
      case QCBOR_TYPE_FLOAT:
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
         if(uConvertTypes & QCBOR_CONVERT_TYPE_FLOAT) {
            if(uConvertTypes & QCBOR_CONVERT_TYPE_FLOAT) {
               // Simple cast does the job.
               *pdValue = (double)pItem->val.fnum;
            } else {
               return QCBOR_ERR_UNEXPECTED_TYPE;
            }
         }
#else /* QCBOR_DISABLE_FLOAT_HW_USE */
         return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
         break;

      case QCBOR_TYPE_DOUBLE:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_FLOAT) {
            if(uConvertTypes & QCBOR_CONVERT_TYPE_FLOAT) {
               *pdValue = pItem->val.dfnum;
            } else {
               return QCBOR_ERR_UNEXPECTED_TYPE;
            }
         }
         break;

      case QCBOR_TYPE_INT64:
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
         if(uConvertTypes & QCBOR_CONVERT_TYPE_XINT64) {
            // A simple cast seems to do the job with no worry of exceptions.
            // There will be precision loss for some values.
            *pdValue = (double)pItem->val.int64;

         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
#else
         return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
         break;

      case QCBOR_TYPE_UINT64:
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
         if(uConvertTypes & QCBOR_CONVERT_TYPE_XINT64) {
            // A simple cast seems to do the job with no worry of exceptions.
            // There will be precision loss for some values.
            *pdValue = (double)pItem->val.uint64;
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;
#else
         return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */

      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;
   }

   return QCBOR_SUCCESS;
}


void QCBORDecode_GetDoubleConvertInternal(QCBORDecodeContext *pMe,
                                          uint32_t            uConvertTypes,
                                          double             *pdValue,
                                          QCBORItem          *pItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;

   QCBORError uError = QCBORDecode_GetNext(pMe, &Item);
   if(uError) {
      pMe->uLastError = (uint8_t)uError;
      return;
   }

   if(pItem) {
      *pItem = Item;
   }

   pMe->uLastError = (uint8_t)ConvertDouble(&Item, uConvertTypes, pdValue);
}


void QCBORDecode_GetDoubleConvertInternalInMapN(QCBORDecodeContext *pMe,
                                               int64_t             nLabel,
                                               uint32_t            uConvertTypes,
                                               double             *pdValue,
                                               QCBORItem          *pItem)
{
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)ConvertDouble(pItem, uConvertTypes, pdValue);
}


void QCBORDecode_GetDoubleConvertInternalInMapSZ(QCBORDecodeContext *pMe,
                                               const char *          szLabel,
                                               uint32_t              uConvertTypes,
                                               double               *pdValue,
                                               QCBORItem            *pItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)ConvertDouble(pItem, uConvertTypes, pdValue);
}


#ifndef QCBOR_DISABLE_FLOAT_HW_USE
static double ConvertBigNumToDouble(const UsefulBufC BigNum)
{
   double dResult;

   dResult = 0.0;
   const uint8_t *pByte = BigNum.ptr;
   size_t uLen = BigNum.len;
   /* This will overflow and become the float value INFINITY if the number
    is too large to fit. */
   while(uLen--) {
      dResult = (dResult * 256.0) + (double)*pByte++;
   }

   return dResult;
}
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */


static QCBORError
DoubleConvertAll(const QCBORItem *pItem, uint32_t uConvertTypes, double *pdValue)
{
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
   /*
    * What Every Computer Scientist Should Know About Floating-Point Arithmetic
    * https://docs.oracle.com/cd/E19957-01/806-3568/ncg_goldberg.html
    */
   switch(pItem->uDataType) {

#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
      case QCBOR_TYPE_DECIMAL_FRACTION:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            // Underflow gives 0, overflow gives infinity
            *pdValue = (double)pItem->val.expAndMantissa.Mantissa.nInt *
                        pow(10.0, (double)pItem->val.expAndMantissa.nExponent);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIGFLOAT ) {
            // Underflow gives 0, overflow gives infinity
            *pdValue = (double)pItem->val.expAndMantissa.Mantissa.nInt *
                              exp2((double)pItem->val.expAndMantissa.nExponent);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;
#endif /* ndef QCBOR_DISABLE_EXP_AND_MANTISSA */

      case QCBOR_TYPE_POSBIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIG_NUM) {
            *pdValue = ConvertBigNumToDouble(pItem->val.bigNum);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_NEGBIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIG_NUM) {
            *pdValue = -1-ConvertBigNumToDouble(pItem->val.bigNum);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            double dMantissa = ConvertBigNumToDouble(pItem->val.expAndMantissa.Mantissa.bigNum);
            *pdValue = dMantissa * pow(10, (double)pItem->val.expAndMantissa.nExponent);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
        if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
         double dMantissa = -ConvertBigNumToDouble(pItem->val.expAndMantissa.Mantissa.bigNum);
         *pdValue = dMantissa * pow(10, (double)pItem->val.expAndMantissa.nExponent);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_POS_BIGNUM:
        if(uConvertTypes & QCBOR_CONVERT_TYPE_BIGFLOAT) {
         double dMantissa = ConvertBigNumToDouble(pItem->val.expAndMantissa.Mantissa.bigNum);
         *pdValue = dMantissa * exp2((double)pItem->val.expAndMantissa.nExponent);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM:
        if(uConvertTypes & QCBOR_CONVERT_TYPE_BIGFLOAT) {
         double dMantissa = -1-ConvertBigNumToDouble(pItem->val.expAndMantissa.Mantissa.bigNum);
         *pdValue = dMantissa * exp2((double)pItem->val.expAndMantissa.nExponent);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;
#endif /* ndef QCBOR_DISABLE_EXP_AND_MANTISSA */

      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;
   }

   return QCBOR_SUCCESS;

#else
   (void)pItem;
   (void)uConvertTypes;
   (void)pdValue;
   return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */

}


/*
   Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetDoubleConvertAll(QCBORDecodeContext *pMe,
                                     uint32_t           uConvertTypes,
                                     double *pdValue)
{

   QCBORItem Item;

   QCBORDecode_GetDoubleConvertInternal(pMe, uConvertTypes, pdValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)DoubleConvertAll(&Item, uConvertTypes, pdValue);
}


/*
   Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetDoubleConvertAllInMapN(QCBORDecodeContext *pMe,
                                           int64_t             nLabel,
                                           uint32_t            uConvertTypes,
                                           double             *pdValue)
{
   QCBORItem Item;

   QCBORDecode_GetDoubleConvertInternalInMapN(pMe, nLabel, uConvertTypes, pdValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)DoubleConvertAll(&Item, uConvertTypes, pdValue);
}


/*
   Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetDoubleConvertAllInMapSZ(QCBORDecodeContext *pMe,
                                            const char         *szLabel,
                                            uint32_t            uConvertTypes,
                                            double             *pdValue)
{
   QCBORItem Item;
   QCBORDecode_GetDoubleConvertInternalInMapSZ(pMe, szLabel, uConvertTypes, pdValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)DoubleConvertAll(&Item, uConvertTypes, pdValue);
}
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */




#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
static inline UsefulBufC ConvertIntToBigNum(uint64_t uInt, UsefulBuf Buffer)
{
   while((uInt & 0xff00000000000000UL) == 0) {
      uInt = uInt << 8;
   };

   UsefulOutBuf UOB;

   UsefulOutBuf_Init(&UOB, Buffer);

   while(uInt) {
      const uint64_t xx = uInt & 0xff00000000000000UL;
      UsefulOutBuf_AppendByte(&UOB, (uint8_t)((uInt & 0xff00000000000000UL) >> 56));
      uInt = uInt << 8;
      (void)xx;
   }

   return UsefulOutBuf_OutUBuf(&UOB);
}


static QCBORError MantissaAndExponentTypeHandler(QCBORDecodeContext *pMe,
                                                 TagSpecification    TagSpec,
                                                 QCBORItem          *pItem)
{
   QCBORError uErr;
   // Loops runs at most 1.5 times. Making it a loop saves object code.
   while(1) {
      uErr = CheckTagRequirement(TagSpec, pItem);
      if(uErr != QCBOR_SUCCESS) {
         goto Done;
      }

      if(pItem->uDataType != QCBOR_TYPE_ARRAY) {
         break; // Successful exit. Moving on to finish decoding.
      }

      // The item is an array, which means an undecoded
      // mantissa and exponent, so decode it. It will then
      // have a different type and exit the loop if.
      uErr = QCBORDecode_MantissaAndExponent(pMe, pItem);
      if(uErr != QCBOR_SUCCESS) {
         goto Done;
      }

      // Second time around, the type must match.
      TagSpec.uTagRequirement = QCBOR_TAG_REQUIREMENT_TAG;
   }
Done:
   return uErr;
}


static void ProcessMantissaAndExponent(QCBORDecodeContext *pMe,
                                       TagSpecification    TagSpec,
                                       QCBORItem          *pItem,
                                       int64_t            *pnMantissa,
                                       int64_t            *pnExponent)
{
   QCBORError uErr;

   uErr = MantissaAndExponentTypeHandler(pMe, TagSpec, pItem);
   if(uErr != QCBOR_SUCCESS) {
      goto Done;
   }

   switch (pItem->uDataType) {

      case QCBOR_TYPE_DECIMAL_FRACTION:
      case QCBOR_TYPE_BIGFLOAT:
         *pnMantissa = pItem->val.expAndMantissa.Mantissa.nInt;
         *pnExponent = pItem->val.expAndMantissa.nExponent;
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
      case QCBOR_TYPE_BIGFLOAT_POS_BIGNUM:
         *pnExponent = pItem->val.expAndMantissa.nExponent;
         uErr = ConvertPositiveBigNumToSigned(pItem->val.expAndMantissa.Mantissa.bigNum, pnMantissa);
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
      case QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM:
         *pnExponent = pItem->val.expAndMantissa.nExponent;
         uErr = ConvertNegativeBigNumToSigned(pItem->val.expAndMantissa.Mantissa.bigNum, pnMantissa);
         break;

      default:
         uErr = QCBOR_ERR_UNEXPECTED_TYPE;
   }

   Done:
      pMe->uLastError = (uint8_t)uErr;
}


static void ProcessMantissaAndExponentBig(QCBORDecodeContext *pMe,
                                          TagSpecification    TagSpec,
                                          QCBORItem          *pItem,
                                          UsefulBuf           BufferForMantissa,
                                          UsefulBufC         *pMantissa,
                                          bool               *pbIsNegative,
                                          int64_t            *pnExponent)
{
   QCBORError uErr;

   uErr = MantissaAndExponentTypeHandler(pMe, TagSpec, pItem);
   if(uErr != QCBOR_SUCCESS) {
      goto Done;
   }

   uint64_t uMantissa;

   switch (pItem->uDataType) {

      case QCBOR_TYPE_DECIMAL_FRACTION:
      case QCBOR_TYPE_BIGFLOAT:
         if(pItem->val.expAndMantissa.Mantissa.nInt >= 0) {
            uMantissa = (uint64_t)pItem->val.expAndMantissa.Mantissa.nInt;
            *pbIsNegative = false;
         } else {
            uMantissa = (uint64_t)-pItem->val.expAndMantissa.Mantissa.nInt;
            *pbIsNegative = true;
         }
         *pMantissa = ConvertIntToBigNum(uMantissa, BufferForMantissa);
         *pnExponent = pItem->val.expAndMantissa.nExponent;
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
      case QCBOR_TYPE_BIGFLOAT_POS_BIGNUM:
         *pnExponent = pItem->val.expAndMantissa.nExponent;
         *pMantissa = pItem->val.expAndMantissa.Mantissa.bigNum;
         *pbIsNegative = false;
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
      case QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM:
         *pnExponent = pItem->val.expAndMantissa.nExponent;
         *pMantissa = pItem->val.expAndMantissa.Mantissa.bigNum;
         *pbIsNegative = true;
         break;

      default:
         uErr = QCBOR_ERR_UNEXPECTED_TYPE;
   }

Done:
   pMe->uLastError = (uint8_t)uErr;
}


/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetDecimalFraction(QCBORDecodeContext *pMe,
                                    uint8_t             uTagRequirement,
                                    int64_t             *pnMantissa,
                                    int64_t             *pnExponent)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;
   QCBORError uError = QCBORDecode_GetNext(pMe, &Item);
   if(uError) {
      pMe->uLastError = (uint8_t)uError;
      return;
   }

   const TagSpecification TagSpec =
   {
      uTagRequirement,
      {QCBOR_TYPE_DECIMAL_FRACTION, QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM,
         QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM, QCBOR_TYPE_NONE},
      {QCBOR_TYPE_ARRAY, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
   };

   ProcessMantissaAndExponent(pMe, TagSpec, &Item, pnMantissa, pnExponent);
}


/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetDecimalFractionInMapN(QCBORDecodeContext *pMe,
                                          int64_t             nLabel,
                                          uint8_t             uTagRequirement,
                                          int64_t             *pnMantissa,
                                          int64_t             *pnExponent)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);

   const TagSpecification TagSpec =
   {
      uTagRequirement,
      {QCBOR_TYPE_DECIMAL_FRACTION, QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM,
         QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM, QCBOR_TYPE_NONE},
      {QCBOR_TYPE_ARRAY, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
   };

   ProcessMantissaAndExponent(pMe, TagSpec, &Item, pnMantissa, pnExponent);
}


/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetDecimalFractionInMapSZ(QCBORDecodeContext *pMe,
                                           const char         *szLabel,
                                           uint8_t             uTagRequirement,
                                           int64_t             *pnMantissa,
                                           int64_t             *pnExponent)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);

   const TagSpecification TagSpec =
   {
      uTagRequirement,
      {QCBOR_TYPE_DECIMAL_FRACTION, QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM,
         QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM, QCBOR_TYPE_NONE},
      {QCBOR_TYPE_ARRAY, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
   };

   ProcessMantissaAndExponent(pMe, TagSpec, &Item, pnMantissa, pnExponent);
}


/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetDecimalFractionBig(QCBORDecodeContext *pMe,
                                       uint8_t             uTagRequirement,
                                       UsefulBuf          MantissaBuffer,
                                       UsefulBufC         *pMantissa,
                                       bool               *pbMantissaIsNegative,
                                       int64_t            *pnExponent)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;
   QCBORError uError = QCBORDecode_GetNext(pMe, &Item);
   if(uError) {
      pMe->uLastError = (uint8_t)uError;
      return;
   }

   const TagSpecification TagSpec =
   {
      uTagRequirement,
      {QCBOR_TYPE_DECIMAL_FRACTION, QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM,
         QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM, QCBOR_TYPE_NONE},
      {QCBOR_TYPE_ARRAY, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
   };

   ProcessMantissaAndExponentBig(pMe,
                                 TagSpec,
                                 &Item,
                                 MantissaBuffer,
                                 pMantissa,
                                 pbMantissaIsNegative,
                                 pnExponent);
}


/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetDecimalFractionBigInMapN(QCBORDecodeContext *pMe,
                                             int64_t             nLabel,
                                             uint8_t             uTagRequirement,
                                             UsefulBuf           BufferForMantissa,
                                             UsefulBufC         *pMantissa,
                                             bool               *pbIsNegative,
                                             int64_t            *pnExponent)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   const TagSpecification TagSpec =
   {
      uTagRequirement,
      {QCBOR_TYPE_DECIMAL_FRACTION, QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM,
         QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM, QCBOR_TYPE_NONE},
      {QCBOR_TYPE_ARRAY, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
   };

   ProcessMantissaAndExponentBig(pMe,
                                 TagSpec,
                                 &Item,
                                 BufferForMantissa,
                                 pMantissa,
                                 pbIsNegative,
                                 pnExponent);
}


/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetDecimalFractionBigInMapSZ(QCBORDecodeContext *pMe,
                                              const char         *szLabel,
                                              uint8_t             uTagRequirement,
                                              UsefulBuf           BufferForMantissa,
                                              UsefulBufC         *pMantissa,
                                              bool               *pbIsNegative,
                                              int64_t            *pnExponent)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   const TagSpecification TagSpec =
   {
      uTagRequirement,
      {QCBOR_TYPE_DECIMAL_FRACTION, QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM,
         QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM, QCBOR_TYPE_NONE},
      {QCBOR_TYPE_ARRAY, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
   };

   ProcessMantissaAndExponentBig(pMe, TagSpec, &Item, BufferForMantissa, pMantissa, pbIsNegative, pnExponent);
}


/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetBigFloat(QCBORDecodeContext *pMe,
                             uint8_t             uTagRequirement,
                             int64_t             *pnMantissa,
                             int64_t             *pnExponent)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;
   QCBORError uError = QCBORDecode_GetNext(pMe, &Item);
   if(uError) {
      pMe->uLastError = (uint8_t)uError;
      return;
   }
   const TagSpecification TagSpec =
   {
      uTagRequirement,
      {QCBOR_TYPE_BIGFLOAT, QCBOR_TYPE_BIGFLOAT_POS_BIGNUM,
         QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM, QCBOR_TYPE_NONE},
      {QCBOR_TYPE_ARRAY, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
   };

   ProcessMantissaAndExponent(pMe, TagSpec, &Item, pnMantissa, pnExponent);
}


/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetBigFloatInMapN(QCBORDecodeContext *pMe,
                                   int64_t             nLabel,
                                   uint8_t             uTagRequirement,
                                   int64_t            *pnMantissa,
                                   int64_t            *pnExponent)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   const TagSpecification TagSpec =
   {
      uTagRequirement,
      {QCBOR_TYPE_BIGFLOAT, QCBOR_TYPE_BIGFLOAT_POS_BIGNUM,
         QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM, QCBOR_TYPE_NONE},
      {QCBOR_TYPE_ARRAY, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
   };

   ProcessMantissaAndExponent(pMe, TagSpec, &Item, pnMantissa, pnExponent);
}


/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetBigFloatInMapSZ(QCBORDecodeContext *pMe,
                                    const char         *szLabel,
                                    uint8_t             uTagRequirement,
                                    int64_t            *pnMantissa,
                                    int64_t            *pnExponent)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   const TagSpecification TagSpec =
   {
      uTagRequirement,
      {QCBOR_TYPE_BIGFLOAT, QCBOR_TYPE_BIGFLOAT_POS_BIGNUM,
         QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM, QCBOR_TYPE_NONE},
      {QCBOR_TYPE_ARRAY, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
   };

   ProcessMantissaAndExponent(pMe, TagSpec, &Item, pnMantissa, pnExponent);
}


/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetBigFloatBig(QCBORDecodeContext *pMe,
                                uint8_t             uTagRequirement,
                                UsefulBuf          MantissaBuffer,
                                UsefulBufC         *pMantissa,
                                bool               *pbMantissaIsNegative,
                                int64_t            *pnExponent)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;
   QCBORError uError = QCBORDecode_GetNext(pMe, &Item);
   if(uError) {
      pMe->uLastError = (uint8_t)uError;
      return;
   }

   const TagSpecification TagSpec =
   {
      uTagRequirement,
      {QCBOR_TYPE_BIGFLOAT, QCBOR_TYPE_BIGFLOAT_POS_BIGNUM,
         QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM, QCBOR_TYPE_NONE},
      {QCBOR_TYPE_ARRAY, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
   };

   ProcessMantissaAndExponentBig(pMe, TagSpec, &Item, MantissaBuffer, pMantissa, pbMantissaIsNegative, pnExponent);
}


/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetBigFloatBigInMapN(QCBORDecodeContext *pMe,
                                      int64_t             nLabel,
                                      uint8_t             uTagRequirement,
                                      UsefulBuf           BufferForMantissa,
                                      UsefulBufC         *pMantissa,
                                      bool               *pbIsNegative,
                                      int64_t            *pnExponent)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   const TagSpecification TagSpec =
   {
      uTagRequirement,
      {QCBOR_TYPE_BIGFLOAT, QCBOR_TYPE_BIGFLOAT_POS_BIGNUM,
         QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM, QCBOR_TYPE_NONE},
      {QCBOR_TYPE_ARRAY, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
   };

   ProcessMantissaAndExponentBig(pMe,
                                 TagSpec,
                                 &Item,
                                 BufferForMantissa,
                                 pMantissa,
                                 pbIsNegative,
                                 pnExponent);
}


/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetBigFloatBigInMapSZ(QCBORDecodeContext *pMe,
                                       const char         *szLabel,
                                       uint8_t             uTagRequirement,
                                       UsefulBuf           BufferForMantissa,
                                       UsefulBufC         *pMantissa,
                                       bool               *pbIsNegative,
                                       int64_t            *pnExponent)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   const TagSpecification TagSpec =
   {
      uTagRequirement,
      {QCBOR_TYPE_BIGFLOAT, QCBOR_TYPE_BIGFLOAT_POS_BIGNUM,
         QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM, QCBOR_TYPE_NONE},
      {QCBOR_TYPE_ARRAY, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
   };

   ProcessMantissaAndExponentBig(pMe,
                                 TagSpec,
                                 &Item,
                                 BufferForMantissa,
                                 pMantissa,
                                 pbIsNegative,
                                 pnExponent);
}

#endif /* QCBOR_DISABLE_EXP_AND_MANTISSA */
