/* =========================================================================
   ub-example.c -- Example code for UsefulBuf

   Copyright (c) 2022, Laurence Lundblade. All rights reserved.

   SPDX-License-Identifier: BSD-3-Clause

   See BSD-3-Clause license in README.md

   Created on 4/8/22
  ========================================================================== */

#include "ub-example.h"

#include "UsefulBuf.h"


/*
 * A considerable number of the security issues with C code come from
 * mistakes made with pointers and lengths.  UsefulBuf adopts a
 * convention that a pointer and length *always* go together to help
 * mitigate this.  With UsefulBuf there are never pointers without
 * lengths, so you always know how big a buffer or some binary data
 * is.
 *
 * C99 allows passing structures so a structure is used. Compilers are
 * smart these days so the object code produced is little different
 * than passing two separate parameters. Passing structures also makes
 * the interfaces prettier. Assignments of structures also can make
 * code prettier.
 *
 * ALong with the UsefulBuf structure, there are a bunch of (tested!)
 * functions to manipulate them so code using it may have no pointer
 * manipulation at all.
 *
 * Constness is also a useful and desirous thing. See
 * https://stackoverflow.com/questions/117293/use-of-const-for-function-parameters
 * Keeping const distinct from non-const is helpful when reading the
 * code and helps avoid some coding mistakes.  In this example the
 * buffers filled in with data are const and the ones that are
 * to-be-filled in are not const.
 *
 * This contrived example copies data from input to output expanding
 * bytes with the value 'x' to 'xx'.
 *
 * Input -- This is the pointer and length of the input, the bytes to
 * copy. Note that UsefulBufC.ptr is a const void * indicating that
 * input data won't be changed by this function.  There is a "C" in
 * "UsefulBufC "to indicate the value is const.  The length here is
 * the length of the valid input data. Note also that the parameter
 * Input is const, so this is fully const and clearly an [in]
 * parameter.
 *
 * OutputBuffer -- This is a pointer and length of the memory to be
 * used to store the output. The correct length here is critical for
 * code security. Note that UsefulBuf.ptr is void *, it is not const
 * indicating data can be written to it. Note that the parameter
 * itself *is* const indicating that the code below will not point
 * this to some other buffer or change the length and clearly marking
 * it as an [in] parameter.
 *
 * Output -- This is the interesting and unusual one. To stay
 * consistent with always pairing a length and a pointer, this is
 * returned as a UsefulBuC. Also, to stay consistent with valid data
 * being const, it is a UsefulBufC, not a UsefulBuf. It is however, an
 * [out] parameter so the parameter is a pointer to a UsefulBufC.
 *
 * In this case and most cases, the pointer in Output->ptr will be the
 * same as OutputBuffer.ptr. This may seem redundant, but there are a
 * few reasons for it. First, is the goal of always pairing a pointer
 * and a length.  Second is being more strict and correct with
 * constness. Third is the code hygiene and clarity of having
 * variables for to-be-filled buffers be distinct from those
 * containing valid data. Fourth, there are no [in,out] parameters,
 * only [in] parameters and [out] parameters (the to-be-filled-in
 * buffer is considered an [in] parameter).
 *
 * Note that the compiler will be smart and should generate pretty
 * much the same code as for a traditional interface. On x86 with
 * gcc-11 and no stack guards, the UB code is 81 bytes and the
 * traditional code is 77 bytes.
 *
 * Finally, this supports computing of the length of the would-be
 * output without actually doing any outputting. Pass {NULL, SIZE_MAX}
 * for the OutputBuffer and the length will be returned in Output.
 */
int
ExpandxUB(const UsefulBufC   Input,
          const UsefulBuf    OutputBuffer,
          UsefulBufC        *Output)
{
    size_t uInputPosition;
    size_t uOutputPosition;

    uOutputPosition = 0;

    /* Loop over all the bytes in Input */
    for(uInputPosition = 0; uInputPosition < Input.len; uInputPosition++) {
        const uint8_t uInputByte = ((const uint8_t*)Input.ptr)[uInputPosition];

        /* Copy every byte */
        if(OutputBuffer.ptr != NULL) {
            ((uint8_t *)OutputBuffer.ptr)[uOutputPosition] = uInputByte;
        }
        uOutputPosition++;
        if(uOutputPosition >= OutputBuffer.len) {
            return -1;
        }

        /* Double output 'x' because that is what this contrived example does */
        if(uInputByte== 'x') {
            if(OutputBuffer.ptr != NULL) {
                ((uint8_t *)OutputBuffer.ptr)[uOutputPosition] = 'x';
            }
            uOutputPosition++;
            if(uOutputPosition >= OutputBuffer.len) {
                return -1;
            }
        }
    }

    *Output = (UsefulBufC){OutputBuffer.ptr, uOutputPosition};

    return 0; /* success */
}


/* This is the more tradional way to implement this. */
int
ExpandxTraditional(const uint8_t  *pInputPointer,
                   const size_t    uInputLength,
                   uint8_t        *pOutputBuffer,
                   const size_t    uOutputBufferLength,
                   size_t         *puOutputLength)
{
    size_t uInputPosition;
    size_t uOutputPosition;

    uOutputPosition = 0;

    /* Loop over all the bytes in Input */
    for(uInputPosition = 0; uInputPosition < uInputLength; uInputPosition++) {
        const uint8_t uInputByte = ((const uint8_t*)pInputPointer)[uInputPosition];

        /* Copy every byte */
        if(pOutputBuffer != NULL) {
            ((uint8_t *)pOutputBuffer)[uOutputPosition] = uInputByte;
        }
        uOutputPosition++;
        if(uOutputPosition >= uOutputBufferLength) {
            return -1;
        }

        /* Double output 'x' because that is what this contrived example does */
        if(uInputByte== 'x') {
            if(pOutputBuffer != NULL) {
                ((uint8_t *)pOutputBuffer)[uOutputPosition] = 'x';
            }
            uOutputPosition++;
            if(uOutputPosition >= uOutputBufferLength) {
                return -1;
            }
        }
    }

   *puOutputLength = uOutputPosition;

    return 0; /* success */
}


/*
 * Here's an example of going from a traditional interface
 * interface to a UsefulBuf interface.
 */
int
ExpandxTraditionalAdaptor(const uint8_t  *pInputPointer,
                          size_t          uInputLength,
                          uint8_t        *pOutputBuffer,
                          size_t          uOutputBufferLength,
                          size_t         *puOutputLength)
{
    UsefulBufC  Input;
    UsefulBuf   OutputBuffer;
    UsefulBufC  Output;
    int         nReturn;

    Input = (UsefulBufC){pInputPointer, uInputLength};
    OutputBuffer = (UsefulBuf){pOutputBuffer, uOutputBufferLength};

    nReturn = ExpandxUB(Input, OutputBuffer, &Output);

    *puOutputLength = Output.len;

    return nReturn;
}


/* Here's an example for going from a UsefulBuf interface
 to a traditional interface. */
int
ExpandxUBAdaptor(const UsefulBufC   Input,
                 const UsefulBuf    OutputBuffer,
                 UsefulBufC        *Output)
{
   Output->ptr = OutputBuffer.ptr;

   return ExpandxTraditional(Input.ptr, Input.len,
                             OutputBuffer.ptr, OutputBuffer.len,
                           &(Output->len));
}



#define INPUT "xyz123xyz"

int32_t RunUsefulBufExample()
{
   /* ------------ UsefulBuf examples ------------- */
   UsefulBufC Input = UsefulBuf_FROM_SZ_LITERAL(INPUT);

   /* This macros makes a 20 byte buffer on the stack. It also makes
    * a UsefulBuf on the stack. It sets up the UsefulBuf to point to
    * the 20 byte buffer and sets it's length to 20 bytes. This
    * is the empty, to-be-filled in memory for the output. It is not
    * const. */
   MakeUsefulBufOnStack(OutBuf, sizeof(INPUT) * 2);

   /* This is were the pointer and the length of the completed output
    * will be placed. Output.ptr is a pointer to const bytes. */
   UsefulBufC           Output;

   ExpandxUB(Input, OutBuf, &Output);

   ExpandxUBAdaptor(Input, OutBuf, &Output);



   /* ------ Get Size example  -------- */
   ExpandxUB(Input, (UsefulBuf){NULL, SIZE_MAX}, &Output);

   /* Size is in Output.len */



   /* ---------- Traditional examples (for comparison) --------- */
   uint8_t puBuffer[sizeof(INPUT) * 2];
   size_t  uOutputSize;

   ExpandxTraditional((const uint8_t *)INPUT, sizeof(INPUT),
                     puBuffer, sizeof(puBuffer),
                     &uOutputSize);


   ExpandxTraditionalAdaptor((const uint8_t *)INPUT, sizeof(INPUT),
                            puBuffer, sizeof(puBuffer),
                           &uOutputSize);

   return 0;
}
