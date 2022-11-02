/*==============================================================================
 run_tests.c -- test aggregator and results reporting

 Copyright (c) 2018-2021, Laurence Lundblade. All rights reserved.
 Copyright (c) 2021, Arm Limited. All rights reserved.

 SPDX-License-Identifier: BSD-3-Clause

 See BSD-3-Clause license in README.md

 Created on 9/30/18
 =============================================================================*/

#include "run_tests.h"
#include "UsefulBuf.h"
#include <stdbool.h>

#include "float_tests.h"
#include "qcbor_decode_tests.h"
#include "qcbor_encode_tests.h"
#include "UsefulBuf_Tests.h"



// For size printing and some conditionals
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"

/*
 Test configuration
 */

typedef int32_t (test_fun_t)(void);
typedef const char * (test_fun2_t)(void);


#define TEST_ENTRY(test_name)  {#test_name, test_name, true}
#define TEST_ENTRY_DISABLED(test_name)  {#test_name, test_name, false}

typedef struct {
    const char  *szTestName;
    test_fun_t  *test_fun;
    bool         bEnabled;
} test_entry;

typedef struct {
    const char *szTestName;
    test_fun2_t  *test_fun;
    bool         bEnabled;
} test_entry2;


static test_entry2 s_tests2[] = {
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
    TEST_ENTRY(UBUTest_CopyUtil),
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
    TEST_ENTRY(UOBTest_NonAdversarial),
    TEST_ENTRY(TestBasicSanity),
    TEST_ENTRY(UOBTest_BoundaryConditionsTest),
    TEST_ENTRY(UBMacroConversionsTest),
    TEST_ENTRY(UBUtilTests),
    TEST_ENTRY(UIBTest_IntegerFormat),
    TEST_ENTRY(UBAdvanceTest)
};


static test_entry s_tests[] = {
    TEST_ENTRY(OpenCloseBytesTest),
    TEST_ENTRY(EnterBstrTest),
    TEST_ENTRY(IntegerConvertTest),
    TEST_ENTRY(EnterMapTest),
    TEST_ENTRY(QCBORHeadTest),
    TEST_ENTRY(EmptyMapsAndArraysTest),
    TEST_ENTRY(NotWellFormedTests),
    TEST_ENTRY(ParseMapAsArrayTest),
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
    TEST_ENTRY(IndefiniteLengthNestTest),
    TEST_ENTRY(IndefiniteLengthArrayMapTest),
    TEST_ENTRY(NestedMapTestIndefLen),
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */
    TEST_ENTRY(ParseSimpleTest),
    TEST_ENTRY(DecodeFailureTests),
    TEST_ENTRY(EncodeRawTest),
    TEST_ENTRY(RTICResultsTest),
    TEST_ENTRY(MapEncodeTest),
    TEST_ENTRY(ArrayNestingTest1),
    TEST_ENTRY(ArrayNestingTest2),
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
    TEST_ENTRY(ArrayNestingTest3),
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */
    TEST_ENTRY(EncodeDateTest),
    TEST_ENTRY(SimpleValuesTest1),
    TEST_ENTRY(IntegerValuesTest1),
    TEST_ENTRY(AllAddMethodsTest),
    TEST_ENTRY(ParseTooDeepArrayTest),
    TEST_ENTRY(ComprehensiveInputTest),
    TEST_ENTRY(ParseMapTest),
    TEST_ENTRY(BasicEncodeTest),
    TEST_ENTRY(NestedMapTest),
    TEST_ENTRY(BignumParseTest),
    TEST_ENTRY(OptTagParseTest),
    TEST_ENTRY(DateParseTest),
    TEST_ENTRY(SpiffyDateDecodeTest),
    TEST_ENTRY(ShortBufferParseTest2),
    TEST_ENTRY(ShortBufferParseTest),
    TEST_ENTRY(ParseDeepArrayTest),
    TEST_ENTRY(SimpleArrayTest),
    TEST_ENTRY(IntegerValuesParseTest),
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
    TEST_ENTRY(AllocAllStringsTest),
    TEST_ENTRY(MemPoolTest),
    TEST_ENTRY(IndefiniteLengthStringTest),
    TEST_ENTRY(SpiffyIndefiniteLengthStringsTests),
    TEST_ENTRY(SetUpAllocatorTest),
    TEST_ENTRY(CBORTestIssue134),
#endif /* #ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
    TEST_ENTRY(HalfPrecisionDecodeBasicTests),
    TEST_ENTRY(DoubleAsSmallestTest),
    TEST_ENTRY(HalfPrecisionAgainstRFCCodeTest),
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
    TEST_ENTRY(GeneralFloatEncodeTests),
    TEST_ENTRY(GeneralFloatDecodeTests),
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
    TEST_ENTRY(BstrWrapTest),
    TEST_ENTRY(BstrWrapErrorTest),
    TEST_ENTRY(BstrWrapNestTest),
    TEST_ENTRY(CoseSign1TBSTest),
    TEST_ENTRY(StringDecoderModeFailTest),
    TEST_ENTRY_DISABLED(BigComprehensiveInputTest),
    TEST_ENTRY_DISABLED(TooLargeInputTest),
    TEST_ENTRY(EncodeErrorTests),
    TEST_ENTRY(SimpleValuesIndefiniteLengthTest1),
    TEST_ENTRY(EncodeLengthThirtyoneTest),
    TEST_ENTRY(CBORSequenceDecodeTests),
    TEST_ENTRY(IntToTests),
    TEST_ENTRY(DecodeTaggedTypeTests),
    TEST_ENTRY(PeekAndRewindTest),
#ifndef     QCBOR_DISABLE_EXP_AND_MANTISSA
    TEST_ENTRY(EncodeLengthThirtyoneTest),
    TEST_ENTRY(ExponentAndMantissaDecodeTests),
    TEST_ENTRY(ExponentAndMantissaDecodeFailTests),
    TEST_ENTRY(ExponentAndMantissaEncodeTests),
#endif /* QCBOR_DISABLE_EXP_AND_MANTISSA */
    TEST_ENTRY(ParseEmptyMapInMapTest),
    TEST_ENTRY(BoolTest)
};




/*
 Convert a number up to 999999999 to a string. This is so sprintf doesn't
 have to be linked in so as to minimized dependencies even in test code.

 StringMem should be 12 bytes long, 9 for digits, 1 for minus and
 1 for \0 termination.
 */
static const char *NumToString(int32_t nNum, UsefulBuf StringMem)
{
   const int32_t nMax = 1000000000;

   UsefulOutBuf OutBuf;
   UsefulOutBuf_Init(&OutBuf, StringMem);

   if(nNum < 0) {
      UsefulOutBuf_AppendByte(&OutBuf, '-');
      nNum = -nNum;
   }
   if(nNum > nMax-1) {
      return "XXX";
   }

   bool bDidSomeOutput = false;
   for(int32_t n = nMax; n > 0; n/=10) {
      int nDigitValue = nNum/n;
      if(nDigitValue || bDidSomeOutput){
         bDidSomeOutput = true;
         UsefulOutBuf_AppendByte(&OutBuf, (uint8_t)('0' + nDigitValue));
         nNum -= nDigitValue * n;
      }
   }
   if(!bDidSomeOutput){
      UsefulOutBuf_AppendByte(&OutBuf, '0');
   }
   UsefulOutBuf_AppendByte(&OutBuf, '\0');

   return UsefulOutBuf_GetError(&OutBuf) ? "" : StringMem.ptr;
}


/*
 Public function. See run_test.h.
 */
int RunTestsQCBOR(const char *szTestNames[],
             OutputStringCB pfOutput,
             void *poutCtx,
             int *pNumTestsRun)
{
    int nTestsFailed = 0;
    int nTestsRun = 0;

    UsefulBuf_MAKE_STACK_UB(StringStorage, 12);

    test_entry2 *t2;
    const test_entry2 *s_tests2_end = s_tests2 + sizeof(s_tests2)/sizeof(test_entry2);

    for(t2 = s_tests2; t2 < s_tests2_end; t2++) {
        if(szTestNames[0]) {
            // Some tests have been named
            const char **szRequestedNames;
            for(szRequestedNames = szTestNames; *szRequestedNames;  szRequestedNames++) {
                if(!strcmp(t2->szTestName, *szRequestedNames)) {
                    break; // Name matched
                }
            }
            if(*szRequestedNames == NULL) {
                // Didn't match this test
                continue;
            }
        } else {
            // no tests named, but don't run "disabled" tests
            if(!t2->bEnabled) {
                // Don't run disabled tests when all tests are being run
                // as indicated by no specific test names being given
                continue;
            }
        }

        const char * szTestResult = (t2->test_fun)();
        nTestsRun++;
        if(pfOutput) {
            (*pfOutput)(t2->szTestName, poutCtx, 0);
        }

        if(szTestResult) {
            if(pfOutput) {
                (*pfOutput)(" FAILED (returned ", poutCtx, 0);
                (*pfOutput)(szTestResult, poutCtx, 0);
                (*pfOutput)(")", poutCtx, 1);
            }
            nTestsFailed++;
        } else {
            if(pfOutput) {
                (*pfOutput)( " PASSED", poutCtx, 1);
            }
        }
    }


    test_entry *t;
    const test_entry *s_tests_end = s_tests + sizeof(s_tests)/sizeof(test_entry);

    for(t = s_tests; t < s_tests_end; t++) {
        if(szTestNames[0]) {
            // Some tests have been named
            const char **szRequestedNames;
            for(szRequestedNames = szTestNames; *szRequestedNames;  szRequestedNames++) {
                if(!strcmp(t->szTestName, *szRequestedNames)) {
                    break; // Name matched
                }
            }
            if(*szRequestedNames == NULL) {
                // Didn't match this test
                continue;
            }
        } else {
            // no tests named, but don't run "disabled" tests
            if(!t->bEnabled) {
                // Don't run disabled tests when all tests are being run
                // as indicated by no specific test names being given
                continue;
            }
        }

        int32_t nTestResult = (t->test_fun)();
        nTestsRun++;
        if(pfOutput) {
            (*pfOutput)(t->szTestName, poutCtx, 0);
        }

        if(nTestResult) {
            if(pfOutput) {
                (*pfOutput)(" FAILED (returned ", poutCtx, 0);
                (*pfOutput)(NumToString(nTestResult, StringStorage), poutCtx, 0);
                (*pfOutput)(")", poutCtx, 1);
            }
            nTestsFailed++;
        } else {
            if(pfOutput) {
                (*pfOutput)( " PASSED", poutCtx, 1);
            }
        }
    }

    if(pNumTestsRun) {
        *pNumTestsRun = nTestsRun;
    }

    if(pfOutput) {
        (*pfOutput)( "SUMMARY: ", poutCtx, 0);
        (*pfOutput)( NumToString(nTestsRun, StringStorage), poutCtx, 0);
        (*pfOutput)( " tests run; ", poutCtx, 0);
        (*pfOutput)( NumToString(nTestsFailed, StringStorage), poutCtx, 0);
        (*pfOutput)( " tests failed", poutCtx, 1);
    }

    return nTestsFailed;
}




/*
 Public function. See run_test.h.
 */
static void PrintSize(const char *szWhat,
                      uint32_t uSize,
                      OutputStringCB pfOutput,
                      void *pOutCtx)
{
   UsefulBuf_MAKE_STACK_UB(buffer, 20);

   (*pfOutput)(szWhat, pOutCtx, 0);
   (*pfOutput)(" ", pOutCtx, 0);
   (*pfOutput)(NumToString((int32_t)uSize, buffer), pOutCtx, 0);
   (*pfOutput)("", pOutCtx, 1);
}


/*
 Public function. See run_test.h.
 */
void PrintSizesQCBOR(OutputStringCB pfOutput, void *pOutCtx)
{
   // These will never be large so cast is safe
   PrintSize("sizeof(QCBORTrackNesting)",   (uint32_t)sizeof(QCBORTrackNesting),  pfOutput, pOutCtx);
   PrintSize("sizeof(QCBOREncodeContext)",  (uint32_t)sizeof(QCBOREncodeContext), pfOutput, pOutCtx);
   PrintSize("sizeof(QCBORDecodeNesting)",  (uint32_t)sizeof(QCBORDecodeNesting), pfOutput, pOutCtx);
   PrintSize("sizeof(QCBORDecodeContext)",  (uint32_t)sizeof(QCBORDecodeContext), pfOutput, pOutCtx);
   PrintSize("sizeof(QCBORItem)",           (uint32_t)sizeof(QCBORItem),          pfOutput, pOutCtx);
   PrintSize("sizeof(QCBORTagListIn)",      (uint32_t)sizeof(QCBORTagListIn),     pfOutput, pOutCtx);
   PrintSize("sizeof(QCBORTagListOut)",     (uint32_t)sizeof(QCBORTagListOut),    pfOutput, pOutCtx);
   PrintSize("sizeof(TagSpecification)",    (uint32_t)sizeof(TagSpecification),    pfOutput, pOutCtx);
   (*pfOutput)("", pOutCtx, 1);
}
