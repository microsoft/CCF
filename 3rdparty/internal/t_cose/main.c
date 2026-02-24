/*
 *  main.c
 *
 * Copyright 2019-2020, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md.
 *
 * Created 4/21/2019.
 */

#include <stdio.h>
#include "run_tests.h"
#include "t_cose_make_test_pub_key.h"


/*
 This is an implementation of OutputStringCB built using stdio. If
 you don't have stdio, replaces this.
 */
static void fputs_wrapper(const char *szString, void *pOutCtx, int bNewLine)
{
    fputs(szString, (FILE *)pOutCtx);
    if(bNewLine) {
        fputs("\n", pOutCtx);
    }
}


int main(int argc, const char * argv[])
{
    int return_value;

    (void)argc; // Avoid unused parameter error

    // This call prints out sizes of data structures to remind us
    // to keep them small.
    PrintSizesTCose(&fputs_wrapper, stdout);

    // This runs all the tests
    return_value = RunTestsTCose(argv+1, &fputs_wrapper, stdout, NULL);

    if(return_value) {
        return return_value;
    }

    return_value = check_for_key_pair_leaks();
    if(return_value) {
        printf("Detected key pair leaks: %d FAIL\n", return_value);
    }

    return return_value;
}
