// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define DOCTEST_CONFIG_IMPLEMENT
#include "doctest/doctest.h"

#include <fstream>
#include <iostream>

extern "C"
{
#include <evercrypt/EverCrypt_AutoConfig2.h>
}

#include "test/test_ledger_replay.h"
#include "test/test_node.h"

// We need an explicit main to initialize and EverCrypt
int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  ::EverCrypt_AutoConfig2_init();
  int res = context.run();
  if (context.shouldExit())
  {
    return res;
  }
  return res;
}
