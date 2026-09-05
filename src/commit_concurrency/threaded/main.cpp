// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// Doctest entry point for the commit-concurrency suite: real OS threads
// exercising a real Store, Aft, and MerkleTxHistory together. See
// fixture.h for the harness, and deterministic.cpp/fuzzer.cpp for what
// each covers.

#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES
#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  return context.run();
}
