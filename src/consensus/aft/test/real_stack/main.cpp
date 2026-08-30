// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// Doctest entry point for the real-stack concurrency suite. See fixture.h
// for what "real-stack" means here, and README-style commentary at the top
// of deterministic.cpp and fuzzer.cpp for what each file covers.

#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES
#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  return context.run();
}
