// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// Doctest entry point for the model-checked concurrency suite: unlike
// commit_concurrency_test (real OS-thread timing, seeded but not
// exactly replayable), this suite drives the same real Store + Aft +
// MerkleTxHistory stack through ccf::kv::test::explore_all_interleavings(),
// exhaustively trying every legal interleaving of a bounded scenario rather
// than sampling a subset of them.

#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES
#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  return context.run();
}
