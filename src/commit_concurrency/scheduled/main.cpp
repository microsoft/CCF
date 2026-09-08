// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// Doctest entry point for the scheduled concurrency-testing suite: unlike
// commit_concurrency_test (real OS-thread timing, seeded but not exactly
// replayable), this suite drives the same real Store + Aft + MerkleTxHistory
// stack through ccf::kv::test::DeterministicScheduler
// (src/commit_concurrency/scheduled/deterministic_scheduler.h), which
// systematically explores the space of legal interleavings of a bounded
// scenario - exhaustively where that space is small enough
// (explore_all_interleavings()), or by random sampling where it isn't
// (explore_random_interleavings(), used by every scenario below).

#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES
#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  return context.run();
}
