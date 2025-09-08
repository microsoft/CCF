// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../history.h"
#include "ds/framework_logger.h"

#include <algorithm>
#include <random>
#include <sys/resource.h>
#include <sys/time.h>

using namespace std;

static constexpr size_t appends = 1'000'000;
static constexpr size_t max_tree_size = 1000;
static constexpr size_t flushes_without_retract = 10;

static constexpr size_t max_expected_rss = 4096;

static size_t get_maxrss()
{
  rusage r;
  auto rc = getrusage(RUSAGE_SELF, &r);
  if (rc != 0)
    throw std::logic_error("getrusage failed");
  return r.ru_maxrss;
}

static ccf::crypto::Sha256Hash random_hash(std::random_device& rdev)
{
  ccf::crypto::Sha256Hash h;
  for (size_t j = 0; j < ccf::crypto::Sha256Hash::SIZE; j++)
    h.h[j] = rdev();
  return h;
}

static int append_flush_and_retract()
{
  ccf::MerkleTreeHistory t;
  std::random_device r;

  for (size_t index = 0; index < appends; ++index)
  {
    auto h = random_hash(r);
    t.append(h);

    if (index > 0 && index % max_tree_size == 0)
    {
      if (index % (flushes_without_retract * max_tree_size) == 0)
      {
        t.retract(index - max_tree_size);
        LOG_DEBUG_FMT("retract() {}", index - max_tree_size);
      }
      else
      {
        t.flush(index - max_tree_size);
        LOG_DEBUG_FMT("flush() {}", index - max_tree_size);
      }
    }
    if (index % (appends / 10) == 0)
    {
      LOG_INFO_FMT("At {}", index);
      LOG_INFO_FMT("  MAX RSS: {}Kb", get_maxrss());
      const auto serialised = t.serialise();
      LOG_INFO_FMT("  SERIALISED: {}Kb", serialised.size() / 1024);
      const auto receipt = t.get_proof(t.end_index());
      LOG_INFO_FMT("  SERIALISED RECEIPT: {}bytes", receipt.to_v().size());
    }
  }
  LOG_INFO_FMT("MAX RSS: {}Kb", get_maxrss());

  return get_maxrss() < max_expected_rss ? 0 : 1;
}

int main(int argc, char* argv[])
{
  return append_flush_and_retract();
}