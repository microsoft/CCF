// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../ledger.h"

#include <doctest/doctest.h>
#include <string>

TEST_CASE("Read/Write test")
{
  ringbuffer::Circuit eio(1024);
  auto wf = ringbuffer::WriterFactory(eio);

  const std::vector<uint8_t> e1 = {1, 2, 3};
  const std::vector<uint8_t> e2 = {5, 5, 6, 7};
  {
    asynchost::Ledger l("testlog", wf);
    l.truncate(0);
    REQUIRE(l.get_last_idx() == 0);
    l.write_entry(e1.data(), e1.size());
    l.write_entry(e2.data(), e2.size());
  }

  asynchost::Ledger l("testlog", wf);
  REQUIRE(l.get_last_idx() == 2);
  auto r1 = l.read_entry(1);
  REQUIRE(e1 == r1);
  auto r2 = l.read_entry(2);
  REQUIRE(e2 == r2);
}

TEST_CASE("Entry sizes")
{
  ringbuffer::Circuit eio(1024);
  auto wf = ringbuffer::WriterFactory(eio);

  const std::vector<uint8_t> e1 = {1, 2, 3};
  const std::vector<uint8_t> e2 = {5, 5, 6, 7};

  asynchost::Ledger l("testlog", wf);
  l.truncate(0);
  REQUIRE(l.get_last_idx() == 0);
  l.write_entry(e1.data(), e1.size());
  l.write_entry(e2.data(), e2.size());

  REQUIRE(l.entry_size(1) == e1.size());
  REQUIRE(l.entry_size(2) == e2.size());
  REQUIRE(l.entry_size(0) == 0);
  REQUIRE(l.entry_size(3) == 0);

  REQUIRE(l.framed_entries_size(1, 1) == (e1.size() + sizeof(uint32_t)));
  REQUIRE(
    l.framed_entries_size(1, 2) ==
    (e1.size() + sizeof(uint32_t) + e2.size() + sizeof(uint32_t)));

  /*
    auto e = l.read_framed_entries(1, 1);
    for (auto c : e)
      std::cout << std::hex << (int)c;
    std::cout << std::endl;*/
}