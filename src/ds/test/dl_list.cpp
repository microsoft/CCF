// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/dl_list.h"

#include <cstddef>
#include <doctest/doctest.h>

using namespace ds;

struct Element
{
  size_t i;

  Element* prev;
  Element* next;
};

TEST_CASE(
  "Intrusive doubly-linked list" * doctest::test_suite("doubly linked list"))
{
  static constexpr size_t elements_count = 1000;
  DLList<Element> list;

  INFO("No-ops on empty list");
  {
    REQUIRE(list.is_empty());
    REQUIRE(list.get_head() == list.get_tail());
    list.clear();
    REQUIRE(list.is_empty());
    REQUIRE(list.get_head() == list.get_tail());
  }

  INFO("Fill list");
  {
    for (size_t i = 0; i < elements_count; i++)
    {
      auto* e = new Element{i};
      if (i % 2 == 0)
      {
        list.insert(e);
        REQUIRE(list.get_head() == e);
      }
      else
      {
        list.insert_back(e);
        REQUIRE(list.get_tail() == e);
      }
      REQUIRE(!list.is_empty());
      if (i > 0)
      {
        REQUIRE(list.get_head() != list.get_tail());
      }
    }
  }

  INFO("Pop elements until empty");
  {
    for (size_t i = 0; i < elements_count; i++)
    {
      Element* e = nullptr;
      if (i % 2 == 0)
      {
        auto h = list.get_head();
        e = list.pop();
        REQUIRE(e == h);
      }
      else
      {
        auto t = list.get_tail();
        e = list.pop_tail();
        REQUIRE(e == t);
      }
      delete e;
    }
    REQUIRE(list.is_empty());
  }
}