// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/nonstd.h"

#include <doctest/doctest.h>
#include <iostream>

void check_split_string(
  const std::string& s,
  char delim,
  const std::vector<std::string>& expected_elements)
{
  const auto split = nonstd::split_string(s, delim);
  REQUIRE(split.size() == expected_elements.size());
  for (size_t i = 0; i < split.size(); ++i)
  {
    REQUIRE(split[i] == expected_elements[i]);
  }
}

TEST_CASE("split_string" * doctest::test_suite("nonstd"))
{
  check_split_string("hello world", ' ', {"hello", "world"});
  check_split_string("hello", ' ', {"hello"});
  check_split_string(" hello ", ' ', {"", "hello", ""});
  check_split_string("/some/url/path", '/', {"", "some", "url", "path"});
}