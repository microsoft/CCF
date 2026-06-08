// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "../tpcc_tables.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

template <typename T>
void check_roundtrip(const T& t)
{
  tpcc::TpccSerialiser<T> serdes;

  // T may not have an equality operator, so we serialise twice and check the
  // (comparable) serialised forms match
  const auto ser = serdes.to_serialised(t);
  const auto des = serdes.from_serialised(ser);
  const auto ser2 = serdes.to_serialised(des);

  CHECK(ser == ser2);
}

TEST_CASE("Serialization")
{
  tpcc::Item item;
  item.id = 42;
  item.im_id = 100;
  item.price = 1.101f;
  memcpy(item.name.data(), "Item name", strlen("Item name"));
  memcpy(item.data.data(), "Item data", strlen("Item data"));

  check_roundtrip(item);
}