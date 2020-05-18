// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv/serialise_early.h"

#include "kv/store.h"

#include <doctest/doctest.h>

TEST_CASE("Foo")
{
  kv::Store kv_store;
  // using TMap = kv::typed::Map<std::string, std::string>;
  // auto& map = kv_store.create<TMap>("map");

  // TODO: Views should be managed by Tx, this is a leak
  //auto view = map.create_view(0);

  // {
  //   const auto it = view->get(5);
  //   CHECK(!it.has_value());
  // }

  // CHECK(view->put(5, 42));

  // {
  //   const auto it = view->get(5);
  //   CHECK(it.has_value());
  //   CHECK(*it == 42);
  // }
}
