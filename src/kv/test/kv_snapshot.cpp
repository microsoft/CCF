// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv/kv_serialiser.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/tx.h"

#include <doctest/doctest.h>

struct MapTypes
{
  using StringString = kv::Map<std::string, std::string>;
  using NumNum = kv::Map<size_t, size_t>;
  using NumString = kv::Map<size_t, std::string>;
  using StringNum = kv::Map<std::string, size_t>;
};

TEST_CASE("Simple snapshot" * doctest::test_suite("snapshot"))
{
  const char* map_name = "map";
  kv::SecurityDomain security_domain = kv::SecurityDomain::PUBLIC;
  kv::Store kv_store;
  auto& map =
    kv_store.create<MapTypes::StringString>(map_name, security_domain);

  INFO("Apply transactions to original store");
  {
    kv::Tx tx1, tx2;
    auto view_1 = tx1.get_view(map);
    auto view_2 = tx2.get_view(map);

    view_1->put("foo", "foo");
    view_2->put("bar", "bar");

    REQUIRE(tx1.commit() == kv::CommitSuccess::OK);
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK);

    kv::Tx tx3;
    auto view_3 = tx1.get_view(map);
    view_3->put("baz", "baz");
    // Do not commit tx3
  }

  auto s_1 = kv_store.snapshot(1);
  auto s_2 = kv_store.snapshot(2);

  INFO("Verify content of snapshot");
  {
    auto& vec_s = s_1->get_snapshots();
    for (auto& s : vec_s)
    {
      REQUIRE_EQ(s->get_name(), map_name);
      REQUIRE_EQ(s->get_security_domain(), security_domain);
      REQUIRE_EQ(s->get_is_replicated(), true);
      REQUIRE_GT(s->get_serialized_size(), 0);
    }
  }

  INFO("Apply snapshot at 1 to new store");
  {
    kv::Store new_store;
    auto& new_map =
      new_store.create<MapTypes::StringString>(map_name, security_domain);
    new_store.deserialize(s_1);
    REQUIRE_EQ(new_store.current_version(), 1);

    kv::Tx tx1;
    auto view = tx1.get_view(new_map);

    auto v = view->get("foo");
    REQUIRE(v.has_value());
    REQUIRE(v.value() == "foo");

    v = view->get("bar");
    REQUIRE(!v.has_value());
    v = view->get("baz");
    REQUIRE(!v.has_value());
  }

  INFO("Apply snapshot at 2 to new store");
  {
    kv::Store new_store;
    auto& new_map =
      new_store.create<MapTypes::StringString>(map_name, security_domain);
    new_store.deserialize(s_2);
    REQUIRE_EQ(new_store.current_version(), 2);

    kv::Tx tx1;
    auto view = tx1.get_view(new_map);

    auto v = view->get("foo");
    REQUIRE(v.has_value());
    REQUIRE(v.value() == "foo");

    v = view->get("bar");
    REQUIRE(v.has_value());
    REQUIRE(v.value() == "bar");
    v = view->get("baz");
    REQUIRE(!v.has_value());
  }
}