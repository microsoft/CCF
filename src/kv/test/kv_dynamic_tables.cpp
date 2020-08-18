// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "kv/store.h"
#include "kv/test/null_encryptor.h"

#include <doctest/doctest.h>

struct MapTypes
{
  using StringString = kv::Map<std::string, std::string>;
  using NumNum = kv::Map<size_t, size_t>;
  using NumString = kv::Map<size_t, std::string>;
  using StringNum = kv::Map<std::string, size_t>;
};

TEST_CASE("Basic dynamic table" * doctest::test_suite("dynamic"))
{
  kv::Store kv_store;

  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  constexpr auto map_name = "mapA";

  INFO("Dynamically created maps can be used like normal maps");

  {
    auto map_a = kv_store.get<MapTypes::StringString>(map_name);
    REQUIRE(map_a == nullptr);
  }

  {
    auto tx = kv_store.create_tx();

    auto view = tx.get_view2<MapTypes::StringString>(map_name);
    view->put("foo", "bar");

    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  {
    INFO("Old style access");
    auto map_a = kv_store.get<MapTypes::StringString>(map_name);
    REQUIRE(map_a != nullptr);

    auto tx = kv_store.create_tx();

    auto view = tx.get_view(*map_a);
    const auto it = view->get("foo");
    REQUIRE(it.has_value());
    REQUIRE(it.value() == "bar");
  }

  {
    INFO("New style access");
    auto tx = kv_store.create_tx();

    auto view = tx.get_view2<MapTypes::StringString>(map_name);
    const auto it = view->get("foo");
    REQUIRE(it.has_value());
    REQUIRE(it.value() == "bar");
  }

  {
    INFO("Dynamic tables remain through compaction");
    kv_store.compact(kv_store.current_version());

    auto map_a = kv_store.get<MapTypes::StringString>(map_name);
    REQUIRE(map_a != nullptr);

    auto tx = kv_store.create_tx();

    auto view = tx.get_view(*map_a);
    const auto it = view->get("foo");
    REQUIRE(it.has_value());
    REQUIRE(it.value() == "bar");
  }

  {
    INFO("Multiple dynamic tables can be created in a single tx");
    auto tx = kv_store.create_tx();

    auto [v1, v2] =
      tx.get_view2<MapTypes::StringString, MapTypes::StringNum>("1", "2");
    auto [v2a, v3] =
      tx.get_view2<MapTypes::StringNum, MapTypes::NumString>("2", "3");

    REQUIRE(v2 == v2a);

    v1->put("foo", "bar");
    v3->put(42, "hello");

    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    REQUIRE(kv_store.get<MapTypes::StringString>("1") != nullptr);
    REQUIRE(kv_store.get<MapTypes::NumString>("3") != nullptr);

    // No writes => map is not created
    REQUIRE(kv_store.get<MapTypes::StringNum>("2") == nullptr);
  }
}

TEST_CASE("Dynamic table opacity" * doctest::test_suite("dynamic"))
{
  kv::Store kv_store;

  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  constexpr auto map_name = "dynamic_map";

  auto tx1 = kv_store.create_tx();
  auto tx2 = kv_store.create_tx();

  auto view1 = tx1.get_view2<MapTypes::StringString>(map_name);
  view1->put("foo", "bar");
  REQUIRE(view1->get("foo").value() == "bar");

  auto view2 = tx2.get_view2<MapTypes::StringString>(map_name);
  view2->put("foo", "baz");
  REQUIRE(view2->get("foo").value() == "baz");

  {
    INFO("Maps are not visible externally until commit");
    REQUIRE(kv_store.get<MapTypes::StringString>(map_name) == nullptr);
  }

  {
    INFO("First transaction commits successfully");
    REQUIRE(tx1.commit() == kv::CommitSuccess::OK);
  }

  {
    INFO("Committed transaction results are persisted");
    auto txx = kv_store.create_tx();
    auto view = txx.get_view2<MapTypes::StringString>(map_name);
    const auto v = view->get("foo");
    REQUIRE(v.has_value());
    REQUIRE(v.value() == "bar");
  }

  {
    INFO("Second transaction conflicts");
    REQUIRE(tx2.commit() == kv::CommitSuccess::CONFLICT);
  }

  {
    INFO("Conflicting transaction can be rerun, on existing map");
    auto tx3 = kv_store.create_tx();
    auto view3 = tx3.get_view2<MapTypes::StringString>(map_name);
    const auto v = view3->get("foo");
    REQUIRE(v.has_value());
    view3->put("foo", "baz");
    REQUIRE(view3->get("foo").value() == "baz");

    REQUIRE(tx3.commit() == kv::CommitSuccess::OK);
  }

  {
    REQUIRE(kv_store.get<MapTypes::StringString>(map_name) != nullptr);
  }

  {
    INFO("Subsequent transactions over dynamic map are persisted");
    auto tx4 = kv_store.create_tx();
    auto view4 = tx4.get_view2<MapTypes::StringString>(map_name);
    const auto v = view4->get("foo");
    REQUIRE(v.has_value());
    REQUIRE(v.value() == "baz");
  }
}

TEST_CASE(
  "Dynamic table visibility by version" * doctest::test_suite("dynamic"))
{
  kv::Store kv_store;

  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  auto& static_map = kv_store.create<MapTypes::StringString>("static_map");

  constexpr auto map_name = "dynamic_map";

  auto tx1 = kv_store.create_tx();
  auto tx2 = kv_store.create_tx();
  auto tx3 = kv_store.create_tx();
  auto tx4 = kv_store.create_tx();

  auto view1 = tx1.get_view2<MapTypes::StringString>(map_name);
  view1->put("foo", "bar");

  // Map created in tx1 is not visible
  auto view2 = tx2.get_view2<MapTypes::StringString>(map_name);
  REQUIRE(!view2->get("foo").has_value());

  // tx3 takes a read dependency at an early version, before the map is visible
  auto view3_static = tx3.get_view(static_map);

  REQUIRE(tx1.commit() == kv::CommitSuccess::OK);

  // Even after commit, the new map is not visible to tx3 because it is reading
  // from an earlier version
  auto view3 = tx3.get_view2<MapTypes::StringString>(map_name);
  REQUIRE(!view3->get("foo").has_value());

  // Map created in tx1 is visible, because tx4 first _reads_ (creates a
  // view) after tx1 has committed
  auto view4 = tx4.get_view2<MapTypes::StringString>(map_name);
  REQUIRE(view4->get("foo").has_value());
}

TEST_CASE("Mixed map dependencies" * doctest::test_suite("dynamic"))
{
  kv::Store kv_store;

  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  constexpr auto dynamic_map_a = "dynamic_map_a";
  constexpr auto dynamic_map_b = "dynamic_map_b";

  auto& static_map = kv_store.create<MapTypes::StringString>("static_map");

  SUBCASE("Parallel independent map creation")
  {
    auto tx1 = kv_store.create_tx();
    auto tx2 = kv_store.create_tx();

    auto view1 = tx1.get_view2<MapTypes::NumString>(dynamic_map_a);
    auto view2 = tx2.get_view2<MapTypes::StringNum>(dynamic_map_b);

    view1->put(42, "hello");
    view2->put("hello", 42);

    REQUIRE(tx1.commit() == kv::CommitSuccess::OK);
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK);
  }

  SUBCASE("Map creation blocked by standard conflict")
  {
    constexpr auto key = "foo";
    auto tx1 = kv_store.create_tx();
    {
      auto view1 = tx1.get_view(static_map);
      const auto v = view1->get(key);
      if (!v.has_value())
      {
        view1->put(key, "bar");
        auto dynamic_view = tx1.get_view2<MapTypes::NumString>(dynamic_map_a);
        dynamic_view->put(42, "hello world");
      }
    }

    auto tx2 = kv_store.create_tx();
    {
      auto view2 = tx2.get_view(static_map);
      const auto v = view2->get(key);
      if (!v.has_value())
      {
        view2->put(key, "bar");
        auto dynamic_view = tx2.get_view2<MapTypes::StringNum>(dynamic_map_b);
        dynamic_view->put("hello world", 42);
      }
    }

    REQUIRE(tx1.commit() == kv::CommitSuccess::OK);
    REQUIRE(tx2.commit() == kv::CommitSuccess::CONFLICT);

    REQUIRE(kv_store.get<MapTypes::NumString>(dynamic_map_a) != nullptr);
    REQUIRE(kv_store.get<MapTypes::StringNum>(dynamic_map_b) == nullptr);
  }
}

// TODO
// - Rollback deletes dynamic maps
// - If a transaction is mid-execution over a deleted-by-rollback map, it should
// continue safely (and fail with conflict)
// - Serialisation of map creation