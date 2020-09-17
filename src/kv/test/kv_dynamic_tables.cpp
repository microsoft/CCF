// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"

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
    // NB: Don't access these maps old-style, because you need to know this
    // implementation detail that the map is _actually_ untyped
    auto map_a_wrong = kv_store.get<MapTypes::StringString>(map_name);
    REQUIRE(map_a_wrong == nullptr);

    auto map_a = kv_store.get<kv::untyped::Map>(map_name);
    REQUIRE(map_a != nullptr);
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

    auto tx = kv_store.create_tx();

    auto view = tx.get_view2<MapTypes::StringString>(map_name);
    const auto it = view->get("foo");
    REQUIRE(it.has_value());
    REQUIRE(it.value() == "bar");
  }

  const auto version_before = kv_store.current_version();

  constexpr auto new_map1 = "new_map1";
  constexpr auto new_map2 = "new_map2";
  constexpr auto new_map3 = "new_map3";

  {
    INFO("Multiple dynamic tables can be created in a single tx");
    auto tx = kv_store.create_tx();

    auto [v1, v2] = tx.get_view2<MapTypes::StringString, MapTypes::StringNum>(
      new_map1, new_map2);
    auto [v2a, v3] = tx.get_view2<MapTypes::StringNum, MapTypes::NumString>(
      new_map2, new_map3);

    REQUIRE(v2 == v2a);

    v1->put("foo", "bar");
    v3->put(42, "hello");

    auto va = tx.get_view2<MapTypes::StringString>(map_name);
    va->put("foo", "baz");

    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    {
      auto check_tx = kv_store.create_tx();
      auto check_va = check_tx.get_view2<MapTypes::StringString>(map_name);
      const auto v = check_va->get("foo");
      REQUIRE(v.has_value());
      REQUIRE(v.value() == "baz");
    }

    REQUIRE(kv_store.get<kv::untyped::Map>(new_map1) != nullptr);
    REQUIRE(kv_store.get<kv::untyped::Map>(new_map3) != nullptr);

    // No writes => map is not created
    REQUIRE(kv_store.get<kv::untyped::Map>(new_map2) == nullptr);
  }

  {
    INFO("Rollback can delete dynamic tables");
    kv_store.rollback(version_before);

    REQUIRE(kv_store.get<kv::untyped::Map>(new_map1) == nullptr);
    REQUIRE(kv_store.get<kv::untyped::Map>(new_map2) == nullptr);
    REQUIRE(kv_store.get<kv::untyped::Map>(new_map3) == nullptr);

    // Previously created map is retained
    REQUIRE(kv_store.get<kv::untyped::Map>(map_name) != nullptr);

    {
      INFO("Retained dynamic maps have their state rolled back");
      auto check_tx = kv_store.create_tx();
      auto check_va = check_tx.get_view2<MapTypes::StringString>(map_name);
      const auto v = check_va->get("foo");
      REQUIRE(v.has_value());
      REQUIRE(v.value() == "bar");
    }
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
    REQUIRE(kv_store.get<kv::untyped::Map>(map_name) != nullptr);
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
      const auto v = view1->get(key); // Introduce read-dependency
      view1->put(key, "bar");
      auto dynamic_view = tx1.get_view2<MapTypes::NumString>(dynamic_map_a);
      dynamic_view->put(42, "hello world");
    }

    auto tx2 = kv_store.create_tx();
    {
      auto view2 = tx2.get_view(static_map);
      const auto v = view2->get(key); // Introduce read-dependency
      view2->put(key, "bar");
      auto dynamic_view = tx2.get_view2<MapTypes::StringNum>(dynamic_map_b);
      dynamic_view->put("hello world", 42);
    }

    REQUIRE(tx1.commit() == kv::CommitSuccess::OK);
    REQUIRE(tx2.commit() == kv::CommitSuccess::CONFLICT);

    {
      auto tx3 = kv_store.create_tx();

      auto [view1, view2] =
        tx3.get_view2<MapTypes::NumString, MapTypes::StringNum>(
          dynamic_map_a, dynamic_map_b);

      const auto v1 = view1->get(42);
      REQUIRE(v1.has_value());
      REQUIRE(v1.value() == "hello world");

      const auto v2 = view2->get("hello world");
      REQUIRE_FALSE(v2.has_value());
    }

    REQUIRE(kv_store.get<kv::untyped::Map>(dynamic_map_a) != nullptr);
    REQUIRE(kv_store.get<MapTypes::StringNum>(dynamic_map_b) == nullptr);
  }
}

TEST_CASE("Dynamic map serialisation" * doctest::test_suite("dynamic"))
{
  auto consensus = std::make_shared<kv::StubConsensus>();
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();

  kv::Store kv_store(consensus);
  kv_store.set_encryptor(encryptor);

  kv::Store kv_store_target;
  kv_store_target.set_encryptor(encryptor);

  const auto map_name = "new_map";
  const auto key = "foo";
  const auto value = "bar";

  {
    INFO("Commit a map creation in source store");
    auto tx = kv_store.create_tx();
    auto view = tx.get_view2<MapTypes::StringString>(map_name);
    view->put(key, value);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  {
    INFO("Deserialise transaction in target store");
    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());

    REQUIRE(
      kv_store_target.deserialise(latest_data.value()) ==
      kv::DeserialiseSuccess::PASS);

    auto tx_target = kv_store_target.create_tx();
    auto view_target = tx_target.get_view2<MapTypes::StringString>(map_name);
    const auto v = view_target->get(key);
    REQUIRE(v.has_value());
    REQUIRE(v.value() == value);
  }
}

TEST_CASE("Dynamic map snapshot serialisation" * doctest::test_suite("dynamic"))
{
  kv::Store store;
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);

  constexpr auto map_name = "string_map";

  kv::Version snapshot_version;
  INFO("Create maps in original store");
  {
    auto tx1 = store.create_tx();
    auto view_1 = tx1.get_view2<MapTypes::StringString>(map_name);
    view_1->put("foo", "foo");
    REQUIRE(tx1.commit() == kv::CommitSuccess::OK);

    auto tx2 = store.create_tx();
    auto view_2 = tx2.get_view2<MapTypes::StringString>(map_name);
    view_2->put("bar", "bar");
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK);

    snapshot_version = tx2.commit_version();
  }

  INFO("Create snapshot of original store");
  auto snapshot = store.snapshot(snapshot_version);
  auto serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

  INFO("Apply snapshot to create maps in new store");
  {
    kv::Store new_store;
    new_store.set_encryptor(encryptor);
    new_store.deserialise_snapshot(serialised_snapshot);

    auto tx = new_store.create_tx();
    auto view = tx.get_view2<MapTypes::StringString>(map_name);

    const auto foo_v = view->get("foo");
    REQUIRE(foo_v.has_value());
    REQUIRE(foo_v.value() == "foo");

    const auto bar_v = view->get("bar");
    REQUIRE(bar_v.has_value());
    REQUIRE(bar_v.value() == "bar");
  }
}

TEST_CASE("Mid rollback safety" * doctest::test_suite("dynamic"))
{
  kv::Store kv_store;

  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  constexpr auto map_name = "my_new_map";

  const auto version_before = kv_store.current_version();

  {
    auto tx = kv_store.create_tx();

    auto view = tx.get_view2<MapTypes::StringString>(map_name);
    view->put("foo", "bar");

    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  {
    auto tx = kv_store.create_tx();
    auto view = tx.get_view2<MapTypes::StringString>(map_name);
    const auto v_0 = view->get("foo");
    REQUIRE(v_0.has_value());
    REQUIRE(v_0.value() == "bar");

    // Rollbacks may happen while a tx is executing, and these can delete the
    // maps this tx is executing over
    kv_store.rollback(version_before);

    const auto v_1 = view->get("foo");
    REQUIRE(v_0.has_value());
    REQUIRE(v_0.value() == "bar");

    auto view_after = tx.get_view2<MapTypes::StringString>(map_name);
    REQUIRE(view_after == view);

    view->put("foo", "baz");

    const auto result = tx.commit();
    REQUIRE(result == kv::CommitSuccess::CONFLICT);
  }
}

TEST_CASE(
  "Security domain is determined by map name" * doctest::test_suite("dynamic"))
{
  kv::Store kv_store;

  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  {
    auto tx = kv_store.create_tx();
    auto view = tx.get_view2<MapTypes::StringString>("public:foo");
    view->put("foo", "bar");

    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  {
    auto tx = kv_store.create_tx();
    auto view = tx.get_view2<MapTypes::StringString>("foo");
    view->put("hello", "world");

    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  {
    auto public_map = kv_store.get<kv::untyped::Map>("public:foo");
    REQUIRE(public_map != nullptr);
    REQUIRE(public_map->get_security_domain() == kv::SecurityDomain::PUBLIC);

    auto private_map = kv_store.get<kv::untyped::Map>("foo");
    REQUIRE(private_map != nullptr);
    REQUIRE(private_map->get_security_domain() == kv::SecurityDomain::PRIVATE);
  }

  {
    auto tx = kv_store.create_tx();
    auto [public_view, private_view] =
      tx.get_view2<MapTypes::StringString, MapTypes::StringString>(
        "public:foo", "foo");

    // These are _different views_ over _different maps_
    REQUIRE(public_view != private_view);

    const auto pub_v = public_view->get("foo");
    REQUIRE(pub_v.has_value());
    REQUIRE(pub_v.value() == "bar");

    const auto priv_v = private_view->get("hello");
    REQUIRE(priv_v.has_value());
    REQUIRE(priv_v.value() == "world");
  }
}

TEST_CASE("Swapping dynamic maps" * doctest::test_suite("dynamic"))
{
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();

  kv::Store s1;
  s1.set_encryptor(encryptor);

  {
    auto tx = s1.create_tx();
    auto [v0, v1] =
      tx.get_view2<MapTypes::StringString, MapTypes::NumString>("foo", "bar");
    v0->put("hello", "world");
    v1->put(42, "everything");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  {
    auto tx = s1.create_tx();
    auto [v0, v1] =
      tx.get_view2<MapTypes::StringString, MapTypes::StringNum>("foo", "baz");
    v0->put("hello", "goodbye");
    v1->put("saluton", 100);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  {
    // Create _public_ state in source store
    auto tx = s1.create_tx();
    auto v0 = tx.get_view2<MapTypes::StringString>("public:source_state");
    v0->put("store", "source");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  kv::Store s2;
  s2.set_encryptor(encryptor);

  // Ensure source store is at _at least_ the same version as source store
  while (s2.current_version() < s1.current_version())
  {
    // Create public state in target store, to confirm it is unaffected
    auto tx = s2.create_tx();
    auto v0 = tx.get_view2<MapTypes::StringString>("public:target_state");
    v0->put("store", "target");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  s1.compact(s1.current_version());

  s2.swap_private_maps(s1);

  {
    INFO("Private state is transferred");
    auto tx = s2.create_tx();

    auto [v0, v1, v2] = tx.get_view2<
      MapTypes::StringString,
      MapTypes::NumString,
      MapTypes::StringNum>("foo", "bar", "baz");

    const auto val0 = v0->get("hello");
    REQUIRE(val0.has_value());
    REQUIRE(val0.value() == "goodbye");

    const auto val1 = v1->get(42);
    REQUIRE(val1.has_value());
    REQUIRE(val1.value() == "everything");

    const auto val2 = v2->get("saluton");
    REQUIRE(val2.has_value());
    REQUIRE(val2.value() == 100);
  }

  {
    INFO("Public state is untouched");
    auto tx = s2.create_tx();

    auto [v0, v1] =
      tx.get_view2<MapTypes::StringString, MapTypes::StringString>(
        "public:source_state", "public:target_state");

    const auto val0 = v0->get("store");
    REQUIRE_FALSE(val0.has_value());

    const auto val1 = v1->get("store");
    REQUIRE(val1.has_value());
    REQUIRE(val1.value() == "target");
  }
}
