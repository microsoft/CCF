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

  auto try_write = [&](kv::Tx& tx, const std::string& s) {
    auto view = tx.get_view(map);

    // Produce read-dependency
    view->get("foo");
    view->put("foo", s);

    view->put(s, s);
  };

  INFO("Simulate parallel execution by interleaving tx steps");
  {
    kv::Tx tx1;
    kv::Tx tx2;

    // First transaction tries to write a value, depending on initial version
    try_write(tx1, "bar");

    {
      // A second transaction is committed, conflicting with the first
      try_write(tx2, "baz");
      const auto res2 = tx2.commit();
      REQUIRE(res2 == kv::CommitSuccess::OK);
    }

    // Trying to commit first transaction produces a conflict
    auto res1 = tx1.commit();
    REQUIRE(res1 == kv::CommitSuccess::CONFLICT);

    // First transaction is rerun with same object, producing different result
    try_write(tx1, "buzz");

    // Expected results are committed
    res1 = tx1.commit();
    REQUIRE(res1 == kv::CommitSuccess::OK);
  }

  // now we serialize the KV that is in the mid point of the known versions
  std::unique_ptr<kv::AbstractStore::Snapshot> s = kv_store.snapshot(1);

  INFO("Verify content of snapshot");
  {
    auto& vec_s = s->get_snapshots();
    for (auto& s : vec_s)
    {
      REQUIRE_EQ(s->get_name(), map_name);
      REQUIRE_EQ(s->get_security_domain(), security_domain);
      REQUIRE_EQ(s->get_is_replicated(), true);
      REQUIRE_GT(s->get_buffer().size(), 0);
    }
  }

  kv::Store new_store;
  auto& new_map =
    new_store.create<MapTypes::StringString>(map_name, security_domain);

  INFO("Apply snapshot to new store");
  {
    new_store.deserialize(s);
    REQUIRE_EQ(new_store.current_version(), 1);

    kv::Tx tx1;
    auto view = tx1.get_view(new_map);

    auto v = view->get("baz");
    REQUIRE(v.has_value());
    REQUIRE(v.value() == "baz");

    v = view->get("buzz");
    REQUIRE(v.has_value());
    REQUIRE(v.value() == "buzz");
  }
}