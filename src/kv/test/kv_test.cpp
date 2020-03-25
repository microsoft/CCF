// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../kv.h"
#include "../kv_serialiser.h"
#include "../node/entities.h"
#include "../node/history.h"
#include "ds/logger.h"
#include "enclave/app_interface.h"
#include "node/encryptor.h"

#include <doctest/doctest.h>
#include <msgpack/msgpack.hpp>
#include <string>
#include <vector>

using namespace ccf;

TEST_CASE("Map creation")
{
  Store kv_store;
  auto& map = kv_store.create<std::string, std::string>("map");

  INFO("Get a map that does not exist");
  {
    // Macros can't handle commas, so we need a single named template argument
    using StringString = Store::Map<std::string, std::string>;
    REQUIRE(kv_store.get<StringString>("invalid_map") == nullptr);
  }

  INFO("Compare different maps");
  {
    auto& map2 = kv_store.create<std::string, std::string>("map2");
    REQUIRE(map != map2);
  }

  INFO("Can't create map that already exists");
  {
    using StringString = Store::Map<std::string, std::string>;
    REQUIRE_THROWS_AS(kv_store.create<StringString>("map"), std::logic_error);
  }

  INFO("Can't get a map with the wrong type");
  {
    using IntInt = Store::Map<int, int>;
    REQUIRE(kv_store.get<IntInt>("map") == nullptr);
    using IntString = Store::Map<int, std::string>;
    REQUIRE(kv_store.get<IntString>("map") == nullptr);
    using StringInt = Store::Map<std::string, int>;
    REQUIRE(kv_store.get<StringInt>("map") == nullptr);
  }

  INFO("Can create a map with a previously invalid name");
  {
    using StringString = Store::Map<std::string, std::string>;
    CHECK_NOTHROW(kv_store.create<StringString>("version"));
  }
}

TEST_CASE("Reads/writes and deletions")
{
  Store kv_store;
  auto& map = kv_store.create<std::string, std::string>(
    "map", kv::SecurityDomain::PUBLIC);

  constexpr auto k = "key";
  constexpr auto invalid_key = "invalid_key";
  constexpr auto v1 = "value1";

  INFO("Start empty transaction");
  {
    Store::Tx tx;
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    REQUIRE_THROWS_AS(tx.commit(), std::logic_error);
  }

  INFO("Read own writes");
  {
    Store::Tx tx;
    auto view = tx.get_view(map);
    auto v = view->get(k);
    REQUIRE(!v.has_value());
    view->put(k, v1);
    auto va = view->get(k);
    REQUIRE(va.has_value());
    REQUIRE(va.value() == v1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  INFO("Read previous writes");
  {
    Store::Tx tx;
    auto view = tx.get_view(map);
    auto v = view->get(k);
    REQUIRE(v.has_value());
    REQUIRE(v.value() == v1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  INFO("Remove keys");
  {
    Store::Tx tx;
    Store::Tx tx2;
    auto view = tx.get_view(map);
    view->put(k, v1);

    REQUIRE(!view->remove(invalid_key));
    REQUIRE(view->remove(k));
    auto va = view->get(k);
    REQUIRE(!va.has_value());

    view->put(k, v1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    auto view2 = tx2.get_view(map);
    REQUIRE(view2->remove(k));
  }

  INFO("Remove key that was deleted from state");
  {
    Store::Tx tx;
    Store::Tx tx2;
    Store::Tx tx3;
    auto view = tx.get_view(map);
    view->put(k, v1);
    auto va = view->get_globally_committed(k);
    REQUIRE(!va.has_value());
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    auto view2 = tx2.get_view(map);
    REQUIRE(view2->remove(k));
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK);

    auto view3 = tx3.get_view(map);
    auto vc = view3->get(k);
    REQUIRE(!vc.has_value());
  }

  INFO("Test early temination of KV foreach");
  {
    Store::Tx tx;
    auto view = tx.get_view(map);
    view->put("key1", "value1");
    view->put("key2", "value2");
    size_t ctr = 0;
    view->foreach([&ctr](const auto& key, const auto& value) {
      ++ctr;
      return false;
    });
    REQUIRE(ctr == 1);
  }
}

TEST_CASE("Rollback and compact")
{
  Store kv_store;
  auto& map = kv_store.create<std::string, std::string>(
    "map", kv::SecurityDomain::PUBLIC);

  constexpr auto k = "key";
  constexpr auto v1 = "value1";

  INFO("Do not read transactions that have been rolled back");
  {
    Store::Tx tx;
    Store::Tx tx2;
    auto view = tx.get_view(map);
    view->put(k, v1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    kv_store.rollback(0);
    auto view2 = tx2.get_view(map);
    auto v = view2->get(k);
    REQUIRE(!v.has_value());
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK);
  }

  INFO("Read committed key");
  {
    Store::Tx tx;
    Store::Tx tx2;
    auto view = tx.get_view(map);
    view->put(k, v1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    kv_store.compact(view->end_order());

    auto view2 = tx2.get_view(map);
    auto va = view2->get_globally_committed(k);
    REQUIRE(va.has_value());
    REQUIRE(va.value() == v1);
  }

  INFO("Read deleted committed key");
  {
    Store::Tx tx;
    Store::Tx tx2;
    auto view = tx.get_view(map);
    REQUIRE(view->remove(k));
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    kv_store.compact(view->end_order());

    auto view2 = tx2.get_view(map);
    auto va = view2->get_globally_committed(k);
    REQUIRE(!va.has_value());
  }
}

TEST_CASE("Clear entire store")
{
  Store kv_store;
  auto& map1 = kv_store.create<std::string, std::string>(
    "map1", kv::SecurityDomain::PUBLIC);
  auto& map2 = kv_store.create<std::string, std::string>(
    "map2", kv::SecurityDomain::PUBLIC);

  INFO("Commit a transaction over two maps");
  {
    Store::Tx tx;
    Store::Tx tx2;
    auto [view1, view2] = tx.get_view(map1, map2);
    view1->put("key1", "value1");
    view2->put("key2", "value2");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    auto [view1_, view2_] = tx2.get_view(map1, map2);
    REQUIRE(view1_->get("key1") == "value1");
    REQUIRE(view2_->get("key2") == "value2");
  }

  INFO("Clear the entire store and make sure it is empty");
  {
    Store::Tx tx;
    Store::Tx tx2;
    auto [view1, view2] = tx.get_view(map1, map2);

    kv_store.clear();

    REQUIRE(kv_store.current_version() == 0);
    REQUIRE(kv_store.commit_version() == 0);
    REQUIRE(view1->get("key1") == "value1");
    auto [view1_, view2_] = tx2.get_view(map1, map2);
    REQUIRE_FALSE(view1_->get("key1").has_value());
    REQUIRE_FALSE(view2_->get("key2").has_value());
  }
}

TEST_CASE("Local commit hooks")
{
  using State = Store::Map<std::string, std::string>::State;
  using Write = Store::Map<std::string, std::string>::Write;
  std::vector<Write> local_writes;
  std::vector<Write> global_writes;

  auto local_hook = [&](kv::Version v, const State& s, const Write& w) {
    local_writes.push_back(w);
  };
  auto global_hook = [&](kv::Version v, const State& s, const Write& w) {
    global_writes.push_back(w);
  };

  Store kv_store;
  auto& map = kv_store.create<std::string, std::string>(
    "map", kv::SecurityDomain::PUBLIC, local_hook, global_hook);

  INFO("Write with hooks");
  {
    Store::Tx tx;
    auto view = tx.get_view(map);
    view->put("key", "value1");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    REQUIRE(global_writes.size() == 0);
    REQUIRE(local_writes.size() == 1);
    REQUIRE(local_writes.front().at("key").value == "value1");

    local_writes.clear();
  }

  INFO("Write without hooks");
  {
    map.set_local_hook(nullptr);
    map.set_global_hook(nullptr);

    Store::Tx tx;
    auto view = tx.get_view(map);
    view->put("key", "value2");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    REQUIRE(local_writes.size() == 0);
    REQUIRE(global_writes.size() == 0);
  }

  INFO("Write with hook again");
  {
    map.set_local_hook(local_hook);
    map.set_global_hook(global_hook);

    Store::Tx tx;
    auto view = tx.get_view(map);
    view->put("key", "value3");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    REQUIRE(global_writes.size() == 0);
    REQUIRE(local_writes.size() == 1);
    REQUIRE(local_writes.front().at("key").value == "value3");

    local_writes.clear();
  }
}

TEST_CASE("Global commit hooks")
{
  using State = Store::Map<std::string, std::string>::State;
  using Write = Store::Map<std::string, std::string>::Write;
  struct GlobalHookInput
  {
    kv::Version version;
    Write writes;
  };

  std::vector<GlobalHookInput> global_writes;

  auto global_hook = [&](kv::Version v, const State& s, const Write& w) {
    global_writes.emplace_back(GlobalHookInput({v, w}));
  };

  Store kv_store;
  auto& map_with_hook = kv_store.create<std::string, std::string>(
    "map_with_hook", kv::SecurityDomain::PUBLIC, nullptr, global_hook);
  auto& map_no_hook = kv_store.create<std::string, std::string>(
    "map_no_hook", kv::SecurityDomain::PUBLIC);

  INFO("Compact an empty store");
  {
    kv_store.compact(0);

    REQUIRE(global_writes.size() == 0);
  }

  INFO("Compact one transaction");
  {
    Store::Tx tx1;
    auto view_hook = tx1.get_view(map_with_hook);
    view_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == kv::CommitSuccess::OK);

    kv_store.compact(1);

    REQUIRE(global_writes.size() == 1);
    REQUIRE(global_writes.at(0).version == 1);
    REQUIRE(global_writes.at(0).writes.at("key1").value == "value1");

    global_writes.clear();
    kv_store.clear();
  }

  INFO("Compact beyond the last map version");
  {
    Store::Tx tx1, tx2, tx3;
    auto view_hook = tx1.get_view(map_with_hook);
    view_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == kv::CommitSuccess::OK);

    view_hook = tx2.get_view(map_with_hook);
    view_hook->put("key2", "value2");
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK);

    // This does not affect map_with_hook but still increments the current
    // version of the store
    auto view_no_hook = tx3.get_view(map_no_hook);
    view_no_hook->put("key3", "value3");
    REQUIRE(tx3.commit() == kv::CommitSuccess::OK);

    kv_store.compact(3);

    // Only the changes made to map_with_hook should be passed to the global
    // hook
    REQUIRE(global_writes.size() == 2);
    REQUIRE(global_writes.at(0).version == 1);
    REQUIRE(global_writes.at(0).writes.at("key1").value == "value1");
    REQUIRE(global_writes.at(1).version == 2);
    REQUIRE(global_writes.at(1).writes.at("key2").value == "value2");

    global_writes.clear();
    kv_store.clear();
  }

  INFO("Compact in between two map versions");
  {
    Store::Tx tx1, tx2, tx3;
    auto view_hook = tx1.get_view(map_with_hook);
    view_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == kv::CommitSuccess::OK);

    // This does not affect map_with_hook but still increments the current
    // version of the store
    auto view_no_hook = tx2.get_view(map_no_hook);
    view_no_hook->put("key2", "value2");
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK);

    view_hook = tx3.get_view(map_with_hook);
    view_hook->put("key3", "value3");
    REQUIRE(tx3.commit() == kv::CommitSuccess::OK);

    kv_store.compact(2);

    // Only the changes made to map_with_hook should be passed to the global
    // hook
    REQUIRE(global_writes.size() == 1);
    REQUIRE(global_writes.at(0).version == 1);
    REQUIRE(global_writes.at(0).writes.at("key1").value == "value1");

    global_writes.clear();
    kv_store.clear();
  }

  INFO("Compact twice");
  {
    Store::Tx tx1, tx2;
    auto view_hook = tx1.get_view(map_with_hook);
    view_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == kv::CommitSuccess::OK);

    kv_store.compact(1);
    global_writes.clear();

    view_hook = tx2.get_view(map_with_hook);
    view_hook->put("key2", "value2");
    REQUIRE(tx2.commit() == kv::CommitSuccess::OK);

    kv_store.compact(2);

    // Only writes since the last compact are passed to the global hook
    REQUIRE(global_writes.size() == 1);
    REQUIRE(global_writes.at(0).version == 2);
    REQUIRE(global_writes.at(0).writes.at("key2").value == "value2");

    global_writes.clear();
    kv_store.clear();
  }
}

TEST_CASE("Clone schema")
{
  auto encryptor = std::make_shared<ccf::NullTxEncryptor>();
  Store store;
  store.set_encryptor(encryptor);

  auto& public_map =
    store.create<size_t, std::string>("public", kv::SecurityDomain::PUBLIC);
  auto& private_map = store.create<size_t, std::string>("private");
  Store::Tx tx1(store.next_version());
  auto [view1, view2] = tx1.get_view(public_map, private_map);
  view1->put(42, "aardvark");
  view2->put(14, "alligator");
  auto [success, reqid, data] = tx1.commit_reserved();
  REQUIRE(success == kv::CommitSuccess::OK);

  Store clone;
  clone.clone_schema(store);
  clone.set_encryptor(encryptor);

  REQUIRE(clone.deserialise(data) == kv::DeserialiseSuccess::PASS);
}

TEST_CASE("Deserialise return status")
{
  Store store;

  auto& signatures = store.create<ccf::Signatures>(
    ccf::Tables::SIGNATURES, kv::SecurityDomain::PUBLIC);
  auto& nodes =
    store.create<ccf::Nodes>(ccf::Tables::NODES, kv::SecurityDomain::PUBLIC);
  auto& data = store.create<size_t, size_t>("data", kv::SecurityDomain::PUBLIC);

  auto kp = tls::make_key_pair();

  auto history =
    std::make_shared<ccf::NullTxHistory>(store, 0, *kp, signatures, nodes);
  store.set_history(history);

  {
    Store::Tx tx(store.next_version());
    auto data_view = tx.get_view(data);
    data_view->put(42, 42);
    auto [success, reqid, data] = tx.commit_reserved();
    REQUIRE(success == kv::CommitSuccess::OK);

    REQUIRE(store.deserialise(data) == kv::DeserialiseSuccess::PASS);
  }

  {
    Store::Tx tx(store.next_version());
    auto sig_view = tx.get_view(signatures);
    ccf::Signature sigv(0, 2);
    sig_view->put(0, sigv);
    auto [success, reqid, data] = tx.commit_reserved();
    REQUIRE(success == kv::CommitSuccess::OK);

    REQUIRE(store.deserialise(data) == kv::DeserialiseSuccess::PASS_SIGNATURE);
  }

  INFO("Signature transactions with additional contents should fail");
  {
    Store::Tx tx(store.next_version());
    auto [sig_view, data_view] = tx.get_view(signatures, data);
    ccf::Signature sigv(0, 2);
    sig_view->put(0, sigv);
    data_view->put(43, 43);
    auto [success, reqid, data] = tx.commit_reserved();
    REQUIRE(success == kv::CommitSuccess::OK);

    REQUIRE(store.deserialise(data) == kv::DeserialiseSuccess::FAILED);
  }
}

TEST_CASE("map swap between stores")
{
  auto encryptor = std::make_shared<ccf::NullTxEncryptor>();
  Store s1;
  s1.set_encryptor(encryptor);

  auto& d1 = s1.create<size_t, size_t>("data");
  auto& pd1 =
    s1.create<size_t, size_t>("public_data", kv::SecurityDomain::PUBLIC);

  Store s2;
  s2.set_encryptor(encryptor);
  auto& d2 = s2.create<size_t, size_t>("data");
  auto& pd2 =
    s2.create<size_t, size_t>("public_data", kv::SecurityDomain::PUBLIC);

  {
    Store::Tx tx;
    auto v = tx.get_view(d1);
    v->put(42, 42);
    tx.commit();
  }

  {
    Store::Tx tx;
    auto v = tx.get_view(pd1);
    v->put(14, 14);
    tx.commit();
  }

  {
    Store::Tx tx;
    auto v = tx.get_view(d2);
    v->put(41, 41);
    tx.commit();
  }

  s2.swap_private_maps(s1);

  {
    Store::Tx tx;
    auto v = tx.get_view(d1);
    auto val = v->get(41);
    REQUIRE_FALSE(v->get(42).has_value());
    REQUIRE(val.has_value());
    REQUIRE(val.value() == 41);
  }

  {
    Store::Tx tx;
    auto v = tx.get_view(pd1);
    auto val = v->get(14);
    REQUIRE(val.has_value());
    REQUIRE(val.value() == 14);
  }

  {
    Store::Tx tx;
    auto v = tx.get_view(d2);
    auto val = v->get(42);
    REQUIRE_FALSE(v->get(41).has_value());
    REQUIRE(val.has_value());
    REQUIRE(val.value() == 42);
  }

  {
    Store::Tx tx;
    auto v = tx.get_view(pd2);
    REQUIRE_FALSE(v->get(14).has_value());
  }
}

TEST_CASE("invalid map swaps")
{
  {
    Store s1;
    s1.create<size_t, size_t>("one");

    Store s2;
    s2.create<size_t, size_t>("one");
    s2.create<size_t, size_t>("two");

    REQUIRE_THROWS_WITH(
      s2.swap_private_maps(s1),
      "Private map list mismatch during swap, missing at least two");
  }

  {
    Store s1;
    s1.create<size_t, size_t>("one");
    s1.create<size_t, size_t>("two");

    Store s2;
    s2.create<size_t, size_t>("one");

    REQUIRE_THROWS_WITH(
      s2.swap_private_maps(s1),
      "Private map list mismatch during swap, two not found");
  }
}

TEST_CASE("private recovery map swap")
{
  auto encryptor = std::make_shared<ccf::NullTxEncryptor>();
  Store s1;
  s1.set_encryptor(encryptor);
  auto& priv1 = s1.create<size_t, size_t>("private");
  auto& pub1 =
    s1.create<size_t, std::string>("public", kv::SecurityDomain::PUBLIC);

  Store s2;
  s2.set_encryptor(encryptor);
  auto& priv2 = s2.create<size_t, size_t>("private");
  auto& pub2 =
    s2.create<size_t, std::string>("public", kv::SecurityDomain::PUBLIC);

  INFO("Populate s1 with public entries");
  // We compact twice, deliberately. A public KV during recovery
  // would have compacted some number of times.
  {
    Store::Tx tx;
    auto v = tx.get_view(pub1);
    v->put(42, "42");
    tx.commit();
  }
  {
    Store::Tx tx;
    auto v = tx.get_view(pub1);
    v->put(42, "43");
    tx.commit();
  }
  s1.compact(s1.current_version());
  {
    Store::Tx tx;
    auto v = tx.get_view(pub1);
    v->put(44, "44");
    tx.commit();
  }
  s1.compact(s1.current_version());
  {
    Store::Tx tx;
    auto v = tx.get_view(pub1);
    v->put(45, "45");
    tx.commit();
  }

  INFO("Populate s2 with private entries");
  // We compact only once, at a lower index than we did for the public
  // KV, which is what we expect during recovery of the private KV.
  {
    Store::Tx tx;
    auto v = tx.get_view(priv2);
    v->put(12, 12);
    tx.commit();
  }
  s2.compact(s2.current_version());
  {
    Store::Tx tx;
    auto v = tx.get_view(priv2);
    v->put(13, 13);
    tx.commit();
  }

  INFO("Swap in private maps");
  s1.swap_private_maps(s2);

  INFO("Check state looks as expected in s1");
  {
    Store::Tx tx;
    auto [priv, pub] = tx.get_view(priv1, pub1);
    {
      auto val = pub->get(42);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "43");

      val = pub->get(44);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "44");

      val = pub->get(45);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "45");

      REQUIRE(s1.commit_version() == 3);
    }
    {
      auto val = priv->get(12);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == 12);

      val = priv->get(13);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == 13);
    }
  }

  INFO("Check committed state looks as expected in s1");
  {
    Store::Tx tx;
    tx.set_read_committed();
    auto [priv, pub] = tx.get_view(priv1, pub1);
    {
      auto val = pub->get(42);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "43");

      val = pub->get(44);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "44");

      val = pub->get(45);
      REQUIRE_FALSE(val.has_value());
    }
    {
      auto val = priv->get(12);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == 12);

      val = priv->get(13);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == 13);

      // Uncompacted state is visible, which is expected, but isn't
      // something that would happen in recovery (only compacted state
      // would be swapped in). There is deliberately no check for compacted
      // state later than the compact level on the public KV, as this is
      // impossible during recovery.
    }
  }
}

TEST_CASE("Conflict resolution")
{
  Store kv_store;
  auto& map = kv_store.create<std::string, std::string>(
    "map", kv::SecurityDomain::PUBLIC);

  auto try_write = [&](Store::Tx& tx, const std::string& s) {
    auto view = tx.get_view(map);

    // Introduce read-dependency
    view->get("foo");
    view->put("foo", s);

    view->put(s, s);
  };

  auto confirm_state = [&](
                         const std::vector<std::string>& present,
                         const std::vector<std::string>& missing) {
    Store::Tx tx;
    auto view = tx.get_view(map);

    for (const auto& s : present)
    {
      const auto it = view->get(s);
      REQUIRE(it.has_value());
      REQUIRE(it.value() == s);
    }

    for (const auto& s : missing)
    {
      const auto it = view->get(s);
      REQUIRE(!it.has_value());
    }
  };

  // Simulate parallel execution by interleaving tx steps
  Store::Tx tx1;
  Store::Tx tx2;

  // First transaction tries to write a value, depending on initial version
  try_write(tx1, "bar");

  {
    // A second transaction is committed, conflicting with the first
    try_write(tx2, "baz");
    const auto res2 = tx2.commit();
    REQUIRE(res2 == kv::CommitSuccess::OK);

    confirm_state({"baz"}, {"bar"});
  }

  // Trying to commit first transaction produces a conflict
  auto res1 = tx1.commit();
  REQUIRE(res1 == kv::CommitSuccess::CONFLICT);
  confirm_state({"baz"}, {"bar"});

  // First transaction is rerun with same object, producing different result
  try_write(tx1, "buzz");

  // Expected results are committed
  res1 = tx1.commit();
  REQUIRE(res1 == kv::CommitSuccess::OK);
  confirm_state({"baz", "buzz"}, {"bar"});

  // Re-running a _committed_ transaction is exceptionally bad
  REQUIRE_THROWS(tx1.commit());
  REQUIRE_THROWS(tx2.commit());
}