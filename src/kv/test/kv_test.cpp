// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/logger.h"
#include "enclave/app_interface.h"
#include "kv/kv_serialiser.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "node/entities.h"
#include "node/history.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#undef FAIL
#include <msgpack/msgpack.hpp>
#include <set>
#include <string>
#include <vector>

struct MapTypes
{
  using StringString = kv::Map<std::string, std::string>;
  using NumNum = kv::Map<size_t, size_t>;
  using NumString = kv::Map<size_t, std::string>;
  using StringNum = kv::Map<std::string, size_t>;
};

TEST_CASE("Map name parsing")
{
  using SD = kv::SecurityDomain;
  using AC = kv::AccessCategory;

  auto parse = kv::parse_map_name;
  auto mp = std::make_pair<SD, AC>;

  REQUIRE(parse("foo") == mp(SD::PRIVATE, AC::APPLICATION));
  REQUIRE(parse("public:foo") == mp(SD::PUBLIC, AC::APPLICATION));
  REQUIRE(parse("ccf.gov.foo") == mp(SD::PRIVATE, AC::GOVERNANCE));
  REQUIRE(parse("public:ccf.gov.foo") == mp(SD::PUBLIC, AC::GOVERNANCE));
  REQUIRE(parse("ccf.internal.foo") == mp(SD::PRIVATE, AC::INTERNAL));
  REQUIRE(parse("public:ccf.internal.foo") == mp(SD::PUBLIC, AC::INTERNAL));

  REQUIRE_THROWS(parse("ccf.foo"));
  REQUIRE_THROWS(parse("public:ccf.foo"));

  // Typos may lead to unexpected behaviour!
  REQUIRE(parse("publik:ccf.gov.foo") == mp(SD::PRIVATE, AC::APPLICATION));
  REQUIRE(parse("PUBLIC:ccf.gov.foo") == mp(SD::PRIVATE, AC::APPLICATION));
  REQUIRE(parse("public:Ccf.gov.foo") == mp(SD::PUBLIC, AC::APPLICATION));

  REQUIRE(parse("ccf_foo") == mp(SD::PRIVATE, AC::APPLICATION));
  REQUIRE(parse("public:ccf_foo") == mp(SD::PUBLIC, AC::APPLICATION));
}

TEST_CASE("Reads/writes and deletions")
{
  kv::Store kv_store;

  MapTypes::StringString map("public:map");

  constexpr auto k = "key";
  constexpr auto invalid_key = "invalid_key";
  constexpr auto v1 = "value1";

  INFO("Start empty transaction");
  {
    auto tx = kv_store.create_tx();
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    REQUIRE_THROWS_AS(tx.commit(), std::logic_error);
  }

  INFO("Read own writes");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    REQUIRE(!handle->has(k));
    auto v = handle->get(k);
    REQUIRE(!v.has_value());
    REQUIRE(!handle->get_version_of_previous_write(k).has_value());
    handle->put(k, v1);
    REQUIRE(handle->has(k));
    auto va = handle->get(k);
    REQUIRE(va.has_value());
    REQUIRE(va.value() == v1);
    REQUIRE(!handle->get_version_of_previous_write(k).has_value());
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  const auto commit_v = kv_store.current_version();

  INFO("Read previous writes");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    REQUIRE(handle->has(k));
    auto v = handle->get(k);
    REQUIRE(v.has_value());
    REQUIRE(v.value() == v1);
    const auto ver = handle->get_version_of_previous_write(k);
    REQUIRE(ver.has_value());
    REQUIRE(ver.value() == commit_v);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  INFO("Remove keys");
  {
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put(k, v1);

      REQUIRE(!handle->has(invalid_key));
      REQUIRE(!handle->remove(invalid_key));
      REQUIRE(!handle->get_version_of_previous_write(invalid_key).has_value());
      REQUIRE(handle->get_version_of_previous_write(k).has_value());
      REQUIRE(handle->get_version_of_previous_write(k).value() == commit_v);
      REQUIRE(handle->remove(k));
      REQUIRE(handle->get_version_of_previous_write(k).has_value());
      REQUIRE(handle->get_version_of_previous_write(k).value() == commit_v);
      REQUIRE(!handle->has(k));
      auto va = handle->get(k);
      REQUIRE(!va.has_value());

      handle->put(k, v1);
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    }

    {
      auto tx2 = kv_store.create_tx();
      auto handle2 = tx2.rw(map);
      REQUIRE(handle2->has(k));
      REQUIRE(handle2->remove(k));
    }
  }

  INFO("Remove key that was deleted from state");
  {
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put(k, v1);
      auto va = handle->get_globally_committed(k);
      REQUIRE(!va.has_value());
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    }

    {
      auto tx2 = kv_store.create_tx();
      auto handle2 = tx2.rw(map);
      REQUIRE(handle2->has(k));
      REQUIRE(handle2->remove(k));
      REQUIRE(!handle2->has(k));
      REQUIRE(tx2.commit() == kv::CommitResult::SUCCESS);
    }

    {
      auto tx3 = kv_store.create_tx();
      auto handle3 = tx3.rw(map);
      REQUIRE(!handle3->has(k));
      auto vc = handle3->get(k);
      REQUIRE(!vc.has_value());
    }
  }
}

TEST_CASE("get_version_of_previous_write")
{
  kv::Store kv_store;
  MapTypes::StringString map("public:map");

  const auto k1 = "k1";
  const auto k2 = "k2";
  const auto k3 = "k3";

  const auto v1 = "v1";
  const auto v2 = "v2";
  const auto v3 = "v3";

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put(k1, v1);
    handle->put(k2, v1);

    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  const auto first_version = kv_store.current_version();

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put(k1, v2);
    handle->remove(k2);

    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  const auto second_version = kv_store.current_version();

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);

    {
      auto tx_other = kv_store.create_tx();
      auto handle = tx_other.rw(map);
      handle->put(k2, v3);
      tx_other.commit();
    }

    {
      // We don't see effects of tx_other because we started executing earlier.
      // k1 is at second_version
      const auto ver1 = handle->get_version_of_previous_write(k1);
      REQUIRE(ver1.has_value());
      REQUIRE(ver1.value() == second_version);

      // k2 was removed, so has no version...
      REQUIRE(!handle->get_version_of_previous_write(k2).has_value());

      // ...just like k3 which was never written
      REQUIRE(!handle->get_version_of_previous_write(k3).has_value());

      {
        INFO("Reading from these keys doesn't change this");
        handle->has(k1);
        handle->has(k2);
        handle->has(k3);

        REQUIRE(
          handle->get_version_of_previous_write(k1).value() == second_version);
        REQUIRE(!handle->get_version_of_previous_write(k2).has_value());
        REQUIRE(!handle->get_version_of_previous_write(k3).has_value());

        handle->get(k1);
        handle->get(k2);
        handle->get(k3);

        REQUIRE(
          handle->get_version_of_previous_write(k1).value() == second_version);
        REQUIRE(!handle->get_version_of_previous_write(k2).has_value());
        REQUIRE(!handle->get_version_of_previous_write(k3).has_value());
      }

      SUBCASE("Writing to these keys doesn't change this")
      {
        handle->put(k1, v3);
        handle->put(k2, v3);
        handle->put(k3, v3);

        REQUIRE(
          handle->get_version_of_previous_write(k1).value() == second_version);
        REQUIRE(!handle->get_version_of_previous_write(k2).has_value());
        REQUIRE(!handle->get_version_of_previous_write(k3).has_value());

        handle->remove(k1);
        handle->remove(k2);
        handle->remove(k3);

        REQUIRE(
          handle->get_version_of_previous_write(k1).value() == second_version);
        REQUIRE(!handle->get_version_of_previous_write(k2).has_value());
        REQUIRE(!handle->get_version_of_previous_write(k3).has_value());
      }

      // This conflicts with tx_other so is not committed
      REQUIRE(tx.commit() == kv::CommitResult::FAIL_CONFLICT);
    }
  }

  const auto third_version = kv_store.current_version();

  {
    INFO("Version is per-key");
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);

    const auto ver1 = handle->get_version_of_previous_write(k1);
    const auto ver2 = handle->get_version_of_previous_write(k2);

    REQUIRE(ver1.has_value());
    REQUIRE(ver2.has_value());

    REQUIRE(ver1.value() == second_version);
    REQUIRE(ver2.value() == third_version);
  }
}

TEST_CASE("foreach")
{
  kv::Store kv_store;
  MapTypes::StringString map("public:map");

  std::map<std::string, std::string> iterated_entries;

  auto store_iterated =
    [&iterated_entries](const auto& key, const auto& value) {
      auto it = iterated_entries.find(key);
      REQUIRE(it == iterated_entries.end());
      iterated_entries[key] = value;
      return true;
    };

  SUBCASE("Empty map")
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->foreach(store_iterated);
    REQUIRE(iterated_entries.empty());
  }

  SUBCASE("Reading own writes")
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("key1", "value1");
    handle->put("key2", "value2");
    handle->foreach(store_iterated);
    REQUIRE(iterated_entries.size() == 2);
    REQUIRE(iterated_entries["key1"] == "value1");
    REQUIRE(iterated_entries["key2"] == "value2");

    iterated_entries.clear();

    INFO("Uncommitted writes from other txs are not visible");
    auto tx2 = kv_store.create_tx();
    auto handle2 = tx2.rw(map);
    handle2->foreach(store_iterated);
    REQUIRE(iterated_entries.empty());
  }

  SUBCASE("Reading committed writes")
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("key1", "value1");
    handle->put("key2", "value2");
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);

    auto tx2 = kv_store.create_tx();
    auto handle2 = tx2.rw(map);
    handle2->foreach(store_iterated);
    REQUIRE(iterated_entries.size() == 2);
    REQUIRE(iterated_entries["key1"] == "value1");
    REQUIRE(iterated_entries["key2"] == "value2");
  }

  SUBCASE("Mix of committed and own writes")
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("key1", "value1");
    handle->put("key2", "value2");
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);

    auto tx2 = kv_store.create_tx();
    auto handle2 = tx2.rw(map);
    handle2->put("key2", "replaced2");
    handle2->put("key3", "value3");
    handle2->foreach(store_iterated);
    REQUIRE(iterated_entries.size() == 3);
    REQUIRE(iterated_entries["key1"] == "value1");
    REQUIRE(iterated_entries["key2"] == "replaced2");
    REQUIRE(iterated_entries["key3"] == "value3");
  }

  SUBCASE("Deletions")
  {
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put("key1", "value1");
      handle->put("key2", "value2");
      handle->put("key3", "value3");
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    }

    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->remove("key1");
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    }

    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->foreach(store_iterated);
      REQUIRE(iterated_entries.size() == 2);
      REQUIRE(iterated_entries["key2"] == "value2");
      REQUIRE(iterated_entries["key3"] == "value3");

      iterated_entries.clear();

      handle->remove("key2");
      handle->foreach(store_iterated);
      REQUIRE(iterated_entries.size() == 1);
      REQUIRE(iterated_entries["key3"] == "value3");

      iterated_entries.clear();

      handle->put("key1", "value1");
      handle->put("key2", "value2");
      handle->foreach(store_iterated);
      REQUIRE(iterated_entries.size() == 3);
      REQUIRE(iterated_entries["key1"] == "value1");
      REQUIRE(iterated_entries["key2"] == "value2");
      REQUIRE(iterated_entries["key3"] == "value3");
    }
  }

  SUBCASE("Early termination")
  {
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put("key1", "value1");
      handle->put("key2", "value2");
      handle->put("key3", "value3");
      size_t ctr = 0;
      handle->foreach([&ctr](const auto& key, const auto& value) {
        ++ctr;
        return ctr < 2; // Continue after the first, but not the second (so
                        // never see the third)
      });
      REQUIRE(ctr == 2);
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    }

    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put("key4", "value4");
      handle->put("key5", "value5");

      {
        size_t ctr = 0;
        handle->foreach([&ctr](const auto&, const auto&) {
          ++ctr;
          return ctr < 2; //< See only committed state
        });
        REQUIRE(ctr == 2);
      }

      {
        size_t ctr = 0;
        handle->foreach([&ctr](const auto&, const auto&) {
          ++ctr;
          return ctr < 4; //< See mix of old state and new writes
        });
        REQUIRE(ctr == 4);
      }

      {
        size_t ctr = 0;
        handle->foreach([&ctr](const auto&, const auto&) {
          ++ctr;
          return ctr < 100; //< See as much as possible
        });
        REQUIRE(ctr == 5);
      }
    }
  }
}

TEST_CASE("Modifications during foreach iteration")
{
  kv::Store kv_store;
  MapTypes::NumString map("public:map");

  const auto value1 = "foo";
  const auto value2 = "bar";

  std::set<size_t> keys;
  {
    INFO("Insert initial keys");

    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    for (size_t i = 0; i < 60; ++i)
    {
      keys.insert(i);
      handle->put(i, value1);
    }

    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  auto tx = kv_store.create_tx();
  auto handle = tx.rw(map);

  // 5 types of key:
  // 1) previously committed and unmodified
  const auto initial_keys_size = keys.size();
  const auto keys_per_category = keys.size() / 3;
  // We do nothing to the first keys_per_category keys

  // 2) previously committed and had their values changed
  for (size_t i = keys_per_category; i < 2 * keys_per_category; ++i)
  {
    keys.insert(i);
    handle->put(i, value2);
  }

  // 3) previously committed and now removed
  for (size_t i = 2 * keys_per_category; i < initial_keys_size; ++i)
  {
    keys.erase(i);
    handle->remove(i);
  }

  // 4) newly written
  for (size_t i = initial_keys_size; i < initial_keys_size + keys_per_category;
       ++i)
  {
    keys.insert(i);
    handle->put(i, value2);
  }

  // 5) newly written and then removed
  for (size_t i = initial_keys_size + keys_per_category;
       i < initial_keys_size + 2 * keys_per_category;
       ++i)
  {
    keys.insert(i);
    handle->put(i, value2);

    keys.erase(i);
    handle->remove(i);
  }

  size_t keys_seen = 0;
  const auto expected_keys_seen = keys.size();

  SUBCASE("Removing current key while iterating")
  {
    auto should_remove = [](size_t n) { return n % 3 == 0 || n % 5 == 0; };

    handle->foreach(
      [&handle, &keys, &keys_seen, should_remove](const auto& k, const auto&) {
        ++keys_seen;
        const auto it = keys.find(k);
        REQUIRE(it != keys.end());

        // Remove a 'random' set of keys while iterating
        if (should_remove(k))
        {
          handle->remove(k);
          keys.erase(it);
        }

        return true;
      });

    REQUIRE(keys_seen == expected_keys_seen);

    // Check all expected keys are still there...
    handle->foreach([&keys, should_remove](const auto& k, const auto&) {
      REQUIRE(!should_remove(k));
      const auto it = keys.find(k);
      REQUIRE(it != keys.end());
      keys.erase(it);
      return true;
    });

    // ...and nothing else
    REQUIRE(keys.empty());
  }

  SUBCASE("Removing other keys while iterating")
  {
    auto should_remove = [](size_t n) { return n % 3 == 0 || n % 5 == 0; };

    std::optional<size_t> removal_trigger = std::nullopt;

    handle->foreach(
      [&handle, &keys, &keys_seen, &removal_trigger, should_remove](
        const auto& k, const auto&) {
        ++keys_seen;

        // The first time we find a removable, remove _all the others_ (not
        // ourself!)
        if (should_remove(k) && !removal_trigger.has_value())
        {
          REQUIRE(!removal_trigger.has_value());
          removal_trigger = k;

          auto remove_it = keys.begin();
          while (remove_it != keys.end())
          {
            const auto n = *remove_it;
            if (should_remove(n) && n != k)
            {
              handle->remove(n);
              remove_it = keys.erase(remove_it);
            }
            else
            {
              ++remove_it;
            }
          }
        }

        return true;
      });

    REQUIRE(keys_seen == expected_keys_seen);

    REQUIRE(removal_trigger.has_value());

    // Check all expected keys are still there...
    handle->foreach(
      [&keys, removal_trigger, should_remove](const auto& k, const auto&) {
        const auto should_be_here =
          !should_remove(k) || k == removal_trigger.value();
        REQUIRE(should_be_here);
        const auto it = keys.find(k);
        REQUIRE(it != keys.end());
        keys.erase(it);
        return true;
      });

    // ...and nothing else
    REQUIRE(keys.empty());
  }

  static constexpr auto value3 = "baz";

  SUBCASE("Modifying and adding other keys while iterating")
  {
    auto should_modify = [](size_t n) { return n % 3 == 0 || n % 5 == 0; };

    std::set<size_t> updated_keys;

    handle->foreach([&handle, &keys, &keys_seen, &updated_keys, should_modify](
                      const auto& k, const auto& v) {
      ++keys_seen;

      if (should_modify(k))
      {
        // Modify ourselves
        handle->put(k, value3);
        updated_keys.insert(k);

        // Modify someone else ('before' and 'after' are guesses - iteration
        // order is undefined!)
        const auto before = k / 2;
        handle->put(before, value3);
        keys.insert(before);
        updated_keys.insert(before);

        const auto after = k * 2;
        handle->put(after, value3);
        keys.insert(after);
        updated_keys.insert(after);

        // Note discrepancy with externally visible value
        const auto visible_v = handle->get(k);
        REQUIRE(visible_v.has_value());
        REQUIRE(visible_v.value() == value3);
        REQUIRE(visible_v.value() != v); // !!
      }

      return true;
    });

    REQUIRE(keys_seen == expected_keys_seen);

    // Check all expected keys are still there...
    handle->foreach([&keys, &updated_keys](const auto& k, const auto& v) {
      const auto updated_it = updated_keys.find(k);
      if (updated_it != updated_keys.end())
      {
        REQUIRE(v == value3);
        updated_keys.erase(updated_it);
      }
      else
      {
        REQUIRE(v != value3);
      }

      const auto it = keys.find(k);
      if (it != keys.end())
      {
        keys.erase(it);
      }

      return true;
    });

    // ...and nothing else
    REQUIRE(keys.empty());
    REQUIRE(updated_keys.empty());
  }

  SUBCASE("Rewriting to new keys")
  {
    // Rewrite map, placing each value at a new key
    handle->foreach([&handle, &keys_seen](const auto& k, const auto& v) {
      ++keys_seen;

      handle->remove(k);

      const auto new_key = k + 1000;
      REQUIRE(!handle->has(new_key));
      handle->put(new_key, v);

      return true;
    });

    REQUIRE(keys_seen == expected_keys_seen);

    // Check map contains only new keys, and the same count
    keys_seen = 0;
    handle->foreach([&handle, &keys, &keys_seen](const auto& k, const auto& v) {
      ++keys_seen;

      REQUIRE(keys.find(k) == keys.end());

      return true;
    });

    REQUIRE(keys_seen == expected_keys_seen);
  }
}

TEST_CASE("Read-only tx")
{
  kv::Store kv_store;
  MapTypes::StringString map("public:map");

  constexpr auto k = "key";
  constexpr auto invalid_key = "invalid_key";
  constexpr auto v1 = "value1";

  INFO("Write some keys");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    auto v = handle->get(k);
    REQUIRE(!v.has_value());
    handle->put(k, v1);
    auto va = handle->get(k);
    REQUIRE(va.has_value());
    REQUIRE(va.value() == v1);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  INFO("Do only reads with an overpowered Tx");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.ro(map);
    REQUIRE(handle->has(k));
    const auto v = handle->get(k);
    REQUIRE(v.has_value());
    REQUIRE(v.value() == v1);

    REQUIRE(!handle->has(invalid_key));
    const auto invalid_v = handle->get(invalid_key);
    REQUIRE(!invalid_v.has_value());

    // The following won't compile:
    // handle->put(k, v1);
    // handle->remove(k);
  }

  INFO("Read with read-only tx");
  {
    auto tx = kv_store.create_read_only_tx();
    auto handle = tx.ro(map);
    REQUIRE(handle->has(k));
    const auto v = handle->get(k);
    REQUIRE(v.has_value());
    REQUIRE(v.value() == v1);

    REQUIRE(!handle->has(invalid_key));
    const auto invalid_v = handle->get(invalid_key);
    REQUIRE(!invalid_v.has_value());

    // The following won't compile:
    // handle->put(k, v1);
    // handle->remove(k);
  }

  INFO("Write-only handles");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.wo(map);

    handle->put(k, v1);
    handle->remove(k);

    // The following won't compile:
    // handle->has(k);
    // handle->get(k);
    // handle->foreach([](const auto&, const auto&) {});
  }
}

TEST_CASE("Rollback and compact")
{
  kv::Store kv_store;
  MapTypes::StringString map("public:map");

  constexpr auto k = "key";
  constexpr auto v1 = "value1";

  INFO("Do not read transactions that have been rolled back");
  {
    auto tx = kv_store.create_tx();
    auto tx2 = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put(k, v1);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);

    kv_store.rollback(0);
    auto handle2 = tx2.rw(map);
    auto v = handle2->get(k);
    REQUIRE(!v.has_value());
    REQUIRE(tx2.commit() == kv::CommitResult::SUCCESS);
  }

  INFO("Read committed key");
  {
    auto tx = kv_store.create_tx();
    auto tx2 = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put(k, v1);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    kv_store.compact(kv_store.current_version());

    auto handle2 = tx2.rw(map);
    auto va = handle2->get_globally_committed(k);
    REQUIRE(va.has_value());
    REQUIRE(va.value() == v1);
  }

  INFO("Read deleted committed key");
  {
    auto tx = kv_store.create_tx();
    auto tx2 = kv_store.create_tx();
    auto handle = tx.rw(map);
    REQUIRE(handle->remove(k));
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    kv_store.compact(kv_store.current_version());

    auto handle2 = tx2.rw(map);
    auto va = handle2->get_globally_committed(k);
    REQUIRE(!va.has_value());
  }
}

TEST_CASE("Local commit hooks")
{
  using Write = MapTypes::StringString::Write;
  std::vector<Write> local_writes;
  std::vector<Write> global_writes;

  auto map_hook = [&](kv::Version v, const Write& w) -> kv::ConsensusHookPtr {
    local_writes.push_back(w);
    return kv::ConsensusHookPtr(nullptr);
  };
  auto global_hook = [&](kv::Version v, const Write& w) {
    global_writes.push_back(w);
  };

  kv::Store kv_store;
  constexpr auto map_name = "public:map";
  MapTypes::StringString map(map_name);
  kv_store.set_map_hook(map_name, map.wrap_map_hook(map_hook));
  kv_store.set_global_hook(map_name, map.wrap_commit_hook(global_hook));

  INFO("Write with hooks");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("key1", "value1");
    handle->put("key2", "value2");
    handle->remove("key2");
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);

    REQUIRE(global_writes.size() == 0);
    REQUIRE(local_writes.size() == 1);
    const auto& latest_writes = local_writes.front();
    REQUIRE(latest_writes.at("key1").has_value());
    REQUIRE(latest_writes.at("key1").value() == "value1");
    INFO("Local removals are not seen");
    REQUIRE(latest_writes.find("key2") == latest_writes.end());
    REQUIRE(latest_writes.size() == 1);

    local_writes.clear();
  }

  INFO("Write without hooks");
  {
    kv_store.unset_map_hook(map_name);
    kv_store.unset_global_hook(map_name);

    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("key2", "value2");
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);

    REQUIRE(local_writes.size() == 0);
    REQUIRE(global_writes.size() == 0);
  }

  INFO("Write with hook again");
  {
    kv_store.set_map_hook(map_name, map.wrap_map_hook(map_hook));
    kv_store.set_global_hook(map_name, map.wrap_commit_hook(global_hook));

    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->remove("key2");
    handle->put("key3", "value3");
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);

    REQUIRE(global_writes.size() == 0);
    REQUIRE(local_writes.size() == 1);
    const auto& latest_writes = local_writes.front();
    INFO("Old writes are not included");
    REQUIRE(latest_writes.find("key1") == latest_writes.end());
    INFO("Visible removals are included");
    const auto it2 = latest_writes.find("key2");
    REQUIRE(it2 != latest_writes.end());
    REQUIRE(!it2->second.has_value());
    const auto it3 = latest_writes.find("key3");
    REQUIRE(it3 != latest_writes.end());
    REQUIRE(it3->second.has_value());
    REQUIRE(it3->second.value() == "value3");
    REQUIRE(latest_writes.size() == 2);

    local_writes.clear();
  }
}

TEST_CASE("Global commit hooks")
{
  using Write = MapTypes::StringString::Write;

  struct GlobalHookInput
  {
    kv::Version version;
    Write writes;
  };

  std::vector<GlobalHookInput> global_writes;

  auto global_hook = [&](kv::Version v, const Write& w) {
    global_writes.emplace_back(GlobalHookInput({v, w}));
  };

  kv::Store kv_store;
  using MapT = kv::Map<std::string, std::string>;
  MapT map_with_hook("public:map_with_hook");
  kv_store.set_global_hook(
    map_with_hook.get_name(), map_with_hook.wrap_commit_hook(global_hook));

  MapT map_no_hook("public:map_no_hook");

  INFO("Compact an empty store");
  {
    kv_store.compact(0);

    REQUIRE(global_writes.size() == 0);
  }

  SUBCASE("Compact one transaction")
  {
    auto tx1 = kv_store.create_tx();
    auto handle_hook = tx1.rw(map_with_hook);
    handle_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == kv::CommitResult::SUCCESS);

    kv_store.compact(1);

    REQUIRE(global_writes.size() == 1);
    const auto& latest_writes = global_writes.front();
    REQUIRE(latest_writes.version == 1);
    const auto it1 = latest_writes.writes.find("key1");
    REQUIRE(it1 != latest_writes.writes.end());
    REQUIRE(it1->second.has_value());
    REQUIRE(it1->second.value() == "value1");
  }

  SUBCASE("Compact beyond the last map version")
  {
    auto tx1 = kv_store.create_tx();
    auto tx2 = kv_store.create_tx();
    auto tx3 = kv_store.create_tx();
    auto handle_hook = tx1.rw(map_with_hook);
    handle_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == kv::CommitResult::SUCCESS);

    handle_hook = tx2.rw(map_with_hook);
    handle_hook->put("key2", "value2");
    REQUIRE(tx2.commit() == kv::CommitResult::SUCCESS);

    const auto compact_version = kv_store.current_version();

    // This does not affect map_with_hook but still increments the current
    // version of the store
    auto handle_no_hook = tx3.rw(map_no_hook);
    handle_no_hook->put("key3", "value3");
    REQUIRE(tx3.commit() == kv::CommitResult::SUCCESS);

    kv_store.compact(compact_version);

    // Only the changes made to map_with_hook should be passed to the global
    // hook
    REQUIRE(global_writes.size() == 2);
    REQUIRE(global_writes.at(0).version == 1);
    const auto it1 = global_writes.at(0).writes.find("key1");
    REQUIRE(it1 != global_writes.at(0).writes.end());
    REQUIRE(it1->second.has_value());
    REQUIRE(it1->second.value() == "value1");
    const auto it2 = global_writes.at(1).writes.find("key2");
    REQUIRE(it2 != global_writes.at(1).writes.end());
    REQUIRE(it2->second.has_value());
    REQUIRE(it2->second.value() == "value2");
  }

  SUBCASE("Compact in between two map versions")
  {
    auto tx1 = kv_store.create_tx();
    auto tx2 = kv_store.create_tx();
    auto tx3 = kv_store.create_tx();
    auto handle_hook = tx1.rw(map_with_hook);
    handle_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == kv::CommitResult::SUCCESS);

    // This does not affect map_with_hook but still increments the current
    // version of the store
    auto handle_no_hook = tx2.rw(map_no_hook);
    handle_no_hook->put("key2", "value2");
    REQUIRE(tx2.commit() == kv::CommitResult::SUCCESS);

    const auto compact_version = kv_store.current_version();

    handle_hook = tx3.rw(map_with_hook);
    handle_hook->put("key3", "value3");
    REQUIRE(tx3.commit() == kv::CommitResult::SUCCESS);

    kv_store.compact(compact_version);

    // Only the changes made to map_with_hook should be passed to the global
    // hook
    REQUIRE(global_writes.size() == 1);
    REQUIRE(global_writes.at(0).version == 1);
    const auto it1 = global_writes.at(0).writes.find("key1");
    REQUIRE(it1 != global_writes.at(0).writes.end());
    REQUIRE(it1->second.has_value());
    REQUIRE(it1->second.value() == "value1");
  }

  SUBCASE("Compact twice")
  {
    auto tx1 = kv_store.create_tx();
    auto tx2 = kv_store.create_tx();
    auto handle_hook = tx1.rw(map_with_hook);
    handle_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == kv::CommitResult::SUCCESS);

    kv_store.compact(kv_store.current_version());
    global_writes.clear();

    handle_hook = tx2.rw(map_with_hook);
    handle_hook->put("key2", "value2");
    REQUIRE(tx2.commit() == kv::CommitResult::SUCCESS);

    kv_store.compact(kv_store.current_version());

    // Only writes since the last compact are passed to the global hook
    REQUIRE(global_writes.size() == 1);
    REQUIRE(global_writes.at(0).version == 2);
    const auto it2 = global_writes.at(0).writes.find("key2");
    REQUIRE(it2 != global_writes.at(0).writes.end());
    REQUIRE(it2->second.has_value());
    REQUIRE(it2->second.value() == "value2");
  }
}

TEST_CASE("Deserialising from other Store")
{
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv::Store store;
  store.set_encryptor(encryptor);

  MapTypes::NumString public_map("public:public");
  MapTypes::NumString private_map("private");
  auto tx1 = store.create_reserved_tx(store.next_version());
  auto handle1 = tx1.rw(public_map);
  auto handle2 = tx1.rw(private_map);
  handle1->put(42, "aardvark");
  handle2->put(14, "alligator");
  auto [success, reqid, data, hooks] = tx1.commit_reserved();
  REQUIRE(success == kv::CommitResult::SUCCESS);

  kv::Store clone;
  clone.set_encryptor(encryptor);

  REQUIRE(
    clone.apply(data, ConsensusType::CFT)->execute() == kv::ApplyResult::PASS);
}

TEST_CASE("Deserialise return status")
{
  kv::Store store;

  ccf::Signatures signatures(ccf::Tables::SIGNATURES);
  ccf::Nodes nodes(ccf::Tables::NODES);
  MapTypes::NumNum data("public:data");

  auto kp = tls::make_key_pair();

  auto history = std::make_shared<ccf::NullTxHistory>(store, 0, *kp);
  store.set_history(history);

  {
    auto tx = store.create_reserved_tx(store.next_version());
    auto data_handle = tx.rw(data);
    data_handle->put(42, 42);
    auto [success, reqid, data, hooks] = tx.commit_reserved();
    REQUIRE(success == kv::CommitResult::SUCCESS);

    REQUIRE(
      store.apply(data, ConsensusType::CFT)->execute() ==
      kv::ApplyResult::PASS);
  }

  {
    auto tx = store.create_reserved_tx(store.next_version());
    auto sig_handle = tx.rw(signatures);
    ccf::PrimarySignature sigv(0, 2);
    sig_handle->put(0, sigv);
    auto [success, reqid, data, hooks] = tx.commit_reserved();
    REQUIRE(success == kv::CommitResult::SUCCESS);

    REQUIRE(
      store.apply(data, ConsensusType::CFT)->execute() ==
      kv::ApplyResult::PASS_SIGNATURE);
  }

  INFO("Signature transactions with additional contents should fail");
  {
    auto tx = store.create_reserved_tx(store.next_version());
    auto sig_handle = tx.rw(signatures);
    auto data_handle = tx.rw(data);
    ccf::PrimarySignature sigv(0, 2);
    sig_handle->put(0, sigv);
    data_handle->put(43, 43);
    auto [success, reqid, data, hooks] = tx.commit_reserved();
    REQUIRE(success == kv::CommitResult::SUCCESS);

    REQUIRE(
      store.apply(data, ConsensusType::CFT)->execute() ==
      kv::ApplyResult::FAIL);
  }
}

TEST_CASE("Map swap between stores")
{
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv::Store s1;
  s1.set_encryptor(encryptor);

  kv::Store s2;
  s2.set_encryptor(encryptor);

  MapTypes::NumNum d("data");
  MapTypes::NumNum pd("public:data");

  {
    auto tx = s1.create_tx();
    auto v = tx.rw(d);
    v->put(42, 42);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  {
    auto tx = s1.create_tx();
    auto v = tx.rw(pd);
    v->put(14, 14);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  const auto target_version = s1.current_version();
  while (s2.current_version() < target_version)
  {
    auto tx = s2.create_tx();
    auto v = tx.rw(d);
    v->put(41, 41);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  s2.swap_private_maps(s1);

  {
    auto tx = s1.create_tx();
    auto v = tx.rw(d);
    auto val = v->get(41);
    REQUIRE_FALSE(v->get(42).has_value());
    REQUIRE(val.has_value());
    REQUIRE(val.value() == 41);
  }

  {
    auto tx = s1.create_tx();
    auto v = tx.rw(pd);
    auto val = v->get(14);
    REQUIRE(val.has_value());
    REQUIRE(val.value() == 14);
  }

  {
    auto tx = s2.create_tx();
    auto v = tx.rw(d);
    auto val = v->get(42);
    REQUIRE_FALSE(v->get(41).has_value());
    REQUIRE(val.has_value());
    REQUIRE(val.value() == 42);
  }

  {
    auto tx = s2.create_tx();
    auto v = tx.rw(pd);
    REQUIRE_FALSE(v->get(14).has_value());
  }
}

TEST_CASE("Private recovery map swap")
{
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv::Store s1;
  s1.set_encryptor(encryptor);
  MapTypes::NumNum priv1("private");
  MapTypes::NumString pub1("public:data");

  kv::Store s2;
  s2.set_encryptor(encryptor);
  MapTypes::NumNum priv2("private");
  MapTypes::NumString pub2("public:data");

  INFO("Populate s1 with public entries");
  // We compact twice, deliberately. A public KV during recovery
  // would have compacted some number of times.
  {
    auto tx = s1.create_tx();
    auto v = tx.rw(pub1);
    v->put(42, "42");
    tx.commit();
  }
  {
    auto tx = s1.create_tx();
    auto v = tx.rw(pub1);
    v->put(42, "43");
    tx.commit();
  }
  s1.compact(s1.current_version());
  {
    auto tx = s1.create_tx();
    auto v = tx.rw(pub1);
    v->put(44, "44");
    tx.commit();
  }
  s1.compact(s1.current_version());
  {
    auto tx = s1.create_tx();
    auto v = tx.rw(pub1);
    v->put(45, "45");
    tx.commit();
  }

  INFO("Populate s2 with private entries");
  // We compact only once, at a lower index than we did for the public
  // KV, which is what we expect during recovery of the private KV. We do expect
  // that the _entire_ private state is compacted
  {
    auto tx = s2.create_tx();
    auto v = tx.rw(priv2);
    v->put(12, 12);
    tx.commit();
  }
  {
    auto tx = s2.create_tx();
    auto v = tx.rw(priv2);
    v->put(13, 13);
    tx.commit();
  }
  s2.compact(s2.current_version());
  {
    auto tx = s2.create_tx();
    auto v = tx.rw(priv2);
    v->put(14, 14);
    tx.commit();
  }
  {
    auto tx = s2.create_tx();
    auto v = tx.rw(priv2);
    v->put(15, 15);
    tx.commit();
  }

  INFO("Swap in private maps");
  REQUIRE(s1.current_version() == s2.current_version());
  REQUIRE_NOTHROW(s1.swap_private_maps(s2));

  INFO("Check state looks as expected in s1");
  {
    auto tx = s1.create_tx();
    auto priv = tx.rw(priv1);
    auto pub = tx.rw(pub1);
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
      for (size_t i : {12, 13, 14, 15})
      {
        auto val = priv->get(i);
        REQUIRE(val.has_value());
        REQUIRE(val.value() == i);
      }
    }
  }

  INFO("Check committed state looks as expected in s1");
  {
    auto tx = s1.create_tx();
    auto priv = tx.rw(priv1);
    auto pub = tx.rw(pub1);
    {
      auto val = pub->get_globally_committed(42);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "43");

      val = pub->get_globally_committed(44);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "44");

      val = pub->get_globally_committed(45);
      REQUIRE_FALSE(val.has_value());
    }
    {
      auto val = priv->get_globally_committed(12);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == 12);

      val = priv->get_globally_committed(13);
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
  kv::Store kv_store;
  MapTypes::StringString map("public:map");

  {
    // Ensure this map already exists, by making a prior write to it
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("foo", "initial");
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  auto try_write = [&](kv::Tx& tx, const std::string& s) {
    auto handle = tx.rw(map);

    // Introduce read-dependency
    handle->get("foo");
    handle->put("foo", s);

    handle->put(s, s);
  };

  auto confirm_state = [&](
                         const std::vector<std::string>& present,
                         const std::vector<std::string>& missing) {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);

    for (const auto& s : present)
    {
      const auto it = handle->get(s);
      REQUIRE(it.has_value());
      REQUIRE(handle->has(s));
      REQUIRE(it.value() == s);
    }

    for (const auto& s : missing)
    {
      const auto it = handle->get(s);
      REQUIRE(!it.has_value());
      REQUIRE(!handle->has(s));
    }
  };

  // Simulate parallel execution by interleaving tx steps
  auto tx1 = kv_store.create_tx();
  auto tx2 = kv_store.create_tx();

  // First transaction tries to write a value, depending on initial version
  try_write(tx1, "bar");

  {
    // A second transaction is committed, conflicting with the first
    try_write(tx2, "baz");
    const auto res2 = tx2.commit();
    REQUIRE(res2 == kv::CommitResult::SUCCESS);

    confirm_state({"baz"}, {"bar"});
  }

  // Trying to commit first transaction produces a conflict
  auto res1 = tx1.commit();
  REQUIRE(res1 == kv::CommitResult::FAIL_CONFLICT);
  confirm_state({"baz"}, {"bar"});

  // A third transaction just wants to read the value
  auto tx3 = kv_store.create_tx();
  auto handle3 = tx3.rw(map);
  REQUIRE(handle3->has("foo"));

  // First transaction is rerun with same object, producing different result
  try_write(tx1, "buzz");

  // Expected results are committed
  res1 = tx1.commit();
  REQUIRE(res1 == kv::CommitResult::SUCCESS);
  confirm_state({"baz", "buzz"}, {"bar"});

  // Third transaction completes later, has no conflicts but reports the earlier
  // version it read
  auto res3 = tx3.commit();
  REQUIRE(res3 == kv::CommitResult::SUCCESS);

  REQUIRE(tx1.commit_version() > tx2.commit_version());
  REQUIRE(tx2.get_read_version() >= tx2.get_read_version());

  // Re-running a _committed_ transaction is exceptionally bad
  REQUIRE_THROWS(tx1.commit());
  REQUIRE_THROWS(tx2.commit());
}

TEST_CASE("Mid-tx compaction")
{
  kv::Store kv_store;
  MapTypes::StringNum map_a("public:A");
  MapTypes::StringNum map_b("public:B");

  constexpr auto key_a = "a";
  constexpr auto key_b = "b";

  auto increment_vals = [&]() {
    auto tx = kv_store.create_tx();
    auto handle_a = tx.rw(map_a);
    auto handle_b = tx.rw(map_b);

    auto a_opt = handle_a->get(key_a);
    auto b_opt = handle_b->get(key_b);

    REQUIRE(a_opt == b_opt);

    const auto new_val = a_opt.has_value() ? *a_opt + 1 : 0;

    handle_a->put(key_a, new_val);
    handle_b->put(key_b, new_val);

    const auto result = tx.commit();
    REQUIRE(result == kv::CommitResult::SUCCESS);
  };

  increment_vals();

  {
    INFO("Compaction before get_handles");
    auto tx = kv_store.create_tx();

    increment_vals();
    kv_store.compact(kv_store.current_version());

    auto handle_a = tx.rw(map_a);
    auto handle_b = tx.rw(map_b);

    auto a_opt = handle_a->get(key_a);
    auto b_opt = handle_b->get(key_b);

    REQUIRE(a_opt == b_opt);

    const auto result = tx.commit();
    REQUIRE(result == kv::CommitResult::SUCCESS);
  }

  {
    INFO("Compaction after get_handles");
    auto tx = kv_store.create_tx();

    auto handle_a = tx.rw(map_a);
    increment_vals();
    auto handle_b = tx.rw(map_b);
    kv_store.compact(kv_store.current_version());

    auto a_opt = handle_a->get(key_a);
    auto b_opt = handle_b->get(key_b);

    REQUIRE(a_opt == b_opt);

    const auto result = tx.commit();
    REQUIRE(result == kv::CommitResult::SUCCESS);
  }

  {
    INFO("Compaction between get_handles");
    bool threw = false;

    try
    {
      auto tx = kv_store.create_tx();

      auto handle_a = tx.rw(map_a);
      // This transaction does something slow. Meanwhile...

      // ...another transaction commits...
      increment_vals();
      // ...and is compacted...
      kv_store.compact(kv_store.current_version());

      // ...then the original transaction proceeds, expecting to read a single
      // version
      // This should throw a CompactedVersionConflict error
      auto handle_b = tx.rw(map_b);

      auto a_opt = handle_a->get(key_a);
      auto b_opt = handle_b->get(key_b);

      REQUIRE(a_opt == b_opt);

      const auto result = tx.commit();
      REQUIRE(result == kv::CommitResult::SUCCESS);
    }
    catch (const kv::CompactedVersionConflict& e)
    {
      threw = true;
    }

    REQUIRE(threw);
    // In real operation, this transaction would be re-executed and hope to not
    // intersect a compaction
  }
}

TEST_CASE("Store clear")
{
  kv::Store kv_store;
  kv_store.set_term(42);

  auto map_a_name = "public:A";
  auto map_b_name = "public:B";
  MapTypes::StringNum map_a(map_a_name);
  MapTypes::StringNum map_b(map_b_name);

  INFO("Apply transactions and compact store");
  {
    size_t tx_count = 10;
    for (int i = 0; i < tx_count; i++)
    {
      auto tx = kv_store.create_tx();
      auto handle_a = tx.rw(map_a);
      auto handle_b = tx.rw(map_b);

      handle_a->put("key" + std::to_string(i), 42);
      handle_b->put("key" + std::to_string(i), 42);
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    }

    auto current_version = kv_store.current_version();
    kv_store.compact(current_version);

    REQUIRE(kv_store.get_map(current_version, map_a_name) != nullptr);
    REQUIRE(kv_store.get_map(current_version, map_b_name) != nullptr);

    REQUIRE(kv_store.current_version() != 0);
    REQUIRE(kv_store.commit_version() != 0);
    auto tx_id = kv_store.current_txid();
    REQUIRE(tx_id.term != 0);
    REQUIRE(tx_id.version != 0);
  }

  INFO("Verify that store state is cleared");
  {
    kv_store.clear();
    auto current_version = kv_store.current_version();

    REQUIRE(kv_store.get_map(current_version, map_a_name) == nullptr);
    REQUIRE(kv_store.get_map(current_version, map_b_name) == nullptr);

    REQUIRE(kv_store.current_version() == 0);
    REQUIRE(kv_store.commit_version() == 0);
    auto tx_id = kv_store.current_txid();
    REQUIRE(tx_id.term == 0);
    REQUIRE(tx_id.version == 0);
  }
}