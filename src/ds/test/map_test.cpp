// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ccf/byte_vector.h"
#include "ccf/ds/logger.h"
#include "ccf/kv/serialisers/serialised_entry.h"
#include "ds/champ_map.h"
#include "ds/rb_map.h"
#include "ds/std_formatters.h"
#include "kv/untyped_change_set.h"

#include <doctest/doctest.h>
#include <random>
#include <unordered_map>

template <class K>
struct CollisionHash
{
  size_t operator()(const K& k) const noexcept
  {
    return std::hash<K>()(k) % 100;
  }
};

using K = kv::serialisers::SerialisedEntry;
using V = kv::serialisers::SerialisedEntry;
constexpr static size_t max_key_value_size = 128;

namespace map
{
  inline size_t get_size(uint64_t)
  {
    return sizeof(size_t);
  }
}

struct KVPair
{
  K k;
  V v;

  bool operator==(const KVPair&) const = default;
};

template <typename K>
using H = CollisionHash<K>;
// using H = std::hash<K>;

// Useful types
template <typename Key, typename Value>
using UntypedChampMap = champ::Map<Key, Value, H<Key>>;
using ChampMap = UntypedChampMap<K, V>;

template <typename Key, typename Value>
using UntypedRBMap = rb::Map<Key, Value>;
using RBMap = UntypedRBMap<K, V>;

class Model
{
  std::unordered_map<K, V> internal;

public:
  std::optional<V> get(const K& key) const
  {
    auto it = internal.find(key);
    if (it == internal.end())
      return {};

    return it->second;
  }

  Model put(const K& key, const V& value) const
  {
    auto next = *this;
    next.internal[key] = value;
    return next;
  }

  Model remove(const K& key) const
  {
    auto next = *this;
    next.internal.erase(key);
    return next;
  }
};

template <class M>
struct Op
{
  virtual ~Op() = default;
  virtual std::pair<const Model, const M> apply(const Model& a, const M& b) = 0;
  virtual std::string str() = 0;
};

template <class M>
struct Put : public Op<M>
{
  K k;
  V v;

  Put(K k_, V v_) : k(k_), v(v_) {}

  std::pair<const Model, const M> apply(const Model& a, const M& b)
  {
    return std::make_pair(a.put(k, v), b.put(k, v));
  }

  std::string str()
  {
    auto ss = std::stringstream();
    ss << "Put(" << H<K>()(k) << ", value of size " << v.size() << ")";
    return ss.str();
  }
};

template <class M>
struct Remove : public Op<M>
{
  K k;

  Remove(K k_) : k(k_) {}

  std::pair<const Model, const M> apply(const Model& a, const M& b)
  {
    return std::make_pair(a.remove(k), b.remove(k));
  }

  std::string str()
  {
    auto ss = std::stringstream();
    ss << "Remove(" << H<K>()(k) << ")";
    return ss.str();
  }
};

template <class M>
struct NoOp : public Op<M>
{
  NoOp() = default;

  std::pair<const Model, const M> apply(const Model& a, const M& b)
  {
    return std::make_pair(a, b);
  }

  std::string str()
  {
    auto ss = std::stringstream();
    ss << "NoOp (Remove not implemented!)";
    return ss.str();
  }
};

template <typename M>
std::vector<std::unique_ptr<Op<M>>> gen_ops(size_t n)
{
  std::random_device rand_dev;
  auto seed = rand_dev();
  LOG_INFO_FMT("Seed: {}", seed);
  std::mt19937 gen(seed);
  std::uniform_int_distribution<> gen_op(0, 3);

  std::vector<std::unique_ptr<Op<M>>> ops;
  std::vector<K> keys;
  for (size_t i = 0; i < n; ++i)
  {
    V v(gen() % max_key_value_size, 'v');
    std::unique_ptr<Op<M>> op;
    auto op_i = keys.empty() ? 0 : gen_op(gen);
    switch (op_i)
    {
      case 0:
      case 1: // insert
      {
        K k(gen() % max_key_value_size, 'k');
        keys.push_back(k);
        op = std::make_unique<Put<M>>(k, v);

        break;
      }
      case 2: // update
      {
        std::uniform_int_distribution<> gen_idx(0, keys.size() - 1);
        auto k = keys[gen_idx(gen)];
        op = std::make_unique<Put<M>>(k, v);

        break;
      }
      case 3: // remove
      {
        // Remove operation is not yet implemented for RBMap
        if constexpr (std::is_same_v<M, ChampMap>)
        {
          std::uniform_int_distribution<> gen_idx(0, keys.size() - 1);
          auto i = gen_idx(gen);
          auto k = keys[i];
          keys.erase(keys.begin() + i);
          op = std::make_unique<Remove<M>>(k);
        }
        else
        {
          op = std::make_unique<NoOp<M>>();
        }
        break;
      }
      default:
        throw std::logic_error("bad op number");
    }
    ops.push_back(std::move(op));
  }

  return ops;
}

TEST_CASE_TEMPLATE("Persistent map operations", M, RBMap, ChampMap)
{
  Model model;
  M map;

  auto ops = gen_ops<M>(500);
  for (auto& op : ops)
  {
    LOG_DEBUG_FMT("{}", op->str());
    auto r = op->apply(model, map);
    auto model_new = r.first;
    auto map_new = r.second;

    INFO("check consistency of persistent maps");
    {
      size_t n = 0;
      map_new.foreach([&](const auto& k, const auto& v) {
        n++;
        auto model_value = model_new.get(k);
        REQUIRE(model_value.has_value());
        REQUIRE(model_value.value() == v);
        return true;
      });
      REQUIRE(n == map_new.size());
    }

    INFO("check persistence of previous versions");
    {
      size_t n = 0;
      map.foreach([&](const auto& k, const auto& v) {
        n++;
        auto model_value = model.get(k);
        REQUIRE(model_value.has_value());
        REQUIRE(model_value.value() == v);
        return true;
      });
      REQUIRE(n == map.size());
    }

    model = model_new;
    map = map_new;
  }
}

template <class M>
static const M gen_map(size_t size)
{
  M map;
  Model model;

  auto ops = gen_ops<M>(size);
  for (auto& op : ops)
  {
    auto r = op->apply(model, map);
    map = r.second;
  }

  return map;
}

TEST_CASE_TEMPLATE("Snapshot map", M, ChampMap, RBMap)
{
  size_t ops_count = 2048;
  auto map = gen_map<M>(ops_count);
  std::map<K, V> contents; // Ordered content as Champ is unordered
  std::vector<uint8_t> serialised_snapshot;

  M new_map;

  INFO("Record content of source map");
  {
    map.foreach([&contents](const auto& key, const auto& value) {
      contents[key] = value;
      return true;
    });
    REQUIRE_EQ(map.size(), contents.size());
  }

  INFO("Generate snapshot");
  {
    auto snapshot = map.make_snapshot();
    serialised_snapshot.resize(map.get_serialized_size());
    snapshot->serialize(serialised_snapshot.data());

    INFO("Ensure serialised state is byte identical");
    {
      auto snapshot_2 = map.make_snapshot();
      std::vector<uint8_t> serialised_snapshot_2(map.get_serialized_size());
      snapshot_2->serialize(serialised_snapshot_2.data());
      REQUIRE_EQ(serialised_snapshot, serialised_snapshot_2);
    }
  }

  INFO("Apply snapshot to target map");
  {
    new_map = map::deserialize_map<M>(serialised_snapshot);
    REQUIRE_EQ(map.size(), new_map.size());

    std::map<K, V> new_contents;
    new_map.foreach([&new_contents](const auto& key, const auto& value) {
      new_contents[key] = value;
      return true;
    });
    REQUIRE_EQ(contents.size(), new_contents.size());
    REQUIRE_EQ(contents, new_contents);
  }

  INFO("Check that new entries can be added to target map");
  {
    Model new_model;
    auto new_ops = gen_ops<M>(ops_count);
    for (auto& op : new_ops)
    {
      auto r = op->apply(new_model, new_map);
      new_map = r.second;
    }
  }
}

template <typename M>
std::map<K, V> get_all_entries(const M& map)
{
  std::map<K, V> entries;
  map.foreach([&entries](const K& k, const V& v) {
    REQUIRE(entries.find(k) == entries.end()); // assert for no duplicates
    entries.insert({k, v});
    return true;
  });
  return entries;
}

TEST_CASE_TEMPLATE("Snapshot is immutable", M, ChampMap, RBMap)
{
  size_t ops_count = 2048;
  auto map = gen_map<M>(ops_count);

  // Take snapshot at original state
  auto snapshot = map.make_snapshot();
  size_t serialised_snapshot_before_size = snapshot->get_serialized_size();
  std::vector<uint8_t> serialised_snapshot_before(
    serialised_snapshot_before_size);
  snapshot->serialize(serialised_snapshot_before.data());

  INFO("Meanwhile, modify map");
  {
    // Remove operation is not yet implemented for RBMap
    if constexpr (std::is_same_v<M, ChampMap>)
    {
      auto all_entries = get_all_entries(map);
      auto& key_to_remove = all_entries.begin()->first;
      map = map.remove(key_to_remove);
    }

    // Modify existing key with value that must be different from what `gen_map`
    // populated the map with
    auto all_entries = get_all_entries(map);
    auto& key_to_add = all_entries.begin()->first;
    map = map.put(key_to_add, V(max_key_value_size * 2, 'x'));
  }

  INFO("Even though map has been updated, original snapshot is not modified");
  {
    REQUIRE_EQ(
      snapshot->get_serialized_size(), serialised_snapshot_before_size);
    std::vector<uint8_t> serialised_snapshot_after(
      serialised_snapshot_before_size);
    snapshot->serialize(serialised_snapshot_after.data());
    REQUIRE_EQ(serialised_snapshot_before, serialised_snapshot_after);
  }

  INFO("But new snapshot is different");
  {
    auto new_snapshot = map.make_snapshot();
    size_t serialised_snapshot_new_size = new_snapshot->get_serialized_size();
    std::vector<uint8_t> serialised_snapshot_new(serialised_snapshot_new_size);
    new_snapshot->serialize(serialised_snapshot_new.data());
    REQUIRE_NE(serialised_snapshot_before, serialised_snapshot_new);
  }
}

template <class S, class T>
void verify_snapshot_compatibility(const S& source_map, T& target_map)
{
  auto source_entries = get_all_entries(source_map);
  REQUIRE(source_entries.size() == source_map.size());

  auto snapshot = source_map.make_snapshot();
  std::vector<uint8_t> s(source_map.get_serialized_size());
  snapshot->serialize(s.data());

  target_map = map::deserialize_map<T>(s);
  REQUIRE(target_map.size() == source_map.size());

  auto target_entries = get_all_entries(target_map);
  REQUIRE(target_entries.size() == target_map.size());
  REQUIRE(source_entries == target_entries);
}

TEST_CASE("Snapshot compatibility")
{
  size_t size = 100;

  INFO("CHAMP -> RB");
  {
    auto champ_map = gen_map<ChampMap>(size);
    RBMap rb_map;
    verify_snapshot_compatibility<ChampMap, RBMap>(champ_map, rb_map);
  }

  INFO("RB -> CHAMP");
  {
    auto rb_map = gen_map<RBMap>(size);
    ChampMap champ_map;
    verify_snapshot_compatibility<RBMap, ChampMap>(rb_map, champ_map);
  }
}

template <typename M>
void forall_threshold(const M& map, size_t threshold)
{
  size_t iterations_count = 0;
  map.foreach([&iterations_count, threshold](const K& k, const V& v) {
    if (iterations_count >= threshold)
    {
      return false;
    }
    iterations_count++;
    return true;
  });
  REQUIRE(iterations_count == threshold);
}

TEST_CASE_TEMPLATE("Foreach", M, RBMap, ChampMap)
{
  size_t size = 100;
  auto map = gen_map<M>(size);

  size_t threshold = map.size() / 2;
  forall_threshold(map, threshold);
}
