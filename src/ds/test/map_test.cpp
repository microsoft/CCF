// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../champ_map.h"
#include "../rb_map.h"

#include <doctest/doctest.h>
#include <random>

using namespace std;

template <class K>
struct CollisionHash
{
  size_t operator()(const K& k) const noexcept
  {
    return std::hash<K>()(k) % 100;
  }
};

using K = uint64_t;
using V = uint64_t;

// using H = std::hash<K>;
using H = CollisionHash<K>;

struct Op
{
  virtual ~Op() = default;
  virtual pair<const RBMap<K, V>, const champ::Map<K, V, H>> apply(
    const RBMap<K, V>& a, const champ::Map<K, V, H>& b) = 0;
  virtual string str() = 0;
};

struct Put : public Op
{
  K k;
  V v;

  Put(K k_, V v_) : k(k_), v(v_) {}

  pair<const RBMap<K, V>, const champ::Map<K, V, H>> apply(
    const RBMap<K, V>& a, const champ::Map<K, V, H>& b)
  {
    return make_pair(a.put(k, v), b.put(k, v));
  }

  string str()
  {
    auto ss = stringstream();
    ss << "Put(" << H()(k) << ", " << v << ")";
    return ss.str();
  }
};

vector<unique_ptr<Op>> gen_ops(size_t n)
{
  random_device rand_dev;
  auto seed = rand_dev();
  mt19937 gen(seed);
  uniform_int_distribution<> gen_op(0, 2);

  vector<unique_ptr<Op>> ops;
  vector<K> keys;
  for (V v = 0; v < n; ++v)
  {
    unique_ptr<Op> op;
    auto op_i = ops.empty() ? 0 : gen_op(gen);
    switch (op_i)
    {
      case 0:
      case 1: // insert
      {
        auto k = gen();
        keys.push_back(k);
        op = make_unique<Put>(k, v);

        break;
      }
      case 2: // update
      {
        uniform_int_distribution<> gen_idx(0, keys.size() - 1);
        auto k = keys[gen_idx(gen)];
        op = make_unique<Put>(k, v);

        break;
      }
      default:
        throw logic_error("bad op number");
    }
    ops.push_back(move(op));
  }

  return ops;
}

TEST_CASE("persistent map operations")
{
  RBMap<K, V> rb;
  champ::Map<K, V, H> champ;

  auto ops = gen_ops(500);
  for (auto& op : ops)
  {
    auto r = op->apply(rb, champ);
    auto rb_new = r.first;
    auto champ_new = r.second;

    INFO("check consistency of persistent maps");
    {
      size_t n = 0;
      champ_new.foreach([&](const auto& k, const auto& v) {
        n++;
        auto p = rb_new.get(k);
        REQUIRE(p.has_value());
        REQUIRE(p.value() == v);
        return true;
      });
      REQUIRE(n == champ_new.size());
    }

    INFO("check persistence of previous versions");
    {
      size_t n = 0;
      champ.foreach([&](const auto& k, const auto& v) {
        n++;
        auto p = rb.get(k);
        REQUIRE(p.has_value());
        REQUIRE(p.value() == v);
        return true;
      });
      REQUIRE(n == champ.size());
    }

    rb = rb_new;
    champ = champ_new;
  }
}

static const champ::Map<K, V, H> gen_map(size_t size)
{
  champ::Map<K, V, H> map;
  for (uint32_t j = 0; j < 2; ++j)
  {
    for (uint64_t i = 0; i < size; ++i)
    {
      map = map.put(i, i);
    }
  }
  return map;
}

TEST_CASE("serialize map")
{
  struct pair
  {
    K k;
    V v;
  };

  std::vector<pair> results;
  uint32_t num_elements = 100;
  auto map = gen_map(num_elements);
  INFO("make sure we can serialize a map");
  {
    map.foreach([&results](const auto& key, const auto& value) {
      results.push_back({key, value});
      return true;
    });
    REQUIRE_EQ(num_elements, results.size());
  }

  INFO("make sure we can deserialize a map");
  {
    std::set<K> keys;
    champ::Map<K, V, H> new_map;
    for (const auto& p : results)
    {
      REQUIRE_LT(p.k, num_elements);
      keys.insert(p.k);
      new_map = new_map.put(p.k, p.v);
    }
    REQUIRE_EQ(num_elements, new_map.size());
    REQUIRE_EQ(num_elements, keys.size());
  }

  std::function<uint32_t(const K& key)> fn_size_k = [](const K& k) {
    return sizeof(K) + sizeof(uint64_t);
  };
  std::function<uint32_t(const K& key, uint8_t*& data, size_t& size)>
    fn_serialize_k = [](const K& k, uint8_t*& data, size_t& size) {
      uint64_t key_size = sizeof(K);
      serialized::write(
        data, size, reinterpret_cast<const uint8_t*>(&key_size), sizeof(K));
      serialized::write(
        data, size, reinterpret_cast<const uint8_t*>(&k), sizeof(K));
      return 2 * sizeof(K);
    };
  std::function<uint32_t(const V& value)> fn_size_v = [](const V& v) {
    return sizeof(V) + sizeof(uint64_t);
  };
  std::function<uint32_t(const V& value, uint8_t*& data, size_t& size)>
    fn_serialize_v = [](const V& v, uint8_t*& data, size_t& size) {
      uint64_t value_size = sizeof(V);
      serialized::write(
        data, size, reinterpret_cast<const uint8_t*>(&value_size), sizeof(V));
      serialized::write(
        data, size, reinterpret_cast<const uint8_t*>(&v), sizeof(V));
      return 2 * sizeof(V);
    };

  std::function<K(const uint8_t*& key, size_t&)> make_k =
    [](const uint8_t*& data, size_t& size) -> K {
    size_t key_size = serialized::read<size_t>(data, size);
    return serialized::read<K>(data, size);
  };
  std::function<V(const uint8_t*& key, size_t&)> make_v =
    [](const uint8_t*& data, size_t& size) -> V {
    size_t value_size = serialized::read<size_t>(data, size);
    return serialized::read<V>(data, size);
  };

  INFO("Serialize map to array");
  {
    champ::Snapshot<K, V, H> snapshot(
      map, /*fn_size_k,*/ fn_serialize_k, /*fn_size_v,*/ fn_serialize_v);
    const std::vector<uint8_t>& s = snapshot.get_buffer();

    champ::Map<K, V, H> new_map =
      champ::Map<K, V, H>::deserialize_map(s, make_k, make_v);

    std::set<K> keys;
    new_map.foreach([&keys](const auto& key, const auto& value) {
      keys.insert(key);
      REQUIRE_EQ(key, value);
      return true;
    });
    REQUIRE_EQ(map.size(), new_map.size());
    REQUIRE_EQ(map.size(), keys.size());

    uint32_t offset = 1000;
    for (uint32_t i = offset; i < offset + num_elements; ++i)
    {
      new_map = new_map.put(i, i);
    }
    REQUIRE_EQ(new_map.size(), map.size() + num_elements);
    for (uint32_t i = offset; i < offset + num_elements; ++i)
    {
      auto p = new_map.get(i);
      REQUIRE(p.has_value());
      REQUIRE(p.value() == i);
    }
  }

  INFO("Ensure serialized state is byte identical");
  {
    champ::Snapshot<K, V, H> snapshot_1(
      //map, fn_size_k, fn_serialize_k, fn_size_v, fn_serialize_v);
      map, /*fn_size_k,*/ fn_serialize_k, /*fn_size_v,*/ fn_serialize_v);
    const std::vector<uint8_t>& s_1 = snapshot_1.get_buffer();

    champ::Snapshot<K, V, H> snapshot_2(
      //map, fn_size_k, fn_serialize_k, fn_size_v, fn_serialize_v);
      map, /*fn_size_k,*/ fn_serialize_k, /*fn_size_v,*/ fn_serialize_v);
    const std::vector<uint8_t>& s_2 = snapshot_2.get_buffer();

    REQUIRE_EQ(s_1.size(), s_2.size());
    for (uint32_t i = 0; i < s_1.size(); ++i)
    {
      REQUIRE_EQ(s_1[i], s_2[i]);
    }
  }
}