// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/buffer.h"
#include "ds/ccf_assert.h"
#include "ds/champ_map_serializers.h"

#include <algorithm>
#include <array>
#include <memory>
#include <optional>
#include <vector>

namespace champ
{
  // A persistent hash map based on the Compressed Hash-Array Mapped Preﬁx-tree
  // from 'Fast and Lean Immutable Multi-Maps on the JVM based on Heterogeneous
  // Hash-Array Mapped Tries' by Michael J. Steindorfer and Jurgen J. Vinju
  // (https://arxiv.org/pdf/1608.01036.pdf).

  static constexpr size_t index_mask_bits = 5;
  static constexpr size_t index_mask = (1 << index_mask_bits) - 1;

  using Hash = uint32_t;
  static constexpr size_t hash_bits = sizeof(Hash) * 8;

  using SmallIndex = uint8_t;
  static constexpr size_t small_index_bits = sizeof(SmallIndex) * 8;
  static_assert(small_index_bits > index_mask_bits);

  static constexpr size_t collision_node_bits = hash_bits % index_mask_bits;
  static_assert(collision_node_bits > 0);
  static constexpr SmallIndex collision_depth = hash_bits / index_mask_bits;
  static constexpr size_t collision_bins = 1 << collision_node_bits;

  static constexpr SmallIndex mask(Hash hash, SmallIndex depth)
  {
    return (hash >> ((Hash)depth * index_mask_bits)) & index_mask;
  }

  class Bitmap
  {
    uint32_t _bits;

  public:
    constexpr Bitmap() : _bits(0) {}

    constexpr Bitmap(uint32_t bits) : _bits(bits) {}

    constexpr Bitmap operator&(const Bitmap& other) const
    {
      return Bitmap(_bits & other._bits);
    }

    constexpr SmallIndex pop() const
    {
      return __builtin_popcount(_bits);
    }

    constexpr Bitmap set(SmallIndex idx) const
    {
      return Bitmap(_bits | ((uint32_t)1 << idx));
    }

    constexpr Bitmap clear(SmallIndex idx) const
    {
      return Bitmap(_bits & ~((uint32_t)1 << idx));
    }

    constexpr bool check(SmallIndex idx) const
    {
      return (_bits & ((uint32_t)1 << idx)) != 0;
    }
  };

  template <class K, class V, class H>
  struct SubNodes;

  template <class K, class V>
  struct Entry
  {
    K key;
    V value;

    Entry(K k, V v) : key(k), value(v) {}

    const V* getp(const K& k) const
    {
      if (k == key)
        return &value;
      else
        return nullptr;
    }
  };

  uint32_t static get_padding(uint32_t size)
  {
    uint32_t padding = size % sizeof(uintptr_t);
    if (padding != 0)
    {
      padding = sizeof(uintptr_t) - padding;
    }
    return padding;
  }

  template <class K, class V>
  size_t static get_size_with_padding(const K& k, const V& v)
  {
    uint32_t size_k = champ::get_size(k);
    uint32_t size_v = champ::get_size(v);
    return size_k + get_padding(size_k) + size_v + get_padding(size_v);
  }

  template <class K, class V, class H>
  using Node = std::shared_ptr<void>;

  template <class K, class V, class H>
  struct Collisions
  {
    std::array<std::vector<std::shared_ptr<Entry<K, V>>>, collision_bins> bins;

    const V* getp(Hash hash, const K& k) const
    {
      const auto idx = mask(hash, collision_depth);
      const auto& bin = bins[idx];
      for (const auto& node : bin)
      {
        if (k == node->key)
          return &node->value;
      }
      return nullptr;
    }

    size_t put_mut(Hash hash, const K& k, const V& v)
    {
      const auto idx = mask(hash, collision_depth);
      auto& bin = bins[idx];
      for (size_t i = 0; i < bin.size(); ++i)
      {
        const auto& entry = bin[i];
        if (k == entry->key)
        {
          bin[i] = std::make_shared<Entry<K, V>>(k, v);
          return champ::get_size<K>(k) + champ::get_size<V>(v);
        }
      }
      bin.push_back(std::make_shared<Entry<K, V>>(k, v));
      return 0;
    }

    size_t remove_mut(Hash hash, const K& k)
    {
      const auto idx = mask(hash, collision_depth);
      auto& bin = bins[idx];
      for (size_t i = 0; i < bin.size(); ++i)
      {
        const auto& entry = bin[i];
        if (k == entry->key)
        {
          const auto diff =
            champ::get_size<K>(entry->key) + champ::get_size<V>(entry->value);
          bin.erase(bin.begin() + i);
          return diff;
        }
      }
      return 0;
    }

    template <class F>
    bool foreach(F&& f) const
    {
      for (const auto& bin : bins)
      {
        for (const auto& entry : bin)
          if (!f(entry->key, entry->value))
            return false;
      }
      return true;
    }
  };

  template <class K, class V, class H>
  struct SubNodes
  {
    std::vector<Node<K, V, H>> nodes;
    Bitmap node_map;
    Bitmap data_map;

    SubNodes() {}

    SubNodes(std::vector<Node<K, V, H>>&& ns) : nodes(std::move(ns)) {}

    SubNodes(std::vector<Node<K, V, H>>&& ns, Bitmap nm, Bitmap dm) :
      nodes(std::move(ns)),
      node_map(nm),
      data_map(dm)
    {}

    SmallIndex compressed_idx(SmallIndex idx) const
    {
      if (!node_map.check(idx) && !data_map.check(idx))
        return (SmallIndex)-1;

      const auto mask = Bitmap(~((uint32_t)-1 << idx));
      if (data_map.check(idx))
        return (data_map & mask).pop();

      return data_map.pop() + (node_map & mask).pop();
    }

    const V* getp(SmallIndex depth, Hash hash, const K& k) const
    {
      const auto idx = mask(hash, depth);
      const auto c_idx = compressed_idx(idx);

      if (c_idx == (SmallIndex)-1)
        return nullptr;

      if (data_map.check(idx))
        return node_as<Entry<K, V>>(c_idx)->getp(k);

      if (depth == (collision_depth - 1))
        return node_as<Collisions<K, V, H>>(c_idx)->getp(hash, k);

      return node_as<SubNodes<K, V, H>>(c_idx)->getp(depth + 1, hash, k);
    }

    size_t put_mut(SmallIndex depth, Hash hash, const K& k, const V& v)
    {
      const auto idx = mask(hash, depth);
      auto c_idx = compressed_idx(idx);

      if (c_idx == (SmallIndex)-1)
      {
        data_map = data_map.set(idx);
        c_idx = compressed_idx(idx);
        nodes.insert(
          nodes.begin() + c_idx, std::make_shared<Entry<K, V>>(k, v));
        return 0;
      }

      if (node_map.check(idx))
      {
        size_t insert;
        if (depth < (collision_depth - 1))
        {
          auto sn = *node_as<SubNodes<K, V, H>>(c_idx);
          insert = sn.put_mut(depth + 1, hash, k, v);
          nodes[c_idx] = std::make_shared<SubNodes<K, V, H>>(std::move(sn));
        }
        else
        {
          auto sn = *node_as<Collisions<K, V, H>>(c_idx);
          insert = sn.put_mut(hash, k, v);
          nodes[c_idx] = std::make_shared<Collisions<K, V, H>>(std::move(sn));
        }
        return insert;
      }

      const auto& entry0 = node_as<Entry<K, V>>(c_idx);
      if (k == entry0->key)
      {
        auto current_size =
          get_size_with_padding<K, V>(entry0->key, entry0->value);
        nodes[c_idx] = std::make_shared<Entry<K, V>>(k, v);
        return current_size;
      }

      if (depth < (collision_depth - 1))
      {
        const auto hash0 = H()(entry0->key);
        const auto idx0 = mask(hash0, depth + 1);
        auto sub_node =
          SubNodes<K, V, H>({entry0}, Bitmap(0), Bitmap(0).set(idx0));
        sub_node.put_mut(depth + 1, hash, k, v);

        nodes.erase(nodes.begin() + c_idx);
        data_map = data_map.clear(idx);
        node_map = node_map.set(idx);
        c_idx = compressed_idx(idx);
        nodes.insert(
          nodes.begin() + c_idx,
          std::make_shared<SubNodes<K, V, H>>(std::move(sub_node)));
      }
      else
      {
        auto sub_node = Collisions<K, V, H>();
        const auto hash0 = H()(entry0->key);
        const auto idx0 = mask(hash0, collision_depth);
        sub_node.bins[idx0].push_back(entry0);
        const auto idx1 = mask(hash, collision_depth);
        sub_node.bins[idx1].push_back(std::make_shared<Entry<K, V>>(k, v));

        nodes.erase(nodes.begin() + c_idx);
        data_map = data_map.clear(idx);
        node_map = node_map.set(idx);
        c_idx = compressed_idx(idx);
        nodes.insert(
          nodes.begin() + c_idx,
          std::make_shared<Collisions<K, V, H>>(std::move(sub_node)));
      }
      return 0;
    }

    std::pair<std::shared_ptr<SubNodes<K, V, H>>, size_t> put(
      SmallIndex depth, Hash hash, const K& k, const V& v) const
    {
      auto node = *this;
      auto r = node.put_mut(depth, hash, k, v);
      return std::make_pair(
        std::make_shared<SubNodes<K, V, H>>(std::move(node)), r);
    }

    size_t remove_mut(SmallIndex depth, Hash hash, const K& k)
    {
      const auto idx = mask(hash, depth);
      const auto c_idx = compressed_idx(idx);

      if (c_idx == (SmallIndex)-1)
        return 0;

      if (data_map.check(idx))
      {
        const auto& entry = node_as<Entry<K, V>>(c_idx);
        if (entry->key != k)
          return 0;

        const auto diff = get_size_with_padding<K, V>(entry->key, entry->value);
        nodes.erase(nodes.begin() + c_idx);
        data_map = data_map.clear(idx);
        return diff;
      }

      if (depth == (collision_depth - 1))
      {
        auto sn = *node_as<Collisions<K, V, H>>(c_idx);
        const auto diff = sn.remove_mut(hash, k);
        nodes[c_idx] = std::make_shared<Collisions<K, V, H>>(std::move(sn));
        return diff;
      }

      auto sn = *node_as<SubNodes<K, V, H>>(c_idx);
      const auto diff = sn.remove_mut(depth + 1, hash, k);
      nodes[c_idx] = std::make_shared<SubNodes<K, V, H>>(std::move(sn));
      return diff;
    }

    std::pair<std::shared_ptr<SubNodes<K, V, H>>, size_t> remove(
      SmallIndex depth, Hash hash, const K& k) const
    {
      auto node = *this;
      auto r = node.remove_mut(depth, hash, k);
      return std::make_pair(
        std::make_shared<SubNodes<K, V, H>>(std::move(node)), r);
    }

    template <class F>
    bool foreach(SmallIndex depth, F&& f) const
    {
      const auto entries = data_map.pop();
      for (SmallIndex i = 0; i < entries; ++i)
      {
        const auto& entry = node_as<Entry<K, V>>(i);
        if (!f(entry->key, entry->value))
          return false;
      }
      for (size_t i = entries; i < nodes.size(); ++i)
      {
        if (depth == (collision_depth - 1))
        {
          if (!node_as<Collisions<K, V, H>>(i)->foreach(std::forward<F>(f)))
            return false;
        }
        else
        {
          if (!node_as<SubNodes<K, V, H>>(i)->foreach(
                depth + 1, std::forward<F>(f)))
            return false;
        }
      }
      return true;
    }

  private:
    template <class A>
    const std::shared_ptr<A>& node_as(SmallIndex c_idx) const
    {
      return reinterpret_cast<const std::shared_ptr<A>&>(nodes[c_idx]);
    }
  };

  template <class K, class V, class H = std::hash<K>>
  class Map
  {
  private:
    std::shared_ptr<SubNodes<K, V, H>> root;
    size_t map_size = 0;
    size_t serialized_size = 0;

    Map(
      std::shared_ptr<SubNodes<K, V, H>>&& root_,
      size_t size_,
      size_t serialized_size_) :
      root(std::move(root_)),
      map_size(size_),
      serialized_size(serialized_size_)
    {}

  public:
    Map() : root(std::make_shared<SubNodes<K, V, H>>()) {}

    static Map<K, V, H> deserialize_map(CBuffer serialized_state)
    {
      Map<K, V, H> map;
      const uint8_t* data = serialized_state.p;
      size_t size = serialized_state.rawSize();

      while (size != 0)
      {
        // Deserialize the key
        size_t key_size = size;
        K key = champ::deserialize<K>(data, size);
        key_size -= size;
        serialized::skip(data, size, get_padding(key_size));

        // Deserialize the value
        size_t value_size = size;
        V value = champ::deserialize<V>(data, size);
        value_size -= size;
        serialized::skip(data, size, get_padding(value_size));
        map = map.put(key, value);
      }
      return map;
    }

    size_t size() const
    {
      return map_size;
    }

    size_t get_serialized_size() const
    {
      return serialized_size;
    }

    bool empty() const
    {
      return map_size == 0;
    }

    std::optional<V> get(const K& key) const
    {
      auto v = root->getp(0, H()(key), key);

      if (v)
        return *v;
      else
        return {};
    }

    const V* getp(const K& key) const
    {
      return root->getp(0, H()(key), key);
    }

    const Map<K, V, H> put(const K& key, const V& value) const
    {
      auto r = root->put(0, H()(key), key, value);
      auto size_ = map_size;
      if (r.second == 0)
        size_++;

      int64_t size_change = get_size_with_padding<K, V>(key, value) - r.second;
      return Map(std::move(r.first), size_, size_change + serialized_size);
    }

    const Map<K, V, H> remove(const K& key) const
    {
      auto r = root->remove(0, H()(key), key);
      auto size_ = map_size;
      if (r.second > 0)
        size_--;

      return Map(std::move(r.first), size_, serialized_size - r.second);
    }

    template <class F>
    bool foreach(F&& f) const
    {
      return root->foreach(0, std::forward<F>(f));
    }
  };

  template <class K, class V, class H = std::hash<K>>
  class Snapshot
  {
  private:
    Map<K, V, H> map;
    CBuffer serialized_buffer;

    struct KVTuple
    {
      K* k;
      Hash h_k;
      V* v;

      KVTuple(K* k_, Hash h_k_, V* v_) : k(k_), h_k(h_k_), v(v_) {}
    };
    const uintptr_t padding = 0;

    uint32_t add_padding(uint32_t data_size, uint8_t*& data, size_t& size) const
    {
      uint32_t padding_size = get_padding(data_size);
      if (padding_size != 0)
      {
        serialized::write(
          data, size, reinterpret_cast<const uint8_t*>(&padding), padding_size);
      }
      return padding_size;
    }

  public:
    Snapshot(Map<K, V, H>& map_)
    {
      map = map_;
    }

    size_t get_serialized_size()
    {
      return map.get_serialized_size();
    }

    CBuffer& get_serialized_buffer()
    {
      return serialized_buffer;
    }

    void serialize(uint8_t* data)
    {
      std::vector<KVTuple> ordered_state;
      ordered_state.reserve(map.size());
      size_t size = 0;

      map.foreach([&](auto& key, auto& value) {
        K* k = &key;
        V* v = &value;
        uint32_t ks = champ::get_size(key);
        uint32_t vs = champ::get_size(value);
        uint32_t key_size = ks + get_padding(ks);
        uint32_t value_size = vs + get_padding(vs);

        size += (key_size + value_size);

        ordered_state.emplace_back(k, static_cast<Hash>(H()(key)), v);

        return true;
      });

      // Sort keys to be able to generate byte-for-byte serialised snapshot from
      // the same state
      std::sort(
        ordered_state.begin(), ordered_state.end(), [](KVTuple& i, KVTuple& j) {
          return i.h_k < j.h_k;
        });

      CCF_ASSERT_FMT(
        size == map.get_serialized_size(),
        "size:{}, map->size:{} ==> count:{}, vect:{}",
        size,
        map.get_serialized_size(),
        map.size(),
        ordered_state.size());

      serialized_buffer = CBuffer(data, map.get_serialized_size());

      for (const auto& p : ordered_state)
      {
        // Serialize the key
        uint32_t key_size = champ::serialize(*p.k, data, size);
        add_padding(key_size, data, size);

        // Serialize the value
        uint32_t value_size = champ::serialize(*p.v, data, size);
        add_padding(value_size, data, size);
      }

      CCF_ASSERT_FMT(size == 0, "buffer not filled, remaining:{}", size);
    }
  };
}
