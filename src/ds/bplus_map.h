// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ccf_assert.h"
#include "ds/map_serializers.h"

#include <cassert>
#include <memory>
#include <optional>
#include <vector>

namespace bplus
{
  template <class K, class V>
  class Snapshot;

  // Persistent (immutable) B+ tree map with shared-entry leaves.
  // Leaf nodes hold vector<shared_ptr<const Entry>> — cloning a leaf
  // copies only pointers (refcount bumps), not key/value data.
  // Internal nodes hold separator keys + child pointers.
  template <class K, class V, int B = 16>
  class Map
  {
  public:
    using KeyType = K;
    using ValueType = V;
    using Snapshot = bplus::Snapshot<K, V>;

  private:
    static constexpr int MAX_KEYS = 2 * B;
    static constexpr int MIN_KEYS = B;

    // ── Entry and node types ──────────────────────────────────────────

    struct Entry
    {
      K key;
      V value;
      Entry(const K& k, const V& v) : key(k), value(v) {}
    };

    using EntryPtr = std::shared_ptr<const Entry>;

    struct NodeBase
    {
      bool is_leaf = true;
    };

    struct Internal : NodeBase
    {
      std::vector<K> keys;
      std::vector<std::shared_ptr<const NodeBase>> children;

      Internal()
      {
        this->is_leaf = false;
      }

      int count() const
      {
        return static_cast<int>(keys.size());
      }

      int child_idx(const K& key) const
      {
        int lo = 0, hi = count();
        while (lo < hi)
        {
          int mid = (lo + hi) / 2;
          if (!(key < keys[mid]))
            lo = mid + 1;
          else
            hi = mid;
        }
        return lo;
      }
    };

    struct Leaf : NodeBase
    {
      std::vector<EntryPtr> entries;

      int count() const
      {
        return static_cast<int>(entries.size());
      }

      std::pair<bool, int> find_key(const K& key) const
      {
        int lo = 0, hi = count();
        while (lo < hi)
        {
          int mid = (lo + hi) / 2;
          if (entries[mid]->key < key)
            lo = mid + 1;
          else
            hi = mid;
        }
        if (lo < count() && !(key < entries[lo]->key) &&
            !(entries[lo]->key < key))
          return {true, lo};
        return {false, lo};
      }
    };

    // ── Helpers ───────────────────────────────────────────────────────

    static int node_count(const NodeBase* n)
    {
      if (n->is_leaf)
        return as_leaf(n)->count();
      return as_internal(n)->count();
    }

    static const Internal* as_internal(const NodeBase* n)
    {
      assert(!n->is_leaf);
      return static_cast<const Internal*>(n);
    }

    static const Leaf* as_leaf(const NodeBase* n)
    {
      assert(n->is_leaf);
      return static_cast<const Leaf*>(n);
    }

    static std::shared_ptr<Internal> clone_internal(
      const std::shared_ptr<const NodeBase>& n)
    {
      return std::make_shared<Internal>(*as_internal(n.get()));
    }

    static std::shared_ptr<Leaf> clone_leaf(
      const std::shared_ptr<const NodeBase>& n)
    {
      return std::make_shared<Leaf>(*as_leaf(n.get()));
    }

    static EntryPtr make_entry(const K& k, const V& v)
    {
      return std::make_shared<const Entry>(k, v);
    }

    static size_t kv_ser_size(const K& k, const V& v)
    {
      return map::get_serialized_size_with_padding(k) +
        map::get_serialized_size_with_padding(v);
    }

    std::shared_ptr<const NodeBase> _root;
    size_t _size = 0;
    size_t _serialized_size = 0;

    explicit Map(
      std::shared_ptr<const NodeBase> root, size_t sz, size_t ser_sz) :
      _root(std::move(root)),
      _size(sz),
      _serialized_size(ser_sz)
    {}

    // ── Insert ────────────────────────────────────────────────────────

    struct InsertResult
    {
      std::shared_ptr<const NodeBase> node;
      bool split = false;
      K separator = {};
      std::shared_ptr<const NodeBase> right_node = {};
    };

    static InsertResult insert(
      const std::shared_ptr<const NodeBase>& node,
      const EntryPtr& entry)
    {
      if (node->is_leaf)
        return insert_leaf(node, entry);
      return insert_internal(node, entry);
    }

    static InsertResult insert_leaf(
      const std::shared_ptr<const NodeBase>& node,
      const EntryPtr& entry)
    {
      auto* old = as_leaf(node.get());
      auto [found, idx] = old->find_key(entry->key);

      if (found)
      {
        // Replace existing entry
        auto n = clone_leaf(node);
        n->entries[idx] = entry;
        return {n};
      }
      if (old->count() < MAX_KEYS)
      {
        auto n = clone_leaf(node);
        n->entries.insert(n->entries.begin() + idx, entry);
        return {n};
      }
      return split_leaf(node, idx, entry);
    }

    static InsertResult split_leaf(
      const std::shared_ptr<const NodeBase>& node,
      int idx,
      const EntryPtr& entry)
    {
      auto* old = as_leaf(node.get());
      int total = old->count() + 1;
      int mid = total / 2;

      // Build merged entry list
      std::vector<EntryPtr> all;
      all.reserve(total);
      all.insert(all.end(), old->entries.begin(), old->entries.begin() + idx);
      all.push_back(entry);
      all.insert(
        all.end(), old->entries.begin() + idx, old->entries.end());

      auto left = std::make_shared<Leaf>();
      left->entries.assign(all.begin(), all.begin() + mid);

      auto right = std::make_shared<Leaf>();
      right->entries.assign(all.begin() + mid, all.end());

      return {left, true, right->entries[0]->key, right};
    }

    static InsertResult insert_internal(
      const std::shared_ptr<const NodeBase>& node,
      const EntryPtr& entry)
    {
      auto* old = as_internal(node.get());
      int ci = old->child_idx(entry->key);
      auto cr = insert(old->children[ci], entry);

      if (!cr.split)
      {
        auto n = clone_internal(node);
        n->children[ci] = cr.node;
        return {n};
      }

      if (old->count() < MAX_KEYS)
      {
        auto n = clone_internal(node);
        n->keys.insert(n->keys.begin() + ci, std::move(cr.separator));
        n->children[ci] = cr.node;
        n->children.insert(n->children.begin() + ci + 1, cr.right_node);
        return {n};
      }

      return split_internal(node, ci, cr.separator, cr.node, cr.right_node);
    }

    static InsertResult split_internal(
      const std::shared_ptr<const NodeBase>& node,
      int idx,
      const K& sep,
      const std::shared_ptr<const NodeBase>& lc,
      const std::shared_ptr<const NodeBase>& rc)
    {
      auto* old = as_internal(node.get());
      int total = old->count() + 1;
      int mid = total / 2;

      // Merge keys and children
      std::vector<K> all_keys;
      all_keys.reserve(total);
      std::vector<std::shared_ptr<const NodeBase>> all_children;
      all_children.reserve(total + 1);

      for (int i = 0; i < idx; ++i)
      {
        all_keys.push_back(old->keys[i]);
        all_children.push_back(old->children[i]);
      }
      all_keys.push_back(sep);
      all_children.push_back(lc);
      all_children.push_back(rc);
      for (int i = idx; i < old->count(); ++i)
      {
        all_keys.push_back(old->keys[i]);
        all_children.push_back(old->children[i + 1]);
      }

      auto left = std::make_shared<Internal>();
      left->keys.assign(all_keys.begin(), all_keys.begin() + mid);
      left->children.assign(
        all_children.begin(), all_children.begin() + mid + 1);

      K promoted = std::move(all_keys[mid]);

      auto right = std::make_shared<Internal>();
      right->keys.assign(
        std::make_move_iterator(all_keys.begin() + mid + 1),
        std::make_move_iterator(all_keys.end()));
      right->children.assign(
        std::make_move_iterator(all_children.begin() + mid + 1),
        std::make_move_iterator(all_children.end()));

      return {left, true, std::move(promoted), right};
    }

    // ── Remove ────────────────────────────────────────────────────────

    struct RemoveResult
    {
      std::shared_ptr<const NodeBase> node;
      bool found = false;
      bool underflow = false;
    };

    static RemoveResult do_remove(
      const std::shared_ptr<const NodeBase>& node, const K& key)
    {
      if (node->is_leaf)
      {
        auto* leaf = as_leaf(node.get());
        auto [found, idx] = leaf->find_key(key);
        if (!found)
          return {node, false, false};
        if (leaf->count() == 1)
          return {nullptr, true, true};

        auto n = clone_leaf(node);
        n->entries.erase(n->entries.begin() + idx);
        return {n, true, n->count() < MIN_KEYS};
      }

      auto* internal = as_internal(node.get());
      int ci = internal->child_idx(key);
      auto cr = do_remove(internal->children[ci], key);
      if (!cr.found)
        return {node, false, false};

      auto n = clone_internal(node);
      n->children[ci] = cr.node;
      if (cr.underflow)
        return fix_underflow(n, ci);
      return {n, true, n->count() < MIN_KEYS};
    }

    static RemoveResult fix_underflow(
      std::shared_ptr<Internal>& node, int ci)
    {
      bool children_are_leaves = node->children[ci]->is_leaf;

      if (ci > 0 && node_count(node->children[ci - 1].get()) > MIN_KEYS)
      {
        if (children_are_leaves)
          return borrow_left_leaf(node, ci);
        else
          return borrow_left_internal(node, ci);
      }

      if (
        ci < node->count() &&
        node_count(node->children[ci + 1].get()) > MIN_KEYS)
      {
        if (children_are_leaves)
          return borrow_right_leaf(node, ci);
        else
          return borrow_right_internal(node, ci);
      }

      int mi = ci > 0 ? ci - 1 : ci;
      if (children_are_leaves)
        return merge_leaves(node, mi);
      else
        return merge_internals(node, mi);
    }

    // ── Leaf borrow ───────────────────────────────────────────────────

    static RemoveResult borrow_left_leaf(
      std::shared_ptr<Internal>& parent, int ci)
    {
      auto sib = clone_leaf(parent->children[ci - 1]);
      auto child = clone_leaf(parent->children[ci]);

      child->entries.insert(
        child->entries.begin(), std::move(sib->entries.back()));
      sib->entries.pop_back();

      parent->keys[ci - 1] = child->entries[0]->key;
      parent->children[ci - 1] = sib;
      parent->children[ci] = child;
      return {parent, true, parent->count() < MIN_KEYS};
    }

    static RemoveResult borrow_right_leaf(
      std::shared_ptr<Internal>& parent, int ci)
    {
      auto child = clone_leaf(parent->children[ci]);
      auto sib = clone_leaf(parent->children[ci + 1]);

      child->entries.push_back(std::move(sib->entries.front()));
      sib->entries.erase(sib->entries.begin());

      parent->keys[ci] = sib->entries[0]->key;
      parent->children[ci] = child;
      parent->children[ci + 1] = sib;
      return {parent, true, parent->count() < MIN_KEYS};
    }

    // ── Internal borrow ───────────────────────────────────────────────

    static RemoveResult borrow_left_internal(
      std::shared_ptr<Internal>& parent, int ci)
    {
      auto sib = clone_internal(parent->children[ci - 1]);
      auto child = clone_internal(parent->children[ci]);

      child->keys.insert(
        child->keys.begin(), std::move(parent->keys[ci - 1]));
      child->children.insert(
        child->children.begin(), std::move(sib->children.back()));
      sib->children.pop_back();

      parent->keys[ci - 1] = std::move(sib->keys.back());
      sib->keys.pop_back();

      parent->children[ci - 1] = sib;
      parent->children[ci] = child;
      return {parent, true, parent->count() < MIN_KEYS};
    }

    static RemoveResult borrow_right_internal(
      std::shared_ptr<Internal>& parent, int ci)
    {
      auto child = clone_internal(parent->children[ci]);
      auto sib = clone_internal(parent->children[ci + 1]);

      child->keys.push_back(std::move(parent->keys[ci]));
      child->children.push_back(std::move(sib->children.front()));
      sib->children.erase(sib->children.begin());

      parent->keys[ci] = std::move(sib->keys.front());
      sib->keys.erase(sib->keys.begin());

      parent->children[ci] = child;
      parent->children[ci + 1] = sib;
      return {parent, true, parent->count() < MIN_KEYS};
    }

    // ── Leaf merge ────────────────────────────────────────────────────

    static RemoveResult merge_leaves(
      std::shared_ptr<Internal>& parent, int idx)
    {
      auto left = clone_leaf(parent->children[idx]);
      auto* right = as_leaf(parent->children[idx + 1].get());

      left->entries.insert(
        left->entries.end(), right->entries.begin(), right->entries.end());

      parent->keys.erase(parent->keys.begin() + idx);
      parent->children.erase(parent->children.begin() + idx + 1);
      parent->children[idx] = left;
      return {parent, true, parent->count() < MIN_KEYS};
    }

    // ── Internal merge ────────────────────────────────────────────────

    static RemoveResult merge_internals(
      std::shared_ptr<Internal>& parent, int idx)
    {
      auto left = clone_internal(parent->children[idx]);
      auto* right = as_internal(parent->children[idx + 1].get());

      left->keys.push_back(std::move(parent->keys[idx]));
      left->keys.insert(
        left->keys.end(), right->keys.begin(), right->keys.end());
      left->children.insert(
        left->children.end(), right->children.begin(), right->children.end());

      parent->keys.erase(parent->keys.begin() + idx);
      parent->children.erase(parent->children.begin() + idx + 1);
      parent->children[idx] = left;
      return {parent, true, parent->count() < MIN_KEYS};
    }

    // ── Traversal ─────────────────────────────────────────────────────

    template <class F>
    static bool foreach_node(
      const std::shared_ptr<const NodeBase>& node, F&& f)
    {
      if (!node)
        return true;
      if (node->is_leaf)
      {
        auto* leaf = as_leaf(node.get());
        for (auto& e : leaf->entries)
        {
          if (!f(e->key, e->value))
            return false;
        }
        return true;
      }
      auto* internal = as_internal(node.get());
      for (int i = 0; i <= internal->count(); ++i)
      {
        if (!foreach_node(internal->children[i], std::forward<F>(f)))
          return false;
      }
      return true;
    }

  public:
    Map() = default;

    bool empty() const
    {
      return !_root;
    }

    size_t size() const
    {
      return _size;
    }

    size_t get_serialized_size() const
    {
      return _serialized_size;
    }

    std::optional<V> get(const K& key) const
    {
      auto p = getp(key);
      if (p)
        return *p;
      return std::nullopt;
    }

    const V* getp(const K& key) const
    {
      const NodeBase* n = _root.get();
      while (n && !n->is_leaf)
      {
        auto* internal = as_internal(n);
        n = internal->children[internal->child_idx(key)].get();
      }
      if (!n)
        return nullptr;
      auto* leaf = as_leaf(n);
      auto [found, idx] = leaf->find_key(key);
      return found ? &leaf->entries[idx]->value : nullptr;
    }

    Map put(const K& key, const V& value) const
    {
      size_t new_size = _size;
      size_t new_ser = _serialized_size;
      size_t added = kv_ser_size(key, value);

      auto existing = getp(key);
      if (existing)
      {
        new_ser -= kv_ser_size(key, *existing);
        new_ser += added;
      }
      else
      {
        new_size++;
        new_ser += added;
      }

      auto entry = make_entry(key, value);

      if (!_root)
      {
        auto leaf = std::make_shared<Leaf>();
        leaf->entries.push_back(std::move(entry));
        return Map(leaf, new_size, new_ser);
      }

      auto result = insert(_root, entry);

      if (!result.split)
        return Map(result.node, new_size, new_ser);

      auto new_root = std::make_shared<Internal>();
      new_root->keys.push_back(std::move(result.separator));
      new_root->children.push_back(result.node);
      new_root->children.push_back(result.right_node);
      return Map(new_root, new_size, new_ser);
    }

    Map remove(const K& key) const
    {
      if (!_root)
        return *this;

      auto existing = getp(key);
      if (!existing)
        return *this;

      size_t new_ser = _serialized_size - kv_ser_size(key, *existing);

      auto result = do_remove(_root, key);
      assert(result.found);

      if (!result.node)
        return Map();

      if (!result.node->is_leaf && node_count(result.node.get()) == 0)
      {
        auto child = as_internal(result.node.get())->children[0];
        return Map(child, _size - 1, child ? new_ser : 0);
      }

      return Map(result.node, _size - 1, new_ser);
    }

    template <class F>
    bool foreach(F&& f) const
    {
      return foreach_node(_root, std::forward<F>(f));
    }

    std::unique_ptr<Snapshot> make_snapshot() const
    {
      return std::make_unique<Snapshot>(*this);
    }
  };

  template <class K, class V>
  class Snapshot
  {
  private:
    const Map<K, V> map;

  public:
    Snapshot(const Map<K, V>& map_) : map(map_) {}

    size_t get_serialized_size()
    {
      return map.get_serialized_size();
    }

    void serialize(uint8_t* data)
    {
      size_t size = map.get_serialized_size();

      map.foreach([&data, &size](const K& k, const V& v) {
        uint32_t key_size = map::serialize(k, data, size);
        map::add_padding(key_size, data, size);

        uint32_t value_size = map::serialize(v, data, size);
        map::add_padding(value_size, data, size);
        return true;
      });

      CCF_ASSERT_FMT(size == 0, "buffer not filled, remaining:{}", size);
    }
  };
}
