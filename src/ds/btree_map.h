// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ccf_assert.h"
#include "ds/map_serializers.h"

#include <cassert>
#include <memory>
#include <optional>
#include <vector>

namespace btree
{
  template <class K, class V>
  class Snapshot;

  // Persistent (immutable) B-tree map with shared-entry nodes.
  // Key-value pairs are stored as shared_ptr<const Entry> at every level.
  // Cloning a node copies only pointers — no key/value data is duplicated.
  // Nodes use std::vector so cloning only copies populated slots.
  template <class K, class V, int B = 16>
  class Map
  {
  public:
    using KeyType = K;
    using ValueType = V;
    using Snapshot = btree::Snapshot<K, V>;

  private:
    static constexpr int MAX_KEYS = 2 * B;
    static constexpr int MIN_KEYS = B;

    struct Entry
    {
      K key;
      V value;
      Entry(const K& k, const V& v) : key(k), value(v) {}
    };

    using EntryPtr = std::shared_ptr<const Entry>;

    struct Node
    {
      bool leaf = true;
      std::vector<EntryPtr> entries;
      std::vector<std::shared_ptr<const Node>> children; // empty for leaves

      int count() const
      {
        return static_cast<int>(entries.size());
      }

      // Binary search: returns (found, index).
      // If found, index is position. If not, index is insertion point.
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

    std::shared_ptr<const Node> _root;
    size_t _size = 0;
    size_t _serialized_size = 0;

    explicit Map(
      std::shared_ptr<const Node> root, size_t sz, size_t ser_sz) :
      _root(std::move(root)),
      _size(sz),
      _serialized_size(ser_sz)
    {}

    static std::shared_ptr<Node> clone(const std::shared_ptr<const Node>& n)
    {
      return std::make_shared<Node>(*n);
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

    // ── Insert ────────────────────────────────────────────────────────

    struct InsertResult
    {
      std::shared_ptr<const Node> node;
      bool split = false;
      EntryPtr promoted = {};
      std::shared_ptr<const Node> right_node = {};
      EntryPtr replaced = {}; // non-null if an existing key was updated
    };

    static InsertResult insert(
      const std::shared_ptr<const Node>& node, const EntryPtr& entry)
    {
      auto [found, idx] = node->find_key(entry->key);

      if (node->leaf)
      {
        if (found)
        {
          auto old = node->entries[idx];
          auto n = clone(node);
          n->entries[idx] = entry;
          return {n, false, {}, {}, old};
        }
        if (node->count() < MAX_KEYS)
        {
          auto n = clone(node);
          n->entries.insert(n->entries.begin() + idx, entry);
          return {n};
        }
        return split_node(node, idx, entry, nullptr, nullptr);
      }

      // Internal node
      if (found)
      {
        auto old = node->entries[idx];
        auto n = clone(node);
        n->entries[idx] = entry;
        return {n, false, {}, {}, old};
      }

      auto cr = insert(node->children[idx], entry);
      if (!cr.split)
      {
        auto n = clone(node);
        n->children[idx] = cr.node;
        return {n, false, {}, {}, cr.replaced};
      }

      if (node->count() < MAX_KEYS)
      {
        auto n = clone(node);
        n->entries.insert(n->entries.begin() + idx, cr.promoted);
        n->children[idx] = cr.node;
        n->children.insert(n->children.begin() + idx + 1, cr.right_node);
        return {n};
      }

      return split_node(node, idx, cr.promoted, cr.node, cr.right_node);
    }

    // Unified split for both leaf and internal nodes.
    // For leaves: left_child/right_child are nullptr.
    // For internals: they replace children[idx] and insert after.
    static InsertResult split_node(
      const std::shared_ptr<const Node>& node,
      int idx,
      const EntryPtr& entry,
      const std::shared_ptr<const Node>& left_child,
      const std::shared_ptr<const Node>& right_child)
    {
      int total = node->count() + 1;
      int mid = total / 2;

      // Build merged entries
      std::vector<EntryPtr> all_entries;
      all_entries.reserve(total);
      all_entries.insert(
        all_entries.end(), node->entries.begin(), node->entries.begin() + idx);
      all_entries.push_back(entry);
      all_entries.insert(
        all_entries.end(), node->entries.begin() + idx, node->entries.end());

      // Build merged children (only for internal nodes)
      std::vector<std::shared_ptr<const Node>> all_children;
      if (!node->leaf)
      {
        all_children.reserve(total + 1);
        all_children.insert(
          all_children.end(),
          node->children.begin(),
          node->children.begin() + idx);
        all_children.push_back(left_child);
        all_children.push_back(right_child);
        all_children.insert(
          all_children.end(),
          node->children.begin() + idx + 1,
          node->children.end());
      }

      auto left = std::make_shared<Node>();
      left->leaf = node->leaf;
      left->entries.assign(all_entries.begin(), all_entries.begin() + mid);
      if (!node->leaf)
        left->children.assign(
          all_children.begin(), all_children.begin() + mid + 1);

      auto promoted = all_entries[mid];

      auto right = std::make_shared<Node>();
      right->leaf = node->leaf;
      right->entries.assign(all_entries.begin() + mid + 1, all_entries.end());
      if (!node->leaf)
        right->children.assign(
          all_children.begin() + mid + 1, all_children.end());

      return {left, true, promoted, right};
    }

    // ── Remove ────────────────────────────────────────────────────────

    struct RemoveResult
    {
      std::shared_ptr<const Node> node;
      bool found = false;
      bool underflow = false;
      EntryPtr removed = {}; // non-null if a key was removed
    };

    static RemoveResult do_remove(
      const std::shared_ptr<const Node>& node, const K& key)
    {
      if (!node)
        return {nullptr, false, false};

      auto [found, idx] = node->find_key(key);

      if (node->leaf)
      {
        if (!found)
          return {node, false, false};
        auto old = node->entries[idx];
        if (node->count() == 1)
          return {nullptr, true, true, old};

        auto n = clone(node);
        n->entries.erase(n->entries.begin() + idx);
        return {n, true, n->count() < MIN_KEYS, old};
      }

      if (found)
      {
        // Replace with in-order predecessor (max of left subtree)
        auto old = node->entries[idx];
        auto [pred_child, pred_entry, uf] = remove_max(node->children[idx]);
        auto n = clone(node);
        n->entries[idx] = pred_entry;
        n->children[idx] = pred_child;
        if (uf)
        {
          auto fr = fix_underflow(n, idx);
          fr.removed = old;
          return fr;
        }
        return {n, true, n->count() < MIN_KEYS, old};
      }

      auto cr = do_remove(node->children[idx], key);
      if (!cr.found)
        return {node, false, false};

      auto n = clone(node);
      n->children[idx] = cr.node;
      if (cr.underflow)
      {
        auto fr = fix_underflow(n, idx);
        fr.removed = cr.removed;
        return fr;
      }
      return {n, true, n->count() < MIN_KEYS, cr.removed};
    }

    struct RemoveMaxResult
    {
      std::shared_ptr<const Node> node;
      EntryPtr entry;
      bool underflow;
    };

    static RemoveMaxResult remove_max(const std::shared_ptr<const Node>& node)
    {
      assert(node);
      if (node->leaf)
      {
        auto n = clone(node);
        auto entry = n->entries.back();
        n->entries.pop_back();
        if (n->entries.empty())
          return {nullptr, entry, true};
        return {n, entry, n->count() < MIN_KEYS};
      }

      auto r = remove_max(node->children[node->count()]);
      auto n = clone(node);
      n->children.back() = r.node;
      if (r.underflow)
      {
        auto fr =
          fix_underflow(n, static_cast<int>(n->children.size()) - 1);
        return {fr.node, r.entry, fr.underflow};
      }
      return {n, r.entry, n->count() < MIN_KEYS};
    }

    static RemoveResult fix_underflow(std::shared_ptr<Node>& node, int ci)
    {
      // Try borrow from left sibling
      if (ci > 0 && node->children[ci - 1] &&
          node->children[ci - 1]->count() > MIN_KEYS)
        return borrow_left(node, ci);

      // Try borrow from right sibling
      if (ci < node->count() && node->children[ci + 1] &&
          node->children[ci + 1]->count() > MIN_KEYS)
        return borrow_right(node, ci);

      // Merge
      if (ci > 0)
        return merge(node, ci - 1);
      return merge(node, ci);
    }

    static RemoveResult borrow_left(std::shared_ptr<Node>& parent, int ci)
    {
      auto sib = clone(parent->children[ci - 1]);
      auto child =
        parent->children[ci] ? clone(parent->children[ci]) :
                               std::make_shared<Node>();
      child->leaf = sib->leaf;

      // Rotate: parent entry down to child, sibling's last entry up
      child->entries.insert(
        child->entries.begin(), parent->entries[ci - 1]);
      if (!child->leaf)
        child->children.insert(
          child->children.begin(), sib->children.back());

      parent->entries[ci - 1] = sib->entries.back();
      sib->entries.pop_back();
      if (!sib->leaf)
        sib->children.pop_back();

      parent->children[ci - 1] = sib;
      parent->children[ci] = child;
      return {parent, true, parent->count() < MIN_KEYS};
    }

    static RemoveResult borrow_right(std::shared_ptr<Node>& parent, int ci)
    {
      auto child =
        parent->children[ci] ? clone(parent->children[ci]) :
                               std::make_shared<Node>();
      auto sib = clone(parent->children[ci + 1]);
      child->leaf = sib->leaf;

      // Rotate: parent entry down to child, sibling's first entry up
      child->entries.push_back(parent->entries[ci]);
      if (!child->leaf)
        child->children.push_back(sib->children.front());

      parent->entries[ci] = sib->entries.front();
      sib->entries.erase(sib->entries.begin());
      if (!sib->leaf)
        sib->children.erase(sib->children.begin());

      parent->children[ci] = child;
      parent->children[ci + 1] = sib;
      return {parent, true, parent->count() < MIN_KEYS};
    }

    static RemoveResult merge(std::shared_ptr<Node>& parent, int idx)
    {
      auto left =
        parent->children[idx] ? clone(parent->children[idx]) :
                                std::make_shared<Node>();
      auto* right = parent->children[idx + 1].get();

      // Pull parent entry down, append right's entries and children
      left->entries.push_back(parent->entries[idx]);
      if (right)
      {
        left->entries.insert(
          left->entries.end(), right->entries.begin(), right->entries.end());
        if (!left->leaf)
          left->children.insert(
            left->children.end(),
            right->children.begin(),
            right->children.end());
      }

      // Remove from parent
      parent->entries.erase(parent->entries.begin() + idx);
      parent->children.erase(parent->children.begin() + idx + 1);
      parent->children[idx] = left;

      if (parent->entries.empty())
        return {left, true, left->count() < MIN_KEYS};
      return {parent, true, parent->count() < MIN_KEYS};
    }

    // ── Traversal ─────────────────────────────────────────────────────

    template <class F>
    static bool foreach_node(const std::shared_ptr<const Node>& node, F&& f)
    {
      if (!node)
        return true;
      if (node->leaf)
      {
        for (auto& e : node->entries)
        {
          if (!f(e->key, e->value))
            return false;
        }
        return true;
      }
      for (int i = 0; i < node->count(); ++i)
      {
        if (!foreach_node(node->children[i], std::forward<F>(f)))
          return false;
        if (!f(node->entries[i]->key, node->entries[i]->value))
          return false;
      }
      return foreach_node(node->children[node->count()], std::forward<F>(f));
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
      const Node* n = _root.get();
      while (n)
      {
        auto [found, idx] = n->find_key(key);
        if (found)
          return &n->entries[idx]->value;
        if (n->leaf)
          return nullptr;
        n = n->children[idx].get();
      }
      return nullptr;
    }

    Map put(const K& key, const V& value) const
    {
      auto entry = make_entry(key, value);

      if (!_root)
      {
        auto node = std::make_shared<Node>();
        node->entries.push_back(std::move(entry));
        size_t ser = kv_ser_size(key, value);
        return Map(node, 1, ser);
      }

      auto result = insert(_root, entry);

      size_t new_size = _size;
      size_t new_ser = _serialized_size + kv_ser_size(key, value);
      if (result.replaced)
      {
        new_ser -= kv_ser_size(
          result.replaced->key, result.replaced->value);
      }
      else
      {
        new_size++;
      }

      if (!result.split)
        return Map(result.node, new_size, new_ser);

      auto new_root = std::make_shared<Node>();
      new_root->leaf = false;
      new_root->entries.push_back(result.promoted);
      new_root->children.push_back(result.node);
      new_root->children.push_back(result.right_node);
      return Map(new_root, new_size, new_ser);
    }

    Map remove(const K& key) const
    {
      if (!_root)
        return *this;

      auto result = do_remove(_root, key);
      if (!result.found)
        return *this;

      size_t new_ser = _serialized_size -
        kv_ser_size(result.removed->key, result.removed->value);

      if (!result.node)
        return Map();

      // If root is internal with 0 keys, collapse
      if (!result.node->leaf && result.node->entries.empty())
      {
        auto child = result.node->children[0];
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
