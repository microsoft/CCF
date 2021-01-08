// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <array>
#include <cassert>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <list>
#include <memory>
#include <sstream>
#include <stack>
#include <vector>

#ifdef WIN32
#  include <stdlib.h>
#  if BYTE_ORDER == LITTLE_ENDIAN
#    define htobe32(X) _byteswap_ulong(X)
#    define be32toh(X) _byteswap_ulong(X)
#    define htobe64(X) _byteswap_uint64(X)
#    define be64toh(X) _byteswap_uint64(X)
#  else
#    define htobe32(X) (X)
#    define be32toh(X) (X)
#    define htobe64(X) (X)
#    define be64toh(X) (X)
#  endif
#  undef max
#endif

#ifdef HAVE_OPENSSL
#  include <openssl/sha.h>
#endif

#ifdef HAVE_MBEDTLS
#  include <mbedtls/sha256.h>
#endif

#ifdef MERKLECPP_TRACE_ENABLED
// Hashes in the trace output are truncated to TRACE_HASH_SIZE bytes.
#  define TRACE_HASH_SIZE 3

#  ifndef MERKLECPP_TRACE
#    include <iostream>
#    define MERKLECPP_TOUT std::cout
#    define MERKLECPP_TRACE(X) \
      { \
        X; \
        MERKLECPP_TOUT.flush(); \
      };
#  endif
#else
#  define MERKLECPP_TRACE(X)
#endif

namespace merkle
{
  void serialise_size_t(size_t size, std::vector<uint8_t>& bytes)
  {
    size_t size_be = htobe64(size);
    uint8_t* size_bytes = (uint8_t*)&size_be;
    for (size_t i = 0; i < sizeof(size_t); i++)
      bytes.push_back(size_bytes[i]);
  }

  size_t deserialise_size_t(const std::vector<uint8_t>& bytes, size_t& index)
  {
    size_t result = 0;
    uint8_t* result_bytes = (uint8_t*)&result;
    for (size_t i = 0; i < sizeof(size_t); i++)
      result_bytes[i] = bytes[index++];
    return be64toh(result);
  }

  template <size_t SIZE>
  struct HashT
  {
    uint8_t bytes[SIZE];

    HashT<SIZE>()
    {
      std::fill(bytes, bytes + SIZE, 0);
    }

    HashT<SIZE>(const uint8_t* bytes)
    {
      std::copy(bytes, bytes + SIZE, this->bytes);
    }

    HashT<SIZE>(const std::string& s)
    {
      if (s.length() != 2 * SIZE)
        throw std::runtime_error("invalid hash string");
      for (size_t i = 0; i < SIZE; i++)
      {
        int tmp;
        sscanf(s.c_str() + 2 * i, "%02x", &tmp);
        bytes[i] = tmp;
      }
    }

    HashT<SIZE>(const std::vector<uint8_t>& bytes)
    {
      if (bytes.size() < SIZE)
        throw std::runtime_error("not enough bytes");
      deserialise(bytes);
    }

    HashT<SIZE>(const std::vector<uint8_t>& bytes, size_t& position)
    {
      if (bytes.size() - position < SIZE)
        throw std::runtime_error("not enough bytes");
      deserialise(bytes, position);
    }

    HashT<SIZE>(const std::array<uint8_t, SIZE>& bytes)
    {
      std::copy(bytes.data(), bytes.data() + SIZE, this->bytes);
    }

    size_t size() const
    {
      return SIZE;
    }

    size_t serialised_size() const
    {
      return SIZE;
    }

    std::string to_string(size_t num_bytes = SIZE) const
    {
      size_t num_chars = 2 * num_bytes;
      std::string r(num_chars, '_');
      for (size_t i = 0; i < num_bytes; i++)
        snprintf(r.data() + 2 * i, num_chars + 1 - 2 * i, "%02X", bytes[i]);
      return r;
    }

    HashT<SIZE> operator=(const HashT<SIZE>& other)
    {
      std::copy(other.bytes, other.bytes + SIZE, bytes);
      return *this;
    }

    bool operator==(const HashT<SIZE>& other) const
    {
      return memcmp(bytes, other.bytes, SIZE) == 0;
    }

    bool operator!=(const HashT<SIZE>& other) const
    {
      return memcmp(bytes, other.bytes, SIZE) != 0;
    }

    void serialise(std::vector<uint8_t>& buffer) const
    {
      MERKLECPP_TRACE(MERKLECPP_TOUT << "> HashT::serialise " << std::endl);
      for (auto& b : bytes)
        buffer.push_back(b);
    }

    void deserialise(const std::vector<uint8_t>& buffer, size_t& position)
    {
      MERKLECPP_TRACE(MERKLECPP_TOUT << "> HashT::deserialise " << std::endl);
      if (buffer.size() - position < SIZE)
        throw std::runtime_error("not enough bytes");
      for (size_t i = 0; i < sizeof(bytes); i++)
        bytes[i] = buffer[position++];
    }

    void deserialise(const std::vector<uint8_t>& buffer)
    {
      size_t position = 0;
      deserialise(buffer, position);
    }

    operator std::vector<uint8_t>() const
    {
      std::vector<uint8_t> bytes;
      serialise(bytes);
      return bytes;
    }
  };

  template <
    size_t HASH_SIZE,
    void (*HASH_FUNCTION)(
      const HashT<HASH_SIZE>& l,
      const HashT<HASH_SIZE>& r,
      HashT<HASH_SIZE>& out)>
  class PathT
  {
  public:
    typedef enum
    {
      PATH_LEFT,
      PATH_RIGHT
    } Direction;

    typedef struct
    {
      HashT<HASH_SIZE> hash; // This is a copy; do we want a shared_ptr<HashT>?
      Direction direction;
    } Element;

    PathT(
      const HashT<HASH_SIZE>& leaf,
      size_t leaf_index,
      std::list<Element>&& elements,
      size_t max_index) :
      _leaf(leaf),
      _leaf_index(leaf_index),
      _max_index(max_index),
      elements(elements)
    {}
    PathT(const PathT& other)
    {
      _leaf = other._leaf;
      elements = other.elements;
    }
    PathT(PathT&& other)
    {
      _leaf = std::move(other._leaf);
      elements = std::move(other.elements);
    }
    PathT(const std::vector<uint8_t>& bytes)
    {
      deserialise(bytes);
    }
    PathT(const std::vector<uint8_t>& bytes, size_t& position)
    {
      deserialise(bytes, position);
    }

    std::shared_ptr<HashT<HASH_SIZE>> root() const
    {
      std::shared_ptr<HashT<HASH_SIZE>> result =
        std::make_shared<HashT<HASH_SIZE>>(_leaf);
      MERKLECPP_TRACE(
        MERKLECPP_TOUT << "> PathT::root " << _leaf.to_string(TRACE_HASH_SIZE)
                       << std::endl);
      for (const Element& e : elements)
      {
        if (e.direction == PATH_LEFT)
        {
          MERKLECPP_TRACE(
            MERKLECPP_TOUT << " - " << e.hash.to_string(TRACE_HASH_SIZE)
                           << " x " << result->to_string(TRACE_HASH_SIZE)
                           << std::endl);
          HASH_FUNCTION(e.hash, *result, *result);
        }
        else
        {
          MERKLECPP_TRACE(
            MERKLECPP_TOUT << " - " << result->to_string(TRACE_HASH_SIZE)
                           << " x " << e.hash.to_string(TRACE_HASH_SIZE)
                           << std::endl);
          HASH_FUNCTION(*result, e.hash, *result);
        }
      }
      MERKLECPP_TRACE(
        MERKLECPP_TOUT << " = " << result->to_string(TRACE_HASH_SIZE)
                       << std::endl);
      return result;
    }

    bool verify(const HashT<HASH_SIZE>& expected_root) const
    {
      return *root() == expected_root;
    }

    void serialise(std::vector<uint8_t>& bytes) const
    {
      MERKLECPP_TRACE(MERKLECPP_TOUT << "> PathT::serialise " << std::endl);
      _leaf.serialise(bytes);
      serialise_size_t(_leaf_index, bytes);
      serialise_size_t(_max_index, bytes);
      serialise_size_t(elements.size(), bytes);
      for (auto& e : elements)
      {
        e.hash.serialise(bytes);
        bytes.push_back(e.direction == PATH_LEFT ? 1 : 0);
      }
    }

    void deserialise(const std::vector<uint8_t>& bytes, size_t& position)
    {
      MERKLECPP_TRACE(MERKLECPP_TOUT << "> PathT::deserialise " << std::endl);
      elements.clear();
      _leaf.deserialise(bytes, position);
      _leaf_index = deserialise_size_t(bytes, position);
      _max_index = deserialise_size_t(bytes, position);
      size_t num_elements = deserialise_size_t(bytes, position);
      for (size_t i = 0; i < num_elements; i++)
      {
        HashT<HASH_SIZE> hash(bytes, position);
        PathT::Direction direction =
          bytes[position++] != 0 ? PATH_LEFT : PATH_RIGHT;
        PathT::Element e;
        e.hash = hash;
        e.direction = direction;
        elements.push_back(std::move(e));
      }
    }

    void deserialise(const std::vector<uint8_t>& bytes)
    {
      size_t position = 0;
      deserialise(bytes, position);
    }

    operator std::vector<uint8_t>() const
    {
      std::vector<uint8_t> bytes;
      serialise(bytes);
      return bytes;
    }

    size_t size() const
    {
      return elements.size();
    }

    size_t serialised_size() const
    {
      return sizeof(_leaf) + elements.size() * sizeof(Element);
    }

    size_t leaf_index() const
    {
      return _leaf_index;
    }

    size_t max_index() const
    {
      return _max_index;
    }

    const HashT<HASH_SIZE>& operator[](size_t i) const
    {
      return *elements[i].hash;
    }

    typedef typename std::list<Element>::const_iterator const_iterator;
    const_iterator begin()
    {
      return elements.begin();
    }
    const_iterator end()
    {
      return elements.end();
    }

    std::string to_string(size_t num_bytes = HASH_SIZE) const
    {
      std::stringstream stream;
      stream << _leaf.to_string(num_bytes);
      for (auto& e : elements)
        stream << " " << e.hash.to_string(num_bytes)
               << (e.direction == PATH_LEFT ? "(L)" : "(R)");
      return stream.str();
    }

    const HashT<HASH_SIZE>& leaf() const
    {
      return _leaf;
    }

    bool operator==(const PathT<HASH_SIZE, HASH_FUNCTION>& other) const
    {
      if (_leaf != other._leaf || elements.size() != other.elements.size())
        return false;
      auto it = elements.begin();
      auto other_it = other.elements.begin();
      while (it != elements.end() && other_it != other.elements.end())
      {
        if (it->hash != other_it->hash || it->direction != other_it->direction)
          return false;
        it++;
        other_it++;
      }
      return true;
    }

    bool operator!=(const PathT<HASH_SIZE, HASH_FUNCTION>& other)
    {
      return !this->operator==(other);
    }

  protected:
    HashT<HASH_SIZE> _leaf;
    size_t _leaf_index, _max_index;
    std::list<Element> elements;
  };

  template <
    size_t HASH_SIZE,
    void (*HASH_FUNCTION)(
      const HashT<HASH_SIZE>& l,
      const HashT<HASH_SIZE>& r,
      HashT<HASH_SIZE>& out)>
  class TreeT
  {
  protected:
    struct Node
    {
      static Node* make(const HashT<HASH_SIZE>& hash)
      {
        auto r = new Node();
        r->left = r->right = nullptr;
        r->hash = hash;
        r->dirty = false;
        r->update_sizes();
        assert(r->invariant());
        return r;
      }

      static Node* make(Node* left, Node* right)
      {
        assert(left && right);
        auto r = new Node();
        r->left = left;
        r->right = right;
        r->dirty = true;
        r->update_sizes();
        r->left->parent = r->right->parent = r;
        assert(r->invariant());
        return r;
      }

      static Node* copy_node(
        const Node* from,
        std::vector<Node*>* leaf_nodes = nullptr,
        size_t* num_flushed = nullptr,
        size_t min_index = 0,
        size_t max_index = SIZE_MAX,
        size_t indent = 0)
      {
        if (from == nullptr)
          return nullptr;

        Node* r = make(from->hash);
        r->size = from->size;
        r->height = from->height;
        r->dirty = from->dirty;
        r->parent = nullptr;
        r->left = copy_node(
          from->left,
          leaf_nodes,
          num_flushed,
          min_index,
          max_index,
          indent + 1);
        if (r->left)
          r->left->parent = r;
        r->right = copy_node(
          from->right,
          leaf_nodes,
          num_flushed,
          min_index,
          max_index,
          indent + 1);
        if (r->right)
          r->right->parent = r;
        if (leaf_nodes && r->size == 1 && !r->left && !r->right)
        {
          if (*num_flushed == 0)
            leaf_nodes->push_back(r);
          else
            *num_flushed = *num_flushed - 1;
        }
        return r;
      }

      bool invariant()
      {
        bool c1 = !parent || parent->left == this || parent->right == this;
        bool c2 = (left && right) || (!left && !right);
        bool c3 = !left || !right || (size == left->size + right->size + 1);
        bool cl = !left || left->invariant();
        bool cr = !right || right->invariant();
        bool ch = height <= sizeof(size) * 8;
        bool r = c1 && c2 && c3 && cl && cr && ch;
        return r;
      }

      ~Node()
      {
        assert(invariant());
        parent = nullptr;
        // Potential future improvement: remove recursion and keep nodes for
        // future insertions
        delete (left);
        delete (right);
      }

      bool is_full() const
      {
        size_t max_size = (1 << height) - 1;
        assert(size <= max_size);
        return size == max_size;
      }

      void update_sizes()
      {
        if (left && right)
        {
          size = left->size + right->size + 1;
          height = std::max(left->height, right->height) + 1;
        }
        else
          size = height = 1;
      }

      HashT<HASH_SIZE> hash;
      Node* parent;
      Node *left, *right;
      size_t size;
      uint8_t height;
      bool dirty;
    };

  public:
    typedef HashT<HASH_SIZE> Hash;
    typedef PathT<HASH_SIZE, HASH_FUNCTION> Path;
    typedef TreeT<HASH_SIZE, HASH_FUNCTION> Tree;

    TreeT() {}
    TreeT(const TreeT& other)
    {
      *this = other;
    }
    TreeT(TreeT&& other) :
      leaf_nodes(std::move(other.leaf_nodes)),
      uninserted_leaf_nodes(std::move(other.uninserted_leaf_nodes)),
      _root(std::move(other._root)),
      num_flushed(other.num_flushed),
      insertion_stack(std::move(other.insertion_stack)),
      hashing_stack(std::move(other.hashing_stack)),
      walk_stack(std::move(other.walk_stack))
    {}
    TreeT(const std::vector<uint8_t>& bytes)
    {
      deserialise(bytes);
    }
    TreeT(const std::vector<uint8_t>& bytes, size_t& position)
    {
      deserialise(bytes, position);
    }
    TreeT(const Hash& root)
    {
      insert(root);
    }
    ~TreeT()
    {
      delete (_root);
      for (auto n : uninserted_leaf_nodes)
        delete (n);
    }

    bool invariant()
    {
      return _root ? _root->invariant() : true;
    }

    void insert(const uint8_t* hash)
    {
      insert(Hash(hash));
    }

    void insert(const Hash& hash)
    {
      MERKLECPP_TRACE(MERKLECPP_TOUT << "> insert "
                                     << hash.to_string(TRACE_HASH_SIZE)
                                     << std::endl;);
      uninserted_leaf_nodes.push_back(Node::make(hash));
      statistics.num_insert++;
    }

    void insert(const std::vector<Hash>& hashes)
    {
      for (auto hash : hashes)
        insert(hash);
    }

    void insert(const std::list<Hash>& hashes)
    {
      for (auto hash : hashes)
        insert(hash);
    }

    void flush_to(size_t index)
    {
      MERKLECPP_TRACE(MERKLECPP_TOUT << "> flush_to " << index << std::endl;);
      statistics.num_flush++;

      walk_to(index, false, [this](Node*& n, bool go_right) {
        if (go_right && n->left)
        {
          MERKLECPP_TRACE(MERKLECPP_TOUT
                            << " - conflate "
                            << n->left->hash.to_string(TRACE_HASH_SIZE)
                            << std::endl;);
          if (n->left && n->left->dirty)
            hash(n->left);
          delete (n->left->left);
          n->left->left = nullptr;
          delete (n->left->right);
          n->left->right = nullptr;
        }
        return true;
      });

      size_t num_newly_flushed = index - num_flushed;
      leaf_nodes.erase(
        leaf_nodes.begin(), leaf_nodes.begin() + num_newly_flushed);
      num_flushed += num_newly_flushed;
    }

    void retract_to(size_t index)
    {
      MERKLECPP_TRACE(MERKLECPP_TOUT << "> retract_to " << index << std::endl;);
      statistics.num_retract++;

      if (max_index() < index)
        return;

      if (index < min_index())
        throw std::runtime_error("leaf index out of bounds");

      if (index >= num_flushed + leaf_nodes.size())
      {
        size_t over = index - (num_flushed + leaf_nodes.size()) + 1;
        while (uninserted_leaf_nodes.size() > over)
        {
          delete (uninserted_leaf_nodes.back());
          uninserted_leaf_nodes.pop_back();
        }
        return;
      }

      Node* new_leaf_node =
        walk_to(index, true, [this](Node*& n, bool go_right) {
          bool go_left = !go_right;
          n->dirty = true;
          if (go_left && n->right)
          {
            MERKLECPP_TRACE(MERKLECPP_TOUT
                              << " - eliminate "
                              << n->right->hash.to_string(TRACE_HASH_SIZE)
                              << std::endl;);
            bool is_root = n == _root;

            Node* old_parent = n->parent;
            Node* old_left = n->left;
            delete (n->right);
            n->right = nullptr;

            *n = *old_left;
            n->parent = old_parent;

            old_left->left = old_left->right = nullptr;
            old_left->parent = nullptr;
            delete (old_left);
            old_left = nullptr;

            if (n->left && n->right)
            {
              n->left->parent = n;
              n->right->parent = n;
              n->dirty = true;
            }

            if (is_root)
            {
              MERKLECPP_TRACE(MERKLECPP_TOUT
                                << " - new root: "
                                << n->hash.to_string(TRACE_HASH_SIZE)
                                << std::endl;);
              assert(n->parent == nullptr);
              assert(_root == n);
            }

            assert(n->invariant());

            MERKLECPP_TRACE(MERKLECPP_TOUT
                              << " - after elimination: " << std::endl
                              << to_string(TRACE_HASH_SIZE) << std::endl;);
            return false;
          }
          else
            return true;
        });

      // The leaf is now elsewhere, save the pointer.
      leaf_nodes[index - num_flushed] = new_leaf_node;

      size_t num_retracted = num_leaves() - index - 1;
      if (num_retracted < leaf_nodes.size())
        leaf_nodes.resize(leaf_nodes.size() - num_retracted);
      else
        leaf_nodes.clear();

      assert(num_leaves() == index + 1);
    }

    Tree& operator=(const Tree& other)
    {
      leaf_nodes.clear();
      for (auto n : uninserted_leaf_nodes)
        delete (n);
      uninserted_leaf_nodes.clear();
      insertion_stack.clear();
      hashing_stack.clear();
      walk_stack.clear();

      size_t to_skip = (other.num_flushed % 2 == 0) ? 0 : 1;
      _root = Node::copy_node(
        other._root,
        &leaf_nodes,
        &to_skip,
        other.min_index(),
        other.max_index());
      for (auto n : other.uninserted_leaf_nodes)
        uninserted_leaf_nodes.push_back(Node::copy_node(n));
      num_flushed = other.num_flushed;
      assert(min_index() == other.min_index());
      assert(max_index() == other.max_index());
      return *this;
    }

    const Hash& root()
    {
      MERKLECPP_TRACE(MERKLECPP_TOUT << "> root" << std::endl;);
      statistics.num_root++;
      compute_root();
      assert(_root && !_root->dirty);
      MERKLECPP_TRACE(MERKLECPP_TOUT
                        << " - root: " << _root->hash.to_string(TRACE_HASH_SIZE)
                        << std::endl;);
      return _root->hash;
    }

    std::shared_ptr<Hash> past_root(size_t index)
    {
      MERKLECPP_TRACE(MERKLECPP_TOUT << "> past_root " << index << std::endl;);
      statistics.num_past_root++;

      auto p = path(index);
      auto result = std::make_shared<Hash>(p->leaf());

      MERKLECPP_TRACE(
        MERKLECPP_TOUT << " - " << p->to_string(TRACE_HASH_SIZE) << std::endl;
        MERKLECPP_TOUT << " - " << result->to_string(TRACE_HASH_SIZE)
                       << std::endl;);

      for (auto e : *p)
        if (e.direction == Path::Direction::PATH_LEFT)
          HASH_FUNCTION(e.hash, *result, *result);

      return result;
    }

    Node* walk_to(
      size_t index, bool update, std::function<bool(Node*&, bool)> f)
    {
      if (index < min_index() || max_index() < index)
        throw std::runtime_error("invalid leaf index");

      compute_root();

      assert(index < _root->size);

      Node* cur = _root;
      size_t it = 0;
      if (_root->height > 1)
        it = index << (sizeof(index) * 8 - _root->height + 1);
      assert(walk_stack.empty());

      for (uint8_t height = _root->height; height > 1;)
      {
        assert(cur->invariant());
        bool go_right = (it >> (8 * sizeof(it) - 1)) & 0x01;
        if (update)
          walk_stack.push_back(cur);
        MERKLECPP_TRACE(MERKLECPP_TOUT
                          << " - at " << cur->hash.to_string(TRACE_HASH_SIZE)
                          << " (" << cur->size << "/" << (unsigned)cur->height
                          << ")"
                          << " (" << (go_right ? "R" : "L") << ")"
                          << std::endl;);
        if (cur->height == height)
        {
          if (!f(cur, go_right))
            continue;
          cur = (go_right ? cur->right : cur->left);
        }
        it <<= 1;
        height--;
      }

      if (update)
        while (!walk_stack.empty())
        {
          walk_stack.back()->update_sizes();
          walk_stack.pop_back();
        }

      return cur;
    }

    std::shared_ptr<Path> path(size_t index)
    {
      MERKLECPP_TRACE(MERKLECPP_TOUT << "> path from " << index << std::endl;);
      statistics.num_paths++;
      std::list<typename Path::Element> elements;

      walk_to(index, false, [&elements](Node* n, bool go_right) {
        typename Path::Element e;
        e.hash = go_right ? n->left->hash : n->right->hash;
        e.direction = go_right ? Path::PATH_LEFT : Path::PATH_RIGHT;
        elements.push_front(std::move(e));
        return true;
      });

      return std::make_shared<Path>(
        leaf_node(index)->hash, index, std::move(elements), max_index());
    }

    std::shared_ptr<Path> past_path(size_t index, size_t as_of)
    {
      MERKLECPP_TRACE(MERKLECPP_TOUT << "> past_path from " << index
                                     << " as of " << as_of << std::endl;);
      statistics.num_past_paths++;

      if (
        (index < min_index() || max_index() < index) ||
        (as_of < min_index() || max_index() < as_of) || index > as_of)
        throw std::runtime_error("invalid leaf indices");

      compute_root();

      assert(index < _root->size && as_of < _root->size);

      // Walk down the tree toward `index` and `as_of` from the root. First to
      // the node at which they fork (recorded in `root_to_fork`), then
      // separately to `index` and `as_of`, recording their paths
      // in `fork_to_index` and `fork_to_as_of`.
      std::list<typename Path::Element> root_to_fork, fork_to_index,
        fork_to_as_of;
      Node* fork_node = nullptr;

      Node *cur_i = _root, *cur_a = _root;
      size_t it_i = 0, it_a = 0;
      if (_root->height > 1)
      {
        it_i = index << (sizeof(index) * 8 - _root->height + 1);
        it_a = as_of << (sizeof(index) * 8 - _root->height + 1);
      }

      for (uint8_t height = _root->height; height > 1;)
      {
        assert(cur_i->invariant() && cur_a->invariant());
        bool go_right_i = (it_i >> (8 * sizeof(it_i) - 1)) & 0x01;
        bool go_right_a = (it_a >> (8 * sizeof(it_a) - 1)) & 0x01;

        MERKLECPP_TRACE(MERKLECPP_TOUT
                          << " - at " << (unsigned)height << ": "
                          << cur_i->hash.to_string(TRACE_HASH_SIZE) << " ("
                          << cur_i->size << "/" << (unsigned)cur_i->height
                          << "/" << (go_right_i ? "R" : "L") << ")"
                          << " / " << cur_a->hash.to_string(TRACE_HASH_SIZE)
                          << " (" << cur_a->size << "/"
                          << (unsigned)cur_a->height << "/"
                          << (go_right_a ? "R" : "L") << ")" << std::endl;);

        if (!fork_node && go_right_i != go_right_a)
        {
          assert(cur_i == cur_a);
          assert(!go_right_i && go_right_a);
          MERKLECPP_TRACE(MERKLECPP_TOUT
                            << " - split at "
                            << cur_i->hash.to_string(TRACE_HASH_SIZE)
                            << std::endl;);
          fork_node = cur_i;
        }

        if (!fork_node)
        {
          // Still on the path to the fork
          assert(cur_i == cur_a);
          if (cur_i->height == height)
          {
            if (go_right_i)
            {
              typename Path::Element e;
              e.hash = go_right_i ? cur_i->left->hash : cur_i->right->hash;
              e.direction = go_right_i ? Path::PATH_LEFT : Path::PATH_RIGHT;
              root_to_fork.push_back(std::move(e));
            }
            cur_i = cur_a = (go_right_i ? cur_i->right : cur_i->left);
          }
        }
        else
        {
          // After the fork, record paths to `index` and `as_of`.
          if (cur_i->height == height)
          {
            typename Path::Element e;
            e.hash = go_right_i ? cur_i->left->hash : cur_i->right->hash;
            e.direction = go_right_i ? Path::PATH_LEFT : Path::PATH_RIGHT;
            fork_to_index.push_back(std::move(e));
            cur_i = (go_right_i ? cur_i->right : cur_i->left);
          }
          if (cur_a->height == height)
          {
            // The right path does not take into account anything to the right
            // of `as_of`, as those nodes were inserted into the tree after
            // `as_of`.
            if (go_right_a)
            {
              typename Path::Element e;
              e.hash = go_right_a ? cur_a->left->hash : cur_a->right->hash;
              e.direction = go_right_a ? Path::PATH_LEFT : Path::PATH_RIGHT;
              fork_to_as_of.push_back(std::move(e));
            }
            cur_a = (go_right_a ? cur_a->right : cur_a->left);
          }
        }

        it_i <<= 1;
        it_a <<= 1;
        height--;
      }

      MERKLECPP_TRACE({
        MERKLECPP_TOUT << " - root to split:";
        for (auto e : root_to_fork)
          MERKLECPP_TOUT << " " << e.hash.to_string(TRACE_HASH_SIZE) << "("
                         << e.direction << ")";
        MERKLECPP_TOUT << std::endl;
        MERKLECPP_TOUT << " - split to index:";
        for (auto e : fork_to_index)
          MERKLECPP_TOUT << " " << e.hash.to_string(TRACE_HASH_SIZE) << "("
                         << e.direction << ")";
        MERKLECPP_TOUT << std::endl;
        MERKLECPP_TOUT << " - split to as_of:";
        for (auto e : fork_to_as_of)
          MERKLECPP_TOUT << " " << e.hash.to_string(TRACE_HASH_SIZE) << "("
                         << e.direction << ")";
        MERKLECPP_TOUT << std::endl;
      });

      // Reconstruct the past path from the three path segments recorded.
      std::list<typename Path::Element> path;

      // The hashes along the path from the fork to `index` remain unchanged.
      if (!fork_to_index.empty())
        fork_to_index.pop_front();
      for (auto it = fork_to_index.rbegin(); it != fork_to_index.rend(); it++)
        path.push_back(std::move(*it));

      if (fork_node)
      {
        // The final hash of the path from the fork to `as_of` needs to be
        // computed because that path skipped past tree nodes younger than
        // `as_of`.
        Hash as_of_hash = cur_a->hash;
        if (!fork_to_as_of.empty())
          fork_to_as_of.pop_front();
        for (auto it = fork_to_as_of.rbegin(); it != fork_to_as_of.rend(); it++)
          HASH_FUNCTION(it->hash, as_of_hash, as_of_hash);

        MERKLECPP_TRACE({
          MERKLECPP_TOUT << " - as_of hash: "
                         << as_of_hash.to_string(TRACE_HASH_SIZE) << std::endl;
        });

        typename Path::Element e;
        e.hash = as_of_hash;
        e.direction = Path::PATH_RIGHT;
        path.push_back(std::move(e));
      }

      // The hashes along the path from the fork (now with new fork hash) to the
      // (past) root remains unchanged.
      for (auto it = root_to_fork.rbegin(); it != root_to_fork.rend(); it++)
        path.push_back(std::move(*it));

      return std::make_shared<Path>(
        leaf_node(index)->hash, index, std::move(path), as_of);
    }

    void serialise(std::vector<uint8_t>& bytes)
    {
      MERKLECPP_TRACE(MERKLECPP_TOUT << "> serialise " << std::endl;);

      compute_root();

      MERKLECPP_TRACE(MERKLECPP_TOUT << to_string(TRACE_HASH_SIZE)
                                     << std::endl;);

      serialise_size_t(leaf_nodes.size() + uninserted_leaf_nodes.size(), bytes);
      serialise_size_t(num_flushed, bytes);
      for (auto& n : leaf_nodes)
        n->hash.serialise(bytes);
      for (auto& n : uninserted_leaf_nodes)
        n->hash.serialise(bytes);

      // Find conflated/flushed nodes along the left edge of the tree.
      std::vector<Node*> extras;
      walk_to(min_index(), false, [&extras](Node*& n, bool go_right) {
        if (go_right)
          extras.push_back(n->left);
        return true;
      });

      for (size_t i = extras.size() - 1; i != SIZE_MAX; i--)
        extras[i]->hash.serialise(bytes);
    }

    void deserialise(const std::vector<uint8_t>& bytes)
    {
      size_t position = 0;
      deserialise(bytes, position);
    }

    void deserialise(const std::vector<uint8_t>& bytes, size_t& position)
    {
      MERKLECPP_TRACE(MERKLECPP_TOUT << "> deserialise " << std::endl;);

      delete (_root);
      leaf_nodes.clear();
      for (auto n : uninserted_leaf_nodes)
        delete (n);
      uninserted_leaf_nodes.clear();
      insertion_stack.clear();
      hashing_stack.clear();
      walk_stack.clear();
      _root = nullptr;

      size_t num_leaf_nodes = deserialise_size_t(bytes, position);
      num_flushed = deserialise_size_t(bytes, position);

      leaf_nodes.reserve(num_leaf_nodes);
      for (size_t i = 0; i < num_leaf_nodes; i++)
      {
        Node* n = Node::make(bytes.data() + position);
        position += HASH_SIZE;
        leaf_nodes.push_back(n);
      }

      std::vector<Node*> level = leaf_nodes, next_level;
      size_t it = num_flushed;
      MERKLECPP_TRACE(MERKLECPP_TOUT << "num_flushed=" << num_flushed
                                     << " it=" << it << std::endl;);
      uint8_t level_no = 0;
      while (it != 0 || level.size() > 1)
      {
        // Restore extra hashes on the left edge of the tree
        if (it & 0x01)
        {
          Hash h(bytes, position);
          MERKLECPP_TRACE(MERKLECPP_TOUT << "+";);
          auto n = Node::make(h);
          n->height = level_no + 1;
          n->size = (1 << n->height) - 1;
          assert(n->invariant());
          level.insert(level.begin(), n);
        }

        MERKLECPP_TRACE(for (auto& n
                             : level) MERKLECPP_TOUT
                          << " " << n->hash.to_string(TRACE_HASH_SIZE);
                        MERKLECPP_TOUT << std::endl;);

        // Rebuild the level
        for (size_t i = 0; i < level.size(); i += 2)
        {
          if (i + 1 >= level.size())
            next_level.push_back(level[i]);
          else
            next_level.push_back(Node::make(level[i], level[i + 1]));
        }

        level.swap(next_level);
        next_level.clear();

        it >>= 1;
        level_no++;
      }

      assert(level.size() == 0 || level.size() == 1);

      if (level.size() == 1)
      {
        _root = level[0];
        assert(_root->invariant());
      }
    }

    operator std::vector<uint8_t>() const
    {
      std::vector<uint8_t> bytes;
      serialise(bytes);
      return bytes;
    }

    const Hash& operator[](size_t index) const
    {
      return leaf(index);
    }

    const Hash& leaf(size_t index) const
    {
      MERKLECPP_TRACE(MERKLECPP_TOUT << "> leaf " << index << std::endl;);
      if (index >= num_leaves())
        throw std::runtime_error("leaf index out of bounds");
      if (index - num_flushed >= leaf_nodes.size())
        return uninserted_leaf_nodes[index - num_flushed - leaf_nodes.size()]
          ->hash;
      else
        return leaf_nodes[index - num_flushed]->hash;
    }

    const Node* leaf_node(size_t index) const
    {
      MERKLECPP_TRACE(MERKLECPP_TOUT << "> leaf_node " << index << std::endl;);
      if (index >= num_leaves())
        throw std::runtime_error("leaf index out of bounds");
      if (index - num_flushed >= leaf_nodes.size())
        return uninserted_leaf_nodes[index - num_flushed - leaf_nodes.size()];
      else
        return leaf_nodes[index - num_flushed];
    }

    size_t num_leaves() const
    {
      return num_flushed + leaf_nodes.size() + uninserted_leaf_nodes.size();
    }

    size_t min_index() const
    {
      return num_flushed;
    }

    size_t max_index() const
    {
      return num_leaves() - 1;
    }

    size_t size()
    {
      if (!uninserted_leaf_nodes.empty())
        insert_leaves();
      return _root ? _root->size : 0;
    }

    size_t serialised_size()
    {
      size_t num_extras = 0;
      walk_to(min_index(), false, [&num_extras](Node*&, bool go_right) {
        if (go_right)
          num_extras++;
        return true;
      });

      return sizeof(leaf_nodes.size()) + sizeof(num_flushed) +
        leaf_nodes.size() * sizeof(Hash) + num_extras * sizeof(Hash);
    }

    mutable struct Statistics
    {
      size_t num_insert = 0, num_hash = 0;
      size_t num_root = 0, num_past_root = 0;
      size_t num_flush = 0, num_retract = 0;
      size_t num_split = 0, num_paths = 0;
      size_t num_past_paths = 0;

      std::string to_string() const
      {
        std::stringstream stream;
        stream << "num_insert=" << num_insert << " num_hash=" << num_hash
               << " num_root=" << num_root << " num_retract=" << num_retract
               << " num_flush=" << num_flush << " num_split=" << num_split
               << " num_paths=" << num_paths
               << " num_past_paths=" << num_past_paths;
        return stream.str();
      }
    } statistics;

    std::string to_string(size_t num_bytes = HASH_SIZE) const
    {
      static const std::string dirty_hash(2 * num_bytes, '?');
      std::stringstream stream;
      std::vector<Node*> level, next_level;

      if (num_leaves() == 0)
      {
        stream << "<EMPTY>" << std::endl;
        return stream.str();
      }

      if (!_root)
      {
        stream << "No root." << std::endl;
      }
      else
      {
        size_t level_no = 0;
        level.push_back(_root);
        while (!level.empty())
        {
          stream << level_no++ << ": ";
          for (auto n : level)
          {
            stream << (n->dirty ? dirty_hash : n->hash.to_string(num_bytes));
            stream << "(" << n->size << "," << (unsigned)n->height << ")";
            if (n->left)
              next_level.push_back(n->left);
            if (n->right)
              next_level.push_back(n->right);
            stream << " ";
          }
          stream << std::endl << std::flush;
          std::swap(level, next_level);
          next_level.clear();
        }
      }

      stream << "+: "
             << "leaves=" << leaf_nodes.size() << ", "
             << "uninserted leaves=" << uninserted_leaf_nodes.size() << ", "
             << "flushed=" << num_flushed << std::endl;
      stream << "S: " << statistics.to_string() << std::endl;

      return stream.str();
    }

  protected:
    std::vector<Node*> leaf_nodes;
    std::vector<Node*> uninserted_leaf_nodes;
    size_t num_flushed = 0;
    Node* _root = nullptr;

    typedef struct
    {
      Node* n;
      bool left;
    } InsertionStackElement;
    mutable std::vector<InsertionStackElement> insertion_stack;
    mutable std::vector<Node*> hashing_stack;
    mutable std::vector<Node*> walk_stack;

    void hash(Node* n, size_t indent = 2) const
    {
#ifndef MERKLECPP_WITH_TRACE
      (void)indent;
#endif

      assert(hashing_stack.empty());
      hashing_stack.reserve(n->height);
      hashing_stack.push_back(n);

      while (!hashing_stack.empty())
      {
        n = hashing_stack.back();
        assert((n->left && n->right) || (!n->left && !n->right));

        if (n->left && n->left->dirty)
          hashing_stack.push_back(n->left);
        else if (n->right && n->right->dirty)
          hashing_stack.push_back(n->right);
        else
        {
          assert(n->left && n->right);
          HASH_FUNCTION(n->left->hash, n->right->hash, n->hash);
          statistics.num_hash++;
          MERKLECPP_TRACE(
            MERKLECPP_TOUT << std::string(indent, ' ') << "+ h("
                           << n->left->hash.to_string(TRACE_HASH_SIZE) << ", "
                           << n->right->hash.to_string(TRACE_HASH_SIZE)
                           << ") == " << n->hash.to_string(TRACE_HASH_SIZE)
                           << " (" << n->size << "/" << (unsigned)n->height
                           << ")" << std::endl);
          n->dirty = false;
          hashing_stack.pop_back();
        }
      }
    }

    void compute_root()
    {
      insert_leaves(true);
      assert(_root);
      assert(_root->invariant());
      assert(_root->parent == nullptr);
      if (_root->dirty)
      {
        if (num_leaves() == 0)
          throw std::runtime_error("empty tree does not have a root");
        hash(_root);
        assert(_root && !_root->dirty);
      }
    }

    void insert_leaf_recursive(Node*& n, Node* new_leaf)
    {
      if (!n)
        n = new_leaf;
      else
      {
        if (n->is_full())
        {
          Node* p = n->parent;
          n = Node::make(n, new_leaf);
          n->parent = p;
        }
        else
        {
          MERKLECPP_TRACE(MERKLECPP_TOUT << " @ "
                                         << n->hash.to_string(TRACE_HASH_SIZE)
                                         << std::endl;);
          assert(n->left && n->right);
          if (!n->left->is_full())
            insert_leaf_recursive(n->left, new_leaf);
          else
            insert_leaf_recursive(n->right, new_leaf);
          n->dirty = true;
          n->update_sizes();
        }
      }
    }

    void continue_insertion_stack(Node* n, Node* new_leaf)
    {
      while (true)
      {
        MERKLECPP_TRACE(MERKLECPP_TOUT << "  @ "
                                       << n->hash.to_string(TRACE_HASH_SIZE)
                                       << std::endl;);
        assert(n->invariant());

        if (n->is_full())
        {
          Node* result = Node::make(n, new_leaf);
          assert(!insertion_stack.empty() || result->parent == nullptr);
          if (!insertion_stack.empty())
            result->parent = insertion_stack.back().n;
          insertion_stack.push_back(InsertionStackElement());
          insertion_stack.back().n = result;
          return;
        }
        else
        {
          assert(n->left && n->right);
          insertion_stack.push_back(InsertionStackElement());
          InsertionStackElement& se = insertion_stack.back();
          se.n = n;
          n->dirty = true;
          if (!n->left->is_full())
          {
            se.left = true;
            n = n->left;
          }
          else
          {
            se.left = false;
            n = n->right;
          }
        }
      }
    }

    Node* process_insertion_stack(bool complete = true)
    {
      MERKLECPP_TRACE(
        MERKLECPP_TOUT << "  X " << (complete ? "complete" : "continue") << ":";
        for (size_t i = 0; i < insertion_stack.size(); i++) MERKLECPP_TOUT
        << " " << insertion_stack[i].n->hash.to_string(TRACE_HASH_SIZE);
        MERKLECPP_TOUT << std::endl;);

      Node* result = insertion_stack.back().n;
      insertion_stack.pop_back();

      assert(result->dirty);
      result->update_sizes();

      while (!insertion_stack.empty())
      {
        InsertionStackElement& top = insertion_stack.back();
        Node* n = top.n;
        bool left = top.left;
        insertion_stack.pop_back();

        if (left)
          n->left = result;
        else
          n->right = result;
        n->dirty = true;
        n->update_sizes();

        result = n;

        if (!complete && !result->is_full())
        {
          MERKLECPP_TRACE(MERKLECPP_TOUT
                            << "  X save "
                            << result->hash.to_string(TRACE_HASH_SIZE)
                            << std::endl;);
          return result;
        }
      }

      assert(result->invariant());

      return result;
    }

    void insert_leaf(Node*& root, Node* n)
    {
      MERKLECPP_TRACE(MERKLECPP_TOUT << " - insert_leaf "
                                     << n->hash.to_string(TRACE_HASH_SIZE)
                                     << std::endl;);
      leaf_nodes.push_back(n);
      if (insertion_stack.empty() && !root)
        root = n;
      else
      {
        continue_insertion_stack(root, n);
        root = process_insertion_stack(false);
      }
    }

    void insert_leaves(bool complete = false)
    {
      if (!uninserted_leaf_nodes.empty())
      {
        MERKLECPP_TRACE(MERKLECPP_TOUT
                          << "* insert_leaves " << leaf_nodes.size() << " +"
                          << uninserted_leaf_nodes.size() << std::endl;);
        // Potential future improvement: make this go fast when there are many
        // leaves to insert.
        for (auto& n : uninserted_leaf_nodes)
          insert_leaf(_root, n);
        uninserted_leaf_nodes.clear();
      }
      if (complete && !insertion_stack.empty())
        _root = process_insertion_stack();
    }
  };

  // clang-format off
  void sha256_compress(const HashT<32> &l, const HashT<32> &r, HashT<32> &out) {
    static const uint32_t constants[] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    uint8_t block[32 * 2];
    memcpy(&block[0], l.bytes, 32);
    memcpy(&block[32], r.bytes, 32);

    static const uint32_t s[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

    uint32_t cws[64] = {0};

    for (int i=0; i < 16; i++)
      cws[i] = be32toh(((int32_t *)block)[i]);

    for (int i = 16; i < 64; i++) {
      uint32_t t16 = cws[i - 16];
      uint32_t t15 = cws[i - 15];
      uint32_t t7 = cws[i - 7];
      uint32_t t2 = cws[i - 2];
      uint32_t s1 = (t2 >> 17 | t2 << 15) ^ ((t2 >> 19 | t2 << 13) ^ t2 >> 10);
      uint32_t s0 = (t15 >> 7 | t15 << 25) ^ ((t15 >> 18 | t15 << 14) ^ t15 >> 3);
      cws[i] = (s1 + t7 + s0 + t16);
    }

    uint32_t h[8];
    for (int i=0; i < 8; i++)
      h[i] = s[i];

    for (int i=0; i < 64; i++) {
      uint32_t a0 = h[0], b0 = h[1], c0 = h[2], d0 = h[3], e0 = h[4], f0 = h[5], g0 = h[6], h03 = h[7];
      uint32_t w = cws[i];
      uint32_t t1 = h03 + ((e0 >> 6 | e0 << 26) ^ ((e0 >> 11 | e0 << 21) ^ (e0 >> 25 | e0 << 7))) + ((e0 & f0) ^ (~e0 & g0)) + constants[i] + w;
      uint32_t t2 = ((a0 >> 2 | a0 << 30) ^ ((a0 >> 13 | a0 << 19) ^ (a0 >> 22 | a0 << 10))) + ((a0 & b0) ^ ((a0 & c0) ^ (b0 & c0)));
      h[0] = t1 + t2;
      h[1] = a0;
      h[2] = b0;
      h[3] = c0;
      h[4] = d0 + t1;
      h[5] = e0;
      h[6] = f0;
      h[7] = g0;
    }

    for (int i=0; i < 8; i++)
      ((uint32_t*)out.bytes)[i] = htobe32(s[i] + h[i]);
  }
  // clang-format on

#ifdef HAVE_OPENSSL
  // Note: Some versions of OpenSSL don't provide SHA256_Transform.
  inline void sha256_compress_openssl(
    const HashT<32>& l, const HashT<32>& r, HashT<32>& out)
  {
    unsigned char block[32 * 2];
    memcpy(&block[0], l.bytes, 32);
    memcpy(&block[32], r.bytes, 32);

    SHA256_CTX ctx;
    if (SHA256_Init(&ctx) != 1)
      printf("SHA256_Init error");
    SHA256_Transform(&ctx, &block[0]);

    for (int i = 0; i < 8; i++)
      ((uint32_t*)out.bytes)[i] = htobe32(((uint32_t*)ctx.h)[i]);
  }

  inline void sha256_openssl(
    const merkle::HashT<32>& l,
    const merkle::HashT<32>& r,
    merkle::HashT<32>& out)
  {
    uint8_t block[32 * 2];
    memcpy(&block[0], l.bytes, 32);
    memcpy(&block[32], r.bytes, 32);
    SHA256(block, sizeof(block), out.bytes);
  }
#endif

#ifdef HAVE_MBEDTLS
  // Note: Technically, mbedtls_internal_sha256_process is for internal use
  // only.
  inline void sha256_compress_mbedtls(
    const HashT<32>& l, const HashT<32>& r, HashT<32>& out)
  {
    unsigned char block[32 * 2];
    memcpy(&block[0], l.bytes, 32);
    memcpy(&block[32], r.bytes, 32);

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, false);
    mbedtls_internal_sha256_process(&ctx, &block[0]);

    for (int i = 0; i < 8; i++)
      ((uint32_t*)out.bytes)[i] = htobe32(ctx.state[i]);
  }

  inline void sha256_mbedtls(
    const merkle::HashT<32>& l,
    const merkle::HashT<32>& r,
    merkle::HashT<32>& out)
  {
    uint8_t block[32 * 2];
    memcpy(&block[0], l.bytes, 32);
    memcpy(&block[32], r.bytes, 32);
    mbedtls_sha256_ret(block, sizeof(block), out.bytes, false);
  }
#endif

  // Default tree with default hash function
  typedef HashT<32> Hash;
  typedef PathT<32, sha256_compress> Path;
  typedef TreeT<32, sha256_compress> Tree;
};
