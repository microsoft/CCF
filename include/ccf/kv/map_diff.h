// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/untyped_map_diff.h"

namespace ccf::kv
{
  template <typename K, typename V, typename KSerialiser, typename VSerialiser>
  class MapDiff : public AbstractHandle
  {
  protected:
    ccf::kv::untyped::MapDiff map_diff;

  public:
    using KeyType = K;
    using ValueType = V;

    MapDiff(ccf::kv::untyped::MapDiff map_diff_) :
      map_diff(std::move(map_diff_))
    {}

    MapDiff(ccf::kv::untyped::ChangeSet& changes, const std::string& map_name) :
      map_diff(changes, map_name)
    {}

    /** Get value for key.
     *
     * @param key Key to read
     *
     * @return nullopt if key does not exist, optional<nullopt> if key exists
     * but was deleted and the value if it exists and was not deleted.
     */
    std::optional<std::optional<V>> get(const K& key)
    {
      const auto opt_v_rep = map_diff.get(KSerialiser::to_serialised(key));

      if (opt_v_rep.has_value())
      {
        if (opt_v_rep.value().has_value())
        {
          return VSerialiser::from_serialised(opt_v_rep.value().value());
        }
      }

      return std::nullopt;
    }

    /** Test if key is present and not deleted.
     *
     * @param key Key to read
     *
     * @return Boolean true iff key exists
     */
    bool has(const K& key)
    {
      return map_diff.has(KSerialiser::to_serialised(key));
    }

    /** Test if key is deleted in this diff.
     *
     * @param key Key to read
     *
     * @return Boolean true iff key was deleted
     */
    bool is_deleted(const K& key)
    {
      return map_diff.is_deleted(KSerialiser::to_serialised(key));
    }

    /** Iterate over all entries in the map.
     *
     * The passed functor should have the signature
     * `bool(const K& k, const std::optional<V>& v)`.
     * The iteration order is undefined.
     * A value of nullopt indicates that the key was deleted.
     * Return true to continue iteration, or return false from any invocation to
     * terminate the iteration at that point - the functor will not be invoked
     * again after it returns false.
     *
     * @tparam F Functor type. Should usually be derived implicitly from f
     * @param f Functor instance, taking (const K& k, const std::optional<V>& v)
     * and returning a bool. Return value determines whether the iteration
     * should continue (true) or stop (false)
     */
    template <class F>
    void foreach(F&& f) // NOLINT(cppcoreguidelines-missing-std-forward)
    {
      const auto& g =
        [&](
          const ccf::kv::serialisers::SerialisedEntry& k_rep,
          const std::optional<ccf::kv::serialisers::SerialisedEntry>& v_rep)
        -> bool {
        const auto k = KSerialiser::from_serialised(k_rep);
        if (v_rep.has_value())
        {
          const std::optional<V> v =
            VSerialiser::from_serialised(v_rep.value());
          return f(k, v);
        }
        const std::optional<V> v = std::nullopt;
        return f(k, v);
      };
      map_diff.foreach(g);
    }

    /** Iterate over all keys in the map.
     *
     * @tparam F Functor type. Should usually be derived implicitly from f
     * @param f Functor instance, taking (const K& k) and returning
     * a bool. Return value determines whether the iteration should continue
     * (true) or stop (false)
     */
    template <class F>
    void foreach_key(F&& f) // NOLINT(cppcoreguidelines-missing-std-forward)
    {
      auto g = [&](
                 const ccf::kv::serialisers::SerialisedEntry& k_rep,
                 const ccf::kv::serialisers::SerialisedEntry&) {
        return f(KSerialiser::from_serialised(k_rep));
      };
      map_diff.foreach(g);
    }

    /** Iterate over all values in the map.
     *
     * @tparam F Functor type. Should usually be derived implicitly from f
     * @param f Functor instance, taking (const std::optional<V>& v) and
     * returning a bool. Return value determines whether the iteration should
     * continue (true) or stop (false)
     */
    template <class F>
    void foreach_value(F&& f) // NOLINT(cppcoreguidelines-missing-std-forward)
    {
      auto g =
        [&](
          const ccf::kv::serialisers::SerialisedEntry&,
          const std::optional<ccf::kv::serialisers::SerialisedEntry>& v_rep) {
          if (v_rep.has_value())
          {
            return f(VSerialiser::from_serialised(v_rep));
          }
          return f(std::nullopt);
        };
      map_diff.foreach(g);
    }

    /** Returns number of entries in this map.
     *
     * @return Count of entries
     */
    size_t size()
    {
      return map_diff.size();
    }
  };
}