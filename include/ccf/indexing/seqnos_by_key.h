// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/indexing/strategy.h"
#include "ds/lru.h"
#include "indexing/caching/enclave_cache.h"
#include "indexing/indexing_types.h"

#include <memory>
#include <string>

namespace ccf::indexing::strategies
{
  class VisitEachEntryInMap : public Strategy
  {
  protected:
    std::string map_name;
    ccf::TxID current_txid = {};

    virtual void visit_entry(
      const ccf::TxID& tx_id,
      const kv::serialisers::SerialisedEntry& k,
      const kv::serialisers::SerialisedEntry& v) = 0;

  public:
    VisitEachEntryInMap(
      const std::string& map_name_,
      const std::string& strategy_prefix = "VisitEachEntryIn") :
      Strategy(fmt::format("{} {}", strategy_prefix, map_name_)),
      map_name(map_name_)
    {}

    void handle_committed_transaction(
      const ccf::TxID& tx_id, const StorePtr& store) override
    {
      // NB: Get an untyped view over the map with the same name. This saves
      // deserialisation here, where we hand on the raw key and value.
      auto tx = store->create_read_only_tx();
      auto handle = tx.ro<kv::untyped::Map>(map_name);

      handle->foreach([this, &tx_id](const auto& k, const auto& v) {
        visit_entry(tx_id, k, v);
        return true;
      });
      current_txid = tx_id;
    }

    ccf::TxID get_indexed_watermark() const
    {
      return current_txid;
    }
  };

  // A simple Strategy which stores one large map in-memory
  class SeqnosByKey_InMemory : public VisitEachEntryInMap
  {
  protected:
    // Key is the raw value of a KV key.
    // Value is every SeqNo which talks about that key.
    std::unordered_map<kv::untyped::SerialisedEntry, SeqNoCollection>
      seqnos_by_key;

    void visit_entry(
      const ccf::TxID& tx_id,
      const kv::serialisers::SerialisedEntry& k,
      const kv::serialisers::SerialisedEntry& v) override
    {
      seqnos_by_key[k].insert(tx_id.seqno);
    }

  public:
    SeqnosByKey_InMemory(const std::string& map_name_) :
      VisitEachEntryInMap(map_name_, "SeqnosByKey")
    {}

    std::optional<std::set<ccf::SeqNo>> get_write_txs_in_range(
      const kv::serialisers::SerialisedEntry& serialised_key,
      ccf::SeqNo from,
      ccf::SeqNo to,
      std::optional<size_t> max_seqnos = std::nullopt)
    {
      const auto it = seqnos_by_key.find(serialised_key);
      if (it != seqnos_by_key.end())
      {
        SeqNoCollection& seqnos = it->second;
        auto from_it = seqnos.lower_bound(from);
        auto to_it = from_it;

        if (
          max_seqnos.has_value() &&
          std::distance(from_it, seqnos.end()) > *max_seqnos)
        {
          std::advance(to_it, *max_seqnos);
        }
        else
        {
          to_it = seqnos.upper_bound(to);
        }

        SeqNoCollection sub_range(from_it, to_it);
        return sub_range;
      }

      // In this case we have seen every tx in the requested range, but have not
      // seen the target key at all
      return SeqNoCollection();
    }
  };

  // Stores only a subset of results in-memory, on-demand, and dumps the
  // remainder to disk
  class SeqnosByKey_BucketedCache : public VisitEachEntryInMap
  {
  protected:
    // Inclusive begin, exclusive end
    using Range = std::pair<ccf::SeqNo, ccf::SeqNo>;

    // TODO: Could be a SeqNoCollection? But keeping as a set for simplicity
    // right now
    using SeqNos = std::set<ccf::SeqNo>;

    // Store a single bucket of current results for each key
    using CurrentResult = std::pair<Range, SeqNos>;
    std::unordered_map<kv::untyped::SerialisedEntry, CurrentResult>
      current_results;

    // Maintain an LRU of old, requested buckets, which are asynchronously
    // fetched from disk
    using BucketKey = std::pair<kv::untyped::SerialisedEntry, Range>;
    // First element is a handle while result is being fetched. Second is parsed
    // result, after fetch, at which point the first is set to nullptr
    using BucketValue = std::pair<caching::FetchResultPtr, SeqNos>;
    LRU<BucketKey, BucketValue> old_results;

    caching::EnclaveCache& enclave_cache;

    caching::BlobContents serialise(SeqNos&& seqnos)
    {
      caching::BlobContents blob;

      {
        // Write number of seqnos
        const auto orig_size = blob.size();
        blob.resize(orig_size + sizeof(seqnos.size()));
        auto data = blob.data() + orig_size;
        auto size = blob.size() - orig_size;
        serialized::write(data, size, seqnos.size());
      }

      // Write each seqno
      for (const auto& seqno : seqnos)
      {
        const auto orig_size = blob.size();
        blob.resize(orig_size + sizeof(seqno));
        auto data = blob.data() + orig_size;
        auto size = blob.size() - orig_size;
        serialized::write(data, size, seqno);
      }

      return blob;
    }

    // TODO: Do all of this in a try-catch, and handle it being unserialisable
    // as though it were corrupt?
    SeqNos deserialise(const caching::BlobContents& raw)
    {
      SeqNos result;

      auto data = raw.data();
      auto size = raw.size();

      // Read number of seqnos
      const auto seqno_count = serialized::read<size_t>(data, size);
      SeqNoCollection seqnos;

      for (auto j = 0; j < seqno_count; ++j)
      {
        seqnos.insert(serialized::read<ccf::SeqNo>(data, size));
      }

      return result;
    }

    caching::BlobKey get_blob_name(const BucketKey& bk)
    {
      const auto hex_key = ds::to_hex(bk.first.begin(), bk.first.end());
      const auto& range = bk.second;
      return fmt::format(
        "{}: {} -> {} for {}", get_name(), range.first, range.second, hex_key);
    }

    void store_to_disk(
      const kv::untyped::SerialisedEntry& k,
      const Range& range,
      SeqNos&& seqnos)
    {
      const BucketKey bucket_key{k, range};
      const auto blob_key = get_blob_name(bucket_key);
      enclave_cache.store(blob_key, serialise(std::move(seqnos)));
    }

    // TODO: Templates? Construction parameters?
    // How many seqnos are bucketed together into a single partial
    // result, to be offloaded together?
    static constexpr auto RANGE_SIZE = 10;
    // TODO: Other parameters
    // How many buckets are kept in memory at once?
    // How many of those buckets can be used for historical reconstruction?
    // What is the largest range of SeqNos which can be requested?

    // TODO: Should store a single current bucket, and an LRU of fetching
    // buckets, with a bounded size
    // (Key + Bucket) -> SeqNos
    // Then culling the overfull current bucket is explicit, and we don't need
    // to fiddle with the LRU

    Range get_range_for(ccf::SeqNo seqno)
    {
      const auto begin = (seqno / RANGE_SIZE) * RANGE_SIZE;
      const auto end = begin + RANGE_SIZE;
      return {begin, end};
    }

    void visit_entry(
      const ccf::TxID& tx_id,
      const kv::serialisers::SerialisedEntry& k,
      const kv::serialisers::SerialisedEntry& v) override
    {
      const auto range = get_range_for(tx_id.seqno);

      auto it = current_results.find(k);
      if (it != current_results.end())
      {
        // Have existing results. If they're from an old range, they must be
        // flushed, and the bucket updated to contain the new entry
        auto& current_result = it->second;
        const auto current_range = current_result.first;
        if (range != current_range)
        {
          store_to_disk(k, current_range, std::move(current_result.second));
          current_result.first = range;
          current_result.second.clear();
        }
      }
      else
      {
        // This key has never been seen before. Insert a new bucket for it
        it = current_results.emplace(k, std::make_pair(range, SeqNos())).first;
      }

      auto& current_result = it->second;
      auto& current_seqnos = current_result.second;
      current_seqnos.insert(tx_id.seqno);
    }

  public:
    SeqnosByKey_BucketedCache(
      const std::string& map_name_, caching::EnclaveCache& enclave_cache_) :
      VisitEachEntryInMap(map_name_, "SeqnosByKey"),
      old_results(3), // TODO: Decide how this is set
      enclave_cache(enclave_cache_)
    {}

    virtual ~SeqnosByKey_BucketedCache() = default;

    std::optional<std::set<ccf::SeqNo>> get_write_txs_in_range(
      const kv::serialisers::SerialisedEntry& serialised_key,
      ccf::SeqNo from,
      ccf::SeqNo to,
      std::optional<size_t> max_seqnos = std::nullopt)
    {
      auto from_range = get_range_for(from);
      const auto to_range = get_range_for(to);

      {
        // Check that once the entire requested range is fetched, it will fit
        // into the LRU at the same time
        const auto num_buckets_required =
          1 + (to_range.first - from_range.first) / RANGE_SIZE;
        if (num_buckets_required > old_results.get_max_size())
        {
          throw std::logic_error(fmt::format(
            "Fetching {} to {} would require {} buckets, but we can only store "
            "{} in-memory at once",
            from,
            to,
            num_buckets_required,
            old_results.get_max_size()));
        }
      }

      SeqNos result;

      auto append_bucket_result = [&](const SeqNos& seqnos) {
        // TODO: Need to find a more efficient way of doing this
        for (auto n : seqnos)
        {
          if (max_seqnos.has_value() && result.size() >= *max_seqnos)
          {
            break;
          }

          if (n >= from && n <= to)
          {
            result.insert(n);
          }
        }
      };

      bool complete = true;

      while (true)
      {
        const auto bucket_key = std::make_pair(serialised_key, from_range);
        const auto old_it = old_results.find(bucket_key);
        if (old_it != old_results.end())
        {
          auto& bucket_value = old_it->second;

          // We were already trying to fetch this. If it's finished fetching,
          // parse and store the result
          if (bucket_value.first != nullptr)
          {
            switch (bucket_value.first->fetch_result)
            {
              case (caching::FetchResult::Fetching):
              {
                complete = false;
                break;
              }
              case (caching::FetchResult::Loaded):
              {
                bucket_value.second = deserialise(bucket_value.first->contents);
                bucket_value.first = nullptr;
                break;
              }
              case (caching::FetchResult::NotFound):
              case (caching::FetchResult::Corrupt):
              {
                LOG_FAIL_FMT("TODO case");
                complete = false;
                break;
              }
            }
          }

          if (bucket_value.first == nullptr && complete)
          {
            // Still building a contiguous result, and have a parsed result for
            // this bucket - insert it
            append_bucket_result(bucket_value.second);
          }
        }
        else
        {
          // We're not currently fetching this. First check if it's in our
          // current results
          const auto current_it = current_results.find(serialised_key);
          if (
            current_it != current_results.end() &&
            current_it->second.first == from_range)
          {
            if (complete)
            {
              append_bucket_result(current_it->second.second);
            }
          }
          else
          {
            // Begin fetching this bucket from disk
            auto fetch_handle = enclave_cache.fetch(get_blob_name(bucket_key));
            old_results.insert(
              bucket_key, std::make_pair(fetch_handle, SeqNos()));
            complete = false;
          }
        }

        if (from_range == to_range)
        {
          break;
        }
        else
        {
          from_range.first += RANGE_SIZE;
          from_range.second += RANGE_SIZE;
        }
      }

      if (complete)
      {
        return result;
      }

      return std::nullopt;
    }
  };

  template <typename M, typename Base>
  class SeqnosByKey_Access : public Base
  {
  public:
    using Base::Base;

    template <typename... Ts>
    SeqnosByKey_Access(const M& map, Ts&&... ts) :
      Base(map.get_name(), std::forward<Ts>(ts)...)
    {}

    std::optional<std::set<ccf::SeqNo>> get_write_txs_in_range(
      const typename M::Key& key,
      ccf::SeqNo from,
      ccf::SeqNo to,
      std::optional<size_t> max_seqnos = std::nullopt)
    {
      if (to > Base::current_txid.seqno)
      {
        // If the requested range hasn't been populated yet, indicate
        // that with nullopt
        return std::nullopt;
      }

      return Base::get_write_txs_in_range(
        M::KeySerialiser::to_serialised(key), from, to, max_seqnos);
    }

    std::optional<std::set<ccf::SeqNo>> get_all_write_txs(
      const typename M::Key& key)
    {
      return get_write_txs_in_range(key, 0, Base::current_txid.seqno);
    }
  };

  template <typename M>
  using SeqnosByKey = SeqnosByKey_Access<M, SeqnosByKey_InMemory>;

  // TODO: This shouldn't really have a get_all_write_txs method
  template <typename M>
  using SeqnosByKeyAsync = SeqnosByKey_Access<M, SeqnosByKey_BucketedCache>;
}