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
    VisitEachEntryInMap(const std::string& map_name_) :
      Strategy(fmt::format("VisitEachEntryIn {}", map_name_)),
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
      VisitEachEntryInMap(map_name_)
    {}

    std::optional<std::set<ccf::SeqNo>> get_write_txs_in_range(
      const kv::serialisers::SerialisedEntry& serialised_key,
      ccf::SeqNo from,
      ccf::SeqNo to,
      std::optional<size_t> max_seqnos = std::nullopt)
    {
      if (to > current_txid.seqno)
      {
        // If the requested range hasn't been populated yet, indicate
        // that with nullopt
        return std::nullopt;
      }

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

  class BaseSeqnosByKey : public VisitEachEntryInMap
  {
  protected:
    using Range = std::pair<ccf::SeqNo, ccf::SeqNo>;
    // Key is the raw value of a KV key.
    // Value is every SeqNo which talks about that key.
    // TODO: Value could be a SeqNoCollection for better efficiency? But
    // keeping as a set for simplicity at the moment.
    using PartialResultsMap =
      std::unordered_map<kv::untyped::SerialisedEntry, std::set<ccf::SeqNo>>;

    struct PartialResults
    {
      BaseSeqnosByKey& owner;
      Range covered_range;
      PartialResultsMap seqnos_by_key;

      PartialResults(BaseSeqnosByKey& owner_, const Range& range_) :
        owner(owner_),
        covered_range(range_)
      {}

      // TODO: Want to do this on cull, but not on final teardown! Need to
      // extend LRU
      ~PartialResults()
      {
        if (!seqnos_by_key.empty())
        {
          owner.store_to_disk(covered_range, std::move(seqnos_by_key));
        }
      }
    };

    caching::BlobContents serialise(PartialResultsMap&& map)
    {
      caching::BlobContents blob;

      {
        // Write number of keys
        blob.resize(blob.size() + sizeof(map.size()));
        auto data = blob.data();
        auto size = blob.size();
        serialized::write(data, size, map.size());
      }

      // Write each key
      for (const auto& [map_key, seqnos] : map)
      {
        {
          // Write map key
          const auto orig_size = blob.size();
          blob.resize(orig_size + sizeof(map_key.size()) + map_key.size());
          auto data = blob.data() + orig_size;
          auto size = blob.size() - orig_size;
          serialized::write(data, size, map_key.size());
          serialized::write(data, size, map_key.data(), map_key.size());
        }

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
      }

      return blob;
    }

    // TODO: Do all of this in a try-catch, and handle it being unserialisable
    // as though it were corrupt?
    PartialResultsMap deserialise(const caching::BlobContents& raw)
    {
      PartialResultsMap result;

      auto data = raw.data();
      auto size = raw.size();

      // Read number of keys
      const auto key_count = serialized::read<size_t>(data, size);

      for (auto i = 0; i < key_count; ++i)
      {
        const auto map_name_len = serialized::read<size_t>(data, size);
        const auto map_name_data = serialized::read(data, size, map_name_len);

        // Read number of seqnos
        const auto seqno_count = serialized::read<size_t>(data, size);
        SeqNoCollection seqnos;

        for (auto j = 0; j < seqno_count; ++j)
        {
          seqnos.insert(serialized::read<ccf::SeqNo>(data, size));
        }

        const kv::untyped::SerialisedEntry map_name(
          map_name_data.begin(), map_name_data.end());
        result[map_name] = seqnos;
      }

      return result;
    }

    caching::BlobKey get_blob_name(const Range& range)
    {
      return fmt::format("{}: {} -> {}", get_name(), range.first, range.second);
    }

    void store_to_disk(const Range& range, PartialResultsMap&& map)
    {
      const auto key = get_blob_name(range);
      enclave_cache.store(key, serialise(std::move(map)));
    }

    LRU<Range, std::unique_ptr<PartialResults>> loaded_results;

    caching::EnclaveCache& enclave_cache;

    std::map<Range, caching::FetchResultPtr> fetching;

    // TODO: Templates? Construction parameters?
    // How many seqnos are bucketed together into a single partial
    // result, to be offloaded together?
    static constexpr auto RANGE_SIZE = 10;
    // TODO: Other parameters
    // How many buckets are kept in memory at once?
    // How many of those buckets can be used for historical reconstruction?
    // What is the largest range of SeqNos which can be requested?

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

      // NB: If this is a new range, it may push the oldest PartialResults out
      // of the LRU, calling its destructor and causing us to flush it to disk
      auto partial_it = loaded_results.insert(
        range, std::make_unique<PartialResults>(*this, range));
      auto& partial_map = partial_it->second->seqnos_by_key;
      partial_map[k].insert(tx_id.seqno);
    }

  public:
    BaseSeqnosByKey(
      const std::string& map_name_, caching::EnclaveCache& enclave_cache_) :
      VisitEachEntryInMap(map_name_),
      loaded_results(3), // TODO: Decide how this is set
      enclave_cache(enclave_cache_)
    {}

    virtual ~BaseSeqnosByKey() = default;

    std::optional<std::set<ccf::SeqNo>> get_write_txs_in_range(
      const kv::serialisers::SerialisedEntry& serialised_key,
      ccf::SeqNo from,
      ccf::SeqNo to,
      std::optional<size_t> max_seqnos = std::nullopt)
    {
      if (to > current_txid.seqno)
      {
        // If the requested range hasn't been populated yet, indicate
        // that with nullopt
        return std::nullopt;
      }

      auto from_range = get_range_for(from);
      const auto to_range = get_range_for(to);

      std::set<ccf::SeqNo> result;

      auto append_partial_results = [&](const PartialResultsMap& partial) {
        const auto it = partial.find(serialised_key);
        if (it != partial.end())
        {
          const std::set<ccf::SeqNo>& seqnos = it->second;

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
        }
      };

      bool complete = true;

      while (true)
      {
        const auto partial_it = loaded_results.find(from_range);
        if (partial_it != loaded_results.end())
        {
          if (complete)
          {
            // Have partial result for this sub-range in-memory already
            append_partial_results(partial_it->second->seqnos_by_key);
          }
        }
        else
        {
          // We flushed this already, need to fetch it from the host-side disk
          // storage

          auto should_fetch = true;

          auto it = fetching.find(from_range);
          if (it != fetching.end())
          {
            switch (it->second->fetch_result)
            {
              case (caching::FetchResult::Fetching):
              {
                should_fetch = false;
                complete = false;
                break;
              }
              case (caching::FetchResult::Loaded):
              {
                should_fetch = false;
                if (complete)
                {
                  auto partial_results = deserialise(it->second->contents);
                  append_partial_results(partial_results);
                }
                break;
              }
              case (caching::FetchResult::NotFound):
              {
                throw std::logic_error("TODO");
                break;
              }
              case (caching::FetchResult::Corrupt):
              {
                throw std::logic_error("TODO");
                break;
              }
            }
          }

          if (should_fetch)
          {
            auto fetch_handle = enclave_cache.fetch(get_blob_name(from_range));
            fetching.emplace(from_range, fetch_handle);
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

    SeqnosByKey_Access(const M& map) : Base(map.get_name()) {}

    std::optional<std::set<ccf::SeqNo>> get_write_txs_in_range(
      const typename M::Key& key,
      ccf::SeqNo from,
      ccf::SeqNo to,
      std::optional<size_t> max_seqnos = std::nullopt)
    {
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
}