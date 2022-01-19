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
  template <typename M>
  class SeqnosByKey : public Strategy
  {
  private:
    using Range = std::pair<ccf::SeqNo, ccf::SeqNo>;
    // Key is the raw value of a KV key.
    // Value is every SeqNo which talks about that key.
    // TODO: Value could be a SeqNoCollection for better efficiency? But
    // keeping as a set for simplicity at the moment.
    using PartialResultsMap =
      std::unordered_map<kv::untyped::SerialisedEntry, std::set<ccf::SeqNo>>;

    struct PartialResults
    {
      SeqnosByKey<M>& owner;
      Range covered_range;
      PartialResultsMap seqnos_by_key;

      PartialResults(SeqnosByKey<M>& owner_, const Range& range_) :
        owner(owner_),
        covered_range(range_)
      {}

      // TODO: Want to do this on cull, but not on final teardown! Need to extend LRU
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

    void store_to_disk(const Range& range, PartialResultsMap&& map)
    {
      caching::BlobKey key =
        fmt::format("{}: {} -> {}", get_name(), range.first, range.second);

      enclave_cache.store(key, serialise(std::move(map)));
    }

    LRU<Range, std::unique_ptr<PartialResults>> loaded_results;

    ccf::TxID current_txid = {};

    std::string map_name;
    caching::EnclaveCache& enclave_cache;

    // TODO: Template? Construction parameter?
    static constexpr auto RANGE_SIZE = 10;

    Range get_range_for(ccf::SeqNo seqno)
    {
      const auto begin = (seqno / RANGE_SIZE) * RANGE_SIZE;
      const auto end = begin + RANGE_SIZE;
      return {begin, end};
    }

  public:
    SeqnosByKey(
      const std::string& map_name_, caching::EnclaveCache& enclave_cache_) :
      Strategy(fmt::format("SeqnosByKey for {}", map_name_)),
      loaded_results(3), // TODO: Decide how this is set
      map_name(map_name_),
      enclave_cache(enclave_cache_)
    {}

    SeqnosByKey(const M& map, caching::EnclaveCache& enclave_cache_) :
      SeqnosByKey(map.get_name(), enclave_cache_)
    {}

    void handle_committed_transaction(
      const ccf::TxID& tx_id, const StorePtr& store) override
    {
      // NB: Don't use M, instead get an untyped view over the map with the same
      // name. This saves deserialisation here, where we work with the raw key.
      auto tx = store->create_read_only_tx();
      auto handle = tx.ro<kv::untyped::Map>(map_name);

      const auto range = get_range_for(tx_id.seqno);

      // NB: If this is a new range, it may push the oldest PartialResults out
      // of the LRU, calling its destructor and causing us to flush it to disk
      auto partial_it = loaded_results.insert(
        range, std::make_unique<PartialResults>(*this, range));
      auto& partial_map = partial_it->second->seqnos_by_key;

      handle->foreach([this, &partial_map, seqno = tx_id.seqno](
                        const auto& k, const auto& v) {
        partial_map[k].insert(seqno);
        return true;
      });
      current_txid = tx_id;
    }

    ccf::TxID get_indexed_watermark() const
    {
      return current_txid;
    }

    // TODO: Remove
    std::set<ccf::SeqNo> get_all_write_txs(const typename M::Key& key)
    {
      auto res = get_write_txs_in_range(key, 0, current_txid.seqno);
      if (!res.has_value())
      {
        throw std::logic_error("Range to current txid hasn't been populated");
      }
      return res.value();
    }

    std::optional<std::set<ccf::SeqNo>> get_write_txs_in_range(
      const typename M::Key& key,
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

      const auto serialised_key = M::KeySerialiser::to_serialised(key);

      std::set<ccf::SeqNo> result;

      while (true)
      {
        const auto partial_it = loaded_results.find(from_range);
        if (partial_it != loaded_results.end())
        {
          // Have partial result for this sub-range in-memory already
          const auto it =
            partial_it->second->seqnos_by_key.find(serialised_key);
          if (it != partial_it->second->seqnos_by_key.end())
          {
            std::set<ccf::SeqNo>& seqnos = it->second;

            auto from_it = seqnos.lower_bound(from);
            auto to_it = seqnos.upper_bound(to);

            // TODO: max_seqnos calculation here is wrong, because we're only
            // considering a subrange now
            if (
              max_seqnos.has_value() &&
              std::distance(from_it, to_it) > *max_seqnos)
            {
              to_it = from_it;
              std::advance(to_it, *max_seqnos);
            }

            result.insert(from_it, to_it);
          }
        }
        else
        {
          // Oh no, we flushed this already, need to fetch it from the host-side
          // disk storage
          LOG_FAIL_FMT("TODO");
          throw std::logic_error("Oh no");
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

      return result;
    }
  };
}