// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/indexing/lfs_interface.h"
#include "ccf/indexing/strategies/visit_each_entry_in_map.h"
#include "ccf/seq_no_collection.h"
#include "ds/lru.h"

namespace ccf::indexing::strategies
{
  // Stores only a subset of results in-memory, on-demand, and dumps the
  // remainder to disk. The size of the per-key buckets which will be retained,
  // and the number of buckets which may be held in-memory, are configurable
  template <typename M>
  class SeqnosByKey_Bucketed : public VisitEachEntryInMap
  {
  protected:
    const size_t seqnos_per_bucket;

    // Inclusive begin, exclusive end
    using Range = std::pair<ccf::SeqNo, ccf::SeqNo>;

    // Store a single bucket of current results for each key
    using CurrentResult = std::pair<Range, SeqNoCollection>;
    std::unordered_map<kv::untyped::SerialisedEntry, CurrentResult>
      current_results;

    // Maintain an LRU of old, requested buckets, which are asynchronously
    // fetched from disk
    using BucketKey = std::pair<kv::untyped::SerialisedEntry, Range>;
    // First element is a handle while result is being fetched. Second is parsed
    // result, after fetch completes, at which point the first is set to nullptr
    using BucketValue = std::pair<FetchResultPtr, SeqNoCollection>;
    LRU<BucketKey, BucketValue> old_results;

    AbstractLFSAccess& lfs_access;

    LFSContents serialise(SeqNoCollection&& seqnos)
    {
      LFSContents blob;

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

    SeqNoCollection deserialise(const LFSContents& raw, bool& corrupt)
    {
      corrupt = false;
      try
      {
        auto data = raw.data();
        auto size = raw.size();

        // Read number of seqnos
        const auto seqno_count = serialized::read<size_t>(data, size);
        SeqNoCollection seqnos;

        for (auto j = 0u; j < seqno_count; ++j)
        {
          seqnos.insert(serialized::read<ccf::SeqNo>(data, size));
        }

        if (size != 0)
        {
          LOG_TRACE_FMT("{} bytes remaining after deserialisation", size);
          corrupt = true;
          return {};
        }

        return seqnos;
      }
      // Catch errors thrown by serialized::read
      catch (const std::logic_error& e)
      {
        corrupt = true;
        return {};
      }
    }

    LFSKey get_blob_name(const BucketKey& bk)
    {
      const auto hex_key = ds::to_hex(bk.first.begin(), bk.first.end());
      const auto& range = bk.second;
      return fmt::format(
        "{}: {} -> {} for {}", get_name(), range.first, range.second, hex_key);
    }

    void store_to_disk(
      const kv::untyped::SerialisedEntry& k,
      const Range& range,
      SeqNoCollection&& seqnos)
    {
      const BucketKey bucket_key{k, range};
      const auto blob_key = get_blob_name(bucket_key);
      lfs_access.store(blob_key, serialise(std::move(seqnos)));
    }

    Range get_range_for(ccf::SeqNo seqno) const
    {
      const auto begin = (seqno / seqnos_per_bucket) * seqnos_per_bucket;
      const auto end = begin + seqnos_per_bucket;
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
        it =
          current_results.emplace(k, std::make_pair(range, SeqNoCollection()))
            .first;
      }

      auto& current_result = it->second;
      auto& current_seqnos = current_result.second;
      current_seqnos.insert(tx_id.seqno);
    }

    std::optional<SeqNoCollection> get_write_txs_impl(
      const kv::serialisers::SerialisedEntry& serialised_key,
      ccf::SeqNo from,
      ccf::SeqNo to)
    {
      auto from_range = get_range_for(from);
      const auto to_range = get_range_for(to);

      // Check that once the entire requested range is fetched, it will fit
      // into the LRU at the same time
      if ((to - from) > max_requestable_range())
      {
        const auto num_buckets_required =
          1 + (to_range.first - from_range.first) / seqnos_per_bucket;
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

      SeqNoCollection result;

      auto append_bucket_result = [&](const SeqNoCollection& seqnos) {
        for (auto n : seqnos)
        {
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
            const auto fetch_result = bucket_value.first->fetch_result;
            switch (fetch_result)
            {
              case (FetchResult::Fetching):
              {
                complete = false;
                break;
              }
              case (FetchResult::Loaded):
              {
                bool corrupt = false;
                bucket_value.second =
                  deserialise(bucket_value.first->contents, corrupt);
                if (!corrupt)
                {
                  bucket_value.first = nullptr;
                  break;
                }
                else
                {
                  // Deliberately fall through to the case below. If this can't
                  // deserialise the value, consider the file corrupted
                  LOG_FAIL_FMT("Deserialisation failed");
                }
              }
              case (FetchResult::NotFound):
              case (FetchResult::Corrupt):
              {
                // This class previously wrote a bucket to disk which is no
                // longer available or corrupted. Reset the watermark of what
                // has been indexed, to re-index and rewrite those files.
                complete = false;
                const auto problem =
                  fetch_result == FetchResult::NotFound ? "missing" : "corrupt";
                LOG_FAIL_FMT(
                  "A file that {} requires is {}. Re-indexing.",
                  get_name(),
                  problem);
                LOG_DEBUG_FMT(
                  "The {} file is {}", problem, bucket_value.first->key);

                // NB: This could probably be more precise about what is
                // re-indexed. Technically only need to build an index to build
                // the current query, and that applies to re-indexing too. But
                // for safety, and consistency with the simple indexing
                // strategies currently used, this re-indexes everything from
                // the start of time.
                current_txid = {};
                old_results.clear();
                current_results.clear();

                return std::nullopt;
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
          // Another possibility is that the requested range is _after_ the
          // current_results for this key. That means, assuming we have
          // constructed a complete index up to to_range, that there are no
          // later buckets to fetch - we have constructed a complete result
          else if (
            current_it != current_results.end() &&
            current_it->second.first.first < to_range.first)
          {
            break;
          }
          else
          {
            // Begin fetching this bucket from disk
            auto fetch_handle = lfs_access.fetch(get_blob_name(bucket_key));
            old_results.insert(
              bucket_key, std::make_pair(fetch_handle, SeqNoCollection()));
            complete = false;
          }
        }

        if (from_range == to_range)
        {
          break;
        }
        else
        {
          from_range.first += seqnos_per_bucket;
          from_range.second += seqnos_per_bucket;
        }
      }

      if (complete)
      {
        return result;
      }

      return std::nullopt;
    }

  public:
    SeqnosByKey_Bucketed(
      const std::string& map_name_,
      AbstractLFSAccess& lfs_access_,
      size_t seqnos_per_bucket_ = 1000,
      size_t max_buckets_ = 10) :
      VisitEachEntryInMap(map_name_, "SeqnosByKey"),
      seqnos_per_bucket(seqnos_per_bucket_),
      old_results(max_buckets_),
      lfs_access(lfs_access_)
    {
      if (kv::get_security_domain(map_name_) != kv::SecurityDomain::PUBLIC)
      {
        throw std::logic_error(fmt::format(
          "This Strategy is currently only implemented for public tables, so "
          "cannot be used for '{}'",
          map_name_));
      }
    }

    SeqnosByKey_Bucketed(
      const M& map,
      AbstractLFSAccess& lfs_access_,
      size_t seqnos_per_bucket_ = 1000,
      size_t max_buckets_ = 10) :
      SeqnosByKey_Bucketed(
        map.get_name(), lfs_access_, seqnos_per_bucket_, max_buckets_)
    {}

    virtual ~SeqnosByKey_Bucketed() = default;

    size_t max_requestable_range() const
    {
      return (old_results.get_max_size() * seqnos_per_bucket) - 1;
    }

    std::optional<SeqNoCollection> get_write_txs_in_range(
      const typename M::Key& key, ccf::SeqNo from, ccf::SeqNo to)
    {
      if (to < from)
      {
        throw std::logic_error(
          fmt::format("Range goes backwards: {} -> {}", from, to));
      }

      if (to > current_txid.seqno)
      {
        // If the requested range hasn't been populated yet, indicate
        // that with nullopt
        return std::nullopt;
      }

      return get_write_txs_impl(M::KeySerialiser::to_serialised(key), from, to);
    }
  };
}
