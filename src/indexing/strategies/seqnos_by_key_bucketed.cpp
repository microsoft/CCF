// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/indexing/strategies/seqnos_by_key_bucketed.h"

#include "ccf/ds/hex.h"
#include "ccf/ds/logger.h"
#include "ccf/pal/locking.h"
#include "ds/lru.h"
#include "ds/serialized.h"
#include "indexing/lfs_interface.h"
#include "kv/kv_types.h"

namespace ccf::indexing::strategies
{
  struct SeqnosByKey_Bucketed_Untyped::Impl
  {
  public:
    const size_t seqnos_per_bucket;

    // Inclusive begin, exclusive end
    using Range = std::pair<ccf::SeqNo, ccf::SeqNo>;

    // Store a single bucket of current results for each key
    using CurrentResult = std::pair<Range, SeqNoCollection>;
    std::unordered_map<ccf::ByteVector, CurrentResult> current_results;

    // Maintain an LRU of old, requested buckets, which are asynchronously
    // fetched from disk
    using BucketKey = std::pair<ccf::ByteVector, Range>;
    // First element is a handle while result is being fetched. Second is parsed
    // result, after fetch completes, at which point the first is set to nullptr
    using BucketValue = std::pair<FetchResultPtr, SeqNoCollection>;
    LRU<BucketKey, BucketValue> old_results;

    ccf::pal::Mutex results_access;

    std::string name;

    std::shared_ptr<AbstractLFSAccess> lfs_access;
    ccf::TxID& current_txid;

    Impl(
      const std::string& name_,
      ccf::TxID& current_txid_,
      const std::shared_ptr<AbstractLFSAccess>& lfs_access_,
      size_t seqnos_per_bucket_,
      size_t max_buckets_) :
      seqnos_per_bucket(seqnos_per_bucket_),
      old_results(max_buckets_),
      name(name_),
      lfs_access(lfs_access_),
      current_txid(current_txid_)
    {
      if (lfs_access == nullptr)
      {
        throw std::logic_error(fmt::format(
          "Cannot create this strategy without access to the LFS subsystem"));
      }
    }

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
        "{}: {} -> {} for {}", name, range.first, range.second, hex_key);
    }

    void store_empty_buckets(
      const ccf::ByteVector& k, Range begin, const Range& end)
    {
      while (begin != end)
      {
        LOG_TRACE_FMT(
          "Storing empty bucket for range [{}, {}) for key {:02x}",
          begin.first,
          begin.second,
          fmt::join(k, ""));
        store_to_disk(k, begin, {});
        begin = get_range_for(begin.second);
      }
    }

    void store_to_disk(
      const ccf::ByteVector& k, const Range& range, SeqNoCollection&& seqnos)
    {
      const BucketKey bucket_key{k, range};
      const auto blob_key = get_blob_name(bucket_key);
      lfs_access->store(blob_key, serialise(std::move(seqnos)));
    }

    Range get_range_for(ccf::SeqNo seqno) const
    {
      const auto begin = (seqno / seqnos_per_bucket) * seqnos_per_bucket;
      const auto end = begin + seqnos_per_bucket;
      return {begin, end};
    }

    std::optional<SeqNoCollection> get_write_txs_impl(
      const ccf::ByteVector& serialised_key, ccf::SeqNo from, ccf::SeqNo to)
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

      auto from_range = get_range_for(from);
      const auto to_range = get_range_for(to);

      // Check that once the entire requested range is fetched, it will fit
      // into the LRU at the same time
      const auto range_len = to - from;
      if (range_len > max_requestable_range())
      {
        throw std::logic_error(fmt::format(
          "Requesting transactions from {} to {} requires buckets covering "
          "[{}, {}). These {} transactions are larger than the maximum "
          "requestable {}",
          from,
          to,
          from_range.first,
          to_range.second,
          range_len,
          max_requestable_range()));
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
        std::lock_guard<ccf::pal::Mutex> guard(results_access);

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
                  "A file that {} requires is {}. Re-indexing.", name, problem);
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
          // later buckets to fetch - we have constructed a complete result.
          // Similarly, if we have _no_ current_results for this key, then
          // (assuming we have a complete index), there are no writes to this
          // key, and we have constructed a complete result.
          else if (
            (current_it != current_results.end() &&
             current_it->second.first.first < from_range.first) ||
            current_it == current_results.end())
          {
            break;
          }
          else
          {
            // Begin fetching this bucket from disk
            auto fetch_handle = lfs_access->fetch(get_blob_name(bucket_key));
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

    // This returns the max range which may be requested. This accounts for the
    // case where the range is not aligned with a bucket start, in which case we
    // will have unrequested entries sharing a bucket with the requested entries
    // at the beginning and end, essentially wasting some space.
    size_t max_requestable_range() const
    {
      return ((old_results.get_max_size() - 1) * seqnos_per_bucket);
    }
  };

  void SeqnosByKey_Bucketed_Untyped::visit_entry(
    const ccf::TxID& tx_id, const ccf::ByteVector& k, const ccf::ByteVector& v)
  {
    const auto range = impl->get_range_for(tx_id.seqno);

    std::lock_guard<ccf::pal::Mutex> guard(impl->results_access);

    auto it = impl->current_results.find(k);
    if (it != impl->current_results.end())
    {
      // Have existing results. If they're from an old range, they must be
      // flushed, and the bucket updated to contain the new entry
      auto& current_result = it->second;
      const auto current_range = current_result.first;
      if (range != current_range)
      {
        LOG_TRACE_FMT(
          "Storing {} entries from real range [{}, {}) for key {:02x}",
          current_result.second.size(),
          current_range.first,
          current_range.second,
          fmt::join(k, ""));
        impl->store_to_disk(k, current_range, std::move(current_result.second));

        const auto next_range = impl->get_range_for(current_range.second);
        if (next_range != range)
        {
          impl->store_empty_buckets(k, next_range, range);
        }

        current_result.first = range;
        current_result.second.clear();
      }
    }
    else
    {
      // This key has never been seen before. Insert a new bucket for it
      impl->store_empty_buckets(k, impl->get_range_for(0), range);
      it = impl->current_results
             .emplace(k, std::make_pair(range, SeqNoCollection()))
             .first;
    }

    auto& current_result = it->second;
    auto& current_seqnos = current_result.second;
    current_seqnos.insert(tx_id.seqno);
  }

  nlohmann::json SeqnosByKey_Bucketed_Untyped::describe()
  {
    auto j = VisitEachEntryInMap::describe();
    {
      std::lock_guard<ccf::pal::Mutex> guard(impl->results_access);
      j["seqnos_per_bucket"] = impl->seqnos_per_bucket;
      j["old_results_max_size"] = impl->old_results.get_max_size();
      j["old_results_current_size"] = impl->old_results.size();
      j["current_results_size"] = impl->current_results.size();
    }
    return j;
  }

  std::optional<SeqNoCollection> SeqnosByKey_Bucketed_Untyped::
    get_write_txs_impl(
      const ccf::ByteVector& serialised_key, ccf::SeqNo from, ccf::SeqNo to)
  {
    return impl->get_write_txs_impl(serialised_key, from, to);
  }

  SeqnosByKey_Bucketed_Untyped::SeqnosByKey_Bucketed_Untyped(
    const std::string& map_name_,
    ccfapp::AbstractNodeContext& node_context,
    size_t seqnos_per_bucket_,
    size_t max_buckets_) :
    VisitEachEntryInMap(map_name_, "SeqnosByKey")
  {
    if (kv::get_security_domain(map_name_) != kv::SecurityDomain::PUBLIC)
    {
      throw std::logic_error(fmt::format(
        "This Strategy ({}) is currently only implemented for public tables, "
        "so cannot be used for '{}'",
        get_name(),
        map_name_));
    }

    impl = std::make_shared<Impl>(
      get_name(),
      current_txid,
      node_context.get_subsystem<AbstractLFSAccess>(),
      seqnos_per_bucket_,
      max_buckets_);
  }

  size_t SeqnosByKey_Bucketed_Untyped::max_requestable_range() const
  {
    return impl->max_requestable_range();
  }
}
