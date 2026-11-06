// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/indexing/strategies/seqnos_by_key_bucketed.h"

#include "ccf/ds/hex.h"
#include "ccf/ds/locking.h"
#include "ds/internal_logger.h"
#include "ds/lru.h"
#include "ds/serialized.h"
#include "indexing/lfs_interface.h"
#include "kv/kv_types.h"

#include <algorithm>

namespace ccf::indexing::strategies
{
  struct SeqnosByKey_Bucketed_Untyped::Impl
  {
  public:
    static constexpr size_t DIRECTORY_PAGE_SIZE = 256;
    const size_t seqnos_per_bucket;
    const size_t max_buckets;

    // When both locks are needed, results_access must be acquired first.
    ccf::ds::Mutex results_access CCF_ACQUIRED_BEFORE(current_txid_lock);

    // Inclusive begin, exclusive end
    using Range = std::pair<ccf::SeqNo, ccf::SeqNo>;
    using DirectoryPage = std::vector<ccf::SeqNo>;

    struct CurrentResult
    {
      Range range;
      SeqNoCollection seqnos;
      size_t page_count = 0;
      std::optional<ccf::SeqNo> last_paged_bucket = std::nullopt;
      DirectoryPage directory;
    };

    // These trusted heads must not be evicted: absence means never written.
    std::unordered_map<ccf::ByteVector, CurrentResult> current_results
      CCF_GUARDED_BY(results_access);

    using BucketKey = std::pair<ccf::ByteVector, Range>;
    using PageKey = std::pair<ccf::ByteVector, size_t>;
    using CachedBucket = std::shared_ptr<const SeqNoCollection>;
    LRU<BucketKey, CachedBucket> old_results CCF_GUARDED_BY(results_access);
    LRU<PageKey, DirectoryPage> directory_pages CCF_GUARDED_BY(results_access);

    struct BucketRequest
    {
      ccf::SeqNo start;
      FetchResultPtr pending;
      bool required;
      CachedBucket seqnos = nullptr;
    };

    struct Query
    {
      enum class Phase : uint8_t
      {
        Direct,
        Seek,
        Scan,
        Complete,
      };
      Phase phase = Phase::Direct;
      SeqNoCollection current;
      std::optional<SeqNoCollection> result;
      std::vector<BucketRequest> buckets;
      size_t page_count = 0;
      size_t low = 0;
      size_t high = 0;
      FetchResultPtr page_pending;
    };

    using QueryKey = std::pair<ccf::ByteVector, Range>;
    // Pending reads and search bounds survive eviction from either file cache.
    LRU<QueryKey, Query> queries CCF_GUARDED_BY(results_access);

    bool rebuild_requested CCF_GUARDED_BY(results_access) = false;

    std::string name;
    std::shared_ptr<AbstractLFSAccess> lfs_access;
    ccf::ds::Mutex& current_txid_lock;
    ccf::TxID& current_txid CCF_GUARDED_BY(current_txid_lock);

    Impl(
      std::string name_,
      ccf::ds::Mutex& current_txid_lock_,
      ccf::TxID& current_txid_,
      const std::shared_ptr<AbstractLFSAccess>& lfs_access_,
      size_t seqnos_per_bucket_,
      size_t max_buckets_) :
      seqnos_per_bucket(seqnos_per_bucket_),
      max_buckets(max_buckets_),
      old_results(max_buckets_),
      directory_pages(max_buckets_),
      queries(max_buckets_),
      name(std::move(name_)),
      lfs_access(lfs_access_),
      current_txid_lock(current_txid_lock_),
      current_txid(current_txid_)
    {
      if (lfs_access == nullptr)
      {
        throw std::logic_error(
          "Cannot create this strategy without access to the LFS subsystem");
      }

      if (seqnos_per_bucket == 0 || max_buckets_ == 0)
      {
        throw std::logic_error(
          "Bucketed indexing requires a non-zero bucket size and cache "
          "capacity");
      }
    }

    static LFSContents serialise(const auto& seqnos)
    {
      LFSContents blob(sizeof(size_t) + seqnos.size() * sizeof(ccf::SeqNo));
      auto* data = blob.data();
      auto size = blob.size();
      serialized::write(data, size, seqnos.size());
      for (auto seqno : seqnos)
      {
        serialized::write(data, size, seqno);
      }

      return blob;
    }

    std::optional<std::vector<ccf::SeqNo>> deserialise(
      const LFSContents& raw, size_t max_count)
    {
      try
      {
        const auto* data = raw.data();
        auto size = raw.size();
        const auto count = serialized::read<size_t>(data, size);
        if (
          count == 0 || count > max_count ||
          count != size / sizeof(ccf::SeqNo) || size % sizeof(ccf::SeqNo) != 0)
        {
          LOG_FAIL_FMT("Invalid sparse index contents for {}", name);
          return std::nullopt;
        }

        std::vector<ccf::SeqNo> seqnos;
        seqnos.reserve(count);
        for (size_t j = 0; j < count; ++j)
        {
          const auto seqno = serialized::read<ccf::SeqNo>(data, size);
          if (!seqnos.empty() && seqno <= seqnos.back())
          {
            LOG_FAIL_FMT("Unordered sparse index contents for {}", name);
            return std::nullopt;
          }

          seqnos.push_back(seqno);
        }

        return seqnos;
      }
      catch (const serialized::InsufficientSpaceException& e)
      {
        LOG_FAIL_FMT("Sparse index deserialisation failed: {}", e.what());
        return std::nullopt;
      }
    }

    LFSKey get_blob_name(const BucketKey& bk)
    {
      const auto hex_key = ds::to_hex(bk.first.begin(), bk.first.end());
      return fmt::format(
        "{}: {} -> {} for {}",
        name,
        bk.second.first,
        bk.second.second,
        hex_key);
    }

    LFSKey get_page_name(const PageKey& pk)
    {
      const auto hex_key = ds::to_hex(pk.first.begin(), pk.first.end());
      return fmt::format(
        "{}: directory {} ({} seqnos per bucket) for {}",
        name,
        pk.second,
        seqnos_per_bucket,
        hex_key);
    }

    Range get_range_for(ccf::SeqNo seqno) const
    {
      const auto begin = (seqno / seqnos_per_bucket) * seqnos_per_bucket;
      return {begin, begin + seqnos_per_bucket};
    }

    void rebuild() CCF_REQUIRES(results_access)
    {
      LOG_FAIL_FMT(
        "A file that {} requires is missing or corrupt. Re-indexing.", name);
      rebuild_requested = true;
    }

    const DirectoryPage* load_page(const PageKey& key, Query& query)
      CCF_REQUIRES(results_access)
    {
      auto cached = directory_pages.find(key);
      if (cached != directory_pages.end())
      {
        directory_pages.promote(cached);
        query.page_pending = nullptr;
        return &cached->second;
      }

      if (query.page_pending == nullptr)
      {
        query.page_pending = lfs_access->fetch(get_page_name(key));
      }

      const auto status = query.page_pending->fetch_result.load();
      if (status == FetchResult::FetchResultType::Fetching)
      {
        return nullptr;
      }

      std::optional<DirectoryPage> page;
      if (status == FetchResult::FetchResultType::Loaded)
      {
        page = deserialise(query.page_pending->contents, DIRECTORY_PAGE_SIZE);
      }

      if (
        !page.has_value() || page->size() != DIRECTORY_PAGE_SIZE ||
        std::any_of(page->begin(), page->end(), [&](auto start) {
          return start % seqnos_per_bucket != 0;
        }))
      {
        LOG_FAIL_FMT(
          "Required directory page unavailable: {}", get_page_name(key));
        rebuild();
        return nullptr;
      }

      query.page_pending = nullptr;
      return &directory_pages.insert(key, std::move(*page))->second;
    }

    bool fetch_buckets(const ccf::ByteVector& serialised_key, Query& query)
      CCF_REQUIRES(results_access)
    {
      bool pending = false;
      bool need_directory = false;
      for (auto& request : query.buckets)
      {
        if (request.pending != nullptr)
        {
          const auto status = request.pending->fetch_result.load();
          if (status == FetchResult::FetchResultType::Fetching)
          {
            pending = true;
            continue;
          }

          if (status == FetchResult::FetchResultType::Loaded)
          {
            auto seqnos =
              deserialise(request.pending->contents, seqnos_per_bucket);
            const auto range = get_range_for(request.start);
            if (
              seqnos.has_value() && seqnos->front() >= range.first &&
              seqnos->back() < range.second)
            {
              auto collection = std::make_shared<SeqNoCollection>();
              for (auto seqno : *seqnos)
              {
                collection->insert(seqno);
              }

              request.seqnos = collection;
              old_results.insert(
                {serialised_key, range}, std::move(collection));
            }
          }

          request.pending = nullptr;
        }

        if (request.seqnos == nullptr)
        {
          if (request.required)
          {
            LOG_FAIL_FMT(
              "Required bucket unavailable: {}",
              get_blob_name({serialised_key, get_range_for(request.start)}));
            rebuild();
            return false;
          }

          need_directory = true;
        }
      }

      if (pending)
      {
        return false;
      }

      query.phase =
        need_directory ? Query::Phase::Seek : Query::Phase::Complete;
      return true;
    }

    bool lookup_directory(
      const ccf::ByteVector& serialised_key,
      Query& query,
      const Range& from_range,
      const Range& to_range) CCF_REQUIRES(results_access)
    {
      // Page ordinals are dense and bounded by a trusted count. Unlike data
      // bucket existence, their ordered contents support binary search. Every
      // page consulted here is required; an unavailable page cannot prove a
      // gap.
      while (query.phase == Query::Phase::Seek && query.low < query.high)
      {
        const auto mid = query.low + (query.high - query.low) / 2;
        const auto* page = load_page({serialised_key, mid}, query);
        if (page == nullptr)
        {
          return false;
        }

        if (page->back() < from_range.first)
        {
          query.low = mid + 1;
        }
        else
        {
          query.high = mid;
        }
      }

      if (query.phase == Query::Phase::Seek)
      {
        query.phase = Query::Phase::Scan;
      }

      while (query.phase == Query::Phase::Scan && query.low < query.page_count)
      {
        const auto* page = load_page({serialised_key, query.low}, query);
        if (page == nullptr)
        {
          return false;
        }

        for (auto start : *page)
        {
          if (start < from_range.first || start > to_range.first)
          {
            continue;
          }

          const auto request = std::lower_bound(
            query.buckets.begin(),
            query.buckets.end(),
            start,
            [](const auto& entry, auto bucket_start) {
              return entry.start < bucket_start;
            });
          if (request == query.buckets.end() || request->start != start)
          {
            throw std::logic_error("Directory bucket was not requested");
          }

          if (request->seqnos == nullptr)
          {
            LOG_FAIL_FMT(
              "Directory requires unavailable bucket: {}",
              get_blob_name({serialised_key, get_range_for(start)}));
            rebuild();
            return false;
          }
        }

        ++query.low;
        if (page->back() >= to_range.first)
        {
          break;
        }
      }

      query.phase = Query::Phase::Complete;
      return true;
    }

    std::optional<SeqNoCollection> get_write_txs_impl(
      const ccf::ByteVector& serialised_key, ccf::SeqNo from, ccf::SeqNo to)
    {
      if (to < from)
      {
        throw std::logic_error(
          fmt::format("Range goes backwards: {} -> {}", from, to));
      }

      {
        ccf::ds::MutexGuard guard(current_txid_lock);
        if (to > current_txid.seqno)
        {
          return std::nullopt;
        }
      }

      ccf::ds::MutexGuard results_guard(results_access);
      if (rebuild_requested)
      {
        return std::nullopt;
      }

      if (ccf::ds::MutexGuard guard(current_txid_lock); to > current_txid.seqno)
      {
        // A tick may have reset the index since the initial watermark check.
        return std::nullopt;
      }

      if (to - from > max_requestable_range())
      {
        throw std::logic_error(fmt::format(
          "Requesting transactions from {} to {} exceeds the maximum "
          "requestable {}",
          from,
          to,
          max_requestable_range()));
      }

      const auto from_range = get_range_for(from);
      const auto to_range = get_range_for(to);
      auto append = [&](SeqNoCollection& result, const auto& seqnos) {
        for (auto seqno : seqnos)
        {
          if (seqno >= from && seqno <= to)
          {
            result.insert(seqno);
          }
        }
      };

      const QueryKey query_key{serialised_key, {from, to}};
      auto query_it = queries.find(query_key);
      if (query_it == queries.end())
      {
        const auto head_it = current_results.find(serialised_key);
        if (
          head_it == current_results.end() ||
          head_it->second.range.second <= from)
        {
          return SeqNoCollection{};
        }

        const auto& head = head_it->second;
        Query query;
        append(query.current, head.seqnos);
        query.page_count = head.page_count;
        query.high = head.page_count;
        auto request = [&](ccf::SeqNo start, bool required) CCF_REQUIRES(
                         results_access) {
          const BucketKey key{serialised_key, get_range_for(start)};
          auto cached = old_results.find(key);
          if (cached != old_results.end())
          {
            old_results.promote(cached);
            query.buckets.push_back({start, nullptr, required, cached->second});
          }
          else
          {
            query.buckets.push_back(
              {start, lfs_access->fetch(get_blob_name(key)), required});
          }
        };

        // All speculative reads are confined to the requested range. The
        // trusted unfinished directory proves gaps after the last sealed page.
        if (head.last_paged_bucket.has_value())
        {
          const auto end = std::min(to_range.first, *head.last_paged_bucket);
          for (auto start = from_range.first; start <= end;
               start += seqnos_per_bucket)
          {
            request(start, false);
          }
        }

        for (auto start : head.directory)
        {
          if (start >= from_range.first && start <= to_range.first)
          {
            request(start, true);
          }
        }

        query_it = queries.insert(query_key, std::move(query));
      }

      queries.promote(query_it);
      auto& query = query_it->second;

      if (
        query.phase == Query::Phase::Direct &&
        !fetch_buckets(serialised_key, query))
      {
        return std::nullopt;
      }

      if (!lookup_directory(serialised_key, query, from_range, to_range))
      {
        return std::nullopt;
      }

      if (!query.result.has_value())
      {
        // ContiguousSet is vector-backed. Assemble in bucket order only after
        // all reads and gap proofs complete, avoiding quadratic front inserts
        // when newer buckets were cached before older reads finished.
        auto& result = query.result.emplace();
        for (const auto& request : query.buckets)
        {
          if (request.seqnos != nullptr)
          {
            append(result, *request.seqnos);
          }
        }

        append(result, query.current);
        query.buckets.clear();
        query.current.clear();
      }

      return query.result;
    }

    size_t max_requestable_range() const
    {
      return ((max_buckets - 1) * seqnos_per_bucket);
    }
  };

  void SeqnosByKey_Bucketed_Untyped::tick()
  {
    ccf::ds::MutexGuard guard(impl->results_access);
    if (impl->rebuild_requested)
    {
      // The indexer serializes ticks with transaction delivery and watermark
      // publication, so no in-flight transaction can undo this reset.
      ccf::ds::MutexGuard current_txid_guard(current_txid_lock);
      current_txid = {};
      impl->old_results.clear();
      impl->directory_pages.clear();
      impl->queries.clear();
      impl->current_results.clear();
      impl->rebuild_requested = false;
    }
  }

  void SeqnosByKey_Bucketed_Untyped::visit_entry(
    const ccf::TxID& tx_id, const ccf::ByteVector& k, const ccf::ByteVector& v)
  {
    (void)v;
    const auto range = impl->get_range_for(tx_id.seqno);
    ccf::ds::MutexGuard guard(impl->results_access);
    auto it = impl->current_results.find(k);
    if (it == impl->current_results.end())
    {
      it = impl->current_results
             .emplace(k, Impl::CurrentResult{range, {}, 0, std::nullopt, {}})
             .first;
    }
    else if (it->second.range != range)
    {
      auto& head = it->second;
      impl->lfs_access->store(
        impl->get_blob_name({k, head.range}), Impl::serialise(head.seqnos));
      head.directory.push_back(head.range.first);
      if (head.directory.size() == Impl::DIRECTORY_PAGE_SIZE)
      {
        impl->lfs_access->store(
          impl->get_page_name({k, head.page_count}),
          Impl::serialise(head.directory));
        ++head.page_count;
        head.last_paged_bucket = head.directory.back();
        head.directory.clear();
      }

      head.range = range;
      head.seqnos.clear();
    }

    it->second.seqnos.insert(tx_id.seqno);
  }

  nlohmann::json SeqnosByKey_Bucketed_Untyped::describe()
  {
    auto j = VisitEachEntryInMap::describe();
    {
      ccf::ds::MutexGuard guard(impl->results_access);
      j["seqnos_per_bucket"] = impl->seqnos_per_bucket;
      j["old_results_max_size"] = impl->old_results.get_max_size();
      j["old_results_current_size"] = impl->old_results.size();
      j["current_results_size"] = impl->current_results.size();
      j["directory_page_size"] = Impl::DIRECTORY_PAGE_SIZE;
      j["directory_pages_current_size"] = impl->directory_pages.size();
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
    ccf::AbstractNodeContext& node_context,
    size_t seqnos_per_bucket_,
    size_t max_buckets_) :
    VisitEachEntryInMap(map_name_, "SeqnosByKey")
  {
    if (
      ccf::kv::get_security_domain(map_name_) !=
      ccf::kv::SecurityDomain::PUBLIC)
    {
      throw std::logic_error(fmt::format(
        "This Strategy ({}) is currently only implemented for public tables, "
        "so cannot be used for '{}'",
        get_name(),
        map_name_));
    }
    impl = std::make_shared<Impl>(
      get_name(),
      current_txid_lock,
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
