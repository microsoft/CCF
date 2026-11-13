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
    static constexpr size_t MANIFEST_PAGE_SIZE = 256;
    const size_t seqnos_per_bucket;
    const size_t max_buckets;

    // When both locks are needed, results_access must be acquired first.
    ccf::ds::Mutex results_access CCF_ACQUIRED_BEFORE(current_txid_lock);

    // Inclusive begin, exclusive end
    using Range = std::pair<ccf::SeqNo, ccf::SeqNo>;
    using ManifestPage = std::vector<ccf::SeqNo>;

    struct CurrentResult
    {
      Range range;
      SeqNoCollection seqnos;
      size_t page_count = 0;
      std::optional<ccf::SeqNo> last_paged_bucket = std::nullopt;
      ManifestPage manifest;
    };

    // These trusted heads must not be evicted: absence means never written.
    std::unordered_map<ccf::ByteVector, CurrentResult> current_results
      CCF_GUARDED_BY(results_access);

    using BucketKey = std::pair<ccf::ByteVector, Range>;
    using PageKey = std::pair<ccf::ByteVector, size_t>;
    using BucketValue = std::pair<FetchResultPtr, SeqNoCollection>;
    LRU<BucketKey, BucketValue> old_results CCF_GUARDED_BY(results_access);
    using PageValue = std::pair<FetchResultPtr, ManifestPage>;
    LRU<PageKey, PageValue> manifest_pages CCF_GUARDED_BY(results_access);

    struct ManifestSearch
    {
      size_t low = 0;
      size_t high = 0;
    };

    // Only metadata search bounds survive retries. Data reads and parsed
    // buckets live exclusively in old_results, as in the original strategy.
    LRU<BucketKey, ManifestSearch> manifest_searches
      CCF_GUARDED_BY(results_access);

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
      manifest_pages(max_buckets_),
      manifest_searches(max_buckets_),
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
        "{}: manifest {} ({} seqnos per bucket) for {}",
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

    const ManifestPage* load_page(
      const PageKey& key, ccf::SeqNo last_paged_bucket)
      CCF_REQUIRES(results_access)
    {
      auto cached = manifest_pages.find(key);
      if (cached == manifest_pages.end())
      {
        manifest_pages.insert(key, {lfs_access->fetch(get_page_name(key)), {}});
        return nullptr;
      }

      manifest_pages.promote(cached);
      auto& [fetch, contents] = cached->second;
      if (fetch == nullptr)
      {
        return &contents;
      }

      const auto status = fetch->fetch_result.load();
      if (status == FetchResult::FetchResultType::Fetching)
      {
        return nullptr;
      }

      std::optional<ManifestPage> page;
      if (status == FetchResult::FetchResultType::Loaded)
      {
        page = deserialise(fetch->contents, MANIFEST_PAGE_SIZE);
      }

      if (
        !page.has_value() || page->size() != MANIFEST_PAGE_SIZE ||
        page->back() > last_paged_bucket ||
        std::any_of(page->begin(), page->end(), [&](auto start) {
          return start % seqnos_per_bucket != 0;
        }))
      {
        LOG_FAIL_FMT(
          "Required manifest page unavailable: {}", get_page_name(key));
        rebuild();
        return nullptr;
      }

      contents = std::move(*page);
      fetch = nullptr;
      return &contents;
    }

    std::optional<bool> manifest_contains(
      const BucketKey& key, size_t page_count, ccf::SeqNo last_paged_bucket)
      CCF_REQUIRES(results_access)
    {
      auto it = manifest_searches.find(key);
      if (it == manifest_searches.end())
      {
        it = manifest_searches.insert(key, {0, page_count});
      }
      manifest_searches.promote(it);
      auto& search = it->second;
      const auto start = key.second.first;

      // Page ordinals are dense and bounded by a trusted count. Every page
      // consulted is required; an unavailable page cannot prove a gap.
      while (search.low < search.high)
      {
        const auto mid = search.low + (search.high - search.low) / 2;
        const auto* page = load_page({key.first, mid}, last_paged_bucket);
        if (page == nullptr)
        {
          return std::nullopt;
        }

        if (start > page->back())
        {
          search.low = mid + 1;
        }
        else if (start < page->front())
        {
          search.high = mid;
        }
        else
        {
          const auto found =
            std::binary_search(page->begin(), page->end(), start);
          manifest_searches.erase(key);
          return found;
        }
      }

      manifest_searches.erase(key);
      return false;
    }

    const SeqNoCollection* get_bucket(
      const BucketKey& key, const CurrentResult& head, bool required)
      CCF_REQUIRES(results_access)
    {
      auto it = old_results.find(key);
      if (it == old_results.end())
      {
        old_results.insert(key, {lfs_access->fetch(get_blob_name(key)), {}});
        return nullptr;
      }

      old_results.promote(it);
      auto& [fetch, seqnos] = it->second;
      if (fetch == nullptr)
      {
        return &seqnos;
      }

      const auto status = fetch->fetch_result.load();
      if (status == FetchResult::FetchResultType::Fetching)
      {
        return nullptr;
      }

      if (status == FetchResult::FetchResultType::Loaded)
      {
        const auto parsed = deserialise(fetch->contents, seqnos_per_bucket);
        if (
          parsed.has_value() && parsed->front() >= key.second.first &&
          parsed->back() < key.second.second)
        {
          for (auto seqno : *parsed)
          {
            seqnos.insert(seqno);
          }
          fetch = nullptr;
          return &seqnos;
        }
      }

      if (!required)
      {
        if (!head.last_paged_bucket.has_value())
        {
          LOG_FAIL_FMT(
            "Cannot prove absence of bucket without a sealed manifest: {}",
            get_blob_name(key));
          rebuild();
          return nullptr;
        }

        const auto present =
          manifest_contains(key, head.page_count, *head.last_paged_bucket);
        if (!present.has_value())
        {
          return nullptr;
        }
        required = *present;
      }

      if (required)
      {
        LOG_FAIL_FMT("Required bucket unavailable: {}", get_blob_name(key));
        rebuild();
        return nullptr;
      }

      // Only an authenticated manifest search can turn a failed speculative
      // fetch into a cached empty bucket.
      fetch = nullptr;
      return &seqnos;
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

      const auto head_it = current_results.find(serialised_key);
      if (
        head_it == current_results.end() ||
        head_it->second.range.second <= from)
      {
        return SeqNoCollection{};
      }

      const auto& head = head_it->second;
      SeqNoCollection result;
      auto append = [&](const SeqNoCollection& seqnos) {
        for (auto seqno : seqnos)
        {
          if (seqno >= from && seqno <= to)
          {
            result.insert(seqno);
          }
        }
      };

      bool complete = true;
      const auto last = std::min(to, head.range.first);
      for (auto range = get_range_for(from); range.first <= last;
           range = get_range_for(range.second))
      {
        if (range == head.range)
        {
          if (complete)
          {
            append(head.seqnos);
          }
          break;
        }

        const auto required = std::binary_search(
          head.manifest.begin(), head.manifest.end(), range.first);
        if (
          !required &&
          (!head.last_paged_bucket.has_value() ||
           range.first > *head.last_paged_bucket))
        {
          continue;
        }

        const auto* seqnos =
          get_bucket({serialised_key, range}, head, required);
        if (rebuild_requested)
        {
          return std::nullopt;
        }
        if (seqnos == nullptr)
        {
          complete = false;
        }
        else if (complete)
        {
          append(*seqnos);
        }
      }

      if (!complete)
      {
        return std::nullopt;
      }
      return result;
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
      impl->manifest_pages.clear();
      impl->manifest_searches.clear();
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
      head.manifest.push_back(head.range.first);
      if (head.manifest.size() == Impl::MANIFEST_PAGE_SIZE)
      {
        impl->lfs_access->store(
          impl->get_page_name({k, head.page_count}),
          Impl::serialise(head.manifest));
        ++head.page_count;
        head.last_paged_bucket = head.manifest.back();
        head.manifest.clear();
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
      j["manifest_page_size"] = Impl::MANIFEST_PAGE_SIZE;
      j["manifest_pages_current_size"] = impl->manifest_pages.size();
      j["manifest_searches_current_size"] = impl->manifest_searches.size();
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
