// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/indexing/strategies/seqnos_by_key_paged.h"

#include "ccf/crypto/entropy.h"
#include "ccf/crypto/sha256.h"
#include "ccf/ds/hex.h"
#include "ds/internal_logger.h"
#include "ds/serialized.h"
#include "indexing/lfs_interface.h"
#include "kv/store.h"

#include <algorithm>
#include <limits>
#include <list>
#include <map>
#include <unordered_map>

namespace ccf::indexing::strategies
{
  struct SeqnosByKey_Paged_Untyped::Impl
  {
    using Entry = std::pair<ccf::ByteVector, ccf::SeqNo>;

    struct Ref
    {
      uint64_t id = 0;
      ccf::crypto::HashBytes hash;
    };

    struct Page
    {
      bool leaf = true;
      // Internal entries are the inclusive lower bounds of their children.
      std::vector<Entry> entries;
      std::vector<Ref> children;
    };

    struct Frame
    {
      Ref ref;
      std::shared_ptr<const Page> page;
      size_t child;
    };

    struct CachedPage
    {
      uint64_t id;
      std::shared_ptr<const Page> page;
      size_t charge;
      Entry lower;
      ccf::SeqNo upper = 0;
      SeqNoCollection result;
    };

    struct Query
    {
      Entry lower;
      Entry upper;
      std::vector<Ref> todo;
      SeqNoCollection result;
      bool complete = false;
      bool cancelled = false;
    };

    ccf::ds::Mutex mutex;
    const std::string map_name;
    const std::string prefix;
    const size_t page_bytes;
    const size_t cache_limit;
    std::shared_ptr<AbstractLFSAccess> lfs;
    Ref root;
    uint64_t next_id = 1;
    ccf::TxID watermark = {};
    bool pending_transaction = false;
    ccf::TxID pending_tx = {};
    std::vector<ccf::ByteVector> keys;
    size_t key_heap = 0;
    size_t key_index = 0;
    size_t key_visits = 0;
    size_t key_buffer_peak = 0;
    size_t page_decodes = 0;
    size_t cache_hits = 0;
    std::optional<Entry> inserting;
    std::vector<Frame> path;
    Ref descending;
    LFSBatchResult writing;
    FetchResultPtr fetching;
    Ref fetching_ref;
    std::list<CachedPage> cache;
    std::unordered_map<ccf::ByteVector, SeqNoCollection> recent;
    size_t recent_memory = 0;
    ccf::SeqNo recent_from = 0;
    std::map<uint64_t, std::shared_ptr<Page>> dirty;
    std::vector<uint64_t> obsolete;
    size_t dirty_memory = 0;
    size_t obsolete_bytes = 0;
    size_t working_peak = 0;
    bool flush_requested = false;
    size_t cache_size = 0;
    size_t cache_peak = 0;
    size_t live_pages = 0;
    size_t live_bytes = 0;
    size_t height = 0;
    size_t path_peak = 0;
    bool failed = false;
    std::optional<Query> query;
    static constexpr size_t MAX_HEIGHT = 64;
    static constexpr size_t WORK_QUOTA = 128;

    Impl(
      const std::string& map,
      ccf::AbstractNodeContext& context,
      size_t page_size,
      size_t cache_size_) :
      map_name(map),
      prefix(
        "paged-" + ccf::ds::to_hex(ccf::crypto::get_entropy()->random(16)) +
        "-"),
      page_bytes(page_size),
      cache_limit(cache_size_),
      lfs(context.get_subsystem<AbstractLFSAccess>())
    {
      if (ccf::kv::get_security_domain(map) != ccf::kv::SecurityDomain::PUBLIC)
        throw std::invalid_argument("Paged indexing requires a public table");
      if (!lfs)
        throw std::invalid_argument("Paged indexing requires LFS");
      if (page_bytes < 512 || page_bytes > 1024 * 1024)
        throw std::invalid_argument(
          "Paged page_bytes must be in [512, 1048576]");
      if (cache_limit >= 512)
      {
        recent.reserve(recent_limit() / recent_node_cost());
        recent_memory = recent.bucket_count() * sizeof(void*);
        cache_size = cache_peak = recent_memory;
      }
    }

    LFSKey name(const Ref& ref) const
    {
      return prefix + std::to_string(ref.id);
    }

    static size_t entry_size(const Entry& e, bool leaf)
    {
      return sizeof(uint64_t) * 2 + e.first.size() + (leaf ? 0 : 40);
    }

    static size_t bytes(const Page& page)
    {
      size_t n = 1 + sizeof(uint64_t);
      for (const auto& e : page.entries)
        n += entry_size(e, page.leaf);
      return n;
    }

    static size_t key_memory(const ccf::ByteVector& key)
    {
      return key.capacity() > ccf::ByteVector{}.capacity() ? key.capacity() : 0;
    }

    static size_t page_memory(const Page& page)
    {
      size_t n = sizeof(Page) + 2 * sizeof(void*) +
        page.entries.capacity() * sizeof(Entry) +
        page.children.capacity() * sizeof(Ref);
      for (const auto& e : page.entries)
        n += key_memory(e.first);
      for (const auto& ref : page.children)
        n += ref.hash.capacity();
      return n;
    }

    static size_t dirty_cost(const Page& page)
    {
      return page_memory(page) + sizeof(decltype(dirty)::value_type) +
        4 * sizeof(void*);
    }

    size_t working_limit() const
    {
      return std::max(cache_limit, page_bytes * 8);
    }

    size_t working_bytes() const
    {
      return dirty_memory + obsolete.capacity() * sizeof(uint64_t);
    }

    size_t recent_limit() const
    {
      return cache_limit >= 512 ? cache_limit / 2 : 0;
    }

    static size_t recent_node_cost()
    {
      return sizeof(decltype(recent)::value_type) + 2 * sizeof(void*);
    }

    static size_t result_memory(const SeqNoCollection& result)
    {
      return result.get_ranges().capacity() * sizeof(SeqNoCollection::Range);
    }

    static SeqNoCollection slice(
      const SeqNoCollection& source, ccf::SeqNo from, ccf::SeqNo to)
    {
      const auto& ranges = source.get_ranges();
      const auto begin = std::lower_bound(
        ranges.begin(), ranges.end(), from, [](const auto& range, auto n) {
          return range.first + range.second < n;
        });
      const auto end = std::upper_bound(
        ranges.begin(), ranges.end(), to, [](auto n, const auto& range) {
          return n < range.first;
        });
      if (begin == end)
        return {};
      auto last = std::prev(end);
      const auto offset =
        to >= last->first + last->second ? 0 : to - last->first + 1;
      return SeqNoCollection(
        SeqNoCollection::ConstIterator(
          begin, from > begin->first ? from - begin->first : 0),
        SeqNoCollection::ConstIterator(offset == 0 ? end : last, offset));
    }

    bool reserve_cache(size_t charge)
    {
      if (charge > cache_limit - recent_memory)
        return false;
      while (cache_size > cache_limit - charge)
      {
        cache_size -= cache.back().charge;
        cache.pop_back();
      }
      return true;
    }

    void record_recent(const Entry& entry)
    {
      if (recent_limit() == 0 || entry.second < recent_from)
        return;
      while (true)
      {
        auto it = recent.find(entry.first);
        auto candidate = it == recent.end() ? SeqNoCollection{} : it->second;
        candidate.insert(entry.second);
        const auto old_charge =
          it == recent.end() ? 0 : result_memory(it->second);
        const auto replacement = result_memory(candidate) +
          (it == recent.end() ? recent_node_cost() + key_memory(entry.first) :
                                0);
        const auto new_memory = recent_memory - old_charge + replacement;
        if (new_memory <= recent_limit())
        {
          if (
            replacement > old_charge &&
            !reserve_cache(replacement - old_charge))
            throw std::logic_error("Invalid recent-cache accounting");
          if (it == recent.end())
            recent.emplace(entry.first, std::move(candidate));
          else
            it->second = std::move(candidate);
          recent_memory = new_memory;
          cache_size = cache_size - old_charge + replacement;
          cache_peak = std::max(cache_peak, cache_size);
          return;
        }
        // Evict a complete sequence prefix, not individual keys. This keeps
        // empty answers trustworthy for every key in the retained interval.
        recent_from += (entry.second - recent_from) / 2 + 1;
        for (auto pos = recent.begin(); pos != recent.end();)
        {
          auto kept = slice(pos->second, recent_from, entry.second);
          const auto old = result_memory(pos->second);
          if (kept.empty())
          {
            const auto released =
              old + recent_node_cost() + key_memory(pos->first);
            recent_memory -= released;
            cache_size -= released;
            pos = recent.erase(pos);
          }
          else
          {
            const auto replacement_size = result_memory(kept);
            if (
              replacement_size > old && !reserve_cache(replacement_size - old))
              throw std::logic_error("Invalid recent-cache trimming");
            recent_memory = recent_memory - old + replacement_size;
            cache_size = cache_size - old + replacement_size;
            pos->second = std::move(kept);
            ++pos;
          }
          cache_peak = std::max(cache_peak, cache_size);
        }
        if (entry.second < recent_from)
          return;
      }
    }

    void remember(uint64_t id, const std::shared_ptr<const Page>& page)
    {
      const auto charge =
        page_memory(*page) + sizeof(CachedPage) + 2 * sizeof(void*);
      if (!reserve_cache(charge))
        return;
      cache.push_front({id, page, charge, {}, 0, {}});
      cache_size += charge;
      cache_peak = std::max(cache_peak, cache_size);
    }

    void remember_result(
      const Entry& lower, ccf::SeqNo upper, const SeqNoCollection& result)
    {
      const auto base =
        sizeof(CachedPage) + 2 * sizeof(void*) + key_memory(lower.first);
      if (
        base > cache_limit / 4 ||
        result_memory(result) > cache_limit / 4 - base)
        return;
      CachedPage entry{0, nullptr, 0, lower, upper, result};
      entry.charge = base + result_memory(entry.result);
      if (!reserve_cache(entry.charge))
        return;
      cache_size += entry.charge;
      cache.push_front(std::move(entry));
      cache_peak = std::max(cache_peak, cache_size);
    }

    size_t path_memory() const
    {
      size_t n = path.capacity() * sizeof(Frame);
      for (const auto& frame : path)
      {
        n += frame.ref.hash.capacity() + page_memory(*frame.page);
      }
      return n;
    }

    LFSContents encode(const Page& page)
    {
      LFSContents blob(bytes(page));
      auto* data = blob.data();
      auto size = blob.size();
      serialized::write<uint8_t>(data, size, page.leaf ? 1 : 0);
      serialized::write<uint64_t>(data, size, page.entries.size());
      for (size_t i = 0; i < page.entries.size(); ++i)
      {
        const auto& [key, seqno] = page.entries[i];
        serialized::write<uint64_t>(data, size, key.size());
        serialized::write(data, size, key.data(), key.size());
        serialized::write<uint64_t>(data, size, seqno);
        if (!page.leaf)
        {
          serialized::write<uint64_t>(data, size, page.children[i].id);
          serialized::write(data, size, page.children[i].hash.data(), 32);
        }
      }
      return blob;
    }

    // Only decode after checking against a trusted root/parent hash. Every
    // authenticated byte string was produced by encode in this instance.
    static Page decode(const LFSContents& blob)
    {
      const auto* data = blob.data();
      auto size = blob.size();
      Page page;
      page.leaf = serialized::read<uint8_t>(data, size) != 0;
      auto count = serialized::read<uint64_t>(data, size);
      page.entries.reserve(count);
      if (!page.leaf)
        page.children.reserve(count);
      for (uint64_t i = 0; i < count; ++i)
      {
        auto n = serialized::read<uint64_t>(data, size);
        if (n > size)
          throw std::logic_error("Invalid authenticated paged key length");
        ccf::ByteVector key(data, data + n);
        serialized::skip(data, size, n);
        auto seqno = serialized::read<uint64_t>(data, size);
        page.entries.emplace_back(std::move(key), seqno);
        if (!page.leaf)
        {
          auto id = serialized::read<uint64_t>(data, size);
          auto hash = serialized::read(data, size, 32);
          page.children.push_back({id, std::move(hash)});
        }
      }
      if (size != 0)
        throw std::logic_error("Invalid authenticated paged encoding");
      return page;
    }

    void fail(const std::string& reason)
    {
      LOG_FAIL_FMT("Paged index {} unavailable: {}", map_name, reason);
      failed = true;
      fetching.reset();
      query.reset();
      pending_transaction = false;
      std::vector<ccf::ByteVector>{}.swap(keys);
      key_heap = 0;
      key_index = 0;
      inserting.reset();
      path.clear();
      writing.reset();
    }

    std::shared_ptr<const Page> load(const Ref& ref)
    {
      if (auto it = dirty.find(ref.id); it != dirty.end())
        return it->second;
      for (auto it = cache.begin(); it != cache.end(); ++it)
      {
        if (it->page && it->id == ref.id)
        {
          cache.splice(cache.begin(), cache, it);
          ++cache_hits;
          return cache.front().page;
        }
      }
      if (!fetching)
      {
        fetching_ref = ref;
        fetching = lfs->fetch(name(ref), page_bytes);
      }
      if (fetching_ref.id != ref.id)
        throw std::logic_error("Overlapping paged fetches");
      const auto status = fetching->fetch_result.load();
      if (status == FetchResult::FetchResultType::Fetching)
        return nullptr;
      if (
        status != FetchResult::FetchResultType::Loaded ||
        fetching->contents.size() > page_bytes ||
        ccf::crypto::sha256(fetching->contents) != ref.hash)
      {
        fail("missing or invalid page " + name(ref));
        return nullptr;
      }
      // LFS may coalesce callers onto the same immutable fetch result, even
      // briefly after publishing Loaded. Do not consume its shared contents.
      auto page = std::make_shared<Page>(decode(fetching->contents));
      ++page_decodes;
      fetching.reset();
      remember(ref.id, page);
      return page;
    }

    Ref save(Page&& page)
    {
      if (bytes(page) > page_bytes)
        throw std::logic_error("Oversized paged page");
      if (next_id == std::numeric_limits<uint64_t>::max())
        throw std::overflow_error("Paged page IDs exhausted");
      Ref ref{next_id++, ccf::crypto::HashBytes(32)};
      live_bytes += bytes(page);
      ++live_pages;
      auto stored = std::make_shared<Page>(std::move(page));
      dirty_memory += dirty_cost(*stored);
      dirty.emplace(ref.id, std::move(stored));
      working_peak = std::max(working_peak, working_bytes());
      return ref;
    }

    std::vector<std::pair<Entry, Ref>> split(Page page)
    {
      if (bytes(page) <= page_bytes)
      {
        auto lower = page.entries.front();
        return {{std::move(lower), save(std::move(page))}};
      }
      size_t mid = 0;
      size_t left_bytes = 9;
      const auto target = bytes(page) / 2;
      while (mid + 1 < page.entries.size() && left_bytes < target)
        left_bytes += entry_size(page.entries[mid++], page.leaf);
      Page right;
      right.leaf = page.leaf;
      right.entries.assign(page.entries.begin() + mid, page.entries.end());
      page.entries.resize(mid);
      if (!page.leaf)
      {
        right.children.assign(page.children.begin() + mid, page.children.end());
        page.children.resize(mid);
      }
      auto left_lower = page.entries.front();
      auto right_lower = right.entries.front();
      return {
        {std::move(left_lower), save(std::move(page))},
        {std::move(right_lower), save(std::move(right))}};
    }

    void rewrite(Page leaf, const Ref& old_leaf)
    {
      auto retire = [&](const Ref& ref, const Page& page) {
        if (ref.id != 0)
        {
          --live_pages;
          live_bytes -= bytes(page);
          if (auto it = dirty.find(ref.id); it != dirty.end())
          {
            dirty_memory -= dirty_cost(*it->second);
            dirty.erase(it);
          }
          else
          {
            obsolete.push_back(ref.id);
            obsolete_bytes += bytes(page);
          }
          for (auto it = cache.begin(); it != cache.end();)
          {
            if (it->id == ref.id)
            {
              cache_size -= it->charge;
              it = cache.erase(it);
            }
            else
              ++it;
          }
        }
      };
      retire(old_leaf, leaf);
      auto pos =
        std::lower_bound(leaf.entries.begin(), leaf.entries.end(), *inserting);
      leaf.entries.insert(pos, *inserting);
      auto replacements = split(std::move(leaf));
      while (!path.empty())
      {
        auto frame = std::move(path.back());
        path.pop_back();
        retire(frame.ref, *frame.page);
        auto page = *frame.page;
        page.entries.erase(page.entries.begin() + frame.child);
        page.children.erase(page.children.begin() + frame.child);
        for (size_t i = 0; i < replacements.size(); ++i)
        {
          page.entries.insert(
            page.entries.begin() + frame.child + i, replacements[i].first);
          page.children.insert(
            page.children.begin() + frame.child + i, replacements[i].second);
        }
        replacements = split(std::move(page));
      }
      if (replacements.size() == 1)
        root = replacements.front().second;
      else
      {
        if (height == MAX_HEIGHT)
          throw std::length_error("Paged tree maximum height reached");
        Page parent;
        parent.leaf = false;
        for (const auto& [entry, ref] : replacements)
        {
          parent.entries.push_back(entry);
          parent.children.push_back(ref);
        }
        root = save(std::move(parent));
        ++height;
      }
      if (height == 0)
        height = 1;
      working_peak = std::max(working_peak, working_bytes());
      record_recent(*inserting);
      inserting.reset();
      ++key_index;
    }

    void seal(Ref& ref, LFSWrites& writes)
    {
      auto it = dirty.find(ref.id);
      if (it == dirty.end())
        return;
      auto& page = *it->second;
      for (auto& child : page.children)
        seal(child, writes);
      auto blob = encode(page);
      ref.hash = ccf::crypto::sha256(blob);
      writes.emplace_back(name(ref), std::move(blob));
    }

    void checkpoint()
    {
      if (dirty.empty())
      {
        flush_requested = false;
        return;
      }
      LFSWrites writes;
      seal(root, writes);
      if (writes.size() != dirty.size())
        throw std::logic_error("Unreachable dirty paged pages");
      std::vector<LFSKey> removals;
      for (auto id : obsolete)
        removals.push_back(name(Ref{id, {}}));
      writing = lfs->apply_batch(std::move(writes), std::move(removals));
    }

    bool next_entry()
    {
      if (key_index == keys.size())
      {
        watermark = pending_tx;
        pending_transaction = false;
        std::vector<ccf::ByteVector>{}.swap(keys);
        key_heap = 0;
        key_index = 0;
        return false;
      }
      key_heap -= key_memory(keys[key_index]);
      inserting = Entry{std::move(keys[key_index]), pending_tx.seqno};
      descending = root;
      return true;
    }

    void update()
    {
      if (failed || (query && !query->complete))
        return;
      if (writing)
      {
        const auto status = writing->load();
        if (status == LFSBatchStatus::Pending)
          return;
        if (status == LFSBatchStatus::Failed)
        {
          fail("page write/reclamation failed");
          return;
        }
        for (const auto& [id, page] : dirty)
          remember(id, page);
        dirty.clear();
        dirty_memory = 0;
        obsolete.clear();
        obsolete_bytes = 0;
        writing.reset();
        flush_requested = false;
      }
      for (size_t work = 0; work < WORK_QUOTA; ++work)
      {
        if (
          !inserting &&
          (flush_requested ||
           working_bytes() + obsolete_bytes >= working_limit()))
        {
          checkpoint();
          if (writing)
            return;
        }
        if (!pending_transaction)
          return;
        if (!inserting && !next_entry())
          return;
        if (descending.id == 0)
        {
          rewrite(Page{}, descending);
          continue;
        }
        auto page = load(descending);
        if (!page)
          return;
        if (page->leaf)
        {
          rewrite(*page, descending);
          continue;
        }
        const auto upper = std::upper_bound(
          page->entries.begin(), page->entries.end(), *inserting);
        const size_t child = upper == page->entries.begin() ?
          0 :
          std::distance(page->entries.begin(), upper) - 1;
        auto next = page->children[child];
        path.push_back({descending, std::move(page), child});
        path_peak = std::max(path_peak, path_memory());
        descending = std::move(next);
      }
    }

    void scan()
    {
      if (!query || failed)
        return;
      if (query->cancelled)
      {
        // Do not abandon an outstanding fetch and allow repeated cancellation
        // to build an unbounded queue of orphaned fetch results.
        if (
          fetching &&
          fetching->fetch_result == FetchResult::FetchResultType::Fetching)
          return;
        fetching.reset();
        query.reset();
        return;
      }
      if (query->complete)
        return;
      if (query->todo.empty())
      {
        query->complete = true;
        return;
      }
      for (size_t work = 0; work < WORK_QUOTA; ++work)
      {
        if (query->todo.empty())
        {
          query->complete = true;
          return;
        }
        auto page = load(query->todo.back());
        if (!page)
          return;
        query->todo.pop_back();
        if (page->leaf)
        {
          auto it = std::lower_bound(
            page->entries.begin(), page->entries.end(), query->lower);
          while (it != page->entries.end() && *it <= query->upper)
            query->result.insert((it++)->second);
        }
        else
        {
          auto first = std::upper_bound(
            page->entries.begin(), page->entries.end(), query->lower);
          const size_t begin = first == page->entries.begin() ?
            0 :
            std::distance(page->entries.begin(), first) - 1;
          const auto end = std::upper_bound(
            page->entries.begin(), page->entries.end(), query->upper);
          for (size_t i = std::distance(page->entries.begin(), end);
               i-- > begin;)
            query->todo.push_back(page->children[i]);
        }
      }
      if (query->todo.empty())
        query->complete = true;
    }
  };

  SeqnosByKey_Paged_Untyped::SeqnosByKey_Paged_Untyped(
    const std::string& map_name,
    ccf::AbstractNodeContext& context,
    size_t page_bytes,
    size_t cache_bytes) :
    Strategy("SeqnosByKey_Paged " + map_name),
    impl(std::make_unique<Impl>(map_name, context, page_bytes, cache_bytes))
  {}

  SeqnosByKey_Paged_Untyped::~SeqnosByKey_Paged_Untyped() = default;

  void SeqnosByKey_Paged_Untyped::handle_committed_transaction(
    const ccf::TxID& tx_id, const ccf::kv::ReadOnlyStorePtr& store)
  {
    std::lock_guard<ccf::ds::Mutex> guard(impl->mutex);
    if (
      impl->pending_transaction || impl->writing ||
      tx_id.seqno != impl->watermark.seqno + 1)
      throw std::logic_error("Out-of-order paged transaction");
    std::vector<ccf::ByteVector> keys;
    size_t key_heap = 0;
    auto tx = store->create_read_only_tx();
    tx.ro<ccf::kv::untyped::Map>(impl->map_name)
      ->foreach([&](const auto& key, const auto&) {
        ++impl->key_visits;
        if (key.size() > (impl->page_bytes - 9) / 4 - 56)
        {
          impl->fail("index key too large for configured page_bytes");
          return false;
        }
        keys.push_back(key);
        key_heap += Impl::key_memory(keys.back());
        return true;
      });
    if (impl->failed)
      return;
    std::sort(keys.begin(), keys.end());
    impl->key_buffer_peak = std::max(
      impl->key_buffer_peak,
      keys.capacity() * sizeof(ccf::ByteVector) + key_heap);
    impl->keys = std::move(keys);
    impl->key_heap = key_heap;
    impl->pending_tx = tx_id;
    impl->pending_transaction = true;
    impl->update();
  }

  void SeqnosByKey_Paged_Untyped::tick()
  {
    std::lock_guard<ccf::ds::Mutex> guard(impl->mutex);
    impl->scan();
    impl->update();
  }

  std::optional<ccf::SeqNo> SeqnosByKey_Paged_Untyped::next_requested()
  {
    std::lock_guard<ccf::ds::Mutex> guard(impl->mutex);
    if (impl->pending_transaction || impl->writing || impl->failed)
      return std::nullopt;
    return impl->watermark.seqno + 1;
  }

  ccf::TxID SeqnosByKey_Paged_Untyped::get_indexed_watermark()
  {
    std::lock_guard<ccf::ds::Mutex> guard(impl->mutex);
    return impl->watermark;
  }

  void SeqnosByKey_Paged_Untyped::cancel_query()
  {
    std::lock_guard<ccf::ds::Mutex> guard(impl->mutex);
    if (impl->query)
    {
      impl->query->cancelled = true;
      impl->scan();
    }
  }

  void SeqnosByKey_Paged_Untyped::flush()
  {
    std::lock_guard<ccf::ds::Mutex> guard(impl->mutex);
    impl->flush_requested = true;
    impl->update();
  }

  std::optional<SeqNoCollection> SeqnosByKey_Paged_Untyped::get_write_txs_impl(
    const ccf::ByteVector& key, ccf::SeqNo from, ccf::SeqNo to)
  {
    if (from > to)
      throw std::invalid_argument("Inverted paged query range");
    std::lock_guard<ccf::ds::Mutex> guard(impl->mutex);
    if (impl->writing && impl->writing->load() == LFSBatchStatus::Failed)
      impl->fail("page write/reclamation failed");
    if (impl->failed || to > impl->watermark.seqno)
      return std::nullopt;
    if (impl->recent_limit() != 0 && from >= impl->recent_from)
    {
      const auto it = impl->recent.find(key);
      return it == impl->recent.end() ? SeqNoCollection{} :
                                        Impl::slice(it->second, from, to);
    }
    Impl::Entry lower{key, from};
    Impl::Entry upper{key, to};
    for (auto it = impl->cache.begin(); it != impl->cache.end(); ++it)
    {
      if (!it->page && it->lower == lower && it->upper == to)
      {
        impl->cache.splice(impl->cache.begin(), impl->cache, it);
        return impl->cache.front().result;
      }
    }
    if (impl->writing)
      return std::nullopt;
    if (
      impl->query &&
      (impl->query->cancelled || impl->query->lower != lower ||
       impl->query->upper != upper))
      return std::nullopt;
    if (!impl->query)
    {
      if (impl->pending_transaction)
        return std::nullopt;
      impl->query = Impl::Query{};
      impl->query->lower = std::move(lower);
      impl->query->upper = std::move(upper);
      if (impl->root.id)
        impl->query->todo.push_back(impl->root);
    }
    impl->scan();
    if (!impl->query || !impl->query->complete)
      return std::nullopt;
    auto result = std::move(impl->query->result);
    impl->remember_result(impl->query->lower, to, result);
    impl->query.reset();
    return result;
  }

  nlohmann::json SeqnosByKey_Paged_Untyped::describe()
  {
    auto j = Strategy::describe();
    std::lock_guard<ccf::ds::Mutex> guard(impl->mutex);
    j["indexed_watermark"] = impl->watermark;
    j["page_bytes"] = impl->page_bytes;
    j["cache_bytes"] = impl->cache_size;
    j["cache_peak_bytes"] = impl->cache_peak;
    j["cache_limit_bytes"] = impl->cache_limit;
    j["live_pages"] = impl->live_pages;
    j["live_page_bytes"] = impl->live_bytes;
    j["height"] = impl->height;
    j["pending_transaction"] = impl->pending_transaction;
    j["pending_write_batch"] = impl->writing != nullptr;
    j["update_path_pages"] = impl->path.size();
    j["update_path_peak_bytes"] = impl->path_peak;
    j["dirty_pages"] = impl->dirty.size();
    j["working_set_bytes"] = impl->working_bytes();
    j["working_set_peak_bytes"] = impl->working_peak;
    j["working_set_limit_bytes"] = impl->working_limit();
    j["obsolete_pages"] = impl->obsolete.size();
    j["obsolete_page_bytes"] = impl->obsolete_bytes;
    j["key_visits"] = impl->key_visits;
    j["pending_key_buffer_bytes"] =
      impl->keys.capacity() * sizeof(ccf::ByteVector) + impl->key_heap;
    j["key_buffer_peak_bytes"] = impl->key_buffer_peak;
    j["page_decodes"] = impl->page_decodes;
    j["cache_hits"] = impl->cache_hits;
    j["recent_from"] = impl->recent_from;
    j["recent_cache_bytes"] = impl->recent_memory;
    j["recent_keys"] = impl->recent.size();
    j["query_active"] = impl->query.has_value();
    j["failed"] = impl->failed;
    return j;
  }
}
