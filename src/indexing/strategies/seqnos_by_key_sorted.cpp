// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/indexing/strategies/seqnos_by_key_sorted.h"

#include "ccf/crypto/entropy.h"
#include "ccf/ds/hex.h"
#include "ds/internal_logger.h"
#include "ds/lru.h"
#include "ds/serialized.h"
#include "indexing/lfs_interface.h"
#include "kv/store.h"

#include <algorithm>
#include <array>
#include <deque>
#include <limits>
#include <set>

namespace ccf::indexing::strategies
{
  namespace
  {
    using Entry = std::pair<ccf::ByteVector, ccf::SeqNo>;
    using Entries = std::vector<Entry>;
    using Buffer = std::set<Entry>;
    using State = FetchResult::FetchResultType;

    size_t decoded_entry_bytes(const Entry& e)
    {
      return sizeof(Entry) + e.first.size();
    }

    size_t encoded_entry_bytes(
      const Entry& entry, const ccf::ByteVector* previous_key)
    {
      return sizeof(ccf::SeqNo) +
        (previous_key && *previous_key == entry.first ?
           0 :
           2 * sizeof(uint64_t) + entry.first.size());
    }

    LFSContents encode(const Entries& entries)
    {
      size_t bytes = sizeof(uint64_t);
      const ccf::ByteVector* previous_key = nullptr;
      for (const auto& e : entries)
      {
        bytes += encoded_entry_bytes(e, previous_key);
        previous_key = &e.first;
      }
      LFSContents result(bytes);
      auto* data = result.data();
      auto remaining = result.size();
      serialized::write(data, remaining, uint64_t(entries.size()));
      for (size_t first = 0; first < entries.size();)
      {
        const auto& key = entries[first].first;
        auto end = first + 1;
        while (end < entries.size() && entries[end].first == key)
        {
          ++end;
        }
        serialized::write(data, remaining, uint64_t(key.size()));
        serialized::write(data, remaining, key.data(), key.size());
        serialized::write(data, remaining, uint64_t(end - first));
        for (auto i = first; i < end; ++i)
        {
          serialized::write(data, remaining, entries[i].second);
        }
        first = end;
      }
      return result;
    }

    Entries decode(const LFSContents& contents, size_t decoded_limit)
    {
      const auto* data = contents.data();
      auto remaining = contents.size();
      const auto count = serialized::read<uint64_t>(data, remaining);
      if (
        count == 0 || count > remaining / sizeof(ccf::SeqNo) ||
        count > decoded_limit / sizeof(Entry))
      {
        throw std::invalid_argument("Invalid sorted block entry count");
      }
      Entries result;
      result.reserve(count);
      size_t decoded_bytes = count * sizeof(Entry);
      while (result.size() < count)
      {
        const auto length = serialized::read<uint64_t>(data, remaining);
        if (
          remaining < sizeof(uint64_t) || length > remaining - sizeof(uint64_t))
        {
          throw std::invalid_argument("Invalid sorted block key length");
        }
        const auto* key = data;
        serialized::skip(data, remaining, length);
        const auto group_count = serialized::read<uint64_t>(data, remaining);
        if (
          group_count == 0 || group_count > count - result.size() ||
          group_count > remaining / sizeof(ccf::SeqNo))
        {
          throw std::invalid_argument("Invalid sorted block group count");
        }
        if (
          length != 0 && group_count > (decoded_limit - decoded_bytes) / length)
        {
          throw std::invalid_argument("Sorted block exceeds decoded budget");
        }
        decoded_bytes += group_count * length;
        for (size_t i = 0; i < group_count; ++i)
        {
          const auto seqno = serialized::read<ccf::SeqNo>(data, remaining);
          result.emplace_back(ccf::ByteVector(key, key + length), seqno);
          if (result.size() > 1 && result.back() < result[result.size() - 2])
          {
            throw std::invalid_argument("Unsorted index block");
          }
        }
      }
      if (remaining != 0)
      {
        throw std::invalid_argument("Trailing index block data");
      }
      return result;
    }
  }

  struct SeqnosByKey_Sorted_Untyped::Impl
  {
    const SortedIndexOptions options;
    const std::shared_ptr<AbstractLFSAccess> storage;
    const std::string prefix =
      ds::to_hex(ccf::crypto::get_entropy()->random(16));
    uint64_t next_id = 0;
    ccf::ds::Mutex lock;
    bool rebuild = false;
    bool oversized_key = false;
    size_t compactions = 0;
    size_t blocks_written = 0;
    size_t query_block_decodes = 0;

    struct Run
    {
      uint64_t id;
      size_t blocks = 0;
      ccf::SeqNo from = std::numeric_limits<ccf::SeqNo>::max();
      ccf::SeqNo to = 0;
    };

    using RunPtr = std::shared_ptr<Run>;
    // Binary carry compaction: one run at each level, not one record per key
    // or an ever-growing list of runs. No on-disk manifest is authoritative.
    std::array<RunPtr, 64> levels{};
    RunPtr carry;
    size_t carry_level = 0;

    Buffer buffer;
    size_t buffer_bytes = 0;

    struct Block
    {
      FetchResultPtr pending;
      Entries entries;
      size_t offset = 0;
      size_t ordinal = std::numeric_limits<size_t>::max();
    };

    struct Reader
    {
      RunPtr run;
      size_t next = 0;
      Block block;
    };

    struct Work
    {
      RunPtr output;
      bool flushing = false;
      Buffer::const_iterator flush_at;
      Reader a;
      Reader b;
      Entries entries;
      size_t bytes = sizeof(uint64_t);
      size_t decoded_bytes = 0;
    };

    std::optional<Work> work;

    struct Retired
    {
      RunPtr run;
      size_t next = 0;
    };

    std::deque<Retired> retired;

    struct CachedBlock
    {
      FetchResultPtr pending;
      Entries entries;
    };

    // Reserve room for the encoded input and worst-case decoded entry storage.
    // Decoding releases the encoded input rather than retaining both copies.
    static constexpr size_t CACHE_EXPANSION =
      1 + (sizeof(Entry) + sizeof(ccf::SeqNo) - 1) / sizeof(ccf::SeqNo);
    using BlockKey = std::pair<uint64_t, size_t>;
    LRU<BlockKey, CachedBlock> cache;

    Impl(
      const SortedIndexOptions& opts,
      const std::shared_ptr<AbstractLFSAccess>& access) :
      options(opts),
      storage(access),
      cache(
        opts.block_bytes == 0 ?
          0 :
          opts.query_cache_bytes / opts.block_bytes / CACHE_EXPANSION)
    {
      if (
        !storage || opts.block_bytes < 32 ||
        opts.write_buffer_bytes < opts.block_bytes ||
        cache.get_max_size() == 0 || opts.entries_per_tick == 0)
      {
        throw std::invalid_argument("Invalid sorted index storage or budgets");
      }
    }

    LFSKey key(const Run& run, size_t ordinal) const
    {
      return fmt::format("sorted-v2:{}:{}:{}", prefix, run.id, ordinal);
    }

    size_t decoded_block_limit() const
    {
      return options.block_bytes * (CACHE_EXPANSION - 1);
    }

    RunPtr new_run()
    {
      if (next_id == std::numeric_limits<uint64_t>::max())
      {
        throw std::overflow_error("Index run identities exhausted");
      }
      return std::make_shared<Run>(Run{++next_id});
    }

    void fail(const char* reason)
    {
      LOG_FAIL_FMT("Sorted index unavailable, requesting rebuild: {}", reason);
      rebuild = true;
    }

    bool completed(const FetchResultPtr& result)
    {
      const auto state = result->fetch_result.load();
      if (state == State::Fetching)
      {
        return false;
      }
      if (state != State::Loaded)
      {
        fail("required block missing or corrupt");
        return false;
      }
      return true;
    }

    std::optional<Entries> parse(const LFSContents& contents)
    {
      try
      {
        if (contents.size() > options.block_bytes)
        {
          throw std::invalid_argument("Index block exceeds configured size");
        }
        return decode(contents, decoded_block_limit());
      }
      catch (const serialized::InsufficientSpaceException& e)
      {
        fail(e.what());
      }
      catch (const std::invalid_argument& e)
      {
        fail(e.what());
      }
      return std::nullopt;
    }

    bool load(Block& block, const Run& run, size_t ordinal)
    {
      if (block.ordinal == ordinal && !block.entries.empty())
      {
        return true;
      }
      if (!block.pending)
      {
        block.entries.clear();
        block.pending = storage->fetch(key(run, ordinal));
        return false;
      }
      if (!completed(block.pending))
      {
        return false;
      }
      auto entries = parse(block.pending->contents);
      if (!entries)
      {
        return false;
      }
      block.entries = std::move(*entries);
      block.pending.reset();
      block.ordinal = ordinal;
      block.offset = 0;
      return true;
    }

    bool ready(Reader& reader)
    {
      if (reader.block.offset < reader.block.entries.size())
      {
        return true;
      }
      if (reader.next == reader.run->blocks)
      {
        return true;
      }
      if (!load(reader.block, *reader.run, reader.next))
      {
        return false;
      }
      ++reader.next;
      return true;
    }

    static const Entry* peek(const Reader& reader)
    {
      if (reader.block.offset == reader.block.entries.size())
      {
        return nullptr;
      }
      return &reader.block.entries[reader.block.offset];
    }

    void flush()
    {
      work = Work{};
      work->output = new_run();
      work->flushing = true;
      work->flush_at = buffer.cbegin();
    }

    void advance_work()
    {
      auto& w = *work;
      bool exhausted = false;
      bool full = false;
      for (size_t n = 0; n < options.entries_per_tick; ++n)
      {
        const Entry* entry = nullptr;
        Reader* source = nullptr;
        if (w.flushing)
        {
          if (w.flush_at != buffer.cend())
          {
            entry = &*w.flush_at;
          }
        }
        else
        {
          if (!ready(w.a) || !ready(w.b))
          {
            return;
          }
          const auto* a = peek(w.a);
          const auto* b = peek(w.b);
          source = (a && (!b || *a < *b)) ? &w.a : &w.b;
          entry = peek(*source);
        }
        if (entry == nullptr)
        {
          exhausted = true;
          break;
        }
        const auto encoded_bytes = encoded_entry_bytes(
          *entry, w.entries.empty() ? nullptr : &w.entries.back().first);
        const auto decoded_bytes = decoded_entry_bytes(*entry);
        // Repeating a long key must not turn a small encoded block into an
        // unbounded decoded allocation.
        if (
          encoded_bytes > options.block_bytes - w.bytes ||
          decoded_bytes > decoded_block_limit() - w.decoded_bytes)
        {
          full = true;
          break;
        }
        w.entries.push_back(*entry);
        w.bytes += encoded_bytes;
        w.decoded_bytes += decoded_bytes;
        w.output->from = std::min(w.output->from, entry->second);
        w.output->to = std::max(w.output->to, entry->second);
        if (w.flushing)
        {
          ++w.flush_at;
        }
        else
        {
          ++source->block.offset;
        }
      }
      if (
        !w.entries.empty() &&
        (full || exhausted || w.bytes == options.block_bytes))
      {
        storage->store(key(*w.output, w.output->blocks), encode(w.entries));
        ++w.output->blocks;
        ++blocks_written;
        w.entries.clear();
        w.bytes = sizeof(uint64_t);
        w.decoded_bytes = 0;
        return;
      }
      if (!exhausted)
      {
        return;
      }
      if (w.flushing)
      {
        buffer.clear();
        buffer_bytes = 0;
        carry_level = 0;
      }
      else
      {
        retired.push_back({w.a.run, 0});
        retired.push_back({w.b.run, 0});
        levels[carry_level].reset();
        ++carry_level;
        ++compactions;
      }
      carry = w.output;
      work.reset();
    }

    void reclaim()
    {
      if (retired.empty())
      {
        return;
      }
      auto& old = retired.front();
      if (old.next == old.run->blocks)
      {
        retired.pop_front();
      }
      else
      {
        storage->remove(key(*old.run, old.next++));
      }
    }

    const Entries* query_block(
      const Run& run, size_t ordinal, std::set<BlockKey>& visited)
    {
      const BlockKey block{run.id, ordinal};
      visited.insert(block);
      if (visited.size() > cache.get_max_size())
      {
        throw std::length_error(fmt::format(
          "Sorted index query exceeds its {}-byte block cache. "
          "Request a smaller seqno range or increase query_cache_bytes.",
          options.query_cache_bytes));
      }
      auto found = cache.find(block);
      if (found == cache.end())
      {
        cache.insert(block, {storage->fetch(key(run, ordinal)), {}});
        return nullptr;
      }
      cache.promote(found);
      auto& value = found->second;
      if (value.pending)
      {
        if (!completed(value.pending))
        {
          return nullptr;
        }
        auto entries = parse(value.pending->contents);
        if (!entries)
        {
          return nullptr;
        }
        value.entries = std::move(*entries);
        value.pending.reset();
        ++query_block_decodes;
      }
      return &value.entries;
    }

    bool query_run(
      const Run& run,
      const Entry& lower,
      const Entry& upper,
      std::set<BlockKey>& visited,
      SeqNoCollection& result)
    {
      const auto boundary = [&](bool end) -> std::optional<size_t> {
        size_t low = 0;
        auto high = run.blocks;
        while (low < high)
        {
          const auto mid = low + (high - low) / 2;
          const auto* entries = query_block(run, mid, visited);
          if (!entries)
          {
            return std::nullopt;
          }
          const auto before =
            end ? !(upper < entries->front()) : entries->back() < lower;
          if (before)
          {
            low = mid + 1;
          }
          else
          {
            high = mid;
          }
        }
        return low;
      };
      const auto first = boundary(false);
      if (rebuild)
      {
        return false;
      }
      const auto end = boundary(true);
      if (!first || !end)
      {
        return false;
      }
      bool complete = true;
      for (auto ordinal = *first; ordinal < *end; ++ordinal)
      {
        const auto* entries = query_block(run, ordinal, visited);
        if (!entries)
        {
          if (rebuild)
          {
            return false;
          }
          complete = false;
          continue;
        }
        for (auto it =
               std::lower_bound(entries->begin(), entries->end(), lower);
             it != entries->end();
             ++it)
        {
          if (upper < *it)
          {
            return complete;
          }
          result.insert(it->second);
        }
      }
      return complete;
    }

    void reset()
    {
      cache.clear();
      buffer.clear();
      buffer_bytes = 0;
      if (work)
      {
        retired.push_back({work->output, 0});
        work.reset();
      }
      if (carry)
      {
        retired.push_back({std::move(carry), 0});
      }
      for (auto& level : levels)
      {
        if (level)
        {
          retired.push_back({std::move(level), 0});
        }
      }
      rebuild = false;
    }

    bool busy() const
    {
      return buffer_bytes >= options.write_buffer_bytes || work.has_value() ||
        carry != nullptr || !retired.empty() || oversized_key || rebuild;
    }
  };

  SeqnosByKey_Sorted_Untyped::SeqnosByKey_Sorted_Untyped(
    const std::string& map_name_,
    ccf::AbstractNodeContext& context,
    const SortedIndexOptions& options) :
    VisitEachEntryInMap(map_name_, "SeqnosByKey")
  {
    if (
      ccf::kv::get_security_domain(map_name_) !=
      ccf::kv::SecurityDomain::PUBLIC)
    {
      throw std::invalid_argument(
        "Sorted file indexes support public tables only");
    }
    impl = std::make_unique<Impl>(
      options, context.get_subsystem<AbstractLFSAccess>());
  }

  SeqnosByKey_Sorted_Untyped::~SeqnosByKey_Sorted_Untyped() = default;

  void SeqnosByKey_Sorted_Untyped::visit_entry(
    const ccf::TxID& txid, const ccf::ByteVector& key, const ccf::ByteVector&)
  {
    if (key.size() + 4 * sizeof(uint64_t) > impl->options.block_bytes)
    {
      LOG_FAIL_FMT("Sorted index key exceeds configured block byte budget");
      impl->oversized_key = true;
      return;
    }
    if (impl->buffer.emplace(key, txid.seqno).second)
    {
      impl->buffer_bytes += key.size() + sizeof(Entry) + 4 * sizeof(void*);
    }
  }

  void SeqnosByKey_Sorted_Untyped::handle_committed_transaction(
    const ccf::TxID& txid, const ccf::kv::ReadOnlyStorePtr& store)
  {
    std::lock_guard<ccf::ds::Mutex> guard(impl->lock);
    if (impl->busy())
    {
      throw std::logic_error(
        "Transaction delivered while sorted index is busy");
    }
    auto tx = store->create_read_only_tx();
    auto* handle = tx.ro<ccf::kv::untyped::Map>(map_name);
    handle->foreach([&](const auto& k, const auto& v) {
      visit_entry(txid, k, v);
      return !impl->oversized_key;
    });
    if (!impl->oversized_key)
    {
      std::lock_guard<ccf::ds::Mutex> watermark_guard(current_txid_lock);
      current_txid = txid;
    }
  }

  std::optional<ccf::SeqNo> SeqnosByKey_Sorted_Untyped::next_requested()
  {
    std::lock_guard<ccf::ds::Mutex> guard(impl->lock);
    if (impl->busy())
    {
      return std::nullopt;
    }
    return VisitEachEntryInMap::next_requested();
  }

  void SeqnosByKey_Sorted_Untyped::tick()
  {
    std::lock_guard<ccf::ds::Mutex> guard(impl->lock);
    if (impl->rebuild)
    {
      impl->reset();
      std::lock_guard<ccf::ds::Mutex> watermark_guard(current_txid_lock);
      current_txid = {};
    }
    advance_maintenance();
  }

  void SeqnosByKey_Sorted_Untyped::advance_maintenance()
  {
    if (impl->oversized_key)
    {
      return;
    }
    if (!impl->retired.empty())
    {
      impl->reclaim();
      return;
    }
    if (impl->work)
    {
      impl->advance_work();
      return;
    }
    if (impl->carry)
    {
      if (impl->carry_level == impl->levels.size())
      {
        throw std::overflow_error("Sorted index level capacity exhausted");
      }
      auto& level = impl->levels[impl->carry_level];
      if (level)
      {
        impl->work = Impl::Work{};
        impl->work->output = impl->new_run();
        impl->work->a.run = level;
        impl->work->b.run = impl->carry;
      }
      else
      {
        level = std::move(impl->carry);
      }
      return;
    }
    if (impl->buffer_bytes >= impl->options.write_buffer_bytes)
    {
      impl->flush();
    }
  }

  std::optional<SeqNoCollection> SeqnosByKey_Sorted_Untyped::get_write_txs_impl(
    const ccf::ByteVector& key, ccf::SeqNo from, ccf::SeqNo to)
  {
    if (from > to)
    {
      throw std::invalid_argument("Index query range goes backwards");
    }
    std::lock_guard<ccf::ds::Mutex> guard(impl->lock);
    {
      std::lock_guard<ccf::ds::Mutex> watermark_guard(current_txid_lock);
      if (impl->rebuild || impl->oversized_key || to > current_txid.seqno)
      {
        return std::nullopt;
      }
    }
    if (key.size() > impl->options.block_bytes - 4 * sizeof(uint64_t))
    {
      // Such a key cannot occur in the completely indexed prefix.
      return SeqNoCollection{};
    }
    const Entry lower{key, from};
    const Entry upper{key, to};
    SeqNoCollection result;
    std::set<Impl::BlockKey> visited;
    for (auto it = impl->buffer.lower_bound(lower);
         it != impl->buffer.end() && !(upper < *it);
         ++it)
    {
      result.insert(it->second);
    }
    const auto query = [&](const auto& run) {
      return !run || run->from > to || run->to < from ||
        impl->query_run(*run, lower, upper, visited, result);
    };
    bool complete = true;
    for (const auto& run : impl->levels)
    {
      if (!query(run))
      {
        if (impl->rebuild)
        {
          return std::nullopt;
        }
        complete = false;
      }
    }
    if (!query(impl->carry))
    {
      return std::nullopt;
    }
    if (!complete)
    {
      return std::nullopt;
    }
    return result;
  }

  nlohmann::json SeqnosByKey_Sorted_Untyped::describe()
  {
    auto j = VisitEachEntryInMap::describe();
    std::lock_guard<ccf::ds::Mutex> guard(impl->lock);
    j["storage"] = "authenticated_plaintext_sorted_runs";
    j["buffer_bytes"] = impl->buffer_bytes;
    j["write_buffer_bytes"] = impl->options.write_buffer_bytes;
    j["block_bytes"] = impl->options.block_bytes;
    j["query_cache_bytes"] = impl->options.query_cache_bytes;
    j["cached_blocks"] = impl->cache.size();
    j["cache_capacity_blocks"] = impl->cache.get_max_size();
    j["cache_block_bytes"] = impl->options.block_bytes * Impl::CACHE_EXPANSION;
    j["cache_reserved_bytes"] =
      impl->cache.size() * impl->options.block_bytes * Impl::CACHE_EXPANSION;
    j["query_block_decodes"] = impl->query_block_decodes;
    j["compaction_active"] = impl->work && !impl->work->flushing;
    j["runs"] = std::count_if(
      impl->levels.begin(), impl->levels.end(), [](const auto& r) {
        return r != nullptr;
      });
    j["retired_runs"] = impl->retired.size();
    j["compactions"] = impl->compactions;
    j["blocks_written"] = impl->blocks_written;
    const auto payload_bytes = [](const auto& block) {
      size_t bytes = 0;
      for (const auto& entry : block.entries)
      {
        bytes += decoded_entry_bytes(entry);
      }
      return bytes;
    };
    size_t cached_bytes = 0;
    if (impl->work)
    {
      cached_bytes += payload_bytes(impl->work->a.block);
      cached_bytes += payload_bytes(impl->work->b.block);
    }
    j["merge_input_decoded_bytes"] = cached_bytes;
    j["decoded_block_limit_bytes"] = impl->decoded_block_limit();
    j["compaction_output_bytes"] = impl->work ? impl->work->bytes : 0;
    j["compaction_output_decoded_bytes"] =
      impl->work ? impl->work->decoded_bytes : 0;
    j["busy"] = impl->busy();
    j["oversized_key"] = impl->oversized_key;
    return j;
  }

}
